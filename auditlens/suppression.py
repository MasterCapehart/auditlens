"""
AuditLens Finding Suppression System

Supports three suppression mechanisms:
  1. Inline:  # auditlens: ignore          — suppress this specific line
              # auditlens: ignore RULE-ID   — suppress a specific rule on this line
  2. File:    .auditlens-ignore             — fnmatch patterns + optional rule IDs
  3. Auto:    security-tool whitelist       — subprocess/exec in security tools is expected

.auditlens-ignore format:
    # Comment
    auditlens/web_scanner.py               # ignore all findings in this file
    auditlens/dns_checker.py:CMD-INJECT    # ignore specific rule in specific file
    tests/**                               # glob — ignore entire test directory
    *:WEAK-RANDOM                          # ignore rule everywhere
"""

from __future__ import annotations

import fnmatch
import os
import re
from functools import lru_cache
from typing import List, Optional, Set, Tuple

_INLINE_SUPPRESS_RE = re.compile(
    r'#\s*auditlens\s*:\s*ignore(?:\s+([A-Z0-9_\-]+))?',
    re.IGNORECASE,
)

# Rules that are expected/intentional in security tooling codebases
_SECURITY_TOOL_WHITELIST = {
    'CMD-INJECT',   # security tools legitimately run subprocesses
    'OS-SYSTEM',    # same
    'EVAL',         # rule engines sometimes use eval intentionally
    'PICKLE',       # some serialization is intentional
    'WEAK-HASH',    # tools that compute hashes for comparison
}

_SECURITY_TOOL_MARKERS = {
    'auditlens', 'bandit', 'semgrep', 'trivy', 'snyk',
    'scanner', 'auditor', 'security_tool', 'pentest',
}


def _is_security_tool(project_path: str) -> bool:
    """Heuristic: detect if this project is itself a security tool."""
    name = os.path.basename(os.path.abspath(project_path)).lower()
    if any(m in name for m in _SECURITY_TOOL_MARKERS):
        return True
    # Check setup.py / pyproject.toml for security keywords
    for fname in ('setup.py', 'pyproject.toml', 'README.md'):
        fpath = os.path.join(project_path, fname)
        if os.path.exists(fpath):
            try:
                with open(fpath, encoding='utf-8', errors='replace') as fh:
                    content = fh.read(2000).lower()
                if any(m in content for m in ('sast', 'dast', 'security scanner', 'vulnerability scanner')):
                    return True
            except OSError:
                pass
    return False


@lru_cache(maxsize=8)
def _load_ignore_file(project_root: str) -> List[Tuple[str, Optional[str]]]:
    """
    Load .auditlens-ignore and return list of (file_pattern, rule_id_or_None).
    Cached per project root.
    """
    ignore_path = os.path.join(project_root, '.auditlens-ignore')
    rules: List[Tuple[str, Optional[str]]] = []
    if not os.path.exists(ignore_path):
        return rules
    with open(ignore_path, encoding='utf-8', errors='replace') as fh:
        for raw in fh:
            line = raw.split('#')[0].strip()
            if not line:
                continue
            if ':' in line:
                file_pat, rule_id = line.rsplit(':', 1)
                rules.append((file_pat.strip(), rule_id.strip().upper()))
            else:
                rules.append((line, None))
    return rules


def check_inline_suppress(
    source_line: str,
    rule_id: str,
) -> bool:
    """Return True if this source line carries an inline suppression for rule_id."""
    m = _INLINE_SUPPRESS_RE.search(source_line)
    if not m:
        return False
    suppressed_rule = m.group(1)
    # No specific rule → suppress everything on this line
    if suppressed_rule is None:
        return True
    return suppressed_rule.upper() == rule_id.upper()


def is_suppressed(
    finding: dict,
    project_root: str,
    is_security_tool: Optional[bool] = None,
) -> Tuple[bool, str]:
    """
    Check if a finding should be suppressed.
    Returns (suppressed: bool, reason: str).
    """
    rule_id   = finding.get('rule_id', '')
    file_path = finding.get('file', '')
    line_num  = int(finding.get('line', 0))

    # 1. Inline suppression — read the actual source line
    if file_path and line_num > 0 and os.path.isfile(file_path):
        try:
            with open(file_path, encoding='utf-8', errors='replace') as fh:
                lines = fh.readlines()
            if 0 < line_num <= len(lines):
                src_line = lines[line_num - 1]
                if check_inline_suppress(src_line, rule_id):
                    return True, 'inline suppression (# auditlens: ignore)'
        except OSError:
            pass

    # 2. .auditlens-ignore file
    ignore_rules = _load_ignore_file(project_root)
    rel_path = os.path.relpath(file_path, project_root) if file_path else ''
    for file_pat, supp_rule_id in ignore_rules:
        if fnmatch.fnmatch(rel_path, file_pat) or fnmatch.fnmatch(file_path, file_pat):
            if supp_rule_id is None or supp_rule_id == rule_id.upper():
                return True, f'.auditlens-ignore match: {file_pat}'

    # 3. Security tool auto-whitelist
    if is_security_tool is None:
        is_security_tool = _is_security_tool(project_root)
    if is_security_tool and rule_id.upper() in _SECURITY_TOOL_WHITELIST:
        return True, 'security-tool whitelist (intentional use in security tool)'

    return False, ''


def filter_suppressed(
    findings: List[dict],
    project_root: str,
    verbose: bool = False,
) -> Tuple[List[dict], List[dict]]:
    """
    Split findings into (active, suppressed).
    Attaches suppression_reason to each suppressed finding.
    """
    is_sec_tool = _is_security_tool(project_root)
    active: List[dict] = []
    suppressed: List[dict] = []

    for f in findings:
        suppressed_flag, reason = is_suppressed(f, project_root, is_sec_tool)
        if suppressed_flag:
            f = dict(f, suppressed=True, suppression_reason=reason)
            suppressed.append(f)
            if verbose:
                print(
                    f'\033[90m[suppress]\033[0m {f.get("rule_id")} '
                    f'{f.get("file","")}:{f.get("line","")} — {reason}'
                )
        else:
            active.append(f)

    return active, suppressed
