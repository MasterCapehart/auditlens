"""
AuditLens Baseline Engine — CI diff mode.

Allows teams to save a baseline of accepted findings and only fail on NEW
vulnerabilities introduced since the baseline was saved.

Usage:
    auditlens scan . --save-baseline .auditlens-baseline.json
    auditlens scan . --diff-baseline .auditlens-baseline.json   # exit 1 only on new findings
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, List, Optional


def _fingerprint(finding: dict) -> str:
    """
    Stable fingerprint for a finding.
    Uses rule_id + relative file path + line content (not line number, which drifts).
    This means moving a block of code doesn't invalidate the baseline.
    """
    rel_file = finding.get('file', '')
    # Make path relative to cwd for portability across machines
    try:
        rel_file = os.path.relpath(rel_file)
    except ValueError:
        pass  # Windows cross-drive paths — keep absolute

    line_content = finding.get('line_content', '') or ''
    key = f"{finding.get('rule_id', '')}::{rel_file}::{line_content.strip()}"
    return hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]


def _enrich_with_content(findings: List[dict]) -> List[dict]:
    """
    Add line_content to each finding so fingerprints survive line-number drift.
    """
    enriched = []
    file_cache: Dict[str, List[str]] = {}
    for f in findings:
        fpath = f.get('file', '')
        lineno = f.get('line', 1)
        if fpath not in file_cache:
            try:
                with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                    file_cache[fpath] = fh.readlines()
            except OSError:
                file_cache[fpath] = []
        lines = file_cache[fpath]
        idx = max(0, lineno - 1)
        content = lines[idx].rstrip('\n') if idx < len(lines) else ''
        enriched.append({**f, 'line_content': content})
    return enriched


def save_baseline(findings: List[dict], baseline_path: str) -> None:
    """Persist findings as the new baseline JSON file."""
    enriched = _enrich_with_content(findings)
    baseline: Dict[str, dict] = {}
    for f in enriched:
        fp = _fingerprint(f)
        baseline[fp] = {
            'rule_id': f.get('rule_id'),
            'file': f.get('file'),
            'line': f.get('line'),
            'severity': f.get('severity'),
            'line_content': f.get('line_content', ''),
        }

    os.makedirs(os.path.dirname(os.path.abspath(baseline_path)), exist_ok=True)
    with open(baseline_path, 'w', encoding='utf-8') as fh:
        json.dump({'version': 1, 'findings': baseline}, fh, indent=2)

    print(
        f"\033[92m[AuditLens]\033[0m Baseline saved: {len(baseline)} findings → "
        f"\033[1m{os.path.abspath(baseline_path)}\033[0m"
    )


def load_baseline(baseline_path: str) -> Optional[Dict[str, dict]]:
    """Load a baseline file. Returns None if the file does not exist."""
    if not os.path.exists(baseline_path):
        print(
            f"\033[93m[AuditLens] Warning: baseline file not found: {baseline_path}. "
            f"All findings will be treated as new.\033[0m"
        )
        return None
    try:
        with open(baseline_path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        return data.get('findings', {})
    except (json.JSONDecodeError, OSError) as exc:
        print(f"\033[91m[AuditLens] Error loading baseline: {exc}\033[0m")
        return None


def diff_against_baseline(
    findings: List[dict],
    baseline: Dict[str, dict],
) -> List[dict]:
    """
    Return only findings whose fingerprint is NOT in the baseline.
    These are genuinely new vulnerabilities introduced since the baseline was saved.
    """
    enriched = _enrich_with_content(findings)
    new_findings = []
    for f in enriched:
        fp = _fingerprint(f)
        if fp not in baseline:
            new_findings.append(f)
    return new_findings
