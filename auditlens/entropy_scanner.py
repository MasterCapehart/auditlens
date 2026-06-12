"""
AuditLens Entropy Scanner — detect high-entropy secrets in live source files.

Uses Shannon entropy to find credentials, tokens, and keys that don't match
any known pattern but have statistical properties of random secrets.
Complements pattern-based scanning in rules_engine.py.

Usage (integrated into analyzer.py automatically):
    from auditlens.entropy_scanner import scan_file_for_secrets
    findings = scan_file_for_secrets('/path/to/file.py')
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import List, Optional

_ENTROPY_MIN_LEN = 20
_BASE64_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
_HEX_CHARS    = set('0123456789abcdefABCDEF')

# Thresholds calibrated to minimize false positives
_THRESHOLDS = {
    'BASE64': 4.6,
    'HEX':    3.6,
}

# Regex: secret-like variable name followed by an assignment containing a long token
_CONTEXT_RE = re.compile(
    r'(?i)(?:secret|token|key|password|passwd|pwd|auth|credential|'
    r'api[_\-]?key|private[_\-]?key|access[_\-]?key|signing[_\-]?secret|'
    r'client[_\-]?secret|oauth|bearer)\s*[:=]\s*["\']?([A-Za-z0-9+/=_\-]{20,})["\']?'
)

# Skip these — they look like secrets but are benign
_WHITELIST_PREFIXES = (
    'example', 'placeholder', 'your-', 'YOUR_', 'REPLACE',
    'changeme', 'dummy', 'test', 'fake', 'sample', 'xxx',
)
_WHITELIST_VALUES = {
    'base64encodedstring', 'secretkey', 'mysecretkey', 'password123',
    'thisisasecret', 'changethis',
}

_SUPPORTED_EXTS = {'.py', '.js', '.ts', '.mjs', '.jsx', '.tsx', '.env',
                   '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.conf'}


def _entropy(s: str, charset: set) -> float:
    filtered = [c for c in s if c in charset]
    if len(filtered) < _ENTROPY_MIN_LEN:
        return 0.0
    freq: dict = {}
    for c in filtered:
        freq[c] = freq.get(c, 0) + 1
    total = len(filtered)
    return -sum((n / total) * math.log2(n / total) for n in freq.values())


def _is_whitelisted(token: str) -> bool:
    lower = token.lower()
    if any(lower.startswith(p.lower()) for p in _WHITELIST_PREFIXES):
        return True
    if lower in _WHITELIST_VALUES:
        return True
    # All same character — trivially low entropy but pass check somehow
    if len(set(token)) <= 3:
        return True
    return False


def scan_file_for_secrets(file_path: str) -> List[dict]:
    """
    Scan a single file for high-entropy secrets in secret-context assignments.
    Returns list of findings in AuditLens format.
    """
    path = Path(file_path)
    if path.suffix.lower() not in _SUPPORTED_EXTS:
        return []

    try:
        with open(file_path, encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
    except OSError:
        return []

    findings: List[dict] = []
    seen: set = set()

    for lineno, line in enumerate(lines, 1):
        # Skip pure comments
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
            continue

        for m in _CONTEXT_RE.finditer(line):
            token = m.group(1)
            if len(token) < _ENTROPY_MIN_LEN:
                continue
            if _is_whitelisted(token):
                continue

            for charset_name, charset in [('BASE64', _BASE64_CHARS), ('HEX', _HEX_CHARS)]:
                h = _entropy(token, charset)
                if h >= _THRESHOLDS[charset_name]:
                    dedup = f'{file_path}:{lineno}:{token[:16]}'
                    if dedup in seen:
                        continue
                    seen.add(dedup)
                    findings.append({
                        'rule_id': f'ENTROPY-{charset_name}',
                        'name': f'High-Entropy Secret ({charset_name})',
                        'description': (
                            f'High-entropy {charset_name} string (H={h:.2f}) detected in a '
                            f'secret-context variable assignment. This is likely a hardcoded '
                            f'credential, API key, or signing secret. '
                            f'Token preview: "{token[:30]}…". '
                            f'Move to environment variables or a secrets manager.'
                        ),
                        'severity': 'CRITICAL',
                        'compliance': ['CWE-312', 'CWE-798', 'OWASP-A02:2021', 'PCI-8.2.1'],
                        'file': file_path,
                        'line': lineno,
                        'snippet': line.rstrip()[:120],
                        'source': 'ENTROPY',
                    })
                    break  # one hit per token is enough

    return findings
