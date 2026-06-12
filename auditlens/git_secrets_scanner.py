"""
AuditLens Git Secrets Scanner — escanea historial de commits buscando
secretos que fueron commiteados y luego "borrados" (siguen en el historial).

Usage:
    auditlens git-scan ./repo
    auditlens git-scan ./repo --depth 100 --format docx
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import List, Optional

_SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',        'Hardcoded Password',          'HIGH'),
    (r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\'][A-Za-z0-9_\-]{8,}["\']', 'API Key',              'CRITICAL'),
    (r'(?i)(secret|token|auth_token|access_token)\s*=\s*["\'][^"\']{8,}["\']', 'Secret/Token',       'CRITICAL'),
    (r'(?i)private_key\s*=\s*["\'][^"\']{10,}["\']',                 'Private Key',                 'CRITICAL'),
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',         'Private Key Block',           'CRITICAL'),
    (r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*["\']?[A-Z0-9/+]{16,}', 'AWS Credential','CRITICAL'),
    (r'AKIA[0-9A-Z]{16}',                                             'AWS Access Key ID',           'CRITICAL'),
    (r'(?i)gh[pousr]_[A-Za-z0-9_]{36,}',                             'GitHub Token',                'CRITICAL'),
    (r'(?i)sk-[A-Za-z0-9]{32,}',                                     'OpenAI / Anthropic API Key',  'CRITICAL'),
    (r'(?i)SLACK_TOKEN|xox[baprs]-[0-9A-Za-z\-]{10,}',               'Slack Token',                 'CRITICAL'),
    (r'(?i)(client_secret|oauth_secret)\s*[=:]\s*["\'][^"\']{8,}["\']', 'OAuth Secret',             'CRITICAL'),
    (r'(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}',                        'HTTP Basic Auth Header',      'HIGH'),
    (r'(?i)bearer\s+[A-Za-z0-9\._\-]{20,}',                          'Bearer Token in Code',        'HIGH'),
    (r'(?i)(db_pass|database_password|db_password)\s*[=:]\s*["\'][^"\']{3,}["\']', 'DB Password',   'CRITICAL'),
    (r'(?i)smtp_pass(word)?\s*[=:]\s*["\'][^"\']{4,}["\']',          'SMTP Password',               'HIGH'),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', 'JWT Token',            'HIGH'),
]

_COMPILED = [(re.compile(p), name, sev) for p, name, sev in _SECRET_PATTERNS]

# ── Shannon entropy scanner ────────────────────────────────────────────────────
import math

_ENTROPY_CHARSETS = [
    ('BASE64', set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')),
    ('HEX',    set('0123456789abcdefABCDEF')),
]
_ENTROPY_MIN_LEN = 20      # minimum token length to check
_ENTROPY_THRESHOLD = {
    'BASE64': 4.5,          # high-entropy base64 — likely a secret
    'HEX':    3.5,          # high-entropy hex string
}
# Patterns that surround secret values (assignment or JSON key)
_ENTROPY_CONTEXT_RE = re.compile(
    r'(?i)(?:secret|token|key|password|passwd|pwd|auth|credential|api[_-]?key|'
    r'private[_-]?key|access[_-]?key|signing[_-]?secret)\s*[:=]\s*["\']?([A-Za-z0-9+/=_\-]{20,})["\']?'
)


def _shannon_entropy(s: str, charset: set) -> float:
    """Calculate Shannon entropy of a string over a given character set."""
    s_filtered = [c for c in s if c in charset]
    if len(s_filtered) < _ENTROPY_MIN_LEN:
        return 0.0
    freq: dict = {}
    for c in s_filtered:
        freq[c] = freq.get(c, 0) + 1
    total = len(s_filtered)
    return -sum((n / total) * math.log2(n / total) for n in freq.values())


def _scan_line_entropy(line: str) -> Optional[tuple]:
    """
    Scan a single source line for high-entropy strings in secret-like context.
    Returns (name, severity, token) or None.
    """
    # Only check lines that look like assignments with a potentially secret value
    m = _ENTROPY_CONTEXT_RE.search(line)
    if not m:
        return None

    token = m.group(1)
    if len(token) < _ENTROPY_MIN_LEN:
        return None

    for charset_name, charset in _ENTROPY_CHARSETS:
        entropy = _shannon_entropy(token, charset)
        threshold = _ENTROPY_THRESHOLD.get(charset_name, 4.0)
        if entropy >= threshold:
            return (
                f'High-Entropy Secret ({charset_name}, H={entropy:.2f})',
                'CRITICAL',
                token[:40],
            )
    return None


def _run_git(args: List[str], cwd: str, timeout: int = 60) -> str:
    try:
        result = subprocess.run(
            ['git'] + args, cwd=cwd,
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ''


def scan_git_history(
    repo_path: str,
    max_commits: int = 200,
    branches: str = '--all',
) -> List[dict]:
    """
    Scan git log patches for committed secrets.
    Returns list of findings.
    """
    if not os.path.isdir(os.path.join(repo_path, '.git')):
        print(f'\033[93m[AuditLens Git]\033[0m No .git directory at {repo_path}')
        return []

    print(f'\033[94m[AuditLens Git]\033[0m Escaneando historial ({max_commits} commits)...')

    log_output = _run_git(
        ['log', branches, f'--max-count={max_commits}',
         '--unified=0', '--no-color', '-p',
         '--diff-filter=A',   # only additions
         '--format=COMMIT:%H %ai %s'],
        cwd=repo_path,
    )

    findings: List[dict] = []
    current_commit = ''
    current_msg = ''
    current_date = ''
    current_file = ''
    seen: set = set()

    for line in log_output.splitlines():
        if line.startswith('COMMIT:'):
            parts = line[7:].split(' ', 2)
            current_commit = parts[0] if parts else ''
            current_date = parts[1] if len(parts) > 1 else ''
            current_msg = parts[2] if len(parts) > 2 else ''
        elif line.startswith('+++ b/'):
            current_file = line[6:]
        elif line.startswith('+') and not line.startswith('+++'):
            added_line = line[1:]

            # --- Pattern-based detection ---
            for pattern, name, severity in _COMPILED:
                m = pattern.search(added_line)
                if m:
                    dedup_key = f'{current_commit}:{current_file}:{name}:{m.group(0)[:20]}'
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    findings.append({
                        'rule_id': f'GIT-{name.upper().replace(" ", "-")[:20]}',
                        'name': f'Secret in Git History: {name}',
                        'description': (
                            f'{name} found in commit {current_commit[:8]} ({current_date[:10]}): '
                            f'"{current_msg[:80]}". '
                            f'File: {current_file}. '
                            'Even if later removed, the secret is permanently visible in git history. '
                            'Rotate the credential immediately and consider git history rewrite (git-filter-repo).'
                        ),
                        'severity': severity,
                        'compliance': ['CWE-312', 'CWE-798', 'OWASP-A7:2021', 'ISO-27001:A.9'],
                        'file': current_file,
                        'line': 0,
                        'commit': current_commit,
                        'commit_date': current_date[:10],
                        'commit_msg': current_msg[:100],
                        'source': 'GIT-HISTORY',
                    })

            # --- Entropy-based detection (catches unknown secret formats) ---
            entropy_hit = _scan_line_entropy(added_line)
            if entropy_hit:
                ename, esev, etoken = entropy_hit
                dedup_key = f'{current_commit}:{current_file}:entropy:{etoken[:16]}'
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append({
                        'rule_id': 'GIT-ENTROPY-SECRET',
                        'name': f'Secret in Git History: {ename}',
                        'description': (
                            f'High-entropy string detected in commit {current_commit[:8]} '
                            f'({current_date[:10]}) in {current_file}. '
                            f'Token preview: "{etoken}…". '
                            'This pattern suggests a credential, API key, or signing secret. '
                            'Verify and rotate if sensitive. Consider git history rewrite.'
                        ),
                        'severity': esev,
                        'compliance': ['CWE-312', 'CWE-798', 'OWASP-A2:2021'],
                        'file': current_file,
                        'line': 0,
                        'commit': current_commit,
                        'commit_date': current_date[:10],
                        'commit_msg': current_msg[:100],
                        'source': 'GIT-ENTROPY',
                    })

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f['severity']
        if sev in counts:
            counts[sev] += 1

    print(
        f'\033[92m[AuditLens Git]\033[0m {len(findings)} secretos encontrados en historial '
        f'(CRITICAL:{counts["CRITICAL"]} HIGH:{counts["HIGH"]})'
    )
    return findings
