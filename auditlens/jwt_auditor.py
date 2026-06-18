"""
AuditLens — JWT Security Auditor

Detecta vulnerabilidades en uso de JWT en código fuente:
- Algorithm confusion (alg:none, RS256→HS256)
- Weak/hardcoded secrets
- Missing expiration validation
- JWT hardcodeado en código
- Claims inseguros
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

_SUPPORTED = {'.py', '.js', '.ts', '.mjs', '.jsx', '.tsx', '.java', '.php', '.rb', '.go'}

# Patterns: (regex, rule_id, name, severity, description)
_JWT_PATTERNS = [
    (
        re.compile(r'(?i)algorithm\s*[=:]\s*["\']none["\']'),
        'JWT-ALG-NONE', 'JWT algorithm=none', 'CRITICAL',
        'JWT con algorithm="none" no requiere firma — cualquier token es válido. '
        'CVE-2015-9235. Forzar siempre HS256/RS256.',
    ),
    (
        re.compile(r'(?i)(?:jwt\.decode|verify|decode_token)[^)]*verify\s*=\s*False'),
        'JWT-NO-VERIFY', 'JWT verificación desactivada', 'CRITICAL',
        'La verificación de firma JWT está desactivada. Cualquier token modificado será aceptado.',
    ),
    (
        re.compile(r'(?i)(?:jwt\.decode|verify)[^)]*algorithms\s*=\s*\[[^\]]*(?:HS|RS|ES|PS)'),
        'JWT-ALGO-LIST', 'JWT acepta múltiples algoritmos', 'HIGH',
        'Aceptar múltiples familias de algoritmos (HS+RS) permite algorithm confusion attacks. '
        'Usar una sola familia de algoritmos.',
    ),
    (
        re.compile(
            r'(?i)(?:secret|key|secret_key|jwt_secret)\s*[=:]\s*["\']'
            r'(?:secret|password|changeme|test|dev|example|mysecret|1234)["\']'
        ),
        'JWT-WEAK-SECRET', 'JWT secret débil o de ejemplo', 'CRITICAL',
        'Secret JWT hardcodeado con valor de ejemplo/débil. '
        'Usar secreto aleatorio de 256+ bits desde variable de entorno.',
    ),
    (
        re.compile(
            r'(?i)(?:jwt\.encode|sign)\s*\([^)]*\)'
            r'(?!.*(?:exp|expiresIn|expires_in|expiration))'
        ),
        'JWT-NO-EXP', 'JWT sin expiración', 'HIGH',
        'Token JWT creado sin campo "exp". Los tokens sin expiración son válidos indefinidamente — '
        'riesgo si son robados.',
    ),
    (
        re.compile(
            r'(?i)(?:payload|claims)\s*[=:]\s*\{[^}]*(?:admin|role|is_admin)\s*:\s*'
            r'(?:True|true|1|"admin")[^}]*\}'
        ),
        'JWT-ADMIN-CLAIM', 'JWT con claim de admin en payload', 'HIGH',
        'Claim de privilegio (admin/role) en payload JWT. Si el secret es débil o el alg es none, '
        'un atacante puede forjarlo.',
    ),
    (
        re.compile(
            r'eyJ[A-Za-z0-9+/]{20,}\.[A-Za-z0-9+/]{20,}\.[A-Za-z0-9+/]{10,}'
        ),
        'JWT-HARDCODED', 'JWT token hardcodeado en código', 'CRITICAL',
        'Token JWT real hardcodeado en el código fuente. Puede contener datos sensibles '
        'y es un riesgo si el repositorio es público.',
    ),
    (
        re.compile(r'(?i)(?:hs256|hs384|hs512)\s*(?:and|or|,)\s*(?:rs|es|ps)\d{3}'),
        'JWT-ALGO-CONFUSION', 'Mezcla HS+RS/ES puede permitir confusion attack', 'HIGH',
        'La mezcla de algoritmos simétricos y asimétricos puede permitir algorithm confusion. '
        'Separar claves y algoritmos por tipo de cliente.',
    ),
]


def scan_file_for_jwt_issues(file_path: str) -> List[dict]:
    path = Path(file_path)
    if path.suffix.lower() not in _SUPPORTED:
        return []
    try:
        with open(file_path, encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
    except OSError:
        return []

    findings = []
    seen: set = set()

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(('#', '//', '*')):
            continue
        for pattern, rule_id, name, severity, desc in _JWT_PATTERNS:
            if pattern.search(line):
                key = f'{rule_id}:{file_path}:{lineno}'
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    'rule_id': rule_id,
                    'name': name,
                    'description': desc,
                    'severity': severity,
                    'file': file_path,
                    'line': lineno,
                    'snippet': line.rstrip()[:120],
                    'compliance': ['CWE-347', 'CWE-327', 'OWASP-A02:2021'],
                    'source': 'JWT-AUDITOR',
                })
    return findings


def scan_directory_for_jwt_issues(project_path: str, max_files: int = 500) -> List[dict]:
    skip = {'venv', '.venv', 'node_modules', '.git', '__pycache__', 'build', 'dist'}
    root = Path(project_path).resolve()
    all_findings: List[dict] = []
    count = 0
    for fpath in sorted(root.rglob('*')):
        if count >= max_files:
            break
        if not fpath.is_file():
            continue
        if set(fpath.relative_to(root).parts) & skip:
            continue
        all_findings.extend(scan_file_for_jwt_issues(str(fpath)))
        count += 1
    if all_findings:
        print(f'\033[93m[AuditLens JWT]\033[0m {len(all_findings)} vulnerabilidades JWT detectadas')
    return all_findings
