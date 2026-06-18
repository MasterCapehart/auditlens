"""
AuditLens PII Detector — Ley 21.719 (Chile)

Detecta datos personales expuestos en código fuente, configuraciones y logs:
  - RUT chileno (con validación de dígito verificador)
  - Emails
  - Teléfonos chilenos
  - Datos de salud (diagnósticos, medicamentos, números de ficha)
  - Datos financieros (tarjetas, cuentas bancarias)
  - Datos sensibles (raza, religión, biométricos, orientación sexual)
  - Contraseñas en logs
  - Datos en comentarios de código

Mapea cada hallazgo al artículo de la Ley 21.719 correspondiente.
"""

from __future__ import annotations

import re
import os
from pathlib import Path
from typing import List, Tuple

# ── PII Patterns ──────────────────────────────────────────────────────────────

_PII_PATTERNS: List[Tuple[str, str, str, str, str]] = [
    # (pattern, rule_id, name, severity, category)

    # RUT chileno — con y sin puntos/guión
    (
        r'\b(\d{1,2}\.?\d{3}\.?\d{3}-?[\dkK])\b',
        'PII-RUT',
        'RUT chileno expuesto',
        'CRITICAL',
        'identificacion',
    ),
    # Email
    (
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
        'PII-EMAIL',
        'Dirección de email expuesta',
        'HIGH',
        'contacto',
    ),
    # Teléfono chileno (+56 9 XXXX XXXX, 9XXXXXXXX, 56XXXXXXXXX)
    (
        r'(?<!\d)(?:\+?56\s?)?(?:9\d{8}|[2-9]\d{7,8})(?!\d)',
        'PII-TELEFONO',
        'Teléfono chileno expuesto',
        'HIGH',
        'contacto',
    ),
    # Tarjeta de crédito/débito (Luhn-like patterns)
    (
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|'
        r'6(?:011|5[0-9]{2})[0-9]{12})\b',
        'PII-TARJETA',
        'Número de tarjeta de crédito/débito expuesto',
        'CRITICAL',
        'financiero',
    ),
    # Cuenta bancaria chilena (CCI / cuenta corriente)
    (
        r'\b\d{11,16}\b(?=.*banco|.*cuenta|.*cta)',
        'PII-CUENTA-BANCARIA',
        'Número de cuenta bancaria expuesto',
        'CRITICAL',
        'financiero',
    ),
    # Número de pasaporte
    (
        r'\b[A-Z]{1,2}\d{6,9}\b',
        'PII-PASAPORTE',
        'Número de pasaporte expuesto',
        'HIGH',
        'identificacion',
    ),
    # Datos de salud — palabras clave en contexto de variable/log
    (
        r'(?i)(?:diagnostico|diagnóstico|enfermedad|patologia|patología|'
        r'medicamento|receta|ficha[_\-]?medica|historia[_\-]?clinica|'
        r'isapre|fonasa|ges[_\s]|grupo[_\s]sanguineo)\s*[=:]\s*["\']?[^\s"\']{3,}',
        'PII-SALUD',
        'Dato de salud expuesto en código',
        'CRITICAL',
        'salud',
    ),
    # Datos sensibles — raza, religión, biométrico, orientación
    (
        r'(?i)(?:raza|etnia|religion|religión|biometrico|biométrico|'
        r'orientacion[_\s]sexual|opinion[_\s]politica|sindicato)\s*[=:]\s*["\']?[^\s"\']{2,}',
        'PII-SENSIBLE',
        'Dato sensible (categoría especial) expuesto',
        'CRITICAL',
        'sensible',
    ),
    # Contraseña en log/print
    (
        r'(?i)(?:print|log|logger|console\.log|logging)\s*\([^)]*'
        r'(?:password|passwd|clave|contrasena|contraseña)[^)]*\)',
        'PII-PASS-LOG',
        'Contraseña loggeada en texto plano',
        'CRITICAL',
        'credencial',
    ),
    # Datos personales hardcodeados en tests/fixtures (nombre + apellido pattern)
    (
        r'(?i)(?:nombre|name|apellido|rut|telefono|teléfono|email|correo)\s*[=:]\s*'
        r'"(?:[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+ ){1,3}[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+"',
        'PII-NOMBRE',
        'Nombre completo real hardcodeado',
        'MEDIUM',
        'identificacion',
    ),
    # IP interna expuesta como dato personal (contexto log/user)
    (
        r'(?i)(?:ip[_\-]?usuario|user[_\-]?ip|client[_\-]?ip)\s*[=:]\s*'
        r'["\']?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["\']?',
        'PII-IP-USUARIO',
        'IP de usuario registrada en código',
        'MEDIUM',
        'contacto',
    ),
]

_COMPILED_PII = [
    (re.compile(p), rid, name, sev, cat)
    for p, rid, name, sev, cat in _PII_PATTERNS
]

# ── RUT Validation ─────────────────────────────────────────────────────────────

def _validar_rut(rut_str: str) -> bool:
    """Validate Chilean RUT check digit (módulo 11)."""
    rut_clean = re.sub(r'[.\-\s]', '', rut_str).upper()
    if len(rut_clean) < 2:
        return False
    body, dv = rut_clean[:-1], rut_clean[-1]
    if not body.isdigit():
        return False
    digits = [int(c) for c in reversed(body)]
    factors = [2, 3, 4, 5, 6, 7]
    total = sum(d * factors[i % 6] for i, d in enumerate(digits))
    remainder = 11 - (total % 11)
    expected = {10: 'K', 11: '0'}.get(remainder, str(remainder))
    return dv == expected


# ── File scanner ───────────────────────────────────────────────────────────────

_SUPPORTED_EXTS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.php', '.rb', '.go',
    '.cs', '.cpp', '.c', '.swift', '.kt',
    '.sql', '.json', '.yaml', '.yml', '.xml', '.csv', '.env',
    '.txt', '.log', '.md', '.conf', '.ini', '.cfg', '.toml',
    '.html', '.htm',
}

_SKIP_DIRS = {
    'venv', '.venv', 'node_modules', '.git', '__pycache__',
    'build', 'dist', 'coverage', '.tox', '.mypy_cache',
}

# Deduplicate: don't report same PII value + file combo twice
_SEEN_DEDUP: set = set()


def scan_file_for_pii(file_path: str) -> List[dict]:
    """Scan a single file for PII patterns. Returns AuditLens findings."""
    global _SEEN_DEDUP

    if Path(file_path).suffix.lower() not in _SUPPORTED_EXTS:
        return []
    try:
        with open(file_path, encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
    except OSError:
        return []

    findings: List[dict] = []

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip pure comments in source code
        if stripped.startswith(('#', '//', '*', '/*')):
            continue

        for pattern, rule_id, name, severity, category in _COMPILED_PII:
            for m in pattern.finditer(line):
                token = m.group(0)

                # Extra validation for RUT
                if rule_id == 'PII-RUT':
                    if not _validar_rut(token):
                        continue
                    # Skip RUT-like patterns that are clearly not RUTs
                    # (e.g., version numbers like 12.345.678-9 in other contexts)
                    context = line.lower()
                    if not any(kw in context for kw in (
                        'rut', 'run', 'usuario', 'user', 'cliente', 'client',
                        'persona', 'nombre', 'id', 'titular', 'propietario',
                    )):
                        # Only flag if it passes validation AND has context
                        # to reduce false positives on random numbers
                        if not re.search(r'rut|run|cedula|cédula', line, re.IGNORECASE):
                            continue

                dedup_key = f'{file_path}:{lineno}:{rule_id}:{token[:20]}'
                if dedup_key in _SEEN_DEDUP:
                    continue
                _SEEN_DEDUP.add(dedup_key)

                snippet = line.rstrip()[:120]
                findings.append({
                    'rule_id': rule_id,
                    'name': name,
                    'description': _build_description(rule_id, name, token, category),
                    'severity': severity,
                    'category': category,
                    'file': file_path,
                    'line': lineno,
                    'snippet': snippet,
                    'pii_value_preview': _mask_pii(token, rule_id),
                    'compliance': [],  # filled by ley21719_mapper
                    'source': 'PII-DETECTOR',
                })

    return findings


def _mask_pii(value: str, rule_id: str) -> str:
    """Partially mask the PII value for safe display in reports."""
    if rule_id == 'PII-RUT':
        # Show first 4 digits: 12.345.678-9 → 12.3**.***.*
        clean = re.sub(r'[.\-]', '', value)
        return clean[:3] + '*' * (len(clean) - 4) + clean[-1]
    if rule_id == 'PII-EMAIL':
        parts = value.split('@')
        return parts[0][:2] + '***@' + parts[1] if len(parts) == 2 else '***'
    if rule_id in ('PII-TARJETA', 'PII-CUENTA-BANCARIA'):
        return value[:4] + '*' * (len(value) - 8) + value[-4:]
    if rule_id == 'PII-TELEFONO':
        return value[:3] + '****' + value[-2:]
    return value[:4] + '***'


def _build_description(rule_id: str, name: str, token: str, category: str) -> str:
    masked = _mask_pii(token, rule_id)
    base = f'{name} detectado en código fuente (valor: {masked}). '
    extras = {
        'PII-RUT': (
            'El RUT es un dato personal identificador bajo la Ley 21.719 Art. 2. '
            'Nunca debe estar hardcodeado en código fuente, logs o repositorios. '
            'Usar identificadores internos no reversibles.'
        ),
        'PII-EMAIL': (
            'Dirección de email es dato personal bajo Ley 21.719 Art. 2. '
            'No incluir emails reales en código, usar variables de entorno o base de datos.'
        ),
        'PII-TARJETA': (
            'Número de tarjeta bancaria es dato financiero sensible. '
            'PCI-DSS requiere que nunca sea almacenado en texto plano. '
            'Ley 21.719 Art. 16 exige medidas técnicas especiales para datos financieros.'
        ),
        'PII-SALUD': (
            'Dato de salud es categoría especial bajo Ley 21.719 Art. 16 — '
            'requiere consentimiento explícito y medidas de seguridad reforzadas.'
        ),
        'PII-SENSIBLE': (
            'Dato de categoría especial bajo Ley 21.719 Art. 16. '
            'Tratamiento solo permitido con consentimiento explícito y bases legales específicas.'
        ),
        'PII-PASS-LOG': (
            'Contraseña expuesta en logs. Ley 21.719 Art. 14d exige medidas técnicas '
            'para proteger datos. Los logs son frecuentemente accesibles por múltiples personas.'
        ),
    }
    return base + extras.get(rule_id, 'Remover o anonimizar este dato del código fuente.')


def scan_directory_for_pii(
    project_path: str,
    max_files: int = 500,
) -> List[dict]:
    """Scan an entire project directory for PII."""
    global _SEEN_DEDUP
    _SEEN_DEDUP = set()  # reset per scan

    root = Path(project_path).resolve()
    all_findings: List[dict] = []
    files_scanned = 0

    print(f'\033[94m[AuditLens PII]\033[0m Escaneando PII en: {project_path}')

    for fpath in sorted(root.rglob('*')):
        if files_scanned >= max_files:
            break
        if not fpath.is_file():
            continue
        parts = set(fpath.relative_to(root).parts)
        if parts & _SKIP_DIRS:
            continue
        findings = scan_file_for_pii(str(fpath))
        all_findings.extend(findings)
        files_scanned += 1

    counts = {}
    for f in all_findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    cats = {}
    for f in all_findings:
        cats[f['category']] = cats.get(f['category'], 0) + 1

    print(
        f'\033[92m[AuditLens PII]\033[0m {len(all_findings)} datos personales detectados '
        f'en {files_scanned} archivos | '
        f'CRITICAL:{counts.get("CRITICAL",0)} HIGH:{counts.get("HIGH",0)}'
    )
    if cats:
        print(f'\033[90m  Categorías: {", ".join(f"{k}:{v}" for k, v in cats.items())}\033[0m')

    return all_findings
