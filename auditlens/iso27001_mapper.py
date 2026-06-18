"""
AuditLens — ISO 27001:2022 Compliance Mapper

Maps AuditLens findings to ISO 27001:2022 Annex A controls.
Generates compliance score and formal report.
"""
from __future__ import annotations
from typing import Any, Dict, List

# ISO 27001:2022 Annex A controls (key subset relevant to code/infra audits)
ISO_CONTROLS: Dict[str, Dict[str, str]] = {
    'A.5.1':  {'title': 'Políticas de seguridad de la información', 'domain': 'Organizacional'},
    'A.5.8':  {'title': 'Seguridad de la información en gestión de proyectos', 'domain': 'Organizacional'},
    'A.5.14': {'title': 'Transferencia de información', 'domain': 'Organizacional'},
    'A.5.15': {'title': 'Control de acceso', 'domain': 'Organizacional'},
    'A.5.17': {'title': 'Información de autenticación', 'domain': 'Organizacional'},
    'A.5.23': {'title': 'Seguridad en servicios en la nube', 'domain': 'Organizacional'},
    'A.5.24': {'title': 'Planificación de gestión de incidentes', 'domain': 'Organizacional'},
    'A.5.26': {'title': 'Respuesta a incidentes de seguridad', 'domain': 'Organizacional'},
    'A.6.8':  {'title': 'Reporte de eventos de seguridad', 'domain': 'Personas'},
    'A.7.1':  {'title': 'Perímetros de seguridad física', 'domain': 'Físico'},
    'A.8.2':  {'title': 'Derechos de acceso privilegiado', 'domain': 'Tecnológico'},
    'A.8.3':  {'title': 'Restricción de acceso a información', 'domain': 'Tecnológico'},
    'A.8.4':  {'title': 'Acceso al código fuente', 'domain': 'Tecnológico'},
    'A.8.5':  {'title': 'Autenticación segura', 'domain': 'Tecnológico'},
    'A.8.6':  {'title': 'Gestión de capacidad', 'domain': 'Tecnológico'},
    'A.8.7':  {'title': 'Protección contra malware', 'domain': 'Tecnológico'},
    'A.8.8':  {'title': 'Gestión de vulnerabilidades técnicas', 'domain': 'Tecnológico'},
    'A.8.9':  {'title': 'Gestión de la configuración', 'domain': 'Tecnológico'},
    'A.8.10': {'title': 'Eliminación de información', 'domain': 'Tecnológico'},
    'A.8.11': {'title': 'Enmascaramiento de datos', 'domain': 'Tecnológico'},
    'A.8.12': {'title': 'Prevención de fuga de datos', 'domain': 'Tecnológico'},
    'A.8.13': {'title': 'Respaldo de información', 'domain': 'Tecnológico'},
    'A.8.16': {'title': 'Monitoreo de actividades', 'domain': 'Tecnológico'},
    'A.8.17': {'title': 'Sincronización de relojes', 'domain': 'Tecnológico'},
    'A.8.18': {'title': 'Uso de programas utilitarios privilegiados', 'domain': 'Tecnológico'},
    'A.8.19': {'title': 'Instalación de software en sistemas operativos', 'domain': 'Tecnológico'},
    'A.8.20': {'title': 'Seguridad en redes', 'domain': 'Tecnológico'},
    'A.8.21': {'title': 'Seguridad de servicios de red', 'domain': 'Tecnológico'},
    'A.8.22': {'title': 'Segregación de redes', 'domain': 'Tecnológico'},
    'A.8.23': {'title': 'Filtrado web', 'domain': 'Tecnológico'},
    'A.8.24': {'title': 'Uso de criptografía', 'domain': 'Tecnológico'},
    'A.8.25': {'title': 'Ciclo de vida de desarrollo seguro', 'domain': 'Tecnológico'},
    'A.8.26': {'title': 'Requisitos de seguridad en aplicaciones', 'domain': 'Tecnológico'},
    'A.8.27': {'title': 'Principios de arquitectura segura', 'domain': 'Tecnológico'},
    'A.8.28': {'title': 'Codificación segura', 'domain': 'Tecnológico'},
    'A.8.29': {'title': 'Pruebas de seguridad en desarrollo', 'domain': 'Tecnológico'},
    'A.8.30': {'title': 'Desarrollo externalizado', 'domain': 'Tecnológico'},
    'A.8.31': {'title': 'Separación de entornos desarrollo/producción', 'domain': 'Tecnológico'},
    'A.8.32': {'title': 'Gestión de cambios', 'domain': 'Tecnológico'},
    'A.8.33': {'title': 'Información de pruebas', 'domain': 'Tecnológico'},
    'A.8.34': {'title': 'Protección de sistemas de información durante auditoría', 'domain': 'Tecnológico'},
}

_RULE_TO_ISO: Dict[str, List[str]] = {
    # Secrets / credentials
    'HARDCODED-PASS':       ['A.5.17', 'A.8.5', 'A.8.28'],
    'HARDCODED-SECRET':     ['A.5.17', 'A.8.5', 'A.8.12', 'A.8.28'],
    'GIT-HARDCODED-PASS':   ['A.5.17', 'A.8.5', 'A.8.4'],
    'GIT-SECRET':           ['A.5.17', 'A.8.4', 'A.8.12'],
    'GIT-ENTROPY-SECRET':   ['A.5.17', 'A.8.12', 'A.8.28'],
    'AWS-KEY':              ['A.5.17', 'A.5.23', 'A.8.12'],
    'ENTROPY-BASE64':       ['A.5.17', 'A.8.12'],
    'ENTROPY-HEX':          ['A.5.17', 'A.8.12'],
    # Injection
    'SQLI':                 ['A.8.26', 'A.8.28', 'A.8.29'],
    'SQLI-CONCAT':          ['A.8.26', 'A.8.28'],
    'SQLI-FSTRING':         ['A.8.26', 'A.8.28'],
    'CMD-INJECT':           ['A.8.26', 'A.8.28', 'A.8.18'],
    'XSS':                  ['A.8.26', 'A.8.28'],
    'XSS-INNER':            ['A.8.26', 'A.8.28'],
    # Crypto
    'WEAK-HASH':            ['A.8.24', 'A.8.28'],
    'WEAK-RANDOM':          ['A.8.24', 'A.8.28'],
    'SSL-NOVERIFY':         ['A.8.20', 'A.8.21', 'A.8.24'],
    # Config
    'DEBUG-ON':             ['A.8.9', 'A.8.31'],
    'IAC':                  ['A.8.9', 'A.8.25'],
    # Deserialization
    'PICKLE':               ['A.8.26', 'A.8.28'],
    'YAML-UNSAFE':          ['A.8.26', 'A.8.28'],
    # SCA
    'SCA':                  ['A.8.8', 'A.8.19'],
    # PII
    'PII-RUT':              ['A.8.11', 'A.8.12'],
    'PII-EMAIL':            ['A.8.11', 'A.8.12'],
    'PII-TELEFONO':         ['A.8.11', 'A.8.12'],
    'PII-TARJETA':          ['A.8.11', 'A.8.12', 'A.8.24'],
    'PII-SALUD':            ['A.8.11', 'A.8.12', 'A.8.24'],
    'PII-SENSIBLE':         ['A.8.11', 'A.8.12'],
    'PII-PASS-LOG':         ['A.5.17', 'A.8.16'],
    'PII-NOMBRE':           ['A.8.11', 'A.8.12'],
    # Auth
    'AUTH':                 ['A.5.15', 'A.8.2', 'A.8.3', 'A.8.5'],
    # Taint
    'TAINT-01':             ['A.8.26', 'A.8.28'],
}

_SEV_WEIGHT = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}


def enrich_with_iso27001(findings: List[dict]) -> List[dict]:
    for f in findings:
        rule_id = f.get('rule_id', '')
        controls = _RULE_TO_ISO.get(rule_id)
        if not controls:
            for key in _RULE_TO_ISO:
                if rule_id.upper().startswith(key.upper()):
                    controls = _RULE_TO_ISO[key]
                    break
        if controls:
            f['iso27001'] = controls
            existing = set(f.get('compliance', []))
            for c in controls:
                existing.add(f'ISO27001-{c}')
            f['compliance'] = sorted(existing)
        else:
            f['iso27001'] = []
    return findings


def calculate_iso_score(findings: List[dict]) -> Dict[str, Any]:
    if not findings:
        return {'score': 100, 'risk_level': 'BAJO', 'controls_violated': [],
                'breakdown': {}, 'total_findings': 0}

    control_deductions: Dict[str, float] = {}
    controls_violated: set = set()

    for f in findings:
        sev = f.get('severity', 'LOW')
        w   = _SEV_WEIGHT.get(sev, 1)
        for ctrl in f.get('iso27001', []):
            controls_violated.add(ctrl)
            cur   = control_deductions.get(ctrl, 0.0)
            delta = min(w * 0.4, 12.0 - cur)
            if delta > 0:
                control_deductions[ctrl] = cur + delta

    score = max(0, round(100 - sum(control_deductions.values())))
    risk  = 'CRÍTICO' if score < 40 else 'ALTO' if score < 60 else 'MEDIO' if score < 80 else 'BAJO'

    return {
        'score': score,
        'risk_level': risk,
        'total_findings': len(findings),
        'controls_violated': sorted(controls_violated),
        'breakdown': {
            c: {
                'title': ISO_CONTROLS.get(c, {}).get('title', ''),
                'domain': ISO_CONTROLS.get(c, {}).get('domain', ''),
                'deduction': round(control_deductions.get(c, 0), 1),
            }
            for c in sorted(controls_violated)
        },
    }


def print_iso_summary(score_data: Dict[str, Any]) -> None:
    C = {'RED': '\033[91m', 'YEL': '\033[93m', 'GRN': '\033[92m',
         'CYN': '\033[94m', 'GRY': '\033[90m', 'BLD': '\033[1m', 'RST': '\033[0m'}
    score = score_data['score']
    risk  = score_data['risk_level']
    sc = C['RED'] if score < 40 else C['YEL'] if score < 70 else C['GRN']
    bar = '█' * (score // 5) + '░' * (20 - score // 5)
    print(f'\n{C["BLD"]}{"=" * 56}')
    print(' ISO 27001:2022 — COMPLIANCE SCORE')
    print(f'{"=" * 56}{C["RST"]}')
    print(f'\n  Score: {sc}{C["BLD"]}{score}/100{C["RST"]}  [{sc}{bar}{C["RST"]}]  Riesgo: {sc}{risk}{C["RST"]}')
    print(f'\n{C["BLD"]}  Controles incumplidos ({len(score_data["controls_violated"])}):{C["RST"]}')
    for ctrl in score_data['controls_violated']:
        info = ISO_CONTROLS.get(ctrl, {})
        ded  = score_data['breakdown'].get(ctrl, {}).get('deduction', 0)
        print(f'  {C["RED"]}•{C["RST"]} {C["BLD"]}{ctrl}{C["RST"]} {info.get("title","")} {C["GRY"]}(-{ded} pts){C["RST"]}')
