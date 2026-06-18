"""
AuditLens — CMF Circular 57 + Norma 461 Compliance Mapper (Chile)

Circular 57 (2021): Seguridad de la Información y Ciberseguridad — bancos, cooperativas,
emisores de tarjetas, empresas de servicios de pago.

Norma 461 (2020): Empresas de valores, corredoras, administradoras de fondos.
"""
from __future__ import annotations
from typing import Any, Dict, List

CMF_CIRCULAR57: Dict[str, Dict[str, str]] = {
    'C57-1.1':  {'title': 'Política de seguridad de la información', 'capitulo': 'Cap. 1 Gobernanza'},
    'C57-1.2':  {'title': 'Comité de seguridad y roles formales', 'capitulo': 'Cap. 1 Gobernanza'},
    'C57-2.1':  {'title': 'Clasificación y gestión de activos de información', 'capitulo': 'Cap. 2 Activos'},
    'C57-3.1':  {'title': 'Control de acceso lógico — autenticación fuerte', 'capitulo': 'Cap. 3 Acceso'},
    'C57-3.2':  {'title': 'Gestión de cuentas privilegiadas', 'capitulo': 'Cap. 3 Acceso'},
    'C57-3.3':  {'title': 'Segregación de funciones en sistemas críticos', 'capitulo': 'Cap. 3 Acceso'},
    'C57-4.1':  {'title': 'Cifrado en tránsito y en reposo (TLS 1.2+)', 'capitulo': 'Cap. 4 Criptografía'},
    'C57-4.2':  {'title': 'Gestión segura de claves criptográficas', 'capitulo': 'Cap. 4 Criptografía'},
    'C57-5.1':  {'title': 'Seguridad en desarrollo de software (SDLC)', 'capitulo': 'Cap. 5 Desarrollo'},
    'C57-5.2':  {'title': 'Análisis de vulnerabilidades antes de producción', 'capitulo': 'Cap. 5 Desarrollo'},
    'C57-5.3':  {'title': 'Separación de ambientes dev/QA/prod', 'capitulo': 'Cap. 5 Desarrollo'},
    'C57-6.1':  {'title': 'Detección y respuesta a incidentes cibernéticos', 'capitulo': 'Cap. 6 Incidentes'},
    'C57-6.2':  {'title': 'Notificación a CMF en plazo máximo 24h', 'capitulo': 'Cap. 6 Incidentes'},
    'C57-7.1':  {'title': 'Gestión de vulnerabilidades y parches', 'capitulo': 'Cap. 7 Vulnerabilidades'},
    'C57-7.2':  {'title': 'Pruebas de penetración periódicas', 'capitulo': 'Cap. 7 Vulnerabilidades'},
    'C57-8.1':  {'title': 'Seguridad en servicios de terceros y proveedores', 'capitulo': 'Cap. 8 Terceros'},
    'C57-9.1':  {'title': 'Continuidad operacional — RTO/RPO definidos', 'capitulo': 'Cap. 9 Continuidad'},
    'C57-10.1': {'title': 'Monitoreo continuo de eventos de seguridad (SIEM)', 'capitulo': 'Cap. 10 Monitoreo'},
}

CMF_NORMA461: Dict[str, Dict[str, str]] = {
    'N461-1':  {'title': 'Seguridad de sistemas de negociación electrónica', 'capitulo': 'Parte I'},
    'N461-2':  {'title': 'Integridad de datos de transacciones', 'capitulo': 'Parte I'},
    'N461-3':  {'title': 'Control de acceso a sistemas de valores', 'capitulo': 'Parte II'},
    'N461-4':  {'title': 'Cifrado de datos de clientes e inversiones', 'capitulo': 'Parte II'},
    'N461-5':  {'title': 'Auditoría de logs de transacciones', 'capitulo': 'Parte III'},
    'N461-6':  {'title': 'Continuidad de sistemas críticos de valores', 'capitulo': 'Parte III'},
}

_RULE_TO_CMF: Dict[str, List[str]] = {
    'HARDCODED-PASS':     ['C57-3.1', 'C57-4.2'],
    'HARDCODED-SECRET':   ['C57-3.1', 'C57-4.2', 'C57-5.1'],
    'GIT-SECRET':         ['C57-3.1', 'C57-4.2'],
    'GIT-ENTROPY-SECRET': ['C57-4.2', 'C57-5.1'],
    'AWS-KEY':            ['C57-3.2', 'C57-4.2'],
    'ENTROPY-BASE64':     ['C57-4.2'],
    'SSL-NOVERIFY':       ['C57-4.1'],
    'WEAK-HASH':          ['C57-4.1', 'C57-4.2'],
    'WEAK-RANDOM':        ['C57-4.1'],
    'SQLI':               ['C57-5.1', 'C57-5.2', 'C57-6.1'],
    'SQLI-CONCAT':        ['C57-5.1', 'C57-5.2'],
    'CMD-INJECT':         ['C57-5.1', 'C57-5.2'],
    'XSS':                ['C57-5.1', 'C57-5.2'],
    'DEBUG-ON':           ['C57-5.3', 'C57-3.3'],
    'SCA':                ['C57-7.1', 'C57-7.2'],
    'IAC':                ['C57-5.3', 'C57-9.1'],
    'PII-TARJETA':        ['C57-4.1', 'N461-4'],
    'PII-CUENTA-BANCARIA':['C57-4.1', 'N461-4'],
    'PII-RUT':            ['C57-2.1', 'C57-4.1'],
    'PII-SALUD':          ['C57-2.1', 'C57-4.1'],
    'PII-PASS-LOG':       ['C57-3.1', 'C57-10.1'],
    'AUTH':               ['C57-3.1', 'C57-3.2'],
    'PICKLE':             ['C57-5.1', 'C57-5.2'],
    'YAML-UNSAFE':        ['C57-5.1', 'C57-5.2'],
    'TAINT-01':           ['C57-5.1', 'C57-5.2'],
}

_SEV_WEIGHT = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}


def enrich_with_cmf(findings: List[dict]) -> List[dict]:
    for f in findings:
        rule_id = f.get('rule_id', '')
        controls = _RULE_TO_CMF.get(rule_id)
        if not controls:
            for key in _RULE_TO_CMF:
                if rule_id.upper().startswith(key.upper()):
                    controls = _RULE_TO_CMF[key]
                    break
        if controls:
            f['cmf'] = controls
            existing = set(f.get('compliance', []))
            for c in controls:
                existing.add(f'CMF-{c}')
            f['compliance'] = sorted(existing)
        else:
            f['cmf'] = []
    return findings


def calculate_cmf_score(findings: List[dict]) -> Dict[str, Any]:
    if not findings:
        return {'score': 100, 'risk_level': 'BAJO', 'controls_violated': [],
                'breakdown': {}, 'total_findings': 0}

    ctrl_ded: Dict[str, float] = {}
    violated: set = set()

    for f in findings:
        w = _SEV_WEIGHT.get(f.get('severity', 'LOW'), 1)
        for c in f.get('cmf', []):
            violated.add(c)
            cur   = ctrl_ded.get(c, 0.0)
            delta = min(w * 0.5, 15.0 - cur)
            if delta > 0:
                ctrl_ded[c] = cur + delta

    score = max(0, round(100 - sum(ctrl_ded.values())))
    risk  = 'CRÍTICO' if score < 40 else 'ALTO' if score < 60 else 'MEDIO' if score < 80 else 'BAJO'

    all_controls = {**CMF_CIRCULAR57, **CMF_NORMA461}
    return {
        'score': score,
        'risk_level': risk,
        'total_findings': len(findings),
        'controls_violated': sorted(violated),
        'breakdown': {
            c: {
                'title': all_controls.get(c, {}).get('title', ''),
                'capitulo': all_controls.get(c, {}).get('capitulo', ''),
                'deduction': round(ctrl_ded.get(c, 0), 1),
            }
            for c in sorted(violated)
        },
        'multa_estimada': (
            'Riesgo sanción grave CMF: hasta UF 10.000 (~$390M CLP)'
            if score < 60 else
            'Riesgo observación/sanción leve CMF'
        ),
    }


def print_cmf_summary(score_data: Dict[str, Any]) -> None:
    C = {'RED': '\033[91m', 'YEL': '\033[93m', 'GRN': '\033[92m',
         'BLD': '\033[1m', 'GRY': '\033[90m', 'RST': '\033[0m'}
    score = score_data['score']
    sc = C['RED'] if score < 40 else C['YEL'] if score < 70 else C['GRN']
    bar = '█' * (score // 5) + '░' * (20 - score // 5)
    print(f'\n{C["BLD"]}{"=" * 56}')
    print(' CMF — CIRCULAR 57 / NORMA 461 COMPLIANCE')
    print(f'{"=" * 56}{C["RST"]}')
    print(f'\n  Score: {sc}{C["BLD"]}{score}/100{C["RST"]}  [{sc}{bar}{C["RST"]}]  '
          f'Riesgo: {sc}{score_data["risk_level"]}{C["RST"]}')
    print(f'  {C["YEL"]}{score_data.get("multa_estimada","")}{C["RST"]}')
    all_controls = {**CMF_CIRCULAR57, **CMF_NORMA461}
    if score_data['controls_violated']:
        print(f'\n{C["BLD"]}  Controles incumplidos:{C["RST"]}')
        for c in score_data['controls_violated']:
            info = all_controls.get(c, {})
            ded  = score_data['breakdown'].get(c, {}).get('deduction', 0)
            print(f'  {C["RED"]}•{C["RST"]} {C["BLD"]}{c}{C["RST"]} {info.get("title","")} '
                  f'{C["GRY"]}(-{ded} pts){C["RST"]}')
