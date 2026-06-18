"""
AuditLens — Ley 21.719 Compliance Mapper (Chile)

Mapea hallazgos de AuditLens a los artículos específicos de la
Ley 21.719 sobre Protección de Datos Personales (Chile, 2023).

La ley entró en vigor con plazo de 24 meses desde diciembre 2023.
Vigencia plena: diciembre 2025 / enero 2026.

Referencia: https://www.bcn.cl/leychile/navegar?idNorma=1202434
"""

from __future__ import annotations

from typing import Any, Dict, List

# ── Artículos relevantes de la Ley 21.719 ─────────────────────────────────────

LEY_ARTICULOS: Dict[str, Dict[str, str]] = {
    'Art.2':  {
        'titulo': 'Definición de datos personales',
        'resumen': 'Define qué constituye un dato personal: nombre, RUT, email, '
                   'teléfono, IP, ubicación, u otro identificador.',
        'obligacion': 'El responsable debe identificar qué datos personales trata.',
    },
    'Art.12': {
        'titulo': 'Licitud del tratamiento',
        'resumen': 'El tratamiento de datos requiere base legal: consentimiento, '
                   'obligación legal, interés legítimo u otro.',
        'obligacion': 'Toda operación con datos personales debe tener base legal explícita.',
    },
    'Art.13': {
        'titulo': 'Consentimiento del titular',
        'resumen': 'El consentimiento debe ser libre, informado, específico y '
                   'otorgado de forma inequívoca.',
        'obligacion': 'Sin consentimiento válido, el tratamiento es ilícito.',
    },
    'Art.14': {
        'titulo': 'Principios del tratamiento',
        'resumen': 'Finalidad, proporcionalidad, calidad, seguridad, '
                   'responsabilidad proactiva.',
        'obligacion': 'Los datos deben tratarse solo para la finalidad declarada, '
                      'con medidas de seguridad adecuadas.',
    },
    'Art.14b': {
        'titulo': 'Obligaciones del responsable',
        'resumen': 'Implementar medidas técnicas y organizacionales para '
                   'proteger los datos personales.',
        'obligacion': 'Seguridad técnica: cifrado, control de acceso, '
                      'pseudonimización, backups seguros.',
    },
    'Art.14c': {
        'titulo': 'Registro de actividades de tratamiento',
        'resumen': 'Mantener un registro actualizado de qué datos se tratan, '
                   'con qué finalidad, quién tiene acceso, etc.',
        'obligacion': 'Documentar y mantener actualizado el inventario de datos.',
    },
    'Art.14d': {
        'titulo': 'Medidas de seguridad técnica',
        'resumen': 'Implementar medidas técnicas apropiadas: cifrado en tránsito '
                   'y reposo, gestión de accesos, auditoría.',
        'obligacion': 'El código que maneja datos personales debe usar TLS, '
                      'cifrado, y no exponer datos en logs o código fuente.',
    },
    'Art.16': {
        'titulo': 'Datos de categorías especiales',
        'resumen': 'Datos sensibles: salud, origen racial, religión, biometría, '
                   'orientación sexual, opiniones políticas, datos sindicales.',
        'obligacion': 'Tratamiento solo con consentimiento explícito y '
                      'medidas de seguridad reforzadas.',
    },
    'Art.25': {
        'titulo': 'Notificación de vulneraciones',
        'resumen': 'En caso de brecha de seguridad que afecte datos personales, '
                   'notificar a la Agencia en 72 horas.',
        'obligacion': 'Tener mecanismos de detección de brechas y protocolo '
                      'de notificación en menos de 72h.',
    },
    'Art.28': {
        'titulo': 'Evaluación de Impacto (EIPD)',
        'resumen': 'Obligatoria cuando el tratamiento pueda suponer un alto '
                   'riesgo para los derechos y libertades.',
        'obligacion': 'Realizar EIPD antes de procesar datos sensibles o a gran escala.',
    },
    'Art.33': {
        'titulo': 'Derecho de acceso, rectificación, cancelación y oposición (ARCOP)',
        'resumen': 'Los titulares pueden ejercer derechos de acceso, '
                   'rectificación, cancelación y oposición.',
        'obligacion': 'El sistema debe permitir técnicamente el ejercicio de estos derechos.',
    },
    'Art.49': {
        'titulo': 'Infracciones y multas',
        'resumen': 'Multas de hasta 5.000 UTM (infracción leve), 10.000 UTM '
                   '(grave) o 20.000 UTM (gravísima).',
        'obligacion': 'El incumplimiento de las obligaciones anteriores puede '
                      'resultar en multas significativas.',
    },
}

# ── Tabla de mapeo rule_id → artículos ────────────────────────────────────────

_RULE_TO_ARTICULOS: Dict[str, List[str]] = {

    # PII detectada en código
    'PII-RUT':              ['Art.2', 'Art.14', 'Art.14d', 'Art.14c'],
    'PII-EMAIL':            ['Art.2', 'Art.14', 'Art.14d'],
    'PII-TELEFONO':         ['Art.2', 'Art.14', 'Art.14d'],
    'PII-NOMBRE':           ['Art.2', 'Art.14', 'Art.14d'],
    'PII-IP-USUARIO':       ['Art.2', 'Art.14', 'Art.14d'],
    'PII-TARJETA':          ['Art.2', 'Art.14', 'Art.14d', 'Art.49'],
    'PII-CUENTA-BANCARIA':  ['Art.2', 'Art.14', 'Art.14d', 'Art.49'],
    'PII-PASAPORTE':        ['Art.2', 'Art.14', 'Art.14d'],
    'PII-SALUD':            ['Art.2', 'Art.16', 'Art.14d', 'Art.28', 'Art.49'],
    'PII-SENSIBLE':         ['Art.2', 'Art.16', 'Art.14d', 'Art.28', 'Art.49'],
    'PII-PASS-LOG':         ['Art.14d', 'Art.14b', 'Art.25'],

    # Seguridad técnica
    'SSL-NOVERIFY':         ['Art.14d', 'Art.14b'],
    'WEAK-HASH':            ['Art.14d', 'Art.14b'],
    'WEAK-RANDOM':          ['Art.14d'],
    'HARDCODED-PASS':       ['Art.14d', 'Art.14b', 'Art.25'],
    'HARDCODED-SECRET':     ['Art.14d', 'Art.14b', 'Art.25'],
    'GIT-HARDCODED-PASS':   ['Art.14d', 'Art.14b', 'Art.25'],
    'GIT-SECRET':           ['Art.14d', 'Art.14b', 'Art.25'],
    'GIT-ENTROPY-SECRET':   ['Art.14d', 'Art.14b', 'Art.25'],
    'ENTROPY-BASE64':       ['Art.14d', 'Art.14b'],
    'ENTROPY-HEX':          ['Art.14d', 'Art.14b'],
    'AWS-KEY':              ['Art.14d', 'Art.14b', 'Art.25'],
    'GIT-AWS-CREDENTIAL':   ['Art.14d', 'Art.14b', 'Art.25'],
    'DEBUG-ON':             ['Art.14d', 'Art.14b'],

    # Inyección (riesgo de fuga o modificación de datos personales)
    'SQLI':                 ['Art.14d', 'Art.14b', 'Art.25', 'Art.49'],
    'SQLI-CONCAT':          ['Art.14d', 'Art.14b', 'Art.25', 'Art.49'],
    'SQLI-FSTRING':         ['Art.14d', 'Art.14b', 'Art.25', 'Art.49'],
    'CMD-INJECT':           ['Art.14d', 'Art.14b', 'Art.25'],
    'XSS':                  ['Art.14d', 'Art.14b'],
    'XSS-INNER':            ['Art.14d', 'Art.14b'],

    # Deserialización insegura
    'PICKLE':               ['Art.14d', 'Art.14b'],
    'YAML-UNSAFE':          ['Art.14d', 'Art.14b'],

    # SCA — dependencias vulnerables
    'SCA':                  ['Art.14b', 'Art.14d'],

    # IaC
    'IAC':                  ['Art.14b', 'Art.14d'],

    # Auth
    'AUTH':                 ['Art.14d', 'Art.33'],

    # AST findings
    'AST-01-HARDCODED-SENSITIVE': ['Art.14d', 'Art.14b', 'Art.25'],
    'AST-02':               ['Art.14d', 'Art.49'],
    'AST-03':               ['Art.14d', 'Art.14b'],
}

# ── Peso de gravedad para el score ────────────────────────────────────────────
_SEV_WEIGHT = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}


def enrich_with_ley21719(findings: List[dict]) -> List[dict]:
    """Add Ley 21.719 article references to each finding."""
    for f in findings:
        rule_id = f.get('rule_id', '')
        # Exact match first, then prefix match
        articulos = _RULE_TO_ARTICULOS.get(rule_id)
        if not articulos:
            for key in _RULE_TO_ARTICULOS:
                if rule_id.upper().startswith(key.upper()):
                    articulos = _RULE_TO_ARTICULOS[key]
                    break
        if articulos:
            f['ley21719'] = articulos
            f['ley21719_detail'] = [
                {
                    'articulo': a,
                    'titulo': LEY_ARTICULOS[a]['titulo'],
                    'obligacion': LEY_ARTICULOS[a]['obligacion'],
                }
                for a in articulos if a in LEY_ARTICULOS
            ]
            # Append article codes to compliance list
            existing = set(f.get('compliance', []))
            for a in articulos:
                existing.add(f'LEY21719-{a}')
            f['compliance'] = sorted(existing)
        else:
            f['ley21719'] = []
            f['ley21719_detail'] = []
    return findings


def calculate_compliance_score(findings: List[dict]) -> Dict[str, Any]:
    """
    Calculate a 0-100 compliance score for Ley 21.719.

    Methodology:
    - Start at 100
    - Deduct points per finding weighted by severity and article criticality
    - Cap deductions per article category to avoid double-penalizing
    - Return score, breakdown by article, and risk level
    """
    if not findings:
        return {
            'score': 100,
            'risk_level': 'BAJO',
            'total_findings': 0,
            'pii_findings': 0,
            'security_findings': 0,
            'articles_violated': [],
            'breakdown': {},
            'multa_estimada': 'Sin hallazgos — sin riesgo de multa',
        }

    total_deduction = 0.0
    articles_violated: set = set()
    article_deductions: Dict[str, float] = {}
    pii_count = 0
    security_count = 0

    for f in findings:
        sev   = f.get('severity', 'LOW')
        w     = _SEV_WEIGHT.get(sev, 1)
        arts  = f.get('ley21719', [])
        source = f.get('source', '')

        if source == 'PII-DETECTOR' or f.get('rule_id', '').startswith('PII-'):
            pii_count += 1
        else:
            security_count += 1

        for art in arts:
            articles_violated.add(art)
            # Cap deduction per article at 15 points max
            current = article_deductions.get(art, 0.0)
            delta   = min(w * 0.5, 15.0 - current)
            if delta > 0:
                article_deductions[art] = current + delta
                total_deduction += delta

    score = max(0, round(100 - total_deduction))

    risk_level = (
        'CRÍTICO' if score < 40
        else 'ALTO' if score < 60
        else 'MEDIO' if score < 80
        else 'BAJO'
    )

    # Estimate fine range based on severity
    critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    if critical_count >= 5 or 'Art.49' in articles_violated:
        multa = 'Riesgo de multa GRAVÍSIMA: hasta 20.000 UTM (~$1.200M CLP)'
    elif critical_count >= 2 or len(articles_violated) >= 5:
        multa = 'Riesgo de multa GRAVE: hasta 10.000 UTM (~$600M CLP)'
    elif findings:
        multa = 'Riesgo de multa LEVE: hasta 5.000 UTM (~$300M CLP)'
    else:
        multa = 'Sin riesgo de multa identificado'

    return {
        'score': score,
        'risk_level': risk_level,
        'total_findings': len(findings),
        'pii_findings': pii_count,
        'security_findings': security_count,
        'articles_violated': sorted(articles_violated),
        'breakdown': {
            art: {
                'titulo': LEY_ARTICULOS.get(art, {}).get('titulo', ''),
                'deduction': round(article_deductions.get(art, 0), 1),
            }
            for art in sorted(articles_violated)
        },
        'multa_estimada': multa,
    }


def print_ley21719_summary(score_data: Dict[str, Any], findings: List[dict]) -> None:
    """Print colored terminal summary of Ley 21.719 compliance."""
    C = {
        'RED':    '\033[91m', 'YELLOW': '\033[93m',
        'GREEN':  '\033[92m', 'CYAN':   '\033[94m',
        'GRAY':   '\033[90m', 'BOLD':   '\033[1m',
        'RESET':  '\033[0m',
    }

    score = score_data['score']
    risk  = score_data['risk_level']
    score_color = (
        C['RED'] if score < 40 else
        C['YELLOW'] if score < 70 else
        C['GREEN']
    )
    risk_color = (
        C['RED'] if risk == 'CRÍTICO' else
        C['YELLOW'] if risk in ('ALTO', 'MEDIO') else
        C['GREEN']
    )

    bar_filled = score // 5
    bar = '█' * bar_filled + '░' * (20 - bar_filled)

    print(f'\n{C["BOLD"]}{"=" * 60}')
    print(' LEY 21.719 — PROTECCIÓN DE DATOS PERSONALES (CHILE)')
    print(f'{"=" * 60}{C["RESET"]}')
    print(f'\n  Score de cumplimiento: {score_color}{C["BOLD"]}{score}/100{C["RESET"]}')
    print(f'  {score_color}[{bar}]{C["RESET"]}')
    print(f'  Nivel de riesgo:  {risk_color}{C["BOLD"]}{risk}{C["RESET"]}')
    print(f'  {C["YELLOW"]}{score_data["multa_estimada"]}{C["RESET"]}')

    print(f'\n  Hallazgos PII:       {C["RED"]}{score_data["pii_findings"]}{C["RESET"]}')
    print(f'  Hallazgos seguridad: {score_data["security_findings"]}')

    arts = score_data.get('articles_violated', [])
    if arts:
        print(f'\n{C["BOLD"]}  Artículos incumplidos:{C["RESET"]}')
        for art in arts:
            info = LEY_ARTICULOS.get(art, {})
            ded  = score_data['breakdown'].get(art, {}).get('deduction', 0)
            print(
                f'  {C["RED"]}•{C["RESET"]} {C["BOLD"]}{art}{C["RESET"]} — '
                f'{info.get("titulo", "")} '
                f'{C["GRAY"]}(-{ded} pts){C["RESET"]}'
            )

    # Top PII findings
    pii = [f for f in findings if f.get('rule_id', '').startswith('PII-')]
    if pii:
        print(f'\n{C["BOLD"]}  Datos personales detectados:{C["RESET"]}')
        cats: Dict[str, int] = {}
        for f in pii:
            cats[f.get('name', '')] = cats.get(f.get('name', ''), 0) + 1
        for name, count in sorted(cats.items(), key=lambda x: -x[1])[:6]:
            print(f'  {C["CYAN"]}•{C["RESET"]} {name}: {count} ocurrencia(s)')
