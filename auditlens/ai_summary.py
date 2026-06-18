"""
AuditLens — AI Executive Summary + Compliance Gap Analysis

Usa AI para generar:
1. Resumen ejecutivo en español para CEO/directorio (no técnico)
2. Análisis de brecha de compliance vs framework solicitado
3. Plan de remediación priorizado con estimados de tiempo
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional


def _call_ai(prompt: str, max_tokens: int = 2000) -> str:
    try:
        import anthropic
    except ImportError:
        return '[ERROR] anthropic no instalado: pip install anthropic'

    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        return '[ERROR] ANTHROPIC_API_KEY no definida en variables de entorno.'

    client = anthropic.Anthropic(api_key=api_key)
    try:
        msg = client.messages.create(
            model='ai-model-latest',
            max_tokens=max_tokens,
            messages=[{'role': 'user', 'content': prompt}],
        )
        return msg.content[0].text
    except Exception as e:
        return f'[ERROR AI API] {e}'


def generate_executive_summary(
    findings: List[dict],
    score_data: Optional[Dict[str, Any]] = None,
    empresa: str = 'la empresa',
    framework: str = 'seguridad general',
    language: str = 'es',
) -> str:
    """Generate a non-technical executive summary using AI."""
    sev_counts = {}
    for f in findings:
        sev_counts[f.get('severity', 'LOW')] = sev_counts.get(f.get('severity', 'LOW'), 0) + 1

    top_findings = sorted(
        findings,
        key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x.get('severity', 'LOW'), 4)
    )[:8]
    top_str = '\n'.join(
        f'- [{f.get("severity","")}] {f.get("name","")}: {f.get("description","")[:120]}'
        for f in top_findings
    )

    score_str = ''
    if score_data:
        score_str = (
            f'\nScore de cumplimiento: {score_data.get("score", "N/A")}/100 '
            f'(Riesgo: {score_data.get("risk_level", "N/A")})\n'
            f'Estimación de multa: {score_data.get("multa_estimada", "")}'
        )

    prompt = f"""Eres un consultor de ciberseguridad experto. Debes redactar un RESUMEN EJECUTIVO
en español para el directorio y CEO de {empresa}. El tono debe ser formal, claro y sin jerga técnica.

DATOS DE LA AUDITORÍA:
- Total hallazgos: {len(findings)}
- Críticos: {sev_counts.get('CRITICAL', 0)}
- Altos: {sev_counts.get('HIGH', 0)}
- Medios: {sev_counts.get('MEDIUM', 0)}
- Bajos: {sev_counts.get('LOW', 0)}
{score_str}

PRINCIPALES HALLAZGOS:
{top_str}

Redacta el resumen ejecutivo con estas secciones (máximo 600 palabras):
1. Situación actual (2-3 oraciones)
2. Hallazgos principales (3-5 bullets, en lenguaje de negocio, NO técnico)
3. Impacto potencial para el negocio (riesgo financiero, reputacional, regulatorio)
4. Acciones inmediatas recomendadas (3-5 bullets)
5. Conclusión (1-2 oraciones)

Usa lenguaje de negocio. Convierte términos técnicos en impactos de negocio.
Por ejemplo: "SQL injection" → "vulnerabilidad que permite acceso no autorizado a datos de clientes"."""

    return _call_ai(prompt, max_tokens=1500)


def generate_compliance_gap_analysis(
    findings: List[dict],
    framework: str = 'ley21719',
    empresa: str = 'la empresa',
) -> str:
    """Generate AI compliance gap analysis for a specific framework."""
    framework_names = {
        'ley21719': 'Ley 21.719 (Chile) — Protección de Datos Personales',
        'iso27001': 'ISO 27001:2022',
        'cmf': 'CMF Circular 57 — Ciberseguridad Chile',
        'gdpr': 'GDPR (EU 2016/679)',
        'hipaa': 'HIPAA (45 CFR)',
        'nist': 'NIST Cybersecurity Framework 2.0',
        'pci': 'PCI-DSS v4.0',
    }
    fw_name = framework_names.get(framework.lower(), framework.upper())

    tagged = [f for f in findings if any(
        framework.upper() in tag.upper()
        for tag in f.get('compliance', [])
    )]

    samples = sorted(
        tagged or findings,
        key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x.get('severity', 'LOW'), 4)
    )[:10]

    samples_str = '\n'.join(
        f'- [{f.get("severity","")}] {f.get("rule_id","")} — {f.get("name","")}: {f.get("description","")[:100]}'
        for f in samples
    )

    prompt = f"""Eres un auditor experto en {fw_name}. Analiza los siguientes hallazgos de seguridad
de {empresa} y genera un ANÁLISIS DE BRECHA DE COMPLIANCE detallado.

HALLAZGOS RELEVANTES PARA {fw_name}:
{samples_str}

Total hallazgos del framework: {len(tagged)} de {len(findings)} totales.

Genera el análisis con estas secciones:
1. Resumen de cumplimiento actual (1 párrafo)
2. Brechas críticas identificadas (tabla: Brecha | Artículo/Control | Riesgo)
3. Controles que SÍ se cumplen (si aplica)
4. Plan de remediación priorizado (tabla: Acción | Prioridad | Tiempo estimado | Responsable)
5. Riesgo de sanción o multa si no se corrige
6. Recomendación final

Sé específico con los artículos/controles del framework. Máximo 800 palabras."""

    return _call_ai(prompt, max_tokens=2000)


def generate_remediation_plan(
    findings: List[dict],
    empresa: str = 'la empresa',
) -> str:
    """Generate a prioritized remediation plan."""
    critical = [f for f in findings if f.get('severity') == 'CRITICAL'][:5]
    high     = [f for f in findings if f.get('severity') == 'HIGH'][:5]

    items_str = '\n'.join(
        f'- [{f.get("severity","")}] {f.get("rule_id","")} en {f.get("file","").split("/")[-1]}:{f.get("line","")}: {f.get("name","")}'
        for f in (critical + high)
    )

    prompt = f"""Eres un experto en seguridad de software. Para {empresa}, genera un PLAN DE REMEDIACIÓN
estructurado para los siguientes hallazgos de seguridad.

HALLAZGOS CRÍTICOS Y ALTOS:
{items_str}

Genera una tabla markdown con columnas:
| Hallazgo | Acción concreta | Tiempo | Dificultad | Responsable sugerido |

Luego agrega:
- Quick wins (pueden resolverse en < 1 día)
- Cambios arquitecturales necesarios (> 1 sprint)
- Recomendaciones de herramientas específicas

Sé muy concreto: en vez de "arreglar SQL injection" di "usar parámetros preparados en cursor.execute()".
Máximo 600 palabras."""

    return _call_ai(prompt, max_tokens=1500)


def run_ai_summary(
    findings: List[dict],
    score_data: Optional[Dict[str, Any]] = None,
    empresa: str = 'Empresa',
    framework: Optional[str] = None,
    output_path: Optional[str] = None,
    mode: str = 'all',
) -> Dict[str, str]:
    results = {}

    if mode in ('executive', 'all'):
        print('\033[94m[AuditLens AI]\033[0m Generando resumen ejecutivo...')
        results['executive'] = generate_executive_summary(findings, score_data, empresa)
        print(results['executive'])

    if mode in ('gap', 'all') and framework:
        print(f'\n\033[94m[AuditLens AI]\033[0m Generando análisis de brecha {framework}...')
        results['gap'] = generate_compliance_gap_analysis(findings, framework, empresa)
        print(results['gap'])

    if mode in ('remediation', 'all'):
        print('\n\033[94m[AuditLens AI]\033[0m Generando plan de remediación...')
        results['remediation'] = generate_remediation_plan(findings, empresa)
        print(results['remediation'])

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
        print(f'\033[92m[AuditLens AI]\033[0m Análisis guardado: {output_path}')

    return results
