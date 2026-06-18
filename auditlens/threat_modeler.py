"""
AuditLens AI Threat Modeler (STRIDE) — usa AI API para generar un
modelo de amenazas STRIDE a partir del código fuente o un diagrama arquitectural.

STRIDE:
  S — Spoofing        (Suplantación)
  T — Tampering       (Manipulación)
  R — Repudiation     (Repudio)
  I — Information Disclosure (Divulgación)
  D — Denial of Service      (DoS)
  E — Elevation of Privilege (Elevación de privilegios)

Usage:
    auditlens threat-model ./project --output threat_model.json
    ANTHROPIC_API_KEY=sk-... auditlens threat-model ./project
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


_STRIDE_CATEGORIES = {
    'S': 'Spoofing',
    'T': 'Tampering',
    'R': 'Repudiation',
    'I': 'Information Disclosure',
    'D': 'Denial of Service',
    'E': 'Elevation of Privilege',
}

_SYSTEM_PROMPT = """You are a senior application security engineer performing STRIDE threat modeling.
Given a code summary, identify threats for each STRIDE category.
Return ONLY valid JSON with no extra text.
Schema:
{
  "components": ["list of identified components/services"],
  "data_flows": ["list of identified data flows"],
  "threats": [
    {
      "category": "S|T|R|I|D|E",
      "category_name": "full STRIDE name",
      "title": "short threat title",
      "description": "detailed threat description",
      "affected_component": "component name",
      "attack_vector": "how attacker exploits this",
      "impact": "CRITICAL|HIGH|MEDIUM|LOW",
      "mitigation": "specific mitigation recommendation",
      "stride_letter": "S|T|R|I|D|E"
    }
  ],
  "trust_boundaries": ["list of identified trust boundaries"],
  "summary": "one paragraph executive summary of the threat model"
}
Be specific and technical. Focus on the actual code/architecture, not generic threats."""


def _collect_code_summary(project_path: str, max_chars: int = 12000) -> str:
    """Build a representative code summary from the project."""
    summary_parts = []
    total = 0

    priority_files = [
        'app.py', 'main.py', 'server.py', 'wsgi.py', 'asgi.py',
        'config.py', 'settings.py', 'routes.py', 'urls.py', 'views.py',
        'models.py', 'auth.py', 'middleware.py', 'api.py',
        'requirements.txt', 'package.json', 'Dockerfile', 'docker-compose.yml',
    ]

    root = Path(project_path)

    for fname in priority_files:
        fpath = root / fname
        if fpath.exists():
            try:
                content = fpath.read_text(encoding='utf-8', errors='replace')
                snippet = f'\n\n=== {fname} ===\n{content[:2000]}'
                summary_parts.append(snippet)
                total += len(snippet)
                if total >= max_chars:
                    break
            except OSError:
                pass

    if total < max_chars:
        for fpath in sorted(root.rglob('*.py'))[:20]:
            if total >= max_chars:
                break
            try:
                rel = str(fpath.relative_to(root))
                content = fpath.read_text(encoding='utf-8', errors='replace')
                snippet = f'\n\n=== {rel} ===\n{content[:1500]}'
                summary_parts.append(snippet)
                total += len(snippet)
            except OSError:
                pass

    return ''.join(summary_parts)[:max_chars]


def run_threat_model(
    project_path: str,
    api_key: Optional[str] = None,
    model: str = 'ai-model-latest',
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate STRIDE threat model using AI API.

    Returns dict with components, data_flows, threats, trust_boundaries, summary.
    """
    api_key = api_key or os.environ.get('ANTHROPIC_API_KEY', '')
    if not api_key:
        print('\033[91m[AuditLens ThreatModel]\033[0m ANTHROPIC_API_KEY no configurada.')
        return {}

    try:
        import anthropic
    except ImportError:
        print('\033[91m[AuditLens ThreatModel]\033[0m pip install anthropic')
        return {}

    print(f'\033[94m[AuditLens ThreatModel]\033[0m Analizando proyecto: {project_path}')
    code_summary = _collect_code_summary(project_path)

    if not code_summary.strip():
        print('\033[91m[AuditLens ThreatModel]\033[0m No se encontró código fuente.')
        return {}

    user_prompt = (
        f'Project path: {project_path}\n\n'
        f'Code summary:\n{code_summary}\n\n'
        'Generate a complete STRIDE threat model for this project. '
        'Identify all components, data flows, trust boundaries, and threats.'
    )

    print(f'\033[94m[AuditLens ThreatModel]\033[0m Consultando AI API (STRIDE)...')
    client = anthropic.Anthropic(api_key=api_key)

    try:
        message = client.messages.create(
            model=model,
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            messages=[{'role': 'user', 'content': user_prompt}],
        )
        raw = message.content[0].text.strip()

        # Strip markdown code fences if present
        if raw.startswith('```'):
            raw = raw.split('```')[1]
            if raw.startswith('json'):
                raw = raw[4:]

        result = json.loads(raw)

    except json.JSONDecodeError as exc:
        print(f'\033[91m[AuditLens ThreatModel]\033[0m JSON parse error: {exc}')
        return {}
    except Exception as exc:
        print(f'\033[91m[AuditLens ThreatModel]\033[0m API error: {exc}')
        return {}

    threats = result.get('threats', [])
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for t in threats:
        imp = t.get('impact', 'LOW')
        if imp in counts:
            counts[imp] += 1

    print(
        f'\033[92m[AuditLens ThreatModel]\033[0m {len(threats)} amenazas identificadas '
        f'(CRITICAL:{counts["CRITICAL"]} HIGH:{counts["HIGH"]} '
        f'MEDIUM:{counts["MEDIUM"]} LOW:{counts["LOW"]})'
    )

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        print(f'\033[92m[AuditLens ThreatModel]\033[0m Modelo guardado: {output_path}')

    return result


def print_threat_model(result: Dict[str, Any]) -> None:
    """Print a formatted threat model to stdout."""
    if not result:
        return

    C = {
        'RED': '\033[91m', 'YELLOW': '\033[93m', 'CYAN': '\033[94m',
        'GREEN': '\033[92m', 'BOLD': '\033[1m', 'RESET': '\033[0m',
    }

    print(f'\n{C["BOLD"]}=== STRIDE THREAT MODEL ==={C["RESET"]}')
    print(f'\n{C["CYAN"]}Summary:{C["RESET"]} {result.get("summary", "")}')

    comps = result.get('components', [])
    if comps:
        print(f'\n{C["BOLD"]}Components ({len(comps)}):{C["RESET"]}')
        for c in comps:
            print(f'  • {c}')

    tbs = result.get('trust_boundaries', [])
    if tbs:
        print(f'\n{C["BOLD"]}Trust Boundaries ({len(tbs)}):{C["RESET"]}')
        for tb in tbs:
            print(f'  • {tb}')

    threats = result.get('threats', [])
    if threats:
        print(f'\n{C["BOLD"]}Threats ({len(threats)}):{C["RESET"]}')
        for t in threats:
            impact = t.get('impact', 'LOW')
            color = C['RED'] if impact in ('CRITICAL', 'HIGH') else C['YELLOW']
            stride = t.get('stride_letter', '?')
            name = _STRIDE_CATEGORIES.get(stride, stride)
            print(f'\n  [{color}{impact}{C["RESET"]}] [{C["CYAN"]}{stride}-{name}{C["RESET"]}] {t.get("title", "")}')
            print(f'     Component: {t.get("affected_component", "")}')
            print(f'     Attack:    {t.get("attack_vector", "")}')
            print(f'     Fix:       {t.get("mitigation", "")}')
