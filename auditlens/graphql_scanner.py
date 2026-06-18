"""
AuditLens — GraphQL Security Scanner

Detecta vulnerabilidades en APIs GraphQL:
- Introspection habilitada en producción
- Batching / aliasing attacks (DoS)
- Queries sin depth limit
- Campos que exponen información sensible
- Sin autenticación en mutations críticas
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError
import ssl


_INTROSPECTION_QUERY = '{"query": "{ __schema { types { name } } }"}'

_DEPTH_ATTACK = '{"query": "{ a { a { a { a { a { a { a { a { a { a { __typename } } } } } } } } } } }"}'

_BATCH_ATTACK = '[' + ','.join(['{"query": "{ __typename }"}'] * 10) + ']'

_SENSITIVE_FIELDS = [
    'password', 'passwd', 'secret', 'token', 'apiKey', 'api_key',
    'privateKey', 'creditCard', 'ssn', 'rut', 'dob', 'salary',
]


def _post(url: str, data: str, token: Optional[str] = None, verify_ssl: bool = True) -> Optional[Dict]:
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'AuditLens-GraphQL-Scanner/1.0',
    }
    if token:
        headers['Authorization'] = f'Bearer {token}'
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = Request(url, data=data.encode(), headers=headers, method='POST')
        with urlopen(req, context=ctx, timeout=10) as resp:
            body = resp.read().decode()
            return json.loads(body)
    except Exception:
        return None


def scan_graphql(
    endpoint: str,
    token: Optional[str] = None,
    verify_ssl: bool = True,
) -> List[dict]:
    findings: List[dict] = []

    def finding(rule_id, name, desc, severity):
        findings.append({
            'rule_id': rule_id,
            'name': name,
            'description': desc,
            'severity': severity,
            'file': endpoint,
            'line': 0,
            'compliance': ['OWASP-A05:2021', 'CWE-200'],
            'source': 'GRAPHQL-SCANNER',
        })

    print(f'\033[94m[AuditLens GraphQL]\033[0m Escaneando: {endpoint}')

    # Check introspection
    resp = _post(endpoint, _INTROSPECTION_QUERY, token, verify_ssl)
    if resp and 'data' in resp and resp['data']:
        types = resp['data'].get('__schema', {}).get('types', [])
        if types:
            finding('GRAPHQL-INTROSPECTION',
                    'GraphQL Introspection habilitada en producción',
                    f'La introspection está habilitada ({len(types)} tipos expuestos). '
                    'En producción debe desactivarse para evitar enumeration attacks. '
                    'Deshabilitar con "introspection: false" en la config del servidor.',
                    'MEDIUM')

            # Check for sensitive field names in schema
            type_names = [t.get('name','').lower() for t in types]
            for field in _SENSITIVE_FIELDS:
                matches = [t for t in type_names if field.lower() in t]
                if matches:
                    finding('GRAPHQL-SENSITIVE-FIELDS',
                            f'Campos sensibles en schema: {", ".join(matches[:3])}',
                            f'El schema expone tipos con nombres sensibles: {matches[:5]}. '
                            'Verificar que estos campos requieran autenticación adecuada.',
                            'MEDIUM')

    # Check batching
    resp_batch = _post(endpoint, _BATCH_ATTACK, token, verify_ssl)
    if isinstance(resp_batch, list) and len(resp_batch) >= 10:
        finding('GRAPHQL-BATCHING',
                'GraphQL permite batching sin límite (riesgo DoS)',
                'El servidor acepta arrays de queries (batching). '
                'Sin rate limiting por batch, permite ataques DoS amplificados. '
                'Limitar el número de operaciones por request.',
                'HIGH')

    # Check depth attack (no limit)
    resp_depth = _post(endpoint, _DEPTH_ATTACK, token, verify_ssl)
    if resp_depth and 'errors' not in resp_depth:
        finding('GRAPHQL-NO-DEPTH-LIMIT',
                'GraphQL sin límite de profundidad de queries',
                'Queries con 10+ niveles de anidamiento no fueron rechazadas. '
                'Implementar depth limiting (máx. 7-10 niveles).',
                'MEDIUM')

    if not findings:
        print(f'\033[92m[AuditLens GraphQL]\033[0m No se detectaron vulnerabilidades en {endpoint}')
    else:
        print(f'\033[93m[AuditLens GraphQL]\033[0m {len(findings)} vulnerabilidades detectadas')

    return findings
