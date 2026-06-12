"""
AuditLens OpenAPI/Swagger API Scanner — importa una spec OpenAPI 2/3
y testea cada endpoint con probes de seguridad activos.

Usage:
    auditlens api-scan https://api.example.com/openapi.json --authorized
    auditlens api-scan ./openapi.yaml --base-url https://api.example.com --authorized
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
import yaml

_TIMEOUT = 12
_COMPLIANCE = ['OWASP-API:2023', 'CWE-285', 'CWE-306', 'ISO-27001:A.14']


def _load_spec(source: str) -> Dict[str, Any]:
    """Load OpenAPI spec from URL or file path."""
    if source.startswith('http'):
        resp = requests.get(source, timeout=_TIMEOUT)
        resp.raise_for_status()
        content_type = resp.headers.get('content-type', '')
        if 'json' in content_type or source.endswith('.json'):
            return resp.json()
        return yaml.safe_load(resp.text)
    with open(source, encoding='utf-8') as fh:
        if source.endswith('.json'):
            return json.load(fh)
        return yaml.safe_load(fh)


def _extract_endpoints(spec: Dict[str, Any], base_url: str) -> List[Tuple[str, str, Dict]]:
    """Return list of (method, url, operation) tuples."""
    endpoints = []
    paths = spec.get('paths', {})

    for path, path_item in paths.items():
        for method in ('get', 'post', 'put', 'patch', 'delete', 'head', 'options'):
            op = path_item.get(method)
            if op is None:
                continue
            full_url = base_url.rstrip('/') + path
            endpoints.append((method.upper(), full_url, op))
    return endpoints


def _build_test_params(op: Dict) -> Dict[str, Any]:
    """Build a minimal set of query/body params for probing."""
    params = {}
    for p in op.get('parameters', []):
        if p.get('in') == 'query':
            params[p.get('name', 'test')] = p.get('example', 'test')
    return params


def _probe_endpoint(
    session: requests.Session,
    method: str,
    url: str,
    op: Dict,
    findings: List[dict],
) -> None:
    """Run security probes on a single endpoint."""
    params = _build_test_params(op)

    # 1. Auth bypass — try without auth header
    try:
        resp = session.request(method, url, params=params, timeout=_TIMEOUT, allow_redirects=False)
        if resp.status_code in (200, 201, 202):
            sec = op.get('security', None)
            if sec is not None and len(sec) > 0:
                findings.append({
                    'rule_id': 'API-AUTH-01',
                    'name': f'Endpoint Accessible Without Authentication: {method} {url}',
                    'description': (
                        f'{method} {url} returned HTTP {resp.status_code} without any auth credentials, '
                        'yet the OpenAPI spec declares security requirements. '
                        'Verify the endpoint enforces authentication.'
                    ),
                    'severity': 'HIGH',
                    'compliance': _COMPLIANCE,
                    'url': url,
                    'file': url,
                    'line': 0,
                    'source': 'API-SCAN',
                })
    except Exception:
        pass

    # 2. IDOR probe — replace path ID params with 0 or 1
    if '{' in url:
        test_url = re.sub(r'\{[^}]+\}', '1', url)
        try:
            resp = session.request(method, test_url, params=params, timeout=_TIMEOUT)
            if resp.status_code == 200 and len(resp.content) > 10:
                findings.append({
                    'rule_id': 'API-IDOR-01',
                    'name': f'Potential IDOR: {method} {test_url}',
                    'description': (
                        f'{method} {test_url} returned HTTP 200 with body. '
                        'Path parameter ID "1" may expose another user\'s resource. '
                        'Test with different IDs and verify object-level authorization.'
                    ),
                    'severity': 'MEDIUM',
                    'compliance': ['OWASP-API1:2023', 'CWE-639'],
                    'url': test_url,
                    'file': url,
                    'line': 0,
                    'source': 'API-SCAN',
                })
        except Exception:
            pass

    # 3. HTTP Methods — check if unexpected methods accepted
    if method == 'GET':
        for extra_method in ('DELETE', 'TRACE', 'CONNECT'):
            try:
                resp = session.request(extra_method, url, params=params, timeout=_TIMEOUT)
                if resp.status_code not in (405, 404, 403, 501):
                    findings.append({
                        'rule_id': 'API-METHOD-01',
                        'name': f'Unexpected HTTP Method Accepted: {extra_method} {url}',
                        'description': (
                            f'{extra_method} {url} returned HTTP {resp.status_code} '
                            f'instead of 405 Method Not Allowed. '
                            'Restrict HTTP methods to only those needed by the API.'
                        ),
                        'severity': 'LOW',
                        'compliance': ['CWE-749', 'OWASP-API:2023'],
                        'url': url,
                        'file': url,
                        'line': 0,
                        'source': 'API-SCAN',
                    })
            except Exception:
                pass

    # 4. Mass assignment — POST with extra fields
    if method in ('POST', 'PUT', 'PATCH'):
        try:
            payload = {'id': 99999, 'role': 'admin', 'is_admin': True, 'admin': True}
            resp = session.request(method, url, json=payload, timeout=_TIMEOUT)
            if resp.status_code in (200, 201):
                try:
                    data = resp.json()
                    if 'role' in str(data) or 'admin' in str(data):
                        findings.append({
                            'rule_id': 'API-MASS-01',
                            'name': f'Possible Mass Assignment: {method} {url}',
                            'description': (
                                f'{method} {url} accepted extra fields (role, admin, is_admin) '
                                'and the response may reflect them. '
                                'Use an allowlist of accepted fields and never bind untrusted input directly to models.'
                            ),
                            'severity': 'HIGH',
                            'compliance': ['OWASP-API6:2023', 'CWE-915'],
                            'url': url,
                            'file': url,
                            'line': 0,
                            'source': 'API-SCAN',
                        })
                except Exception:
                    pass
        except Exception:
            pass


def _check_spec_quality(spec: Dict[str, Any], findings: List[dict]) -> None:
    """Static checks on the spec itself."""
    # Global security not defined
    if not spec.get('security') and not spec.get('components', {}).get('securitySchemes'):
        findings.append({
            'rule_id': 'API-SPEC-01',
            'name': 'No Security Schemes Defined in OpenAPI Spec',
            'description': (
                'The OpenAPI specification does not define any security schemes. '
                'Add securitySchemes and reference them with "security:" on endpoints.'
            ),
            'severity': 'HIGH',
            'compliance': _COMPLIANCE,
            'url': 'spec',
            'file': 'openapi.yaml',
            'line': 0,
            'source': 'API-SCAN',
        })

    # Check for server HTTPS
    for server in spec.get('servers', []):
        url = server.get('url', '')
        if url.startswith('http://'):
            findings.append({
                'rule_id': 'API-SPEC-02',
                'name': f'API Server Uses HTTP Instead of HTTPS: {url}',
                'description': (
                    f'OpenAPI spec defines server {url} using plain HTTP. '
                    'API endpoints should be served over HTTPS only.'
                ),
                'severity': 'HIGH',
                'compliance': ['CWE-319', 'OWASP-A2:2021'],
                'url': url,
                'file': 'openapi.yaml',
                'line': 0,
                'source': 'API-SCAN',
            })

    # Check for sensitive info in descriptions
    sensitive_re = re.compile(r'(?i)(password|secret|token|api[_-]?key)\s*[:=]', re.IGNORECASE)
    for path, path_item in spec.get('paths', {}).items():
        for method in ('get', 'post', 'put', 'patch', 'delete'):
            op = path_item.get(method, {})
            desc = op.get('description', '') + op.get('summary', '')
            if sensitive_re.search(desc):
                findings.append({
                    'rule_id': 'API-SPEC-03',
                    'name': f'Sensitive Data in API Documentation: {method.upper()} {path}',
                    'description': (
                        f'Endpoint {method.upper()} {path} description contains what appears to be a '
                        'credential or token. Remove sensitive values from public API docs.'
                    ),
                    'severity': 'MEDIUM',
                    'compliance': ['CWE-312', 'OWASP-A2:2021'],
                    'url': path,
                    'file': 'openapi.yaml',
                    'line': 0,
                    'source': 'API-SCAN',
                })


def run_api_scan(
    spec_source: str,
    base_url: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    max_endpoints: int = 50,
) -> List[dict]:
    """
    Load OpenAPI spec and probe each endpoint.

    Args:
        spec_source: URL or file path to OpenAPI 2/3 spec.
        base_url: Override base URL for probing.
        headers: Auth headers (e.g. {'Authorization': 'Bearer ...'}).
        max_endpoints: Cap on how many endpoints to probe.
    Returns:
        List of finding dicts.
    """
    print(f'\033[94m[AuditLens API]\033[0m Cargando spec: {spec_source}')
    try:
        spec = _load_spec(spec_source)
    except Exception as exc:
        print(f'\033[91m[AuditLens API]\033[0m Error cargando spec: {exc}')
        return []

    findings: List[dict] = []
    _check_spec_quality(spec, findings)

    # Determine base URL
    if not base_url:
        servers = spec.get('servers', [])
        if servers:
            base_url = servers[0].get('url', '')
        elif 'host' in spec:
            scheme = spec.get('schemes', ['https'])[0]
            base_url = f'{scheme}://{spec["host"]}{spec.get("basePath", "")}'
        else:
            print('\033[93m[AuditLens API]\033[0m No se encontró base URL en la spec. Usa --base-url.')
            return findings

    endpoints = _extract_endpoints(spec, base_url)
    print(f'\033[94m[AuditLens API]\033[0m {len(endpoints)} endpoints encontrados. Probando (max {max_endpoints})...')

    session = requests.Session()
    if headers:
        session.headers.update(headers)

    for method, url, op in endpoints[:max_endpoints]:
        _probe_endpoint(session, method, url, op, findings)
        time.sleep(0.2)

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.get('severity', 'LOW')
        if sev in counts:
            counts[sev] += 1

    print(
        f'\033[92m[AuditLens API]\033[0m {len(findings)} hallazgos '
        f'(CRITICAL:{counts["CRITICAL"]} HIGH:{counts["HIGH"]})'
    )
    return findings
