"""
AuditLens — HTTP Security Headers + CORS + TLS Checker

Analiza respuestas HTTP de una URL para detectar:
- Headers de seguridad faltantes (CSP, HSTS, X-Frame-Options, etc.)
- CORS misconfiguration (wildcard origins, credenciales + wildcard)
- TLS/SSL: versión, certificado expirado, HSTS max-age
"""
from __future__ import annotations

import re
import ssl
import socket
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urlparse


_REQUIRED_HEADERS = [
    ('Strict-Transport-Security', 'HSTS',
     'Fuerza HTTPS. Sin este header, ataques SSLstrip son posibles.',
     'HIGH', 'min "max-age=31536000; includeSubDomains"'),
    ('Content-Security-Policy', 'CSP',
     'Previene XSS y data injection. Sin CSP el navegador ejecuta scripts de cualquier origen.',
     'HIGH', 'Definir policy restrictiva: default-src "self"'),
    ('X-Frame-Options', 'Clickjacking',
     'Sin este header, la página puede ser embebida en iframes para ataques clickjacking.',
     'MEDIUM', '"DENY" o "SAMEORIGIN"'),
    ('X-Content-Type-Options', 'MIME sniffing',
     'Sin "nosniff", el browser puede ejecutar archivos con MIME type incorrecto.',
     'MEDIUM', '"nosniff"'),
    ('Referrer-Policy', 'Referrer leak',
     'Sin este header, URLs completas (con tokens/IDs) pueden ser enviadas a terceros.',
     'LOW', '"strict-origin-when-cross-origin"'),
    ('Permissions-Policy', 'Feature Policy',
     'Sin este header, el navegador puede acceder a cámara/micrófono/geolocalización.',
     'LOW', 'Restringir features no usadas'),
]

_BAD_HEADERS = [
    ('Server', 'Server banner',
     'El header Server revela tecnología y versión del servidor (fingerprinting).',
     'LOW'),
    ('X-Powered-By', 'Framework disclosure',
     'X-Powered-By revela el framework/lenguaje (PHP, Express, etc.) facilitando ataques.',
     'LOW'),
    ('X-AspNet-Version', 'ASP.NET version',
     'Revela versión específica de ASP.NET.',
     'LOW'),
]


def check_headers(url: str, verify_ssl: bool = True, timeout: int = 10) -> List[dict]:
    try:
        import urllib.request
        import urllib.error
    except ImportError:
        return []

    findings: List[dict] = []
    parsed = urlparse(url if '://' in url else f'https://{url}')
    host   = parsed.netloc or parsed.path

    # Fetch headers
    try:
        req = urllib.request.Request(url if '://' in url else f'https://{url}',
                                     headers={'User-Agent': 'AuditLens-Security-Scanner/1.0'})
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status  = resp.status
    except Exception as e:
        findings.append({
            'rule_id': 'HEADERS-CONNECT-ERR',
            'name': f'No se pudo conectar a {url}',
            'description': str(e),
            'severity': 'HIGH',
            'file': url,
            'line': 0,
            'source': 'HEADERS-CHECKER',
        })
        return findings

    # Check missing security headers
    for hdr, label, desc, severity, recommendation in _REQUIRED_HEADERS:
        if hdr.lower() not in headers:
            findings.append({
                'rule_id': f'HEADER-MISSING-{hdr.upper().replace("-","_")}',
                'name': f'Header {hdr} ausente',
                'description': f'{desc} Recomendación: {recommendation}',
                'severity': severity,
                'file': url,
                'line': 0,
                'snippet': f'HTTP {status} — {url}',
                'compliance': ['OWASP-A05:2021'],
                'source': 'HEADERS-CHECKER',
            })

    # Check info-disclosure headers
    for hdr, label, desc, severity in _BAD_HEADERS:
        val = headers.get(hdr.lower(), '')
        if val:
            findings.append({
                'rule_id': f'HEADER-DISCLOSURE-{hdr.upper().replace("-","_")}',
                'name': f'Header {hdr} expuesto: {val[:40]}',
                'description': desc,
                'severity': severity,
                'file': url,
                'line': 0,
                'snippet': f'{hdr}: {val}',
                'compliance': ['OWASP-A05:2021'],
                'source': 'HEADERS-CHECKER',
            })

    # CORS check
    cors_origin = headers.get('access-control-allow-origin', '')
    cors_creds  = headers.get('access-control-allow-credentials', '').lower()
    if cors_origin == '*' and cors_creds == 'true':
        findings.append({
            'rule_id': 'CORS-WILDCARD-CREDS',
            'name': 'CORS: wildcard + credentials=true',
            'description': (
                'Access-Control-Allow-Origin: * combinado con Allow-Credentials: true '
                'es inválido en navegadores modernos pero indica una política CORS insegura. '
                'Un origen específico con credenciales permite robo de sesión cross-origin.'
            ),
            'severity': 'CRITICAL',
            'file': url,
            'line': 0,
            'compliance': ['CWE-942', 'OWASP-A01:2021'],
            'source': 'HEADERS-CHECKER',
        })
    elif cors_origin == '*':
        findings.append({
            'rule_id': 'CORS-WILDCARD',
            'name': 'CORS: Access-Control-Allow-Origin: *',
            'description': (
                'Cualquier origen puede leer las respuestas de esta API. '
                'Para APIs públicas esto puede ser intencional, pero para APIs con auth es un riesgo.'
            ),
            'severity': 'MEDIUM',
            'file': url,
            'line': 0,
            'compliance': ['CWE-942'],
            'source': 'HEADERS-CHECKER',
        })

    # HSTS max-age check
    hsts = headers.get('strict-transport-security', '')
    if hsts:
        m = re.search(r'max-age=(\d+)', hsts)
        if m and int(m.group(1)) < 31536000:
            findings.append({
                'rule_id': 'HSTS-SHORT-MAXAGE',
                'name': f'HSTS max-age demasiado corto ({m.group(1)}s)',
                'description': 'HSTS max-age recomendado es 31536000 (1 año) o más.',
                'severity': 'LOW',
                'file': url,
                'line': 0,
                'snippet': f'Strict-Transport-Security: {hsts}',
                'source': 'HEADERS-CHECKER',
            })

    # TLS cert check
    if parsed.scheme == 'https' or '://' not in url:
        try:
            ctx2 = ssl.create_default_context()
            with socket.create_connection((host.split(':')[0], 443), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host.split(':')[0]) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    # Expiry
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        exp = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (exp - datetime.utcnow()).days
                        if days_left < 30:
                            findings.append({
                                'rule_id': 'TLS-CERT-EXPIRING',
                                'name': f'Certificado TLS expira en {days_left} días',
                                'description': f'El certificado expira el {not_after}.',
                                'severity': 'CRITICAL' if days_left < 7 else 'HIGH',
                                'file': url,
                                'line': 0,
                                'source': 'HEADERS-CHECKER',
                            })
                    # Protocol
                    if proto in ('TLSv1', 'TLSv1.1', 'SSLv3'):
                        findings.append({
                            'rule_id': 'TLS-WEAK-PROTOCOL',
                            'name': f'Protocolo TLS obsoleto: {proto}',
                            'description': f'{proto} es inseguro y no debe usarse. Actualizar a TLS 1.2+.',
                            'severity': 'HIGH',
                            'file': url,
                            'line': 0,
                            'compliance': ['PCI-4.2.1'],
                            'source': 'HEADERS-CHECKER',
                        })
        except Exception:
            pass

    return findings


def print_headers_summary(findings: List[dict], url: str) -> None:
    C = {'RED':'\033[91m','YEL':'\033[93m','GRN':'\033[92m','BLD':'\033[1m','GRY':'\033[90m','RST':'\033[0m'}
    print(f'\n{C["BLD"]}HTTP Security Headers — {url}{C["RST"]}')
    if not findings:
        print(f'  {C["GRN"]}✓ Todos los headers de seguridad presentes.{C["RST"]}')
        return
    for f in sorted(findings, key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x.get('severity','LOW'),4)):
        sev = f.get('severity','LOW')
        col = C['RED'] if sev in ('CRITICAL','HIGH') else C['YEL'] if sev == 'MEDIUM' else C['GRY']
        print(f'  {col}[{sev}]{C["RST"]} {f.get("name","")}')
        print(f'  {C["GRY"]}{f.get("description","")[:100]}{C["RST"]}')
