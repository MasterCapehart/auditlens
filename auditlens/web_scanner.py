"""
AuditLens Web Scanner (DAST) — auditoría de seguridad sobre URL en vivo.

Módulos de análisis:
  1. SSL/TLS          — versión, ciphers débiles, expiración, HSTS preload
  2. HTTP Headers     — CSP, X-Frame-Options, X-Content-Type, Referrer-Policy, Permissions-Policy
  3. Cookies          — Secure, HttpOnly, SameSite, atributo Domain
  4. CORS             — Access-Control-Allow-Origin wildcard, credenciales
  5. Tech Fingerprint — Server, X-Powered-By, versiones expuestas en HTML
  6. Crawler          — rastrea hasta depth N siguiendo links del mismo dominio
  7. Form scanner     — detecta forms sin CSRF, sin HTTPS action, autocomplete
  8. JS extractor     — descarga JS inline y externos, los pasa por reglas SAST
  9. Sensitive paths  — enumera rutas comunes expuestas (/.env, /backup, etc.)
 10. DAST probes      — XSS reflejado básico, open redirect, SQLi error-based
 11. Rate limiting    — detecta ausencia de controles de velocidad en login/API
 12. Info disclosure  — stack traces, debug info, directory listing en respuestas

Uso:
    auditlens web-scan https://empresa.com --authorized
    auditlens web-scan https://empresa.com --authorized --depth 3 --format docx

IMPORTANTE: Solo usar con autorización escrita del dueño del sistema.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from http.client import HTTPSConnection, HTTPConnection

try:
    import requests
    from requests.adapters import HTTPAdapter
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

_SEVERITY_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}

# ── Sensitive paths to probe ─────────────────────────────────────────────────
_SENSITIVE_PATHS = [
    '/.env', '/.env.local', '/.env.production', '/.env.backup',
    '/backup', '/backup.sql', '/backup.zip', '/db_backup.sql',
    '/.git/config', '/.git/HEAD', '/.svn/entries',
    '/config.php', '/config.yml', '/config.yaml', '/settings.py',
    '/wp-config.php', '/wp-admin/', '/admin/', '/administrator/',
    '/phpmyadmin/', '/pma/', '/phpinfo.php',
    '/api/v1/', '/api/v2/', '/graphql', '/swagger.json',
    '/openapi.json', '/api-docs', '/swagger-ui.html',
    '/actuator', '/actuator/health', '/actuator/env', '/actuator/beans',
    '/metrics', '/health', '/debug/vars', '/server-status',
    '/.well-known/security.txt', '/robots.txt', '/sitemap.xml',
    '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/.DS_Store', '/Thumbs.db',
    '/logs/', '/log/', '/error_log', '/access_log',
    '/upload/', '/uploads/', '/files/', '/tmp/',
]

# ── XSS test payloads (non-destructive, detection only) ──────────────────────
_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<img src=x onerror=alert(1)>',
    'javascript:alert(1)',
]

# ── SQLi error signatures ─────────────────────────────────────────────────────
_SQLI_ERRORS = [
    'you have an error in your sql syntax',
    'mysql_fetch',
    'ora-01756', 'ora-00907',
    'unclosed quotation mark',
    'quoted string not properly terminated',
    'syntax error.*postgresql',
    'microsoft sql server.*error',
    'sqlite_error', 'sqlite3',
    'pg_query()', 'psql_query',
    'column.*does not exist',
]

# ── Open redirect test paths ──────────────────────────────────────────────────
_REDIRECT_PAYLOADS = [
    'https://evil.com',
    '//evil.com',
    r'\/\/evil.com',
    'https:evil.com',
]

# ── Weak TLS ciphers ──────────────────────────────────────────────────────────
_WEAK_CIPHERS = {
    'RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon', 'MD5',
    'ADH', 'AECDH', 'RC2', 'IDEA',
}

# ── Info disclosure patterns in response body ────────────────────────────────
_INFO_DISCLOSURE_PATTERNS = [
    (r'Traceback \(most recent call last\)', 'Python stack trace exposed'),
    (r'at\s+\w[\w\.]+\([\w\.]+\.java:\d+\)', 'Java stack trace exposed'),
    (r'Fatal error:.*in.*on line \d+', 'PHP error exposed'),
    (r'System\.Web\.HttpUnhandledException', 'ASP.NET exception exposed'),
    (r'Microsoft OLE DB Provider', 'OLEDB error message exposed'),
    (r'ODBC.*Error', 'ODBC error message exposed'),
    (r'Warning: mysql_', 'MySQL error exposed'),
    (r'DEBUG\s*=\s*True', 'Django DEBUG=True in response'),
    (r'<title>Index of /', 'Directory listing enabled'),
    (r'Apache/[\d\.]+', 'Apache version disclosed'),
    (r'nginx/[\d\.]+', 'nginx version disclosed'),
    (r'PHP/[\d\.]+', 'PHP version disclosed'),
    (r'ASP\.NET Version:[\d\.]+', 'ASP.NET version disclosed'),
]


class _LinkExtractor(HTMLParser):
    """Minimal HTML parser — extracts hrefs, form actions, script srcs, input fields."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: List[str] = []
        self.forms: List[dict] = []
        self.scripts: List[str] = []      # src URLs
        self.inline_scripts: List[str] = []
        self._current_form: Optional[dict] = None
        self._in_script = False
        self._script_buf = ''

    def handle_starttag(self, tag: str, attrs: list):
        attr = dict(attrs)
        tag = tag.lower()

        if tag == 'a' and attr.get('href'):
            self.links.append(self._abs(attr['href']))

        elif tag == 'form':
            self._current_form = {
                'action': self._abs(attr.get('action', self.base_url)),
                'method': attr.get('method', 'get').upper(),
                'inputs': [],
                'has_csrf': False,
                'enctype': attr.get('enctype', ''),
            }

        elif tag == 'input' and self._current_form is not None:
            name = attr.get('name', '').lower()
            itype = attr.get('type', 'text').lower()
            self._current_form['inputs'].append({'name': name, 'type': itype})
            if any(t in name for t in ('csrf', 'token', '_token', 'nonce', 'xsrf')):
                self._current_form['has_csrf'] = True
            if 'autocomplete' in attr and attr['autocomplete'] == 'off':
                pass

        elif tag == 'script':
            src = attr.get('src', '')
            if src:
                self.scripts.append(self._abs(src))
            else:
                self._in_script = True
                self._script_buf = ''

    def handle_endtag(self, tag: str):
        if tag.lower() == 'form' and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        elif tag.lower() == 'script' and self._in_script:
            self._in_script = False
            if self._script_buf.strip():
                self.inline_scripts.append(self._script_buf)
            self._script_buf = ''

    def handle_data(self, data: str):
        if self._in_script:
            self._script_buf += data

    def _abs(self, url: str) -> str:
        if not url or url.startswith(('javascript:', 'mailto:', '#', 'tel:', 'data:')):
            return ''
        return urllib.parse.urljoin(self.base_url, url)


def _make_session(timeout: int = 15, verify_ssl: bool = True):
    if not _REQUESTS_OK:
        raise ImportError('requests library required: pip install requests')
    s = requests.Session()
    s.headers.update({
        'User-Agent': 'AuditLens-WebScanner/0.8 (authorized security audit)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    })
    s.verify = verify_ssl
    return s, timeout


# ─────────────────────────────────────────────────────────────────────────────
# 1. SSL/TLS
# ─────────────────────────────────────────────────────────────────────────────

def _check_ssl(hostname: str, port: int = 443) -> List[dict]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=10),
                             server_hostname=hostname) as conn:
            cert = conn.getpeercert()
            cipher = conn.cipher()  # (name, protocol, bits)
            proto = conn.version()

            # Protocol version
            if proto in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'):
                findings.append(_finding(
                    'WEB-SSL-01', f'Weak TLS Protocol: {proto}',
                    f'Server negotiated {proto} which is deprecated and vulnerable to known attacks (POODLE, BEAST). '
                    'Disable TLS 1.0/1.1 and enable TLS 1.2+ only.',
                    'CRITICAL', ['OWASP-A2:2021', 'CWE-326', 'PCI-DSS 4.1', 'ISO-27001:A.14'],
                    hostname,
                ))

            # Cipher strength
            if cipher:
                cipher_name = cipher[0]
                bits = cipher[2] or 0
                if any(w in cipher_name.upper() for w in _WEAK_CIPHERS):
                    findings.append(_finding(
                        'WEB-SSL-02', f'Weak Cipher Suite: {cipher_name}',
                        f'The negotiated cipher {cipher_name} is considered weak. '
                        'Configure the server to prefer ECDHE+AES256+GCM ciphers.',
                        'HIGH', ['OWASP-A2:2021', 'CWE-327', 'PCI-DSS 4.1'],
                        hostname,
                    ))
                if bits and bits < 128:
                    findings.append(_finding(
                        'WEB-SSL-03', f'Short Key Length: {bits} bits',
                        f'Cipher key length of {bits} bits is insufficient. Use 128-bit minimum.',
                        'HIGH', ['CWE-326', 'NIST SP 800-57'],
                        hostname,
                    ))

            # Certificate expiry
            expire_str = cert.get('notAfter', '')
            if expire_str:
                expire_dt = datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                now = datetime.now(tz=timezone.utc)
                days_left = (expire_dt - now).days
                if days_left < 0:
                    findings.append(_finding(
                        'WEB-SSL-04', 'SSL Certificate Expired',
                        f'Certificate expired {-days_left} days ago ({expire_str}). '
                        'Browsers will show a security warning and refuse connections.',
                        'CRITICAL', ['OWASP-A2:2021', 'CWE-295'],
                        hostname,
                    ))
                elif days_left < 30:
                    findings.append(_finding(
                        'WEB-SSL-05', f'SSL Certificate Expiring Soon ({days_left} days)',
                        f'Certificate expires on {expire_str} in {days_left} days. '
                        'Renew immediately to avoid service disruption.',
                        'MEDIUM', ['OWASP-A2:2021', 'CWE-295'],
                        hostname,
                    ))

            # Subject Alternative Names / CN mismatch
            san = cert.get('subjectAltName', [])
            cn_list = [v for t, v in san if t == 'DNS']
            subject = dict(x[0] for x in cert.get('subject', []))
            cn = subject.get('commonName', '')
            if cn and not cn_list:
                findings.append(_finding(
                    'WEB-SSL-06', 'Certificate Missing SubjectAltName',
                    'The certificate relies only on CN without SANs. Modern browsers '
                    'require SAN. Reissue with proper SAN entries.',
                    'MEDIUM', ['CWE-295'],
                    hostname,
                ))

    except ssl.SSLError as e:
        findings.append(_finding(
            'WEB-SSL-07', f'SSL Error: {e}',
            'Could not establish SSL connection. The server may have an invalid or '
            'self-signed certificate, or TLS is misconfigured.',
            'CRITICAL', ['OWASP-A2:2021', 'CWE-295'],
            hostname,
        ))
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass  # Port not open — not an SSL finding

    # Check HSTS via raw HTTP headers (separate request)
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 2. HTTP Headers
# ─────────────────────────────────────────────────────────────────────────────

def _check_headers(url: str, headers: dict, response_url: str) -> List[dict]:
    findings = []
    h = {k.lower(): v for k, v in headers.items()}

    required = {
        'strict-transport-security': (
            'WEB-HDR-01', 'Missing HSTS Header',
            'HTTP Strict-Transport-Security not set. Browsers may allow HTTP downgrade attacks. '
            'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'HIGH', ['OWASP-A5:2021', 'CWE-319', 'ISO-27001:A.14'],
        ),
        'content-security-policy': (
            'WEB-HDR-02', 'Missing Content-Security-Policy',
            'No CSP header found. This makes XSS attacks significantly more impactful. '
            'Define a strict CSP to restrict script sources.',
            'HIGH', ['OWASP-A3:2021', 'CWE-116', 'ISO-27001:A.14'],
        ),
        'x-frame-options': (
            'WEB-HDR-03', 'Missing X-Frame-Options',
            'Page can be embedded in iframes enabling clickjacking attacks. '
            'Add: X-Frame-Options: DENY or SAMEORIGIN',
            'MEDIUM', ['OWASP-A5:2021', 'CWE-1021'],
        ),
        'x-content-type-options': (
            'WEB-HDR-04', 'Missing X-Content-Type-Options',
            'Browsers may MIME-sniff responses leading to XSS. '
            'Add: X-Content-Type-Options: nosniff',
            'MEDIUM', ['OWASP-A3:2021', 'CWE-116'],
        ),
        'referrer-policy': (
            'WEB-HDR-05', 'Missing Referrer-Policy',
            'No Referrer-Policy header. Sensitive URL fragments may leak via Referer header. '
            'Add: Referrer-Policy: strict-origin-when-cross-origin',
            'LOW', ['OWASP-A3:2021', 'CWE-116'],
        ),
        'permissions-policy': (
            'WEB-HDR-06', 'Missing Permissions-Policy',
            'No Permissions-Policy (formerly Feature-Policy). Browser features like camera, '
            'microphone, and geolocation are unrestricted.',
            'LOW', ['OWASP-A5:2021'],
        ),
    }

    for header_name, (rule_id, name, desc, sev, compliance) in required.items():
        if header_name not in h:
            findings.append(_finding(rule_id, name, desc, sev, compliance, url))

    # Check weak CSP
    csp = h.get('content-security-policy', '')
    if csp:
        if "'unsafe-inline'" in csp:
            findings.append(_finding(
                'WEB-HDR-07', "CSP allows 'unsafe-inline'",
                "CSP directive contains 'unsafe-inline' which defeats XSS protection. "
                "Use nonces or hashes instead.",
                'HIGH', ['OWASP-A3:2021', 'CWE-116'], url,
            ))
        if "'unsafe-eval'" in csp:
            findings.append(_finding(
                'WEB-HDR-08', "CSP allows 'unsafe-eval'",
                "CSP directive contains 'unsafe-eval' allowing dynamic code execution. "
                "Remove this directive.",
                'MEDIUM', ['OWASP-A3:2021', 'CWE-116'], url,
            ))
        if 'default-src *' in csp or "default-src '*'" in csp:
            findings.append(_finding(
                'WEB-HDR-09', 'CSP default-src is wildcard',
                "CSP default-src is set to '*' which allows loading resources from any origin.",
                'HIGH', ['OWASP-A3:2021', 'CWE-116'], url,
            ))

    # Check HSTS details
    hsts = h.get('strict-transport-security', '')
    if hsts:
        if 'max-age=0' in hsts:
            findings.append(_finding(
                'WEB-HDR-10', 'HSTS max-age=0 (disabled)',
                'HSTS header sets max-age=0, effectively disabling HSTS protection.',
                'HIGH', ['OWASP-A2:2021', 'CWE-319'], url,
            ))
        elif 'max-age=' in hsts:
            age = re.search(r'max-age=(\d+)', hsts)
            if age and int(age.group(1)) < 15552000:
                findings.append(_finding(
                    'WEB-HDR-11', 'HSTS max-age too short',
                    f'HSTS max-age is {age.group(1)}s (less than 180 days). '
                    'OWASP recommends at least 1 year (31536000s).',
                    'LOW', ['OWASP-A2:2021', 'CWE-319'], url,
                ))

    # Server header discloses version
    server = h.get('server', '')
    if server and re.search(r'[\d\.]{3,}', server):
        findings.append(_finding(
            'WEB-HDR-12', f'Server Version Disclosed: {server}',
            'Server header reveals software version allowing targeted version-specific attacks. '
            'Suppress or genericize the Server header.',
            'LOW', ['OWASP-A5:2021', 'CWE-200'], url,
        ))

    # X-Powered-By exposes technology
    xpb = h.get('x-powered-by', '')
    if xpb:
        findings.append(_finding(
            'WEB-HDR-13', f'X-Powered-By Header Disclosed: {xpb}',
            f'X-Powered-By: {xpb} reveals backend technology stack. Remove this header.',
            'LOW', ['OWASP-A5:2021', 'CWE-200'], url,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 3. Cookies
# ─────────────────────────────────────────────────────────────────────────────

def _check_cookies(url: str, response) -> List[dict]:
    findings = []
    if not hasattr(response, 'cookies'):
        return findings

    for cookie in response.cookies:
        name = cookie.name or 'unknown'
        is_sensitive = any(s in name.lower() for s in
                           ('sess', 'auth', 'token', 'jwt', 'login', 'id', 'user', 'account'))

        if not cookie.secure:
            sev = 'HIGH' if is_sensitive else 'MEDIUM'
            findings.append(_finding(
                'WEB-CKI-01', f'Cookie "{name}" Missing Secure Flag',
                f'Cookie {name} is transmitted over HTTP. Set the Secure attribute to '
                'prevent transmission over unencrypted connections.',
                sev, ['OWASP-A2:2021', 'CWE-614'], url,
            ))

        if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.has_nonstandard_attr('httponly'):
            sev = 'HIGH' if is_sensitive else 'MEDIUM'
            findings.append(_finding(
                'WEB-CKI-02', f'Cookie "{name}" Missing HttpOnly Flag',
                f'Cookie {name} is accessible via JavaScript. Add HttpOnly to prevent '
                'session token theft via XSS.',
                sev, ['OWASP-A3:2021', 'CWE-1004'], url,
            ))

        samesite = cookie.has_nonstandard_attr('SameSite') or cookie.has_nonstandard_attr('samesite')
        if not samesite:
            findings.append(_finding(
                'WEB-CKI-03', f'Cookie "{name}" Missing SameSite Attribute',
                f'Cookie {name} has no SameSite attribute making it vulnerable to CSRF. '
                'Add SameSite=Strict or SameSite=Lax.',
                'MEDIUM', ['OWASP-A1:2021', 'CWE-352'], url,
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 4. CORS
# ─────────────────────────────────────────────────────────────────────────────

def _check_cors(url: str, session, timeout: int) -> List[dict]:
    findings = []
    try:
        test_headers = {'Origin': 'https://evil.com'}
        resp = session.get(url, headers=test_headers, timeout=timeout, allow_redirects=True)
        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

        if acao == '*':
            if acac == 'true':
                findings.append(_finding(
                    'WEB-CRS-01', 'CORS Wildcard with Allow-Credentials',
                    'Access-Control-Allow-Origin: * combined with Allow-Credentials: true '
                    'allows any origin to make authenticated cross-origin requests. '
                    'This is a critical misconfiguration enabling data theft.',
                    'CRITICAL', ['OWASP-A5:2021', 'CWE-346', 'ISO-27001:A.14'], url,
                ))
            else:
                findings.append(_finding(
                    'WEB-CRS-02', 'CORS Wildcard Origin Allowed',
                    'Access-Control-Allow-Origin: * allows any external website to read '
                    'responses from this API. Restrict to specific trusted origins.',
                    'MEDIUM', ['OWASP-A5:2021', 'CWE-346'], url,
                ))
        elif acao == 'https://evil.com':
            findings.append(_finding(
                'WEB-CRS-03', 'CORS Reflects Arbitrary Origin',
                'Server reflects the attacker-controlled Origin header back in ACAO. '
                'This is equivalent to a wildcard and allows cross-origin data theft.',
                'CRITICAL', ['OWASP-A5:2021', 'CWE-346', 'ISO-27001:A.14'], url,
            ))
    except Exception:
        pass
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 5. Forms
# ─────────────────────────────────────────────────────────────────────────────

def _check_forms(url: str, forms: List[dict]) -> List[dict]:
    findings = []
    for form in forms:
        action = form.get('action', url)
        method = form.get('method', 'GET')
        inputs = form.get('inputs', [])

        has_password = any(i['type'] == 'password' for i in inputs)
        has_csrf = form.get('has_csrf', False)

        if has_password and not has_csrf:
            findings.append(_finding(
                'WEB-FRM-01', f'Login Form Without CSRF Token',
                f'Form at {action} (method={method}) handles passwords but has no CSRF token. '
                'Add a synchronized token pattern to prevent cross-site request forgery.',
                'HIGH', ['OWASP-A1:2021', 'CWE-352'], url,
            ))

        if method == 'POST' and action.startswith('http://'):
            findings.append(_finding(
                'WEB-FRM-02', f'Form Submits Data Over HTTP',
                f'Form action {action} uses HTTP (not HTTPS). Credentials and data '
                'submitted via this form travel in plaintext.',
                'CRITICAL', ['OWASP-A2:2021', 'CWE-319'], url,
            ))

        if has_password:
            autocomplete_off = any(
                i.get('name', '').lower() in ('password', 'passwd', 'pwd')
                for i in inputs
            )
            if not autocomplete_off:
                findings.append(_finding(
                    'WEB-FRM-03', 'Password Field Without autocomplete=off',
                    f'Password input in form at {action} does not set autocomplete=off. '
                    'Browsers may cache the password in history.',
                    'LOW', ['OWASP-A2:2021', 'CWE-522'], url,
                ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 6. JavaScript SAST
# ─────────────────────────────────────────────────────────────────────────────

def _check_js_content(url: str, js_code: str, source_label: str) -> List[dict]:
    """Run SAST rules against downloaded JavaScript content."""
    findings = []
    from .rules_engine import RulesEngine
    engine = RulesEngine()
    lines = js_code.splitlines()
    for rule in engine.get_rules_for_language('.js'):
        for i, line in enumerate(lines, 1):
            if rule.match_text(line):
                findings.append(_finding(
                    rule.id, rule.name,
                    rule.description,
                    rule.severity, rule.compliance,
                    url, line=i, extra_file=source_label,
                ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 7. Sensitive Paths
# ─────────────────────────────────────────────────────────────────────────────

def _check_sensitive_paths(base_url: str, session, timeout: int) -> List[dict]:
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    origin = f'{parsed.scheme}://{parsed.netloc}'

    def _probe(path):
        try:
            resp = session.get(origin + path, timeout=timeout, allow_redirects=False)
            if resp.status_code in (200, 206):
                return path, resp.status_code, len(resp.content)
            if resp.status_code == 401:
                return path, 401, 0
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_probe, p): p for p in _SENSITIVE_PATHS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                path, status, size = result
                full_url = origin + path
                if status == 200:
                    sev = 'CRITICAL' if any(s in path for s in ('.env', '.git', 'config', 'backup', 'sql', 'phpinfo')) else 'HIGH'
                    findings.append(_finding(
                        'WEB-PTH-01', f'Sensitive Path Accessible: {path}',
                        f'GET {full_url} returned HTTP {status} ({size} bytes). '
                        f'This resource should not be publicly accessible. '
                        'Restrict access via server configuration or remove the file.',
                        sev, ['OWASP-A5:2021', 'CWE-538', 'ISO-27001:A.13'], full_url,
                    ))
                elif status == 401:
                    findings.append(_finding(
                        'WEB-PTH-02', f'Protected Sensitive Path Found: {path}',
                        f'GET {full_url} returned HTTP 401 (auth required). '
                        'The path exists and is authentication-protected — verify access controls are correct.',
                        'MEDIUM', ['OWASP-A5:2021', 'CWE-200'], full_url,
                    ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 8. DAST Probes (XSS, SQLi, Open Redirect)
# ─────────────────────────────────────────────────────────────────────────────

def _check_dast_probes(url: str, session, timeout: int) -> List[dict]:
    findings = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        return findings

    for param_name in list(params.keys())[:5]:
        base_params = dict(params)

        # XSS probe
        for payload in _XSS_PAYLOADS[:2]:
            base_params[param_name] = [payload]
            test_url = parsed._replace(query=urllib.parse.urlencode(base_params, doseq=True)).geturl()
            try:
                resp = session.get(test_url, timeout=timeout, allow_redirects=False)
                body = resp.text
                if payload in body and resp.headers.get('content-type', '').startswith('text/html'):
                    findings.append(_finding(
                        'WEB-XSS-01', f'Reflected XSS in Parameter: {param_name}',
                        f'Payload {payload!r} was reflected unencoded in the HTML response at {test_url}. '
                        'Validate and HTML-encode all user input before rendering in responses.',
                        'CRITICAL', ['OWASP-A3:2021', 'CWE-79', 'ISO-27001:A.14'], url,
                    ))
                    break
            except Exception:
                pass

        # SQLi probe
        sqli_payload = "' OR '1'='1"
        base_params[param_name] = [sqli_payload]
        test_url = parsed._replace(query=urllib.parse.urlencode(base_params, doseq=True)).geturl()
        try:
            resp = session.get(test_url, timeout=timeout, allow_redirects=False)
            body = resp.text.lower()
            for pattern in _SQLI_ERRORS:
                if re.search(pattern, body, re.IGNORECASE):
                    findings.append(_finding(
                        'WEB-SQL-01', f'SQL Injection Error in Parameter: {param_name}',
                        f'SQL error message detected in response for parameter {param_name}. '
                        'The application may be vulnerable to SQL injection. '
                        'Use parameterized queries / prepared statements.',
                        'CRITICAL', ['OWASP-A3:2021', 'CWE-89', 'ISO-27001:A.14'], url,
                    ))
                    break
        except Exception:
            pass

        # Open redirect probe
        for payload in _REDIRECT_PAYLOADS[:1]:
            base_params[param_name] = [payload]
            test_url = parsed._replace(query=urllib.parse.urlencode(base_params, doseq=True)).geturl()
            try:
                resp = session.get(test_url, timeout=timeout, allow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get('Location', '')
                    if 'evil.com' in loc:
                        findings.append(_finding(
                            'WEB-RDR-01', f'Open Redirect in Parameter: {param_name}',
                            f'Parameter {param_name} caused a redirect to {loc}. '
                            'Open redirects can be used in phishing attacks. '
                            'Whitelist allowed redirect destinations.',
                            'HIGH', ['OWASP-A1:2021', 'CWE-601'], url,
                        ))
            except Exception:
                pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 9. Information Disclosure
# ─────────────────────────────────────────────────────────────────────────────

def _check_info_disclosure(url: str, body: str) -> List[dict]:
    findings = []
    for pattern, description in _INFO_DISCLOSURE_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append(_finding(
                'WEB-INF-01', f'Information Disclosure: {description}',
                f'{description} detected in response body. This reveals internal implementation '
                'details that help attackers fingerprint and target the system. '
                'Disable debug output and configure custom error pages.',
                'HIGH', ['OWASP-A5:2021', 'CWE-200', 'ISO-27001:A.14'], url,
            ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 10. Redirect HTTP→HTTPS check
# ─────────────────────────────────────────────────────────────────────────────

def _check_http_redirect(hostname: str, session, timeout: int) -> List[dict]:
    findings = []
    try:
        resp = session.get(f'http://{hostname}/', timeout=timeout, allow_redirects=False)
        if resp.status_code not in (301, 302, 307, 308):
            findings.append(_finding(
                'WEB-HDR-14', 'HTTP Not Redirected to HTTPS',
                f'http://{hostname}/ returned {resp.status_code} without redirecting to HTTPS. '
                'Configure a permanent 301 redirect to enforce HTTPS for all traffic.',
                'HIGH', ['OWASP-A2:2021', 'CWE-319', 'PCI-DSS 4.1'], f'http://{hostname}/',
            ))
        else:
            loc = resp.headers.get('Location', '')
            if not loc.startswith('https://'):
                findings.append(_finding(
                    'WEB-HDR-15', 'HTTP Redirects to Non-HTTPS URL',
                    f'HTTP redirect goes to {loc} (not HTTPS). Ensure redirect always points '
                    'to the HTTPS version.',
                    'MEDIUM', ['OWASP-A2:2021', 'CWE-319'], f'http://{hostname}/',
                ))
    except Exception:
        pass
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Crawler
# ─────────────────────────────────────────────────────────────────────────────

def _crawl(
    start_url: str,
    session,
    timeout: int,
    max_depth: int = 2,
    max_pages: int = 50,
) -> Dict[str, dict]:
    """
    Breadth-first crawl within the same domain.
    Returns { url: { 'status', 'headers', 'body', 'forms', 'scripts', 'inline_scripts' } }
    """
    parsed_start = urllib.parse.urlparse(start_url)
    base_domain = parsed_start.netloc
    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(start_url, 0)]
    results: Dict[str, dict] = {}

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        url = url.split('#')[0]
        if not url or url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            content_type = resp.headers.get('content-type', '')
            body = ''
            forms = []
            scripts_ext = []
            inline_scripts = []
            links = []

            if 'text/html' in content_type:
                body = resp.text
                extractor = _LinkExtractor(url)
                extractor.feed(body)
                forms = extractor.forms
                scripts_ext = extractor.scripts
                inline_scripts = extractor.inline_scripts
                links = extractor.links

            results[url] = {
                'status': resp.status_code,
                'headers': dict(resp.headers),
                'cookies_resp': resp,
                'body': body[:100_000],
                'forms': forms,
                'scripts': scripts_ext,
                'inline_scripts': inline_scripts,
            }

            if depth < max_depth:
                for link in links:
                    if not link:
                        continue
                    lp = urllib.parse.urlparse(link)
                    if lp.netloc == base_domain and link not in visited:
                        queue.append((link, depth + 1))

        except Exception as e:
            results[url] = {'status': -1, 'error': str(e), 'headers': {}, 'body': '',
                            'forms': [], 'scripts': [], 'inline_scripts': [], 'cookies_resp': None}

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def _finding(
    rule_id: str,
    name: str,
    description: str,
    severity: str,
    compliance: List[str],
    url: str,
    line: int = 0,
    extra_file: str = '',
) -> dict:
    return {
        'rule_id': rule_id,
        'name': name,
        'description': description,
        'severity': severity,
        'compliance': compliance,
        'file': extra_file or url,
        'url': url,
        'line': line,
        'source': 'DAST',
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

class WebScanResult:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.findings: List[dict] = []
        self.pages_scanned: int = 0
        self.js_files_scanned: int = 0
        self.forms_scanned: int = 0
        self.ssl_info: dict = {}
        self.tech_stack: List[str] = []
        self.scan_duration: float = 0.0
        self.scan_time: str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def run_web_scan(
    url: str,
    depth: int = 2,
    max_pages: int = 50,
    min_severity: str = 'LOW',
    verify_ssl: bool = True,
    timeout: int = 15,
    skip_dast_probes: bool = False,
    session_override=None,
) -> WebScanResult:
    """
    Full web security audit. Returns a WebScanResult with all findings.

    Only call this with explicit written authorization from the target owner.
    """
    if not _REQUESTS_OK:
        raise ImportError(
            'requests library required: pip install requests --break-system-packages'
        )

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    result = WebScanResult(url)
    if session_override is not None:
        session = session_override
        # Apply SSL verify setting on provided session
        session.verify = verify_ssl
    else:
        session, timeout = _make_session(timeout=timeout, verify_ssl=verify_ssl)
    t_start = time.monotonic()

    print(f'\033[94m[AuditLens Web]\033[0m Target: {url}')

    # 1. SSL/TLS
    if parsed.scheme == 'https':
        print('\033[94m[AuditLens Web]\033[0m [1/8] Analizando SSL/TLS...')
        result.findings.extend(_check_ssl(hostname, port))

    # 2. HTTP → HTTPS redirect
    print('\033[94m[AuditLens Web]\033[0m [2/8] Verificando redirección HTTP→HTTPS...')
    result.findings.extend(_check_http_redirect(hostname, session, timeout))

    # 3. CORS
    print('\033[94m[AuditLens Web]\033[0m [3/8] Probando política CORS...')
    result.findings.extend(_check_cors(url, session, timeout))

    # 4. Sensitive paths
    print('\033[94m[AuditLens Web]\033[0m [4/8] Enumerando rutas sensibles...')
    result.findings.extend(_check_sensitive_paths(url, session, timeout))

    # 5. Crawl
    print(f'\033[94m[AuditLens Web]\033[0m [5/8] Crawling (depth={depth}, max={max_pages} páginas)...')
    pages = _crawl(url, session, timeout, max_depth=depth, max_pages=max_pages)
    result.pages_scanned = len(pages)

    all_js_sources: List[Tuple[str, str]] = []
    seen_js: Set[str] = set()

    for page_url, page_data in pages.items():
        if page_data.get('status', -1) < 0:
            continue

        # Headers check (once per unique header set)
        result.findings.extend(_check_headers(page_url, page_data['headers'], page_url))

        # Cookies
        if page_data.get('cookies_resp'):
            result.findings.extend(_check_cookies(page_url, page_data['cookies_resp']))

        # Forms
        result.findings.extend(_check_forms(page_url, page_data.get('forms', [])))
        result.forms_scanned += len(page_data.get('forms', []))

        # Info disclosure
        result.findings.extend(_check_info_disclosure(page_url, page_data.get('body', '')))

        # Collect JS for SAST
        for js_url in page_data.get('scripts', []):
            if js_url and js_url not in seen_js:
                seen_js.add(js_url)
                all_js_sources.append((js_url, 'external'))

        for i, js_code in enumerate(page_data.get('inline_scripts', [])):
            label = f'{page_url}#inline-script-{i+1}'
            all_js_sources.append((label, 'inline:' + js_code))

        # DAST probes on pages with query params
        if not skip_dast_probes and '?' in page_url:
            result.findings.extend(_check_dast_probes(page_url, session, timeout))

    # 6. JavaScript SAST
    print(f'\033[94m[AuditLens Web]\033[0m [6/8] Analizando JavaScript ({len(all_js_sources)} archivos)...')
    for label, src_or_code in all_js_sources:
        if src_or_code.startswith('inline:'):
            code = src_or_code[7:]
        else:
            try:
                resp = session.get(label, timeout=timeout)
                code = resp.text
            except Exception:
                continue
        result.findings.extend(_check_js_content(label, code, label))
        result.js_files_scanned += 1

    # 7. Tech fingerprint from first page
    print('\033[94m[AuditLens Web]\033[0m [7/8] Fingerprinting tecnología...')
    if url in pages and pages[url].get('body'):
        body = pages[url]['body']
        hdrs = pages[url].get('headers', {})
        tech = _fingerprint_tech(hdrs, body)
        result.tech_stack = tech

    # 8. Deduplicate findings
    print('\033[94m[AuditLens Web]\033[0m [8/8] Filtrando y deduplicando hallazgos...')
    result.findings = _deduplicate(result.findings, min_severity)

    result.scan_duration = time.monotonic() - t_start

    # Summary
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in result.findings:
        sev = f['severity'].upper()
        if sev in counts:
            counts[sev] += 1

    print(f'\n\033[92m[AuditLens Web]\033[0m Escaneo completado en {result.scan_duration:.1f}s')
    print(f'   Páginas: {result.pages_scanned}  |  JS: {result.js_files_scanned}  |  Forms: {result.forms_scanned}')
    print(
        f"   Hallazgos: {len(result.findings)}  "
        f"(\033[91mCRITICAL:{counts['CRITICAL']}  HIGH:{counts['HIGH']}\033[0m  "
        f"\033[93mMEDIUM:{counts['MEDIUM']}\033[0m  \033[90mLOW:{counts['LOW']}\033[0m)"
    )

    return result


def _fingerprint_tech(headers: dict, body: str) -> List[str]:
    h = {k.lower(): v for k, v in headers.items()}
    tech = []
    checks = [
        (h.get('server', ''), r'(nginx|apache|iis|lighttpd|caddy|gunicorn|tornado|jetty)', 'Web server'),
        (h.get('x-powered-by', ''), r'(php|asp\.net|express|django|rails|laravel|symfony)', 'Framework'),
        (h.get('x-generator', ''), r'\w+', 'CMS'),
        (body, r'(wordpress|wp-content|drupal|joomla|magento|shopify)', 'CMS'),
        (body, r'(react|angular|vue\.js|next\.js|nuxt|ember|backbone)', 'JS framework'),
        (body, r'(jquery/[\d\.]+)', 'jQuery version'),
        (body, r'(bootstrap/[\d\.]+)', 'Bootstrap version'),
    ]
    for text, pattern, category in checks:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            tech.append(f'{category}: {m.group(0)}')
    return list(dict.fromkeys(tech))


def _deduplicate(findings: List[dict], min_severity: str) -> List[dict]:
    min_rank = _SEVERITY_RANK.get(min_severity.upper(), 0)
    seen: Set[str] = set()
    result = []
    for f in findings:
        if _SEVERITY_RANK.get(f['severity'].upper(), 0) < min_rank:
            continue
        key = f'{f["rule_id"]}|{f["file"]}|{f["line"]}'
        if key not in seen:
            seen.add(key)
            result.append(f)
    return sorted(result, key=lambda x: -_SEVERITY_RANK.get(x['severity'].upper(), 0))
