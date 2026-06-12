"""
AuditLens Authenticated DAST Scanner — realiza login antes de crawlear
para descubrir rutas protegidas por autenticación.

Supports:
  - Form-based login (username + password)
  - Bearer token (API key or JWT)

Requires --authorized flag in CLI.

Usage:
    auditlens web-scan https://app.example.com --authorized \\
        --auth-user admin --auth-pass secret123 --auth-login-url https://app.example.com/login
    auditlens web-scan https://app.example.com --authorized \\
        --auth-token Bearer:eyJ...
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .web_scanner import run_web_scan, WebScanResult


def _form_login(
    session: requests.Session,
    login_url: str,
    username: str,
    password: str,
    username_field: str = '',
    password_field: str = '',
    timeout: int = 12,
) -> bool:
    """Attempt form-based login. Returns True on apparent success."""
    try:
        resp = session.get(login_url, timeout=timeout, allow_redirects=True)
        soup = BeautifulSoup(resp.text, 'html.parser')

        form = soup.find('form')
        if not form:
            return False

        data: Dict[str, str] = {}

        # Collect existing hidden fields (CSRF tokens etc.)
        for inp in form.find_all('input'):
            itype = inp.get('type', '').lower()
            iname = inp.get('name', '')
            ival = inp.get('value', '')
            if itype == 'hidden' and iname:
                data[iname] = ival

        # Find username and password fields
        for inp in form.find_all('input'):
            itype = inp.get('type', '').lower()
            iname = inp.get('name', '').lower()
            if itype in ('text', 'email') or 'user' in iname or 'email' in iname or 'login' in iname:
                if username_field:
                    if inp.get('name') == username_field:
                        data[inp.get('name')] = username
                else:
                    data[inp.get('name', 'username')] = username
            elif itype == 'password' or 'pass' in iname:
                if password_field:
                    if inp.get('name') == password_field:
                        data[inp.get('name')] = password
                else:
                    data[inp.get('name', 'password')] = password

        # Determine form action
        action = form.get('action', '')
        if not action:
            action = login_url
        elif not action.startswith('http'):
            action = urljoin(login_url, action)

        method = form.get('method', 'post').lower()
        if method == 'post':
            post_resp = session.post(action, data=data, timeout=timeout, allow_redirects=True)
        else:
            post_resp = session.get(action, params=data, timeout=timeout, allow_redirects=True)

        # Heuristic: if we got redirected away from login page or status 200 with new URL, assume success
        final_url = post_resp.url
        parsed_login = urlparse(login_url).path.rstrip('/')
        parsed_final = urlparse(final_url).path.rstrip('/')
        success = parsed_final != parsed_login and post_resp.status_code in (200, 302)

        if success:
            print(f'\033[92m[AuditLens Auth]\033[0m Login exitoso en {login_url}')
        else:
            print(f'\033[93m[AuditLens Auth]\033[0m Login posiblemente fallido en {login_url} (status {post_resp.status_code})')

        return success

    except Exception as exc:
        print(f'\033[91m[AuditLens Auth]\033[0m Error durante login: {exc}')
        return False


def run_authenticated_web_scan(
    url: str,
    login_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    bearer_token: Optional[str] = None,
    username_field: str = '',
    password_field: str = '',
    depth: int = 3,
    max_pages: int = 50,
    min_severity: str = 'LOW',
    verify_ssl: bool = True,
    timeout: int = 12,
    skip_dast_probes: bool = False,
) -> WebScanResult:
    """
    Run an authenticated DAST scan.
    Either (login_url + username + password) or bearer_token must be provided.
    """
    session = requests.Session()

    if bearer_token:
        # Strip 'Bearer:' prefix if present
        token = bearer_token.replace('Bearer:', '').replace('Bearer ', '').strip()
        session.headers['Authorization'] = f'Bearer {token}'
        print(f'\033[94m[AuditLens Auth]\033[0m Usando Bearer token para: {url}')

    elif login_url and username and password:
        print(f'\033[94m[AuditLens Auth]\033[0m Intentando login en: {login_url}')
        ok = _form_login(
            session, login_url, username, password,
            username_field=username_field,
            password_field=password_field,
            timeout=timeout,
        )
        if not ok:
            print('\033[93m[AuditLens Auth]\033[0m Continuando escaneo sin autenticación confirmada.')
    else:
        print('\033[93m[AuditLens Auth]\033[0m Sin credenciales. Ejecutando escaneo no autenticado.')

    return run_web_scan(
        url=url,
        depth=depth,
        max_pages=max_pages,
        min_severity=min_severity,
        verify_ssl=verify_ssl,
        timeout=timeout,
        skip_dast_probes=skip_dast_probes,
        session_override=session,
    )
