"""
AuditLens Dependency Confusion Detector — detecta paquetes internos privados
que podrían ser suplantados en registros públicos (PyPI / npm).

El ataque: si un paquete privado llamado "mycompany-utils" NO existe en PyPI/npm,
un atacante puede publicarlo allí y los sistemas sin mirror privado
lo descargarán desde el registro público.

Usage:
    auditlens dep-confusion ./project
"""

from __future__ import annotations

import json
import os
import re
from typing import List, Optional, Tuple

import requests

_PRIVATE_INDICATORS = [
    r'\.internal\b', r'\.corp\b', r'\.local\b', r'\.private\b',
    r'\binternal[-_]', r'\bprivate[-_]', r'\bcorp[-_]',
    r'\bmy[-_company]+',
]
_PRIVATE_RE = re.compile('|'.join(_PRIVATE_INDICATORS), re.IGNORECASE)

_COMPLIANCE = ['CWE-829', 'OWASP-A6:2021', 'ISO-27001:A.12']


def _exists_on_pypi(package: str) -> bool:
    try:
        resp = requests.get(
            f'https://pypi.org/pypi/{package}/json',
            timeout=8,
        )
        return resp.status_code == 200
    except Exception:
        return False


def _exists_on_npm(package: str) -> bool:
    try:
        resp = requests.get(
            f'https://registry.npmjs.org/{package}',
            timeout=8,
        )
        return resp.status_code == 200
    except Exception:
        return False


def _parse_requirements(path: str) -> List[Tuple[str, str]]:
    deps = []
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith(('#', '-')):
                    continue
                m = re.match(r'^([A-Za-z0-9][\w\-\.]*)', line)
                if m:
                    deps.append((m.group(1), path))
    except OSError:
        pass
    return deps


def _parse_package_json(path: str) -> List[Tuple[str, str]]:
    deps = []
    try:
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
        for section in ('dependencies', 'devDependencies'):
            for name in data.get(section, {}):
                deps.append((name, path))
    except (OSError, json.JSONDecodeError):
        pass
    return deps


def scan_dependency_confusion(project_path: str) -> List[dict]:
    """
    Check private-looking package names against public registries.
    Returns findings for packages that DON'T exist in public registry
    (prime confusion targets) and optionally for those that DO
    (possible squatting already in progress).
    """
    findings: List[dict] = []

    candidates: List[Tuple[str, str, str]] = []  # (name, source_file, ecosystem)

    req = os.path.join(project_path, 'requirements.txt')
    if os.path.isfile(req):
        for name, src in _parse_requirements(req):
            candidates.append((name, src, 'python'))

    pkg = os.path.join(project_path, 'package.json')
    if os.path.isfile(pkg):
        for name, src in _parse_package_json(pkg):
            candidates.append((name, src, 'node'))

    if not candidates:
        return findings

    print(f'\033[94m[AuditLens DepConf]\033[0m Verificando {len(candidates)} dependencias contra registros públicos...')

    for name, src_file, ecosystem in candidates:
        # Only check packages that look like internal names
        looks_private = (
            bool(_PRIVATE_RE.search(name))
            or '-internal' in name
            or name.startswith('@')  # scoped npm packages can be private
        )

        if ecosystem == 'python':
            exists = _exists_on_pypi(name)
            registry = 'PyPI'
        else:
            exists = _exists_on_npm(name)
            registry = 'npm'

        if looks_private and not exists:
            # Classic confusion target — name is private-looking AND not on public registry
            findings.append({
                'rule_id': 'DEP-CONF-01',
                'name': f'Dependency Confusion Target: {name}',
                'description': (
                    f'Package "{name}" appears to be a private/internal dependency '
                    f'but does NOT exist on {registry}. '
                    'An attacker can publish a malicious package with this exact name on the public registry '
                    'and tools without a proper registry mirror/priority config will install it instead. '
                    'Publish a placeholder package on the public registry or configure your package manager '
                    'to always prefer the private registry.'
                ),
                'severity': 'HIGH',
                'compliance': _COMPLIANCE,
                'file': src_file,
                'line': 0,
                'source': 'DEP-CONFUSION',
            })
        elif not looks_private and not exists:
            # Generic missing package — could be a typo or abandoned
            findings.append({
                'rule_id': 'DEP-CONF-02',
                'name': f'Package Not Found on Public Registry: {name}',
                'description': (
                    f'Package "{name}" is listed as a dependency but was not found on {registry}. '
                    'This may be a typo (typosquatting risk) or a package that has been removed. '
                    'Verify the package name is correct.'
                ),
                'severity': 'LOW',
                'compliance': _COMPLIANCE,
                'file': src_file,
                'line': 0,
                'source': 'DEP-CONFUSION',
            })

    print(f'\033[92m[AuditLens DepConf]\033[0m {len(findings)} posibles vectores de confusión encontrados.')
    return findings
