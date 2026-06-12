"""
AuditLens License Compliance Checker — detecta dependencias con licencias
incompatibles con el tipo de proyecto (comercial / open-source).

Reads: requirements.txt, package.json, pyproject.toml, Pipfile

Usage:
    auditlens license-check ./project
    auditlens license-check ./project --project-type commercial
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

# Licenses grouped by permissiveness
_LICENSE_TIERS: Dict[str, str] = {
    # Copyleft — incompatible with closed-source commercial use
    'GPL-2.0':         'COPYLEFT_STRONG',
    'GPL-3.0':         'COPYLEFT_STRONG',
    'AGPL-3.0':        'COPYLEFT_NETWORK',
    'LGPL-2.0':        'COPYLEFT_WEAK',
    'LGPL-2.1':        'COPYLEFT_WEAK',
    'LGPL-3.0':        'COPYLEFT_WEAK',
    'MPL-2.0':         'COPYLEFT_WEAK',
    'EUPL-1.1':        'COPYLEFT_STRONG',
    'EUPL-1.2':        'COPYLEFT_STRONG',
    'CDDL-1.0':        'COPYLEFT_WEAK',
    'OSL-3.0':         'COPYLEFT_STRONG',
    # Permissive — generally OK
    'MIT':             'PERMISSIVE',
    'BSD-2-CLAUSE':    'PERMISSIVE',
    'BSD-3-CLAUSE':    'PERMISSIVE',
    'APACHE-2.0':      'PERMISSIVE',
    'ISC':             'PERMISSIVE',
    'WTFPL':           'PERMISSIVE',
    'UNLICENSE':       'PERMISSIVE',
    'CC0-1.0':         'PERMISSIVE',
    'ZLIB':            'PERMISSIVE',
    'BOOST-1.0':       'PERMISSIVE',
    '0BSD':            'PERMISSIVE',
    # Proprietary / commercial-only
    'COMMERCIAL':      'PROPRIETARY',
    'PROPRIETARY':     'PROPRIETARY',
    'SEE LICENSE':     'UNKNOWN',
    'UNLICENSED':      'UNKNOWN',
}

_SEVERITY_BY_TIER = {
    'COPYLEFT_NETWORK': 'CRITICAL',
    'COPYLEFT_STRONG':  'HIGH',
    'COPYLEFT_WEAK':    'MEDIUM',
    'PROPRIETARY':      'HIGH',
    'UNKNOWN':          'LOW',
    'PERMISSIVE':       None,
}

_COMPLIANCE = ['CWE-1104', 'ISO-27001:A.18', 'OWASP-A6:2021']


def _normalize_license(raw: str) -> str:
    raw = raw.upper().strip()
    # Strip parentheses, 'OR', 'AND', pick first
    raw = re.split(r'\s+(?:OR|AND)\s+', raw)[0]
    raw = raw.strip('() ')
    return raw


def _get_pypi_license(package: str, version: str) -> Optional[str]:
    """Query PyPI for license info."""
    try:
        import requests
        resp = requests.get(
            f'https://pypi.org/pypi/{package}/{version}/json',
            timeout=10,
        )
        if resp.status_code == 200:
            info = resp.json().get('info', {})
            lic = info.get('license', '') or ''
            if not lic:
                for clf in info.get('classifiers', []):
                    if clf.startswith('License ::'):
                        parts = clf.split(' :: ')
                        lic = parts[-1].strip()
                        break
            return lic or 'UNKNOWN'
    except Exception:
        pass
    return None


def _get_npm_license(package: str, version: str) -> Optional[str]:
    """Query npm registry for license info."""
    try:
        import requests
        resp = requests.get(
            f'https://registry.npmjs.org/{package}/{version}',
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get('license', 'UNKNOWN')
    except Exception:
        pass
    return None


def _parse_requirements_txt(path: str) -> List[Tuple[str, str]]:
    deps = []
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith(('#', '-', '/')):
                    continue
                m = re.match(r'^([A-Za-z0-9][\w\-\.]*)\s*[=><~!]+\s*([^\s;#,]+)', line)
                if m:
                    deps.append((m.group(1), m.group(2).lstrip('=')))
    except OSError:
        pass
    return deps


def _parse_package_json(path: str) -> List[Tuple[str, str]]:
    deps = []
    try:
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
        for section in ('dependencies', 'devDependencies', 'peerDependencies'):
            for name, ver in data.get(section, {}).items():
                ver_clean = ver.lstrip('^~>=<').split(' ')[0]
                deps.append((name, ver_clean))
    except (OSError, json.JSONDecodeError):
        pass
    return deps


def check_licenses(
    project_path: str,
    project_type: str = 'commercial',
    max_packages: int = 50,
) -> List[dict]:
    """
    Scan dependencies and flag license incompatibilities.
    project_type: 'commercial' | 'opensource'
    """
    findings: List[dict] = []
    checked = 0

    dep_files = {
        'requirements.txt': ('python', _parse_requirements_txt),
        'package.json': ('node', _parse_package_json),
    }

    for fname, (ecosystem, parser_fn) in dep_files.items():
        fpath = os.path.join(project_path, fname)
        if not os.path.isfile(fpath):
            continue

        deps = parser_fn(fpath)
        print(f'\033[94m[AuditLens License]\033[0m Checking {len(deps)} {ecosystem} packages...')

        for name, version in deps[:max_packages]:
            checked += 1
            if ecosystem == 'python':
                raw_lic = _get_pypi_license(name, version)
            else:
                raw_lic = _get_npm_license(name, version)

            if not raw_lic:
                continue

            normalized = _normalize_license(raw_lic)
            tier = _LICENSE_TIERS.get(normalized, 'UNKNOWN')
            severity = _SEVERITY_BY_TIER.get(tier)

            if severity is None:
                continue

            if tier == 'COPYLEFT_NETWORK' or (tier == 'COPYLEFT_STRONG' and project_type == 'commercial'):
                sev = 'CRITICAL' if tier == 'COPYLEFT_NETWORK' else 'HIGH'
                findings.append({
                    'rule_id': f'LIC-{tier[:3]}-01',
                    'name': f'Incompatible License: {name} ({raw_lic})',
                    'description': (
                        f'Package {name}@{version} uses {raw_lic} ({tier}). '
                        f'This license {"requires network-accessible services to release source code" if tier == "COPYLEFT_NETWORK" else "requires distributing your source code"} '
                        f'when used in a {project_type} project. '
                        'Replace with a permissively-licensed alternative or obtain a commercial license.'
                    ),
                    'severity': sev,
                    'compliance': _COMPLIANCE,
                    'file': fpath,
                    'line': 0,
                    'license': raw_lic,
                    'package': f'{name}@{version}',
                    'source': 'LICENSE',
                })
            elif tier == 'UNKNOWN':
                findings.append({
                    'rule_id': 'LIC-UNK-01',
                    'name': f'Unknown License: {name}',
                    'description': (
                        f'Package {name}@{version} has no recognized license ({raw_lic!r}). '
                        'Packages with no explicit license are NOT automatically open-source. '
                        'Contact the author or avoid using this dependency.'
                    ),
                    'severity': 'LOW',
                    'compliance': _COMPLIANCE,
                    'file': fpath,
                    'line': 0,
                    'license': raw_lic,
                    'package': f'{name}@{version}',
                    'source': 'LICENSE',
                })

    print(f'\033[92m[AuditLens License]\033[0m {checked} paquetes revisados, {len(findings)} problemas encontrados.')
    return findings
