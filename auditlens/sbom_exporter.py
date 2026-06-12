"""
AuditLens SBOM Exporter — genera Software Bill of Materials en formato
CycloneDX JSON (v1.4) y SPDX JSON (v2.3).

Usage:
    auditlens sbom ./project --format cyclonedx --output sbom.json
    auditlens sbom ./project --format spdx --output sbom.spdx.json
"""

from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple


def _parse_requirements_txt(path: str) -> List[Tuple[str, str, str]]:
    """Returns list of (name, version, ecosystem)."""
    deps = []
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith(('#', '-', '/')):
                    continue
                m = re.match(r'^([A-Za-z0-9][\w\-\.]*)\s*[=><~!]+\s*([^\s;#,]+)', line)
                if m:
                    ver = m.group(2).lstrip('=')
                    deps.append((m.group(1), ver, 'pypi'))
                else:
                    m2 = re.match(r'^([A-Za-z0-9][\w\-\.]*)', line)
                    if m2:
                        deps.append((m2.group(1), 'unknown', 'pypi'))
    except OSError:
        pass
    return deps


def _parse_package_json(path: str) -> List[Tuple[str, str, str]]:
    deps = []
    try:
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
        for section in ('dependencies', 'devDependencies', 'peerDependencies'):
            for name, ver in data.get(section, {}).items():
                ver_clean = ver.lstrip('^~>=<').split(' ')[0] or 'unknown'
                deps.append((name, ver_clean, 'npm'))
    except (OSError, json.JSONDecodeError):
        pass
    return deps


def _collect_components(project_path: str) -> List[Dict[str, str]]:
    components = []
    seen = set()

    for fname, parser in [
        ('requirements.txt', _parse_requirements_txt),
        ('package.json', _parse_package_json),
    ]:
        fpath = os.path.join(project_path, fname)
        if not os.path.isfile(fpath):
            continue
        for name, version, ecosystem in parser(fpath):
            key = f'{ecosystem}:{name}:{version}'
            if key in seen:
                continue
            seen.add(key)
            if ecosystem == 'pypi':
                purl = f'pkg:pypi/{name.lower()}@{version}'
            else:
                purl = f'pkg:npm/{name}@{version}'
            components.append({
                'name': name,
                'version': version,
                'ecosystem': ecosystem,
                'purl': purl,
                'type': 'library',
            })

    return components


def generate_cyclonedx(project_path: str, output_path: str, project_name: str = '') -> str:
    """Generate CycloneDX 1.4 JSON SBOM."""
    if not project_name:
        project_name = os.path.basename(os.path.abspath(project_path))

    components = _collect_components(project_path)

    sbom: Dict[str, Any] = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.4',
        'serialNumber': f'urn:uuid:{uuid.uuid4()}',
        'version': 1,
        'metadata': {
            'timestamp': _now_iso(),
            'tools': [{'vendor': 'AuditLens', 'name': 'auditlens', 'version': '0.9.0'}],
            'component': {
                'type': 'application',
                'name': project_name,
                'bom-ref': str(uuid.uuid4()),
            },
        },
        'components': [
            {
                'type': c['type'],
                'name': c['name'],
                'version': c['version'],
                'purl': c['purl'],
                'bom-ref': str(uuid.uuid4()),
                'scope': 'required',
            }
            for c in components
        ],
    }

    with open(output_path, 'w', encoding='utf-8') as fh:
        json.dump(sbom, fh, indent=2, ensure_ascii=False)

    print(
        f'\033[92m[AuditLens SBOM]\033[0m CycloneDX SBOM generado: {output_path} '
        f'({len(components)} componentes)'
    )
    return output_path


def generate_spdx(project_path: str, output_path: str, project_name: str = '') -> str:
    """Generate SPDX 2.3 JSON SBOM."""
    if not project_name:
        project_name = os.path.basename(os.path.abspath(project_path))

    components = _collect_components(project_path)
    doc_ns = f'https://auditlens.dev/sbom/{project_name}-{uuid.uuid4()}'

    packages = []
    relationships = []
    root_id = 'SPDXRef-DOCUMENT'

    for i, c in enumerate(components):
        elem_id = f'SPDXRef-{i + 1}-{re.sub(r"[^a-zA-Z0-9]", "-", c["name"])[:30]}'
        packages.append({
            'SPDXID': elem_id,
            'name': c['name'],
            'versionInfo': c['version'],
            'downloadLocation': 'NOASSERTION',
            'filesAnalyzed': False,
            'externalRefs': [
                {
                    'referenceCategory': 'PACKAGE-MANAGER',
                    'referenceType': 'purl',
                    'referenceLocator': c['purl'],
                }
            ],
        })
        relationships.append({
            'spdxElementId': root_id,
            'relationshipType': 'DESCRIBES',
            'relatedSpdxElement': elem_id,
        })

    sbom = {
        'SPDXID': root_id,
        'spdxVersion': 'SPDX-2.3',
        'creationInfo': {
            'created': _now_iso(),
            'creators': ['Tool: AuditLens-0.9.0'],
        },
        'name': project_name,
        'dataLicense': 'CC0-1.0',
        'documentNamespace': doc_ns,
        'packages': packages,
        'relationships': relationships,
    }

    with open(output_path, 'w', encoding='utf-8') as fh:
        json.dump(sbom, fh, indent=2, ensure_ascii=False)

    print(
        f'\033[92m[AuditLens SBOM]\033[0m SPDX SBOM generado: {output_path} '
        f'({len(components)} componentes)'
    )
    return output_path


def _now_iso() -> str:
    import datetime
    return datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
