"""
AuditLens — Kubernetes Security Auditor

Analiza manifiestos YAML/JSON de Kubernetes en busca de:
- Contenedores privilegiados
- runAsRoot
- Secretos en variables de entorno
- Sin resource limits
- Sin network policies
- RBAC con permisos excesivos (cluster-admin wildcard)
- Imágenes con tag :latest
- HostPath mounts
- ServiceAccount tokens automontados innecesariamente
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml
    _YAML_OK = True
except ImportError:
    _YAML_OK = False


def _walk_k8s_files(project_path: str) -> List[str]:
    skip = {'venv', '.venv', 'node_modules', '.git', '__pycache__'}
    root = Path(project_path)
    files = []
    for fpath in sorted(root.rglob('*')):
        if not fpath.is_file():
            continue
        if set(fpath.relative_to(root).parts) & skip:
            continue
        if fpath.suffix.lower() in ('.yaml', '.yml'):
            files.append(str(fpath))
    return files


def _check_manifest(manifest: Dict[str, Any], file_path: str) -> List[dict]:
    findings: List[dict] = []
    kind = manifest.get('kind', '')
    name = manifest.get('metadata', {}).get('name', '<unknown>')

    def finding(rule_id, title, desc, severity, line=0):
        findings.append({
            'rule_id': rule_id,
            'name': title,
            'description': desc,
            'severity': severity,
            'file': file_path,
            'line': line,
            'snippet': f'{kind}/{name}',
            'compliance': ['CWE-250', 'OWASP-A05:2021'],
            'source': 'K8S-AUDITOR',
        })

    spec = manifest.get('spec', {})

    # Pod/Deployment/DaemonSet/StatefulSet
    pod_spec = spec
    if kind in ('Deployment', 'DaemonSet', 'StatefulSet', 'ReplicaSet', 'Job', 'CronJob'):
        pod_spec = spec.get('template', {}).get('spec', {})
    if kind == 'CronJob':
        pod_spec = spec.get('jobTemplate', {}).get('spec', {}).get('template', {}).get('spec', {})

    containers = pod_spec.get('containers', []) + pod_spec.get('initContainers', [])

    for c in containers:
        cname = c.get('name', '<container>')
        sc    = c.get('securityContext', {})
        image = c.get('image', '')

        # Privileged
        if sc.get('privileged') is True:
            finding('K8S-PRIVILEGED', f'Contenedor privilegiado: {cname}',
                    'Un contenedor privilegiado tiene acceso completo al host. '
                    'Eliminar "privileged: true" y usar capabilities mínimas.',
                    'CRITICAL')

        # runAsRoot
        if sc.get('runAsUser') == 0 or sc.get('runAsNonRoot') is False:
            finding('K8S-RUN-AS-ROOT', f'Contenedor corre como root: {cname}',
                    'Correr como root (UID 0) aumenta el blast radius si el contenedor es comprometido. '
                    'Usar runAsNonRoot: true y runAsUser: >1000.',
                    'HIGH')

        # No runAsNonRoot set
        if 'runAsNonRoot' not in sc and 'runAsUser' not in sc:
            finding('K8S-NO-NONROOT', f'Sin runAsNonRoot en: {cname}',
                    'No se especifica runAsNonRoot. El contenedor puede correr como root por defecto.',
                    'MEDIUM')

        # :latest image tag
        if image.endswith(':latest') or (':' not in image and '@' not in image):
            finding('K8S-LATEST-TAG', f'Imagen con tag :latest: {image}',
                    'El tag :latest no es determinístico. Usar SHA digest o tag de versión específico.',
                    'MEDIUM')

        # No resource limits
        resources = c.get('resources', {})
        if not resources.get('limits'):
            finding('K8S-NO-LIMITS', f'Sin resource limits en: {cname}',
                    'Sin limits de CPU/memoria, un contenedor puede consumir todos los recursos del nodo.',
                    'MEDIUM')

        # Secrets in env vars
        for env in c.get('env', []):
            ev  = env.get('name', '').lower()
            val = env.get('value', '')
            if any(kw in ev for kw in ('password', 'secret', 'token', 'key', 'pass', 'pwd', 'api_key')):
                if val and not env.get('valueFrom'):
                    finding('K8S-SECRET-ENV', f'Secreto hardcodeado en env: {env.get("name","")}',
                            'Credenciales en variables de entorno deben usar secretFrom/valueFrom con Secret de K8s.',
                            'CRITICAL')

        # allowPrivilegeEscalation not false
        if sc.get('allowPrivilegeEscalation', True) is not False:
            finding('K8S-PRIV-ESC', f'allowPrivilegeEscalation no bloqueado: {cname}',
                    'Establecer allowPrivilegeEscalation: false para evitar que el proceso gane más privilegios.',
                    'MEDIUM')

        # readOnlyRootFilesystem
        if not sc.get('readOnlyRootFilesystem', False):
            finding('K8S-WRITABLE-ROOT', f'Filesystem raíz escribible: {cname}',
                    'readOnlyRootFilesystem: true previene escritura en el filesystem del contenedor.',
                    'LOW')

    # HostPath volumes
    for vol in pod_spec.get('volumes', []):
        if 'hostPath' in vol:
            finding('K8S-HOSTPATH', f'HostPath mount: {vol.get("name","")}',
                    f'HostPath monta directorios del host ({vol["hostPath"].get("path","?")}) en el contenedor. '
                    'Puede permitir escape del contenedor.',
                    'HIGH')

    # automountServiceAccountToken
    if pod_spec.get('automountServiceAccountToken') is not False:
        finding('K8S-SA-AUTOMOUNT', 'Service account token automontado',
                'automountServiceAccountToken: false debe ser explícito si el pod no necesita API access.',
                'LOW')

    # RBAC — ClusterRoleBinding con cluster-admin
    if kind == 'ClusterRoleBinding':
        ref = spec.get('roleRef', {})
        if ref.get('name') == 'cluster-admin':
            subjects = spec.get('subjects', [])
            for sub in subjects:
                finding('K8S-CLUSTER-ADMIN', f'cluster-admin asignado a: {sub.get("name","")}',
                        'El rol cluster-admin da control total del cluster. '
                        'Usar roles con permisos mínimos (principle of least privilege).',
                        'CRITICAL')

    # RBAC wildcard resources/verbs
    if kind in ('Role', 'ClusterRole'):
        for rule in spec.get('rules', []):
            if '*' in rule.get('verbs', []) and '*' in rule.get('resources', []):
                finding('K8S-RBAC-WILDCARD', f'RBAC wildcard en {kind}/{name}',
                        'Permisos wildcard (*) en resources y verbs dan acceso total. '
                        'Especificar permisos mínimos necesarios.',
                        'HIGH')

    # NetworkPolicy — warn if no NetworkPolicy in namespace
    # (can't detect absence here, flagged at directory level)

    return findings


def scan_k8s_manifests(project_path: str) -> List[dict]:
    if not _YAML_OK:
        print('\033[91m[AuditLens K8s]\033[0m PyYAML no disponible. Installar: pip install pyyaml')
        return []

    files = _walk_k8s_files(project_path)
    if not files:
        print(f'\033[93m[AuditLens K8s]\033[0m No se encontraron manifiestos YAML en {project_path}')
        return []

    all_findings: List[dict] = []
    has_network_policy = False
    k8s_files_found = 0

    for fpath in files:
        try:
            with open(fpath, encoding='utf-8', errors='replace') as fh:
                content = fh.read()
            docs = list(yaml.safe_load_all(content))
        except Exception:
            continue

        for doc in docs:
            if not isinstance(doc, dict) or 'kind' not in doc:
                continue
            k8s_files_found += 1
            if doc.get('kind') == 'NetworkPolicy':
                has_network_policy = True
            all_findings.extend(_check_manifest(doc, fpath))

    if k8s_files_found > 0 and not has_network_policy:
        all_findings.append({
            'rule_id': 'K8S-NO-NETWORK-POLICY',
            'name': 'No se encontraron NetworkPolicies',
            'description': (
                'Sin NetworkPolicy, todos los pods pueden comunicarse entre sí sin restricciones. '
                'Implementar network segmentation con NetworkPolicy.'
            ),
            'severity': 'HIGH',
            'file': project_path,
            'line': 0,
            'compliance': ['CWE-284', 'OWASP-A01:2021'],
            'source': 'K8S-AUDITOR',
        })

    counts = {}
    for f in all_findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1
    print(
        f'\033[94m[AuditLens K8s]\033[0m {len(all_findings)} hallazgos en {k8s_files_found} manifiestos | '
        f'CRITICAL:{counts.get("CRITICAL",0)} HIGH:{counts.get("HIGH",0)}'
    )
    return all_findings
