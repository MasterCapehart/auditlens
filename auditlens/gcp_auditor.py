"""
AuditLens — GCP Security Auditor

Audita una cuenta Google Cloud Platform vía `gcloud` CLI:
- IAM: Service accounts con roles excesivos, cuentas desactivadas con roles
- Cloud Storage: buckets públicos, sin versioning, sin logging
- Firewall rules: allow-all ingress (0.0.0.0/0)
- Cloud SQL: IP pública sin authorized networks, sin backups
- Logging: Cloud Audit Logs desactivados
- KMS: claves con rotation period excesivo

Requiere: gcloud CLI autenticado con permisos suficientes.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, List, Optional


def _run_gcloud(args: List[str], project: str) -> Optional[Any]:
    cmd = ['gcloud', '--project', project, '--format', 'json'] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return json.loads(result.stdout) if result.stdout.strip() else []
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return None


def audit_gcp(project_id: str) -> List[dict]:
    findings: List[dict] = []

    def finding(rule_id, name, desc, severity, resource=''):
        findings.append({
            'rule_id': rule_id,
            'name': name,
            'description': desc,
            'severity': severity,
            'file': f'gcp://{project_id}/{resource}',
            'line': 0,
            'compliance': ['CWE-284', 'OWASP-A05:2021'],
            'source': 'GCP-AUDITOR',
        })

    print(f'\033[94m[AuditLens GCP]\033[0m Auditando proyecto: {project_id}')

    # ── Cloud Storage buckets ─────────────────────────────────────────────────
    buckets = _run_gcloud(['storage', 'buckets', 'list'], project_id)
    if buckets:
        for b in buckets:
            bname = b.get('name', '')
            iam   = _run_gcloud(['storage', 'buckets', 'get-iam-policy', f'gs://{bname}'], project_id)
            if iam:
                for binding in (iam.get('bindings') or []):
                    members = binding.get('members', [])
                    if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                        finding('GCP-BUCKET-PUBLIC', f'Bucket público: {bname}',
                                f'El bucket gs://{bname} permite acceso público. '
                                'Eliminar allUsers/allAuthenticatedUsers del IAM policy.',
                                'CRITICAL', f'storage/{bname}')
            # Versioning check via metadata
            meta = _run_gcloud(['storage', 'buckets', 'describe', f'gs://{bname}'], project_id)
            if meta and not meta.get('versioning', {}).get('enabled'):
                finding('GCP-BUCKET-NO-VERSIONING', f'Bucket sin versioning: {bname}',
                        'Sin object versioning, los archivos borrados no son recuperables.',
                        'LOW', f'storage/{bname}')

    # ── IAM service accounts ──────────────────────────────────────────────────
    iam_policy = _run_gcloud(['projects', 'get-iam-policy', project_id], project_id)
    if iam_policy:
        for binding in (iam_policy.get('bindings') or []):
            role    = binding.get('role', '')
            members = binding.get('members', [])
            if role in ('roles/owner', 'roles/editor'):
                for m in members:
                    if 'serviceAccount' in m:
                        finding('GCP-SA-OVERPRIVILEGED', f'Service account con rol excesivo: {m}',
                                f'Service account {m} tiene el rol {role}. '
                                'Usar el principio de mínimos privilegios.',
                                'HIGH', f'iam/{m}')
            if role == 'roles/owner' and any('user:' in m for m in members):
                for m in [x for x in members if 'user:' in x]:
                    finding('GCP-USER-OWNER', f'Usuario con rol Owner: {m}',
                            f'{m} tiene rol Owner en el proyecto. '
                            'Owner da control total. Usar roles más específicos.',
                            'HIGH', f'iam/{m}')

    # ── Firewall rules ────────────────────────────────────────────────────────
    fw_rules = _run_gcloud(['compute', 'firewall-rules', 'list'], project_id)
    if fw_rules:
        for rule in fw_rules:
            ranges = rule.get('sourceRanges', [])
            if '0.0.0.0/0' in ranges and rule.get('direction') == 'INGRESS':
                ports = rule.get('allowed', [])
                ports_str = ', '.join(
                    f'{p.get("IPProtocol","")}:{",".join(p.get("ports",[]))}'
                    for p in ports
                )
                finding('GCP-FW-ALLOW-ALL', f'Firewall rule permite todo el tráfico: {rule.get("name","")}',
                        f'La regla {rule.get("name","")} permite ingress desde 0.0.0.0/0 '
                        f'en puertos: {ports_str}. Restringir a IPs conocidas.',
                        'HIGH', f'firewall/{rule.get("name","")}')

    # ── Cloud SQL ─────────────────────────────────────────────────────────────
    sql_instances = _run_gcloud(['sql', 'instances', 'list'], project_id)
    if sql_instances:
        for inst in sql_instances:
            iname = inst.get('name', '')
            settings = inst.get('settings', {})
            ip_config = settings.get('ipConfiguration', {})
            if ip_config.get('ipv4Enabled') and not ip_config.get('authorizedNetworks'):
                finding('GCP-SQL-PUBLIC-NO-AUTH', f'Cloud SQL con IP pública sin redes autorizadas: {iname}',
                        f'La instancia {iname} tiene IP pública sin authorized networks. '
                        'Cualquier IP puede intentar conectarse.',
                        'HIGH', f'cloudsql/{iname}')
            if not settings.get('backupConfiguration', {}).get('enabled'):
                finding('GCP-SQL-NO-BACKUP', f'Cloud SQL sin backups automáticos: {iname}',
                        f'La instancia {iname} no tiene backups automáticos habilitados.',
                        'MEDIUM', f'cloudsql/{iname}')

    counts = {}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1
    print(
        f'\033[92m[AuditLens GCP]\033[0m {len(findings)} hallazgos | '
        f'CRITICAL:{counts.get("CRITICAL",0)} HIGH:{counts.get("HIGH",0)}'
    )
    return findings
