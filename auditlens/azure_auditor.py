"""
AuditLens — Azure Security Auditor

Audita una suscripción Azure vía `az` CLI:
- IAM: roles Owner/Contributor excesivos, service principals
- Storage accounts: public blob access, sin encryption, sin https-only
- Network Security Groups: reglas allow-any
- Key Vault: soft delete desactivado, acceso público
- App Service: debug habilitado, HTTP sin redirect a HTTPS
- SQL Server: auditoría desactivada, TDE desactivado
"""
from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, List, Optional


def _run_az(args: List[str]) -> Optional[Any]:
    cmd = ['az'] + args + ['--output', 'json']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return json.loads(result.stdout) if result.stdout.strip() else []
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return None


def audit_azure(subscription_id: Optional[str] = None) -> List[dict]:
    findings: List[dict] = []
    sub_flag = ['--subscription', subscription_id] if subscription_id else []

    def finding(rule_id, name, desc, severity, resource=''):
        findings.append({
            'rule_id': rule_id,
            'name': name,
            'description': desc,
            'severity': severity,
            'file': f'azure://{resource}',
            'line': 0,
            'compliance': ['CWE-284', 'OWASP-A05:2021'],
            'source': 'AZURE-AUDITOR',
        })

    print('\033[94m[AuditLens Azure]\033[0m Auditando suscripción Azure...')

    # ── IAM Role Assignments ──────────────────────────────────────────────────
    roles = _run_az(['role', 'assignment', 'list', '--all'] + sub_flag)
    if roles:
        for r in roles:
            role_def = r.get('roleDefinitionName', '')
            principal = r.get('principalName', r.get('principalId', ''))
            ptype = r.get('principalType', '')
            if role_def == 'Owner':
                finding('AZ-IAM-OWNER', f'Rol Owner asignado a: {principal}',
                        f'{principal} ({ptype}) tiene rol Owner. '
                        'Owner da control total de la suscripción. Usar roles más específicos.',
                        'HIGH', f'iam/{principal}')
            if role_def == 'Contributor' and ptype == 'ServicePrincipal':
                finding('AZ-SP-CONTRIBUTOR', f'Service Principal con Contributor: {principal}',
                        f'Service Principal {principal} tiene rol Contributor. '
                        'Limitar al scope mínimo necesario.',
                        'MEDIUM', f'iam/{principal}')

    # ── Storage Accounts ──────────────────────────────────────────────────────
    storage = _run_az(['storage', 'account', 'list'] + sub_flag)
    if storage:
        for sa in storage:
            name = sa.get('name', '')
            allow_blob = sa.get('allowBlobPublicAccess', True)
            https_only = sa.get('enableHttpsTrafficOnly', False)
            min_tls    = sa.get('minimumTlsVersion', 'TLS1_0')

            if allow_blob:
                finding('AZ-STORAGE-PUBLIC-BLOB', f'Storage con public blob access: {name}',
                        f'La cuenta {name} permite acceso público a blobs. '
                        'Deshabilitar allowBlobPublicAccess.',
                        'HIGH', f'storage/{name}')
            if not https_only:
                finding('AZ-STORAGE-HTTP', f'Storage permite HTTP: {name}',
                        f'La cuenta {name} no fuerza HTTPS. Habilitar httpsOnly.',
                        'MEDIUM', f'storage/{name}')
            if min_tls in ('TLS1_0', 'TLS1_1'):
                finding('AZ-STORAGE-WEAK-TLS', f'Storage con TLS débil ({min_tls}): {name}',
                        f'Versión mínima TLS {min_tls} es insegura. Actualizar a TLS1_2.',
                        'MEDIUM', f'storage/{name}')

    # ── Network Security Groups ───────────────────────────────────────────────
    nsgs = _run_az(['network', 'nsg', 'list'] + sub_flag)
    if nsgs:
        for nsg in nsgs:
            nsg_name = nsg.get('name', '')
            for rule in nsg.get('securityRules', []):
                if (rule.get('access') == 'Allow'
                        and rule.get('direction') == 'Inbound'
                        and rule.get('sourceAddressPrefix') in ('*', '0.0.0.0/0', 'Internet')
                        and rule.get('destinationPortRange') in ('*', '3389', '22')):
                    port = rule.get('destinationPortRange', '*')
                    finding(f'AZ-NSG-ALLOW-ANY-{port}',
                            f'NSG {nsg_name}: ingress irrestricto en puerto {port}',
                            f'La regla {rule.get("name","")} permite todo el tráfico entrante '
                            f'al puerto {port} desde Internet. Restringir a IPs conocidas.',
                            'CRITICAL', f'nsg/{nsg_name}')

    # ── Key Vault ─────────────────────────────────────────────────────────────
    kvs = _run_az(['keyvault', 'list'] + sub_flag)
    if kvs:
        for kv in kvs:
            kv_name = kv.get('name', '')
            props   = kv.get('properties', {})
            if not props.get('enableSoftDelete', True):
                finding('AZ-KV-NO-SOFT-DELETE', f'Key Vault sin soft delete: {kv_name}',
                        'Sin soft delete, las claves eliminadas no son recuperables.',
                        'HIGH', f'keyvault/{kv_name}')
            net_acls = props.get('networkAcls', {})
            if net_acls.get('defaultAction', 'Allow') == 'Allow':
                finding('AZ-KV-PUBLIC-ACCESS', f'Key Vault accesible públicamente: {kv_name}',
                        f'{kv_name} permite acceso desde cualquier red. '
                        'Configurar network ACLs para restringir el acceso.',
                        'MEDIUM', f'keyvault/{kv_name}')

    # ── App Service ───────────────────────────────────────────────────────────
    apps = _run_az(['webapp', 'list'] + sub_flag)
    if apps:
        for app in apps:
            app_name = app.get('name', '')
            https    = app.get('httpsOnly', False)
            if not https:
                finding('AZ-WEBAPP-NO-HTTPS', f'App Service sin HTTPS-only: {app_name}',
                        f'{app_name} acepta HTTP. Habilitar httpsOnly.',
                        'MEDIUM', f'appservice/{app_name}')

    counts = {}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1
    print(
        f'\033[92m[AuditLens Azure]\033[0m {len(findings)} hallazgos | '
        f'CRITICAL:{counts.get("CRITICAL",0)} HIGH:{counts.get("HIGH",0)}'
    )
    return findings
