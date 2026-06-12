"""
AuditLens AWS Security Auditor — revisa IAM, S3, Security Groups y
configuración de seguridad básica usando boto3.

Requires: AWS credentials via env vars or ~/.aws/credentials
  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION

Usage:
    auditlens aws-audit
    auditlens aws-audit --profile production --region us-east-1
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

_COMPLIANCE = ['CWE-284', 'ISO-27001:A.9', 'CIS-AWS', 'OWASP-A5:2021']


def _boto3_client(service: str, region: Optional[str] = None, profile: Optional[str] = None):
    try:
        import boto3
        session = boto3.Session(profile_name=profile, region_name=region)
        return session.client(service)
    except ImportError:
        return None
    except Exception:
        return None


def check_iam(region: Optional[str] = None, profile: Optional[str] = None) -> List[dict]:
    findings = []
    client = _boto3_client('iam', region=region, profile=profile)
    if not client:
        return findings

    # Root account access keys
    try:
        summary = client.get_account_summary()['SummaryMap']
        if summary.get('AccountAccessKeysPresent', 0) > 0:
            findings.append({
                'rule_id': 'AWS-IAM-01',
                'name': 'AWS Root Account Has Active Access Keys',
                'description': (
                    'The root AWS account has active API access keys. '
                    'Root access keys bypass all IAM policies and cannot be restricted. '
                    'Delete root access keys immediately and use IAM roles/users instead.'
                ),
                'severity': 'CRITICAL',
                'compliance': _COMPLIANCE + ['CIS-AWS-1.4'],
                'file': 'AWS/IAM',
                'line': 0,
                'source': 'AWS',
            })

        if summary.get('AccountMFAEnabled', 0) == 0:
            findings.append({
                'rule_id': 'AWS-IAM-02',
                'name': 'AWS Root Account MFA Not Enabled',
                'description': (
                    'Multi-Factor Authentication is not enabled on the root AWS account. '
                    'Enable MFA on the root account to prevent unauthorized access even if the password is compromised.'
                ),
                'severity': 'CRITICAL',
                'compliance': _COMPLIANCE + ['CIS-AWS-1.5'],
                'file': 'AWS/IAM',
                'line': 0,
                'source': 'AWS',
            })
    except Exception:
        pass

    # IAM users without MFA
    try:
        paginator = client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                uname = user['UserName']
                mfa = client.list_mfa_devices(UserName=uname)
                if not mfa['MFADevices']:
                    # Check if user has console access
                    try:
                        client.get_login_profile(UserName=uname)
                        has_console = True
                    except Exception:
                        has_console = False
                    if has_console:
                        findings.append({
                            'rule_id': 'AWS-IAM-03',
                            'name': f'IAM User Without MFA: {uname}',
                            'description': (
                                f'IAM user "{uname}" has console access but no MFA device configured. '
                                'Require MFA for all IAM users with console access.'
                            ),
                            'severity': 'HIGH',
                            'compliance': _COMPLIANCE + ['CIS-AWS-1.2'],
                            'file': f'AWS/IAM/users/{uname}',
                            'line': 0,
                            'source': 'AWS',
                        })
    except Exception:
        pass

    # Password policy
    try:
        policy = client.get_account_password_policy()['PasswordPolicy']
        if policy.get('MinimumPasswordLength', 0) < 14:
            findings.append({
                'rule_id': 'AWS-IAM-04',
                'name': 'IAM Password Policy: Minimum Length < 14',
                'description': (
                    f'AWS account password policy requires only {policy.get("MinimumPasswordLength")} characters. '
                    'Set minimum password length to at least 14 characters.'
                ),
                'severity': 'MEDIUM',
                'compliance': _COMPLIANCE + ['CIS-AWS-1.8'],
                'file': 'AWS/IAM/password-policy',
                'line': 0,
                'source': 'AWS',
            })
    except Exception:
        pass

    return findings


def check_s3(region: Optional[str] = None, profile: Optional[str] = None) -> List[dict]:
    findings = []
    client = _boto3_client('s3', region=region, profile=profile)
    if not client:
        return findings

    try:
        buckets = client.list_buckets().get('Buckets', [])
    except Exception:
        return findings

    for bucket in buckets:
        bname = bucket['Name']

        # Public access block
        try:
            pab = client.get_public_access_block(Bucket=bname)['PublicAccessBlockConfiguration']
            if not all([
                pab.get('BlockPublicAcls', False),
                pab.get('IgnorePublicAcls', False),
                pab.get('BlockPublicPolicy', False),
                pab.get('RestrictPublicBuckets', False),
            ]):
                findings.append({
                    'rule_id': 'AWS-S3-01',
                    'name': f'S3 Bucket Public Access Not Fully Blocked: {bname}',
                    'description': (
                        f'S3 bucket "{bname}" does not have all public access block settings enabled. '
                        'Enable all four PublicAccessBlock settings unless the bucket intentionally serves public content.'
                    ),
                    'severity': 'HIGH',
                    'compliance': _COMPLIANCE + ['CIS-AWS-2.1'],
                    'file': f'AWS/S3/{bname}',
                    'line': 0,
                    'source': 'AWS',
                })
        except Exception:
            pass

        # Versioning
        try:
            versioning = client.get_bucket_versioning(Bucket=bname)
            if versioning.get('Status') != 'Enabled':
                findings.append({
                    'rule_id': 'AWS-S3-02',
                    'name': f'S3 Bucket Versioning Disabled: {bname}',
                    'description': (
                        f'S3 bucket "{bname}" does not have versioning enabled. '
                        'Versioning protects against accidental deletion and ransomware. '
                        'Enable versioning for all buckets containing important data.'
                    ),
                    'severity': 'MEDIUM',
                    'compliance': ['CIS-AWS-2.2', 'ISO-27001:A.12'],
                    'file': f'AWS/S3/{bname}',
                    'line': 0,
                    'source': 'AWS',
                })
        except Exception:
            pass

        # Server-side encryption
        try:
            enc = client.get_bucket_encryption(Bucket=bname)
            rules = enc.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            if not rules:
                raise Exception('no encryption')
        except Exception:
            findings.append({
                'rule_id': 'AWS-S3-03',
                'name': f'S3 Bucket Not Encrypted: {bname}',
                'description': (
                    f'S3 bucket "{bname}" does not have default server-side encryption enabled. '
                    'Enable SSE-S3 or SSE-KMS encryption on all buckets.'
                ),
                'severity': 'HIGH',
                'compliance': _COMPLIANCE + ['CIS-AWS-2.4'],
                'file': f'AWS/S3/{bname}',
                'line': 0,
                'source': 'AWS',
            })

    return findings


def check_security_groups(region: Optional[str] = None, profile: Optional[str] = None) -> List[dict]:
    findings = []
    client = _boto3_client('ec2', region=region, profile=profile)
    if not client:
        return findings

    try:
        sgs = client.describe_security_groups()['SecurityGroups']
    except Exception:
        return findings

    for sg in sgs:
        sgid = sg['GroupId']
        sgname = sg.get('GroupName', sgid)
        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort', -1)
            ip_ranges = rule.get('IpRanges', [])
            ipv6_ranges = rule.get('Ipv6Ranges', [])

            open_to_world = any(r.get('CidrIp') == '0.0.0.0/0' for r in ip_ranges) or \
                            any(r.get('CidrIpv6') == '::/0' for r in ipv6_ranges)

            if not open_to_world:
                continue

            if from_port in (22, -1) or (rule.get('IpProtocol') == '-1'):
                port_desc = 'All traffic' if rule.get('IpProtocol') == '-1' else f'port {from_port} (SSH)'
                findings.append({
                    'rule_id': 'AWS-SG-01',
                    'name': f'Security Group Open to 0.0.0.0/0: {sgname} ({port_desc})',
                    'description': (
                        f'Security group "{sgname}" ({sgid}) allows inbound {port_desc} from 0.0.0.0/0 (Internet). '
                        'Restrict inbound rules to specific IP ranges or use VPN/bastion host for SSH access.'
                    ),
                    'severity': 'CRITICAL' if rule.get('IpProtocol') == '-1' else 'HIGH',
                    'compliance': _COMPLIANCE + ['CIS-AWS-4.1', 'CIS-AWS-4.2'],
                    'file': f'AWS/EC2/security-groups/{sgid}',
                    'line': 0,
                    'source': 'AWS',
                })
            elif from_port == 3389:
                findings.append({
                    'rule_id': 'AWS-SG-02',
                    'name': f'Security Group: RDP Open to Internet: {sgname}',
                    'description': (
                        f'Security group "{sgname}" ({sgid}) allows inbound RDP (3389) from 0.0.0.0/0. '
                        'Restrict RDP access to specific IPs and use a bastion host or VPN.'
                    ),
                    'severity': 'CRITICAL',
                    'compliance': _COMPLIANCE + ['CIS-AWS-4.2'],
                    'file': f'AWS/EC2/security-groups/{sgid}',
                    'line': 0,
                    'source': 'AWS',
                })

    return findings


def check_cloudtrail(region: Optional[str] = None, profile: Optional[str] = None) -> List[dict]:
    findings = []
    client = _boto3_client('cloudtrail', region=region, profile=profile)
    if not client:
        return findings

    try:
        trails = client.describe_trails(includeShadowTrails=False).get('trailList', [])
        if not trails:
            findings.append({
                'rule_id': 'AWS-CT-01',
                'name': 'No CloudTrail Trails Configured',
                'description': (
                    'No AWS CloudTrail trails are configured. Without CloudTrail, '
                    'API calls and management events are not logged, making incident investigation impossible. '
                    'Enable CloudTrail in all regions.'
                ),
                'severity': 'HIGH',
                'compliance': _COMPLIANCE + ['CIS-AWS-3.1'],
                'file': 'AWS/CloudTrail',
                'line': 0,
                'source': 'AWS',
            })
        else:
            for trail in trails:
                if not trail.get('IsMultiRegionTrail', False):
                    findings.append({
                        'rule_id': 'AWS-CT-02',
                        'name': f'CloudTrail Not Multi-Region: {trail.get("Name")}',
                        'description': (
                            f'CloudTrail trail "{trail.get("Name")}" is not configured for all regions. '
                            'Attackers can operate in regions not monitored by CloudTrail. '
                            'Enable multi-region logging.'
                        ),
                        'severity': 'MEDIUM',
                        'compliance': ['CIS-AWS-3.3'],
                        'file': f'AWS/CloudTrail/{trail.get("Name")}',
                        'line': 0,
                        'source': 'AWS',
                    })
    except Exception:
        pass

    return findings


def run_aws_audit(
    region: Optional[str] = None,
    profile: Optional[str] = None,
) -> List[dict]:
    """Run all AWS security checks. Returns findings list."""
    try:
        import boto3  # noqa: F401
    except ImportError:
        print('\033[91m[AuditLens AWS]\033[0m boto3 no está instalado. Ejecuta: pip install boto3')
        return []

    region = region or os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
    print(f'\033[94m[AuditLens AWS]\033[0m Auditando cuenta AWS (region: {region})...')

    findings: List[dict] = []
    findings.extend(check_iam(region=region, profile=profile))
    findings.extend(check_s3(region=region, profile=profile))
    findings.extend(check_security_groups(region=region, profile=profile))
    findings.extend(check_cloudtrail(region=region, profile=profile))

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.get('severity', 'LOW')
        if sev in counts:
            counts[sev] += 1

    print(
        f'\033[92m[AuditLens AWS]\033[0m {len(findings)} hallazgos '
        f'(CRITICAL:{counts["CRITICAL"]} HIGH:{counts["HIGH"]} '
        f'MEDIUM:{counts["MEDIUM"]} LOW:{counts["LOW"]})'
    )
    return findings
