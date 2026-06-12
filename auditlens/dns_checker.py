"""
AuditLens DNS/Email Security Checker — verifica SPF, DKIM, DMARC,
DNSSEC y configuración DNS desde un dominio.

Usage:
    auditlens dns-check empresa.com
    auditlens dns-check empresa.com --dkim-selector google
"""

from __future__ import annotations

import re
import socket
import subprocess
from typing import List, Optional


def _dns_query(name: str, rtype: str) -> List[str]:
    """Run dig and return answer lines. Falls back to nslookup."""
    try:
        result = subprocess.run(
            ['dig', '+short', name, rtype],
            capture_output=True, text=True, timeout=10,
        )
        lines = [l.strip().strip('"') for l in result.stdout.splitlines() if l.strip()]
        return lines
    except FileNotFoundError:
        pass
    try:
        result = subprocess.run(
            ['nslookup', '-type=' + rtype, name],
            capture_output=True, text=True, timeout=10,
        )
        return [l.strip() for l in result.stdout.splitlines() if rtype in l]
    except FileNotFoundError:
        return []


def _finding(rule_id, name, description, severity, compliance, domain) -> dict:
    return {
        'rule_id': rule_id,
        'name': name,
        'description': description,
        'severity': severity,
        'compliance': compliance,
        'file': domain,
        'url': domain,
        'line': 0,
        'source': 'DNS',
    }


def check_spf(domain: str) -> List[dict]:
    findings = []
    records = _dns_query(domain, 'TXT')
    spf = [r for r in records if 'v=spf1' in r.lower()]

    if not spf:
        findings.append(_finding(
            'DNS-SPF-01', 'Missing SPF Record',
            f'No SPF TXT record found for {domain}. Without SPF, anyone can send email '
            'claiming to be from this domain (email spoofing). '
            'Add: v=spf1 include:_spf.yourmailprovider.com ~all',
            'HIGH', ['CWE-290', 'ISO-27001:A.13', 'DMARC-RFC7208'], domain,
        ))
        return findings

    spf_record = spf[0]

    if '+all' in spf_record:
        findings.append(_finding(
            'DNS-SPF-02', 'SPF Record Uses +all (Allow All)',
            f'SPF record uses "+all" which allows any server to send email for {domain}. '
            'Change to "~all" (softfail) or "-all" (hardfail).',
            'CRITICAL', ['CWE-290', 'RFC7208'], domain,
        ))
    elif '?all' in spf_record:
        findings.append(_finding(
            'DNS-SPF-03', 'SPF Record Uses ?all (Neutral)',
            f'SPF record uses "?all" which provides no protection. '
            'Use "~all" (softfail) or "-all" (hardfail).',
            'MEDIUM', ['CWE-290', 'RFC7208'], domain,
        ))

    # Too many DNS lookups (RFC limit is 10)
    lookup_count = len(re.findall(r'\b(include|a|mx|exists|redirect):', spf_record))
    if lookup_count > 10:
        findings.append(_finding(
            'DNS-SPF-04', 'SPF Record Exceeds 10 DNS Lookups',
            f'SPF record triggers ~{lookup_count} DNS lookups, exceeding the RFC 7208 limit of 10. '
            'This causes SPF to permerror and may result in legitimate email being rejected.',
            'MEDIUM', ['RFC7208'], domain,
        ))

    return findings


def check_dmarc(domain: str) -> List[dict]:
    findings = []
    records = _dns_query(f'_dmarc.{domain}', 'TXT')
    dmarc = [r for r in records if 'v=dmarc1' in r.lower()]

    if not dmarc:
        findings.append(_finding(
            'DNS-DMARC-01', 'Missing DMARC Record',
            f'No DMARC record found at _dmarc.{domain}. Without DMARC, email spoofing '
            'attacks are not reported and receiving servers have no policy to apply. '
            'Add: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
            'HIGH', ['CWE-290', 'RFC7489', 'ISO-27001:A.13'], domain,
        ))
        return findings

    dmarc_record = dmarc[0]

    # Policy check
    p_match = re.search(r'\bp=(\w+)', dmarc_record, re.IGNORECASE)
    if p_match:
        policy = p_match.group(1).lower()
        if policy == 'none':
            findings.append(_finding(
                'DNS-DMARC-02', 'DMARC Policy is p=none (Monitor Only)',
                f'DMARC record uses p=none which only monitors but does not reject spoofed emails. '
                'Upgrade to p=quarantine or p=reject after reviewing DMARC reports.',
                'MEDIUM', ['RFC7489'], domain,
            ))

    # No rua (aggregate report URI)
    if 'rua=' not in dmarc_record.lower():
        findings.append(_finding(
            'DNS-DMARC-03', 'DMARC Missing Reporting URI (rua)',
            'DMARC record has no rua= tag. Without aggregate reports you cannot monitor '
            'who is sending email from your domain.',
            'LOW', ['RFC7489'], domain,
        ))

    return findings


def check_dkim(domain: str, selector: str = 'default') -> List[dict]:
    findings = []
    selectors = [selector, 'google', 'mail', 'smtp', 'k1', 'selector1', 'selector2']
    found_any = False

    for sel in selectors:
        records = _dns_query(f'{sel}._domainkey.{domain}', 'TXT')
        dkim = [r for r in records if 'v=dkim1' in r.lower() or 'p=' in r.lower()]
        if dkim:
            found_any = True
            dkim_record = dkim[0]
            p_match = re.search(r'\bp=([A-Za-z0-9+/=]*)', dkim_record)
            if p_match and not p_match.group(1):
                findings.append(_finding(
                    'DNS-DKIM-02', f'DKIM Key Revoked (selector: {sel})',
                    f'DKIM selector {sel}._domainkey.{domain} has p= (empty public key), '
                    'indicating the key has been revoked. Ensure active selectors have valid keys.',
                    'MEDIUM', ['RFC6376'], domain,
                ))
            # Check key length if RSA
            if 'k=rsa' in dkim_record.lower() or 'k=' not in dkim_record.lower():
                p_val = p_match.group(1) if p_match else ''
                if p_val:
                    import base64
                    try:
                        key_bytes = base64.b64decode(p_val + '==')
                        if len(key_bytes) < 128:
                            findings.append(_finding(
                                'DNS-DKIM-03', f'DKIM RSA Key Too Short (selector: {sel})',
                                f'DKIM key for selector {sel} appears shorter than 1024 bits. '
                                'Use at least 2048-bit RSA keys.',
                                'HIGH', ['RFC6376', 'NIST SP 800-57'], domain,
                            ))
                    except Exception:
                        pass
            break

    if not found_any:
        findings.append(_finding(
            'DNS-DKIM-01', 'No DKIM Record Found',
            f'No DKIM TXT record found for common selectors on {domain}. '
            'Without DKIM, email recipients cannot verify the message was authorized by your domain.',
            'MEDIUM', ['RFC6376', 'ISO-27001:A.13'], domain,
        ))

    return findings


def check_dnssec(domain: str) -> List[dict]:
    findings = []
    try:
        result = subprocess.run(
            ['dig', '+dnssec', domain, 'A'],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout
        if 'ad' not in output.lower() and 'rrsig' not in output.lower():
            findings.append(_finding(
                'DNS-SEC-01', 'DNSSEC Not Enabled',
                f'DNSSEC is not configured for {domain}. Without DNSSEC, DNS responses '
                'can be forged (DNS cache poisoning / BGP hijack). Enable DNSSEC at your registrar.',
                'MEDIUM', ['CWE-345', 'NIST SP 800-81', 'ISO-27001:A.13'], domain,
            ))
    except FileNotFoundError:
        pass
    return findings


def check_open_relay(domain: str) -> List[dict]:
    """Check MX records exist and flag obvious misconfigurations."""
    findings = []
    mx_records = _dns_query(domain, 'MX')
    if not mx_records:
        findings.append(_finding(
            'DNS-MX-01', 'No MX Records Found',
            f'No MX records found for {domain}. If this domain sends email, missing MX '
            'records can cause delivery issues.',
            'LOW', ['RFC5321'], domain,
        ))
    return findings


def run_dns_check(domain: str, dkim_selector: str = 'default') -> List[dict]:
    """Run all DNS/email security checks. Returns combined findings list."""
    domain = domain.lstrip('https://').lstrip('http://').split('/')[0].strip()
    print(f'\033[94m[AuditLens DNS]\033[0m Analizando seguridad DNS/Email para: {domain}')

    findings: List[dict] = []
    findings.extend(check_spf(domain))
    findings.extend(check_dmarc(domain))
    findings.extend(check_dkim(domain, dkim_selector))
    findings.extend(check_dnssec(domain))
    findings.extend(check_open_relay(domain))

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.get('severity', 'LOW')
        if sev in counts:
            counts[sev] += 1

    print(
        f'\033[92m[AuditLens DNS]\033[0m {len(findings)} hallazgos '
        f'(CRITICAL:{counts["CRITICAL"]} HIGH:{counts["HIGH"]} '
        f'MEDIUM:{counts["MEDIUM"]} LOW:{counts["LOW"]})'
    )
    return findings
