"""
AuditLens Compliance Mapper

Maps every finding's rule_id to:
  - OWASP Top 10 (2021)
  - CWE Top 25 (2023)
  - PCI-DSS v4.0 requirements
  - SOC 2 Trust Service Criteria

Also generates a compliance gap report showing coverage per framework.

Usage:
    from auditlens.compliance_mapper import enrich_with_compliance, generate_compliance_report
    findings = enrich_with_compliance(findings)
    report   = generate_compliance_report(findings)
"""

from __future__ import annotations

from typing import Any, Dict, List

# ── Master mapping table ───────────────────────────────────────────────────────
# Each rule_id prefix maps to a list of framework references.
# Format: {rule_id_prefix: {framework: [codes]}}
_COMPLIANCE_MAP: Dict[str, Dict[str, List[str]]] = {

    # ── Secrets / Credentials ─────────────────────────────────────────────────
    'SEC-01':       {'owasp': ['A02:2021'], 'cwe': ['CWE-312', 'CWE-798'], 'pci': ['PCI-8.2.1', 'PCI-3.4'], 'soc2': ['CC6.1']},
    'HARDCODED':    {'owasp': ['A02:2021'], 'cwe': ['CWE-312', 'CWE-798'], 'pci': ['PCI-8.2.1', 'PCI-3.4'], 'soc2': ['CC6.1']},
    'GIT-HARDCODED':{'owasp': ['A02:2021'], 'cwe': ['CWE-312', 'CWE-798'], 'pci': ['PCI-8.2.1', 'PCI-3.4'], 'soc2': ['CC6.1']},
    'GIT-SECRET':   {'owasp': ['A02:2021'], 'cwe': ['CWE-312', 'CWE-798'], 'pci': ['PCI-8.2.1', 'PCI-3.4'], 'soc2': ['CC6.1']},
    'GIT-API':      {'owasp': ['A02:2021'], 'cwe': ['CWE-798'],            'pci': ['PCI-8.2.1'],              'soc2': ['CC6.1']},
    'GIT-AWS':      {'owasp': ['A02:2021'], 'cwe': ['CWE-798'],            'pci': ['PCI-8.2.1', 'PCI-8.3.4'],'soc2': ['CC6.1', 'CC6.3']},
    'GIT-PRIVATE':  {'owasp': ['A02:2021'], 'cwe': ['CWE-321'],            'pci': ['PCI-3.6'],                'soc2': ['CC6.1']},
    'GIT-BEARER':   {'owasp': ['A02:2021'], 'cwe': ['CWE-522'],            'pci': ['PCI-8.2.1'],              'soc2': ['CC6.1']},
    'GIT-JWT':      {'owasp': ['A02:2021'], 'cwe': ['CWE-347', 'CWE-522'],'pci': ['PCI-8.3.2'],              'soc2': ['CC6.1']},

    # ── Injection ─────────────────────────────────────────────────────────────
    'SEC-02':       {'owasp': ['A03:2021'], 'cwe': ['CWE-89'],             'pci': ['PCI-6.3.3'],              'soc2': ['CC7.1']},
    'SQLI':         {'owasp': ['A03:2021'], 'cwe': ['CWE-89'],             'pci': ['PCI-6.3.3'],              'soc2': ['CC7.1']},
    'CMD-INJECT':   {'owasp': ['A03:2021'], 'cwe': ['CWE-78'],             'pci': ['PCI-6.3.3'],              'soc2': ['CC7.1']},
    'OS-SYSTEM':    {'owasp': ['A03:2021'], 'cwe': ['CWE-78'],             'pci': ['PCI-6.3.3'],              'soc2': ['CC7.1']},
    'EVAL':         {'owasp': ['A03:2021'], 'cwe': ['CWE-95', 'CWE-78'],  'pci': ['PCI-6.3.3'],              'soc2': ['CC7.1']},
    'XSS':          {'owasp': ['A03:2021'], 'cwe': ['CWE-79'],             'pci': ['PCI-6.4.1'],              'soc2': ['CC7.1']},
    'XSS-INNER':    {'owasp': ['A03:2021'], 'cwe': ['CWE-79'],             'pci': ['PCI-6.4.1'],              'soc2': ['CC7.1']},

    # ── Deserialization ───────────────────────────────────────────────────────
    'PICKLE':       {'owasp': ['A08:2021'], 'cwe': ['CWE-502'],            'pci': ['PCI-6.3.3'],              'soc2': ['CC7.1']},
    'YAML-UNSAFE':  {'owasp': ['A08:2021'], 'cwe': ['CWE-502'],            'pci': ['PCI-6.3.3'],              'soc2': ['CC7.1']},
    'DESER':        {'owasp': ['A08:2021'], 'cwe': ['CWE-502'],            'pci': ['PCI-6.3.3'],              'soc2': ['CC7.1']},

    # ── Cryptography ──────────────────────────────────────────────────────────
    'WEAK-HASH':    {'owasp': ['A02:2021'], 'cwe': ['CWE-327', 'CWE-328'],'pci': ['PCI-3.5.1', 'PCI-4.2.1'],'soc2': ['CC6.1']},
    'WEAK-RANDOM':  {'owasp': ['A02:2021'], 'cwe': ['CWE-330', 'CWE-338'],'pci': ['PCI-6.3.3'],              'soc2': ['CC6.1']},
    'SSL-NOVERIFY': {'owasp': ['A02:2021'], 'cwe': ['CWE-295'],            'pci': ['PCI-4.2.1', 'PCI-6.3.3'],'soc2': ['CC6.1', 'CC6.7']},

    # ── Configuration / Security Misconfiguration ─────────────────────────────
    'DEBUG-ON':     {'owasp': ['A05:2021'], 'cwe': ['CWE-489'],            'pci': ['PCI-2.2.7'],              'soc2': ['CC7.2']},
    'CONF':         {'owasp': ['A05:2021'], 'cwe': ['CWE-16'],             'pci': ['PCI-2.2'],                'soc2': ['CC7.2']},
    'IAC':          {'owasp': ['A05:2021'], 'cwe': ['CWE-16', 'CWE-284'], 'pci': ['PCI-1.3', 'PCI-2.2'],    'soc2': ['CC6.6', 'CC7.2']},

    # ── Access Control ────────────────────────────────────────────────────────
    'AUTH':         {'owasp': ['A01:2021'], 'cwe': ['CWE-284', 'CWE-306'],'pci': ['PCI-7.2', 'PCI-8.6'],    'soc2': ['CC6.1', 'CC6.3']},
    'IDOR':         {'owasp': ['A01:2021'], 'cwe': ['CWE-639'],            'pci': ['PCI-7.2'],                'soc2': ['CC6.3']},

    # ── Dependencies / SCA ────────────────────────────────────────────────────
    'SCA':          {'owasp': ['A06:2021'], 'cwe': ['CWE-1035', 'CWE-937'],'pci': ['PCI-6.3.2', 'PCI-6.3.3'],'soc2': ['CC7.1']},
    'DEP-CONFUS':   {'owasp': ['A06:2021'], 'cwe': ['CWE-427'],            'pci': ['PCI-6.3.2'],              'soc2': ['CC7.1']},
    'LICENSE':      {'owasp': [],           'cwe': [],                      'pci': [],                         'soc2': ['A1.2']},

    # ── Logging / Monitoring ──────────────────────────────────────────────────
    'LOG':          {'owasp': ['A09:2021'], 'cwe': ['CWE-778', 'CWE-223'],'pci': ['PCI-10.2'],               'soc2': ['CC7.2', 'CC7.3']},

    # ── SSRF ─────────────────────────────────────────────────────────────────
    'SSRF':         {'owasp': ['A10:2021'], 'cwe': ['CWE-918'],            'pci': ['PCI-6.4.1'],              'soc2': ['CC7.1']},

    # ── GitHub Actions ───────────────────────────────────────────────────────
    'GH-ACTIONS':   {'owasp': ['A05:2021'], 'cwe': ['CWE-78', 'CWE-829'], 'pci': ['PCI-6.3.3'],              'soc2': ['CC8.1']},

    # ── AST findings ─────────────────────────────────────────────────────────
    'AST-01':       {'owasp': ['A02:2021'], 'cwe': ['CWE-312', 'CWE-798'],'pci': ['PCI-8.2.1'],              'soc2': ['CC6.1']},
    'AST-02':       {'owasp': ['A03:2021'], 'cwe': ['CWE-89'],             'pci': ['PCI-6.3.3'],              'soc2': ['CC7.1']},
    'AST-03':       {'owasp': ['A03:2021'], 'cwe': ['CWE-78'],             'pci': ['PCI-6.3.3'],              'soc2': ['CC7.1']},
    'AST-04':       {'owasp': ['A08:2021'], 'cwe': ['CWE-502'],            'pci': ['PCI-6.3.3'],              'soc2': ['CC7.1']},
}

# Human-readable names for each framework reference
_OWASP_NAMES = {
    'A01:2021': 'Broken Access Control',
    'A02:2021': 'Cryptographic Failures',
    'A03:2021': 'Injection',
    'A04:2021': 'Insecure Design',
    'A05:2021': 'Security Misconfiguration',
    'A06:2021': 'Vulnerable & Outdated Components',
    'A07:2021': 'Identification & Authentication Failures',
    'A08:2021': 'Software & Data Integrity Failures',
    'A09:2021': 'Security Logging & Monitoring Failures',
    'A10:2021': 'SSRF',
}
_PCI_NAMES = {
    'PCI-1.3':    'Network access controls',
    'PCI-2.2':    'System configuration hardening',
    'PCI-2.2.7':  'Non-console admin access encryption',
    'PCI-3.4':    'Primary account number rendering',
    'PCI-3.5.1':  'Keyed cryptographic hash of PAN',
    'PCI-3.6':    'Key management procedures',
    'PCI-4.2.1':  'Strong cryptography in transit',
    'PCI-6.3.2':  'Software inventory maintained',
    'PCI-6.3.3':  'Security vulnerabilities addressed',
    'PCI-6.4.1':  'Web-facing application attack prevention',
    'PCI-7.2':    'Access control system',
    'PCI-8.2.1':  'Account and authentication management',
    'PCI-8.3.2':  'Strong cryptography for non-console auth',
    'PCI-8.3.4':  'Invalid authentication attempts',
    'PCI-8.6':    'System/application accounts management',
    'PCI-10.2':   'Audit log events',
}
_SOC2_NAMES = {
    'CC6.1': 'Logical and physical access controls',
    'CC6.3': 'User registration and de-registration',
    'CC6.6': 'Logical access from outside networks',
    'CC6.7': 'Transmission, movement, removal of information',
    'CC7.1': 'Vulnerability detection processes',
    'CC7.2': 'Monitor system components',
    'CC7.3': 'Evaluate security events',
    'CC8.1': 'Change management process',
    'A1.2':  'Availability and capacity management',
}

# ── GDPR (EU 2016/679) ────────────────────────────────────────────────────────
_GDPR_MAP: dict = {
    'HARDCODED':       ['Art.5', 'Art.32'],
    'HARDCODED-PASS':  ['Art.5', 'Art.32'],
    'HARDCODED-SECRET':['Art.5', 'Art.32'],
    'GIT-SECRET':      ['Art.5', 'Art.32'],
    'GIT-ENTROPY':     ['Art.5', 'Art.32'],
    'ENTROPY-BASE64':  ['Art.32'],
    'SSL-NOVERIFY':    ['Art.32'],
    'WEAK-HASH':       ['Art.32'],
    'SQLI':            ['Art.5', 'Art.32', 'Art.33'],
    'CMD-INJECT':      ['Art.32', 'Art.33'],
    'XSS':             ['Art.32'],
    'DEBUG-ON':        ['Art.32'],
    'SCA':             ['Art.32'],
    'PII-':            ['Art.5', 'Art.25', 'Art.32', 'Art.33'],
    'TAINT-01':        ['Art.5', 'Art.32'],
}
_GDPR_NAMES = {
    'Art.5':  'Principios del tratamiento de datos personales',
    'Art.25': 'Protección de datos desde el diseño y por defecto',
    'Art.32': 'Seguridad del tratamiento (medidas técnicas)',
    'Art.33': 'Notificación de violación de seguridad (72h)',
    'Art.35': 'Evaluación de impacto relativa a la protección de datos',
    'Art.83': 'Condiciones generales para la imposición de multas',
}

# ── HIPAA (45 CFR Parts 160, 162, 164) ───────────────────────────────────────
_HIPAA_MAP: dict = {
    'HARDCODED':       ['§164.312(a)', '§164.312(d)'],
    'HARDCODED-PASS':  ['§164.312(a)', '§164.312(d)'],
    'SSL-NOVERIFY':    ['§164.312(e)'],
    'WEAK-HASH':       ['§164.312(a)', '§164.312(e)'],
    'SQLI':            ['§164.306', '§164.312(c)'],
    'PII-SALUD':       ['§164.502', '§164.514'],
    'PII-':            ['§164.502', '§164.514'],
    'DEBUG-ON':        ['§164.312(b)'],
    'SCA':             ['§164.306'],
    'TAINT-01':        ['§164.306', '§164.312(c)'],
}
_HIPAA_NAMES = {
    '§164.306':    'Security standards — general rules',
    '§164.312(a)': 'Access control',
    '§164.312(b)': 'Audit controls',
    '§164.312(c)': 'Integrity controls',
    '§164.312(d)': 'Person or entity authentication',
    '§164.312(e)': 'Transmission security',
    '§164.502':    'Uses and disclosures of PHI',
    '§164.514':    'De-identification of PHI',
}

# ── NIST CSF 2.0 ──────────────────────────────────────────────────────────────
_NIST_MAP: dict = {
    'HARDCODED':       ['PR.AC-1', 'PR.DS-1'],
    'HARDCODED-PASS':  ['PR.AC-1', 'PR.DS-1'],
    'GIT-SECRET':      ['PR.AC-1', 'PR.DS-5'],
    'SSL-NOVERIFY':    ['PR.DS-2'],
    'WEAK-HASH':       ['PR.DS-1', 'PR.DS-2'],
    'SQLI':            ['PR.IP-1', 'DE.CM-8'],
    'CMD-INJECT':      ['PR.IP-1', 'DE.CM-8'],
    'XSS':             ['PR.IP-1'],
    'SCA':             ['ID.RA-1', 'PR.IP-12'],
    'IAC':             ['PR.IP-1'],
    'DEBUG-ON':        ['PR.IP-1'],
    'PII-':            ['PR.DS-1', 'PR.DS-5'],
    'TAINT-01':        ['PR.IP-1', 'DE.CM-8'],
    'ENTROPY-BASE64':  ['PR.DS-1'],
}
_NIST_NAMES = {
    'ID.RA-1':  'Identify — Asset vulnerabilities identified',
    'PR.AC-1':  'Protect — Identities and credentials managed',
    'PR.DS-1':  'Protect — Data-at-rest protected',
    'PR.DS-2':  'Protect — Data-in-transit protected',
    'PR.DS-5':  'Protect — Data leak protections implemented',
    'PR.IP-1':  'Protect — Baseline configuration maintained',
    'PR.IP-12': 'Protect — Vulnerability management plan',
    'DE.CM-8':  'Detect — Vulnerability scans performed',
}

# ── Ley 21.663 — Ley Marco de Ciberseguridad Chile (2024) ────────────────────
_LCIB_MAP: dict = {
    'HARDCODED':       ['Art.6', 'Art.8'],
    'HARDCODED-PASS':  ['Art.6', 'Art.8'],
    'GIT-SECRET':      ['Art.6', 'Art.8'],
    'SSL-NOVERIFY':    ['Art.6'],
    'WEAK-HASH':       ['Art.6'],
    'SQLI':            ['Art.6', 'Art.9'],
    'CMD-INJECT':      ['Art.6', 'Art.9'],
    'SCA':             ['Art.6', 'Art.7'],
    'IAC':             ['Art.6'],
    'DEBUG-ON':        ['Art.6'],
    'PII-':            ['Art.6', 'Art.9'],
    'TAINT-01':        ['Art.6'],
    'ENTROPY-BASE64':  ['Art.6'],
}
_LCIB_NAMES = {
    'Art.6': 'Deberes de ciberseguridad — medidas técnicas mínimas',
    'Art.7': 'Gestión de riesgos de ciberseguridad continua',
    'Art.8': 'Gestión de identidades y control de acceso',
    'Art.9': 'Notificación de incidentes a CSIRT Nacional (24h)',
    'Art.10':'Planes de continuidad operacional',
    'Art.28':'Infracciones y sanciones (hasta UF 20.000)',
}


def _lookup_compliance(rule_id: str) -> Dict[str, List[str]]:
    """Find the best matching compliance entry for a rule_id."""
    rule_upper = rule_id.upper()
    # Exact match first
    if rule_upper in _COMPLIANCE_MAP:
        return _COMPLIANCE_MAP[rule_upper]
    # Prefix match (longest wins)
    best_key = ''
    for key in _COMPLIANCE_MAP:
        if rule_upper.startswith(key) and len(key) > len(best_key):
            best_key = key
    return _COMPLIANCE_MAP.get(best_key, {})


def enrich_with_compliance(findings: List[dict]) -> List[dict]:
    """
    Add compliance tags to each finding in-place.
    Preserves existing compliance list and appends missing entries.
    """
    for f in findings:
        rule_id = f.get('rule_id', '')
        mapping = _lookup_compliance(rule_id)
        existing = set(f.get('compliance', []))

        new_tags = []
        for fw, codes in mapping.items():
            for code in codes:
                if code not in existing:
                    new_tags.append(code)

        if new_tags:
            f['compliance'] = sorted(existing | set(new_tags))

        # Add structured compliance object for richer reports
        f['compliance_detail'] = {
            'owasp': mapping.get('owasp', []),
            'cwe':   mapping.get('cwe', []),
            'pci':   mapping.get('pci', []),
            'soc2':  mapping.get('soc2', []),
        }

        # Enrich with GDPR / HIPAA / NIST CSF / Ley Ciberseguridad Chile
        rule_upper = rule_id.upper()
        for extra_map, tag_prefix in [
            (_GDPR_MAP, 'GDPR'),
            (_HIPAA_MAP, 'HIPAA'),
            (_NIST_MAP, 'NIST'),
            (_LCIB_MAP, 'LCIB'),
        ]:
            matched: List[str] = []
            for key, codes in extra_map.items():
                if rule_upper == key.upper() or rule_upper.startswith(key.upper()):
                    matched = codes
                    break
            if matched:
                f['compliance_detail'][tag_prefix.lower()] = matched
                existing2 = set(f.get('compliance', []))
                for c in matched:
                    existing2.add(f'{tag_prefix}-{c}')
                f['compliance'] = sorted(existing2)

    return findings


def generate_compliance_report(findings: List[dict]) -> Dict[str, Any]:
    """
    Build a per-framework compliance gap report.
    Returns dict with coverage stats and uncovered requirements.
    """
    owasp_covered:  Dict[str, int] = {}
    cwe_covered:    Dict[str, int] = {}
    pci_covered:    Dict[str, int] = {}
    soc2_covered:   Dict[str, int] = {}

    for f in findings:
        detail = f.get('compliance_detail') or {}
        for code in detail.get('owasp', []):
            owasp_covered[code] = owasp_covered.get(code, 0) + 1
        for code in detail.get('cwe', []):
            cwe_covered[code] = cwe_covered.get(code, 0) + 1
        for code in detail.get('pci', []):
            pci_covered[code] = pci_covered.get(code, 0) + 1
        for code in detail.get('soc2', []):
            soc2_covered[code] = soc2_covered.get(code, 0) + 1

    all_owasp = set(_OWASP_NAMES.keys())
    all_pci   = set(_PCI_NAMES.keys())
    all_soc2  = set(_SOC2_NAMES.keys())

    owasp_hit    = set(owasp_covered.keys())
    pci_hit      = set(pci_covered.keys())
    soc2_hit     = set(soc2_covered.keys())

    return {
        'owasp': {
            'covered':   sorted(owasp_hit),
            'uncovered': sorted(all_owasp - owasp_hit),
            'total':     len(all_owasp),
            'hit':       len(owasp_hit),
            'pct':       round(len(owasp_hit) / len(all_owasp) * 100),
            'details':   {k: {'name': _OWASP_NAMES.get(k, k), 'count': v}
                         for k, v in owasp_covered.items()},
        },
        'cwe': {
            'covered':   sorted(cwe_covered.keys()),
            'total_hit': len(cwe_covered),
            'details':   {k: v for k, v in cwe_covered.items()},
        },
        'pci_dss': {
            'covered':   sorted(pci_hit),
            'uncovered': sorted(all_pci - pci_hit),
            'total':     len(all_pci),
            'hit':       len(pci_hit),
            'pct':       round(len(pci_hit) / len(all_pci) * 100),
            'details':   {k: {'name': _PCI_NAMES.get(k, k), 'count': v}
                         for k, v in pci_covered.items()},
        },
        'soc2': {
            'covered':   sorted(soc2_hit),
            'uncovered': sorted(all_soc2 - soc2_hit),
            'total':     len(all_soc2),
            'hit':       len(soc2_hit),
            'pct':       round(len(soc2_hit) / len(all_soc2) * 100),
            'details':   {k: {'name': _SOC2_NAMES.get(k, k), 'count': v}
                         for k, v in soc2_covered.items()},
        },
    }


def print_compliance_summary(report: Dict[str, Any]) -> None:
    """Print a colored compliance gap summary to the terminal."""
    C = {
        'RED': '\033[91m', 'YELLOW': '\033[93m', 'GREEN': '\033[92m',
        'CYAN': '\033[94m', 'GRAY': '\033[90m', 'BOLD': '\033[1m', 'RESET': '\033[0m',
    }

    def _bar(pct: int) -> str:
        filled = pct // 5
        empty  = 20 - filled
        color  = C['GREEN'] if pct >= 60 else C['YELLOW'] if pct >= 30 else C['RED']
        return f'{color}{"█" * filled}{"░" * empty}{C["RESET"]} {pct}%'

    print(f'\n{C["BOLD"]}{"=" * 55}')
    print(' COMPLIANCE COVERAGE REPORT')
    print(f'{"=" * 55}{C["RESET"]}')

    for fw_key, fw_label in [
        ('owasp',   'OWASP Top 10 (2021)'),
        ('pci_dss', 'PCI-DSS v4.0'),
        ('soc2',    'SOC 2 TSC'),
    ]:
        fw = report[fw_key]
        pct = fw['pct']
        print(f'\n  {C["BOLD"]}{fw_label}{C["RESET"]}')
        print(f'  {_bar(pct)}  ({fw["hit"]}/{fw["total"]} categorías cubiertas)')
        if fw.get('covered'):
            print(f'  {C["GREEN"]}Cubiertas:{C["RESET"]} {", ".join(fw["covered"])}')
        if fw.get('uncovered'):
            print(f'  {C["GRAY"]}Sin hallazgos:{C["RESET"]} {", ".join(fw["uncovered"][:5])}{"…" if len(fw["uncovered"]) > 5 else ""}')

    cwe = report['cwe']
    print(f'\n  {C["BOLD"]}CWE{C["RESET"]}')
    print(f'  {len(cwe["covered"])} CWEs identificados: {", ".join(sorted(cwe["covered"])[:8])}{"…" if len(cwe["covered"]) > 8 else ""}')
