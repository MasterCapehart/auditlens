"""
AuditLens CVE Enricher — enriquece hallazgos SCA con datos de CVSS,
descripción y exploit info desde OSV y NVD APIs.

Usage: imported internally by the SCA scanner.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

import requests

_OSV_API = 'https://api.osv.dev/v1/query'
_NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
_TIMEOUT = 12


def _query_osv(package: str, version: str, ecosystem: str) -> List[Dict[str, Any]]:
    """Query OSV.dev for vulnerabilities."""
    payload = {
        'package': {'name': package, 'ecosystem': ecosystem},
        'version': version,
    }
    try:
        resp = requests.post(_OSV_API, json=payload, timeout=_TIMEOUT)
        if resp.status_code == 200:
            return resp.json().get('vulns', [])
    except Exception:
        pass
    return []


def _query_nvd_cve(cve_id: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Query NVD for a specific CVE."""
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    try:
        resp = requests.get(
            _NVD_API,
            params={'cveId': cve_id},
            headers=headers,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            vulns = resp.json().get('vulnerabilities', [])
            if vulns:
                return vulns[0].get('cve', {})
    except Exception:
        pass
    return None


def _severity_from_cvss(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return 'CRITICAL'
    if cvss_score >= 7.0:
        return 'HIGH'
    if cvss_score >= 4.0:
        return 'MEDIUM'
    return 'LOW'


def enrich_sca_findings(
    sca_findings: List[dict],
    nvd_api_key: Optional[str] = None,
    rate_limit_delay: float = 0.5,
) -> List[dict]:
    """
    Enrich SCA findings with CVSS scores, CVE descriptions, and exploit info.
    Modifies findings in place and returns the list.
    """
    enriched = 0
    for finding in sca_findings:
        if finding.get('source') != 'SCA':
            continue

        package = finding.get('package_name', '')
        version = finding.get('package_version', '')
        vuln_id = finding.get('vuln_id', '')

        if not package:
            continue

        # Determine ecosystem from file
        fpath = finding.get('file', '')
        ecosystem = 'PyPI' if 'requirements' in fpath or fpath.endswith('.txt') else 'npm'

        # OSV enrichment
        osv_vulns = _query_osv(package, version, ecosystem)
        for vuln in osv_vulns:
            vid = vuln.get('id', '')
            if vuln_id and vid != vuln_id:
                continue

            # Get CVE aliases
            aliases = vuln.get('aliases', [])
            cve_ids = [a for a in aliases if a.startswith('CVE-')]

            # Get CVSS from OSV severity
            cvss_score = None
            for sev in vuln.get('severity', []):
                if sev.get('type') == 'CVSS_V3':
                    score_str = sev.get('score', '')
                    m = re.search(r'CVSS:3\.\d/[^/]+/[^/]+/[^/]+/[^/]+/[^/]+/[^/]+/[^/]+/([0-9.]+)', score_str)
                    if m:
                        try:
                            cvss_score = float(m.group(1))
                        except ValueError:
                            pass

            summary = vuln.get('summary', '')
            details = vuln.get('details', '')
            aliases_str = ', '.join(aliases) if aliases else ''

            # NVD enrichment for first CVE alias
            nvd_data = None
            if cve_ids:
                time.sleep(rate_limit_delay)
                nvd_data = _query_nvd_cve(cve_ids[0], api_key=nvd_api_key)

            cvss_nvd = None
            nvd_description = ''
            exploit_known = False
            if nvd_data:
                metrics = nvd_data.get('metrics', {})
                for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                    if key in metrics:
                        cvss_nvd = metrics[key][0].get('cvssData', {}).get('baseScore')
                        break
                descs = nvd_data.get('descriptions', [])
                for d in descs:
                    if d.get('lang') == 'en':
                        nvd_description = d.get('value', '')
                        break
                for ref in nvd_data.get('references', []):
                    tags = ref.get('tags', [])
                    if 'Exploit' in tags or 'Proof of Concept' in tags:
                        exploit_known = True
                        break

            final_score = cvss_nvd or cvss_score
            if final_score is not None:
                new_sev = _severity_from_cvss(final_score)
                finding['severity'] = new_sev
                finding['cvss_score'] = final_score

            if aliases_str:
                finding['cve_aliases'] = aliases_str
            if summary:
                finding['cvss_summary'] = summary
            if nvd_description:
                finding['nvd_description'] = nvd_description
                desc = finding.get('description', '')
                finding['description'] = (
                    f'{desc}\n\nCVSS Score: {final_score or "N/A"} | CVE: {aliases_str or vuln_id}\n'
                    f'NVD: {nvd_description[:300]}'
                )
            if exploit_known:
                finding['exploit_known'] = True
                finding['severity'] = 'CRITICAL'
                finding['description'] = (
                    '[EXPLOIT KNOWN] ' + finding.get('description', '')
                )

            enriched += 1
            break  # Only enrich with first matching vuln

        time.sleep(rate_limit_delay)

    print(f'\033[92m[AuditLens CVE]\033[0m {enriched}/{len(sca_findings)} hallazgos SCA enriquecidos con CVE/CVSS.')
    return sca_findings
