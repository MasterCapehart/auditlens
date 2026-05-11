"""
Software Composition Analysis (SCA) Engine for AuditLens.

Changes vs original:
- BUG-08: requirements.txt regex now handles dots, extras, and no-version lines
- BUG-09: version cleaning handles *, x, latest, git URLs
- CQ-03: severity derived from actual OSV CVSS score, not hardcoded CRITICAL
- CQ-04: IndexError fix for empty aliases list
- PERF-01: concurrent HTTP requests via ThreadPoolExecutor (batch)
"""

import os
import json
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Matches package specifiers in requirements.txt including:
#   Django==3.1.0, requests>=2.0, zope.interface==5.4.0, requests[security]==2.28.0
_REQ_RE = re.compile(
    r'^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)'   # package name (PEP 508)
    r'(?:\[[^\]]*\])?'                                   # optional extras [foo,bar]
    r'[=><~!]+([^\s;#,]+)',                              # version specifier
    re.ASCII
)

# Characters that are NOT part of a clean semver: remove them from version strings
_VERSION_CLEAN_RE = re.compile(r'^[~^><=!*\s]+')


def _clean_version(raw: str) -> str | None:
    """
    BUG-09 FIX: strip semver range prefixes and reject non-semver placeholders.
    Returns None when the version cannot be resolved to an exact value.
    """
    v = _VERSION_CLEAN_RE.sub('', raw).strip()
    # Reject wildcards, git URLs, and non-version strings
    if not v or v in ('*', 'latest', 'x', 'X') or v.startswith(('git+', 'http', 'file:')):
        return None
    # Replace x/X wildcard segments (e.g., "1.0.x" -> "1.0.0")
    v = re.sub(r'\b[xX]\b', '0', v)
    return v if v else None


def _osv_severity(vuln: dict) -> str:
    """
    CQ-03 FIX: derive severity from OSV CVSS score instead of hardcoding CRITICAL.
    Falls back to MEDIUM if no CVSS data is available.
    """
    # OSV may carry severity under `database_specific` or `severity`
    severity_entries = vuln.get('severity', [])
    for entry in severity_entries:
        score_str = entry.get('score', '')
        # CVSS v3 score is a float like "7.5" or a vector "CVSS:3.1/..."
        # Try to extract numeric score
        try:
            score = float(score_str)
            if score >= 9.0:
                return 'CRITICAL'
            elif score >= 7.0:
                return 'HIGH'
            elif score >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        except (ValueError, TypeError):
            # CVSS vector string — parse base score segment
            m = re.search(r'/CVSS:[\d.]+/.+', score_str)
            if not m:
                # Try numeric inside string like "CVSS:3.1/AV:N/.../7.5"
                nums = re.findall(r'\b(\d+\.\d+)\b', score_str)
                if nums:
                    try:
                        score = float(nums[-1])
                        if score >= 9.0:
                            return 'CRITICAL'
                        elif score >= 7.0:
                            return 'HIGH'
                        elif score >= 4.0:
                            return 'MEDIUM'
                        return 'LOW'
                    except ValueError:
                        pass

    # Check database_specific for a fallback severity string
    db_spec = vuln.get('database_specific', {})
    sev_str = db_spec.get('severity', '').upper()
    if sev_str in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        return sev_str

    return 'MEDIUM'  # conservative default — never blindly CRITICAL


class SCAEngine:
    def __init__(self, max_workers: int = 10):
        self.osv_api_url = "https://api.osv.dev/v1/query"
        self.max_workers = max_workers

    def analyze_directory(self, root_path: str) -> list:
        findings = []
        exclude_dirs = {
            'node_modules', 'venv', 'env', '.env', '.git',
            '__pycache__', 'build', 'dist', '.tox', '.mypy_cache',
        }
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]

            if 'package.json' in filenames:
                findings.extend(
                    self._scan_package_json(os.path.join(dirpath, 'package.json'))
                )
            if 'requirements.txt' in filenames:
                findings.extend(
                    self._scan_requirements_txt(os.path.join(dirpath, 'requirements.txt'))
                )

        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # File parsers
    # ──────────────────────────────────────────────────────────────────────────

    def _scan_package_json(self, file_path: str) -> list:
        try:
            with open(file_path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception as e:
            print(f"\033[93m[AuditLens SCA] Error reading {file_path}: {e}\033[0m")
            return []

        deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
        tasks = []
        for package, raw_version in deps.items():
            version = _clean_version(str(raw_version))
            if version:
                tasks.append((package, version, 'npm', file_path, 1))
            else:
                print(
                    f"\033[90m[AuditLens SCA] Skipping {package}@{raw_version} "
                    f"(unresolvable version)\033[0m"
                )

        return self._run_batch(tasks)

    def _scan_requirements_txt(self, file_path: str) -> list:
        tasks = []
        try:
            with open(file_path, 'r', encoding='utf-8') as fh:
                for line_num, raw_line in enumerate(fh, 1):
                    line = raw_line.strip()
                    if not line or line.startswith(('#', '-r', '--')):
                        continue

                    # BUG-08 FIX: improved regex handles dots, extras, no-version
                    match = _REQ_RE.match(line)
                    if match:
                        package = match.group(1).strip()
                        version = _clean_version(match.group(3).strip())
                        if version:
                            tasks.append((package, version, 'PyPI', file_path, line_num))
                        else:
                            print(
                                f"\033[90m[AuditLens SCA] Skipping {package} "
                                f"(unresolvable version)\033[0m"
                            )
                    else:
                        # No version pinned — skip silently (can't query OSV without version)
                        pkg_name = re.split(r'[;#\s]', line)[0]
                        print(
                            f"\033[90m[AuditLens SCA] Skipping {pkg_name} "
                            f"(no version pin in requirements.txt)\033[0m"
                        )
        except Exception as e:
            print(f"\033[93m[AuditLens SCA] Error reading {file_path}: {e}\033[0m")

        return self._run_batch(tasks)

    # ──────────────────────────────────────────────────────────────────────────
    # OSV querying — PERF-01 FIX: concurrent requests
    # ──────────────────────────────────────────────────────────────────────────

    def _run_batch(self, tasks: list) -> list:
        """
        PERF-01 FIX: fire all OSV requests concurrently instead of serially.
        tasks: list of (package, version, ecosystem, file_path, line_num)
        """
        if not tasks:
            return []

        findings = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_to_task = {
                pool.submit(self._query_osv, pkg, ver, eco): (pkg, ver, fp, ln)
                for pkg, ver, eco, fp, ln in tasks
            }
            for future in as_completed(future_to_task):
                pkg, ver, fp, ln = future_to_task[future]
                try:
                    vulns = future.result()
                    findings.extend(self._format_vulns(vulns, pkg, ver, fp, ln))
                except Exception as e:
                    print(f"\033[93m[AuditLens SCA] OSV query failed for {pkg}: {e}\033[0m")

        return findings

    def _query_osv(self, package: str, version: str, ecosystem: str) -> list:
        payload = {
            "version": version,
            "package": {"name": package, "ecosystem": ecosystem},
        }
        try:
            response = requests.post(self.osv_api_url, json=payload, timeout=10)
            response.raise_for_status()
            return response.json().get("vulns", [])
        except requests.RequestException:
            return []

    def _format_vulns(self, vulns: list, package: str, version: str,
                      file_path: str, line_num: int = 1) -> list:
        findings = []
        for vuln in vulns:
            # CQ-04 FIX: handle empty or missing aliases list safely
            aliases = vuln.get('aliases') or []
            cve = next(
                (a for a in aliases if a.upper().startswith('CVE-')),
                aliases[0] if aliases else vuln.get('id', 'UNKNOWN-CVE'),
            )

            summary = vuln.get('summary', 'Vulnerability detected in third-party dependency')

            # CQ-03 FIX: use actual OSV severity
            severity = _osv_severity(vuln)

            findings.append({
                "rule_id": f"SCA-{cve}",
                "name": f"Vulnerable Dependency: {package}@{version}",
                "description": f"{cve} in {package}@{version}: {summary}",
                "file": file_path,
                "line": line_num,
                "severity": severity,
                "compliance": ["CWE-1104", "OWASP-A6:2021"],
            })
        return findings
