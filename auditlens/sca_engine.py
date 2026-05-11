"""
AuditLens SCA Engine — with lockfile support and progress indicator.
T2-1: poetry.lock, Pipfile.lock, yarn.lock, package-lock.json
T2-5: progress indicator
"""
from __future__ import annotations
import os, json, re, sys, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple
import requests

_REQ_RE = re.compile(
    r'^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[^\]]*\])?[=><~!]+([^\s;#,]+)', re.ASCII
)
_VERSION_CLEAN_RE = re.compile(r'^[~^><=!*\s]+')

def _clean_version(raw: str) -> Optional[str]:
    v = _VERSION_CLEAN_RE.sub('', raw).strip()
    if not v or v in ('*','latest','x','X') or v.startswith(('git+','http','file:')):
        return None
    v = re.sub(r'\b[xX]\b', '0', v)
    return v if v else None

def _osv_severity(vuln: dict) -> str:
    for entry in vuln.get('severity', []):
        score_str = entry.get('score', '')
        try:
            score = float(score_str)
            if score >= 9.0: return 'CRITICAL'
            if score >= 7.0: return 'HIGH'
            if score >= 4.0: return 'MEDIUM'
            return 'LOW'
        except (ValueError, TypeError):
            nums = re.findall(r'\b(\d+\.\d+)\b', score_str)
            if nums:
                try:
                    score = float(nums[-1])
                    if score >= 9.0: return 'CRITICAL'
                    if score >= 7.0: return 'HIGH'
                    if score >= 4.0: return 'MEDIUM'
                    return 'LOW'
                except ValueError: pass
    db_sev = vuln.get('database_specific', {}).get('severity', '').upper()
    if db_sev in ('CRITICAL','HIGH','MEDIUM','LOW'): return db_sev
    return 'MEDIUM'

class _Progress:
    def __init__(self, total: int):
        self._total = total; self._done = 0; self._lock = threading.Lock()
        self._active = total > 0 and sys.stdout.isatty()
    def tick(self):
        with self._lock:
            self._done += 1
            if self._active:
                pct = int(self._done / self._total * 100)
                sys.stdout.write(f'\r\033[90m[AuditLens SCA] {self._done}/{self._total} ({pct}%)\033[0m   ')
                sys.stdout.flush()
    def done(self):
        if self._active:
            sys.stdout.write('\r' + ' ' * 60 + '\r'); sys.stdout.flush()

def _parse_poetry_lock_manual(file_path: str) -> dict:
    packages = []
    with open(file_path, 'r', encoding='utf-8') as fh:
        content = fh.read()
    for block in re.split(r'\[\[package\]\]', content)[1:]:
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        ver_m  = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name_m and ver_m:
            packages.append({'name': name_m.group(1), 'version': ver_m.group(1)})
    return {'package': packages}

class SCAEngine:
    def __init__(self, max_workers: int = 10):
        self.osv_api_url = 'https://api.osv.dev/v1/query'
        self.max_workers = max_workers

    def analyze_directory(self, root_path: str) -> List[dict]:
        findings: List[dict] = []
        exclude_dirs = {'node_modules','venv','env','.env','.git','__pycache__','build','dist','.tox','.mypy_cache'}
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            fset = set(filenames)
            if 'requirements.txt' in fset:
                findings.extend(self._scan_requirements_txt(os.path.join(dirpath,'requirements.txt')))
            if 'Pipfile.lock' in fset:
                findings.extend(self._scan_pipfile_lock(os.path.join(dirpath,'Pipfile.lock')))
            if 'poetry.lock' in fset:
                findings.extend(self._scan_poetry_lock(os.path.join(dirpath,'poetry.lock')))
            if 'package-lock.json' in fset:
                findings.extend(self._scan_package_lock_json(os.path.join(dirpath,'package-lock.json')))
            elif 'yarn.lock' in fset:
                findings.extend(self._scan_yarn_lock(os.path.join(dirpath,'yarn.lock')))
            elif 'package.json' in fset:
                findings.extend(self._scan_package_json(os.path.join(dirpath,'package.json')))
        return findings

    def _scan_requirements_txt(self, file_path: str) -> List[dict]:
        tasks: List[Tuple] = []
        try:
            with open(file_path, 'r', encoding='utf-8') as fh:
                for line_num, raw in enumerate(fh, 1):
                    line = raw.strip()
                    if not line or line.startswith(('#','-r','--')): continue
                    m = _REQ_RE.match(line)
                    if m:
                        pkg = m.group(1).strip()
                        ver = _clean_version(m.group(3).strip())
                        if ver: tasks.append((pkg, ver, 'PyPI', file_path, line_num))
        except OSError as e:
            print(f'\033[93m[AuditLens SCA] Cannot read {file_path}: {e}\033[0m')
        return self._run_batch(tasks)

    def _scan_pipfile_lock(self, file_path: str) -> List[dict]:
        tasks: List[Tuple] = []
        try:
            with open(file_path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            for section in ('default','develop'):
                for pkg, meta in data.get(section, {}).items():
                    ver = _clean_version(meta.get('version','').lstrip('='))
                    if ver: tasks.append((pkg, ver, 'PyPI', file_path, 1))
        except (OSError, json.JSONDecodeError, ValueError) as e:
            print(f'\033[93m[AuditLens SCA] Cannot read {file_path}: {e}\033[0m')
        return self._run_batch(tasks)

    def _scan_poetry_lock(self, file_path: str) -> List[dict]:
        tasks: List[Tuple] = []
        try:
            try:
                import tomllib
                with open(file_path, 'rb') as fh: data = tomllib.load(fh)
            except ImportError:
                try:
                    import tomli
                    with open(file_path, 'rb') as fh: data = tomli.load(fh)
                except ImportError:
                    data = _parse_poetry_lock_manual(file_path)
            for entry in data.get('package', []):
                pkg = entry.get('name',''); ver = entry.get('version','')
                if pkg and ver: tasks.append((pkg, ver, 'PyPI', file_path, 1))
        except Exception as e:
            print(f'\033[93m[AuditLens SCA] Cannot read {file_path}: {e}\033[0m')
        return self._run_batch(tasks)

    def _scan_package_json(self, file_path: str) -> List[dict]:
        tasks: List[Tuple] = []
        try:
            with open(file_path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            deps = {**data.get('dependencies',{}), **data.get('devDependencies',{})}
            for pkg, raw_ver in deps.items():
                ver = _clean_version(str(raw_ver))
                if ver: tasks.append((pkg, ver, 'npm', file_path, 1))
        except (OSError, json.JSONDecodeError) as e:
            print(f'\033[93m[AuditLens SCA] Cannot read {file_path}: {e}\033[0m')
        return self._run_batch(tasks)

    def _scan_package_lock_json(self, file_path: str) -> List[dict]:
        tasks: List[Tuple] = []
        try:
            with open(file_path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            lock_ver = data.get('lockfileVersion', 1)
            if lock_ver >= 2 and 'packages' in data:
                for pkg_path, meta in data['packages'].items():
                    if not pkg_path: continue
                    pkg_name = pkg_path.split('node_modules/')[-1]
                    ver = meta.get('version','')
                    if pkg_name and ver: tasks.append((pkg_name, ver, 'npm', file_path, 1))
            else:
                def _extract(deps: dict):
                    for pkg, meta in deps.items():
                        ver = meta.get('version','')
                        if ver: tasks.append((pkg, ver, 'npm', file_path, 1))
                        if 'dependencies' in meta: _extract(meta['dependencies'])
                _extract(data.get('dependencies', {}))
        except (OSError, json.JSONDecodeError) as e:
            print(f'\033[93m[AuditLens SCA] Cannot read {file_path}: {e}\033[0m')
        return self._run_batch(tasks)

    def _scan_yarn_lock(self, file_path: str) -> List[dict]:
        tasks: List[Tuple] = []
        try:
            with open(file_path, 'r', encoding='utf-8') as fh:
                content = fh.read()
            pkg_re = re.compile(r'^"?([^@\s"]+)@', re.MULTILINE)
            ver_re = re.compile(r'^\s+version\s+"([^"]+)"', re.MULTILINE)
            for block in re.split(r'\n\n+', content):
                pm = pkg_re.search(block); vm = ver_re.search(block)
                if pm and vm:
                    pkg = pm.group(1).strip('"'); ver = vm.group(1)
                    if pkg and ver: tasks.append((pkg, ver, 'npm', file_path, 1))
        except OSError as e:
            print(f'\033[93m[AuditLens SCA] Cannot read {file_path}: {e}\033[0m')
        return self._run_batch(tasks)

    def _run_batch(self, tasks: List[Tuple]) -> List[dict]:
        if not tasks: return []
        progress = _Progress(len(tasks)); findings: List[dict] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map = {pool.submit(self._query_osv, pkg, ver, eco): (pkg, ver, fp, ln)
                          for pkg, ver, eco, fp, ln in tasks}
            for future in as_completed(future_map):
                pkg, ver, fp, ln = future_map[future]
                progress.tick()
                try:
                    vulns = future.result()
                    findings.extend(self._format_vulns(vulns, pkg, ver, fp, ln))
                except Exception as e:
                    print(f'\033[93m[AuditLens SCA] OSV query failed for {pkg}: {e}\033[0m')
        progress.done(); return findings

    def _query_osv(self, package: str, version: str, ecosystem: str) -> List[dict]:
        payload = {'version': version, 'package': {'name': package, 'ecosystem': ecosystem}}
        try:
            resp = requests.post(self.osv_api_url, json=payload, timeout=10)
            resp.raise_for_status(); return resp.json().get('vulns', [])
        except requests.RequestException: return []

    def _format_vulns(self, vulns: List[dict], package: str, version: str,
                      file_path: str, line_num: int = 1) -> List[dict]:
        findings: List[dict] = []
        for vuln in vulns:
            aliases = vuln.get('aliases') or []
            cve = next((a for a in aliases if a.upper().startswith('CVE-')),
                       aliases[0] if aliases else vuln.get('id','UNKNOWN-CVE'))
            findings.append({'rule_id': f'SCA-{cve}',
                'name': f'Vulnerable Dependency: {package}@{version}',
                'description': f"{cve} in {package}@{version}: {vuln.get('summary','')}",
                'file': file_path, 'line': line_num,
                'severity': _osv_severity(vuln), 'compliance': ['CWE-1104','OWASP-A6:2021']})
        return findings
