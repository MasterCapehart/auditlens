import os
import json
import requests
import re

class SCAEngine:
    def __init__(self):
        self.osv_api_url = "https://api.osv.dev/v1/query"

    def analyze_directory(self, root_path):
        findings = []
        exclude_dirs = {'node_modules', 'venv', 'env', '.env', '.git', '__pycache__', 'build', 'dist'}
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]

            if 'package.json' in filenames:
                file_path = os.path.join(dirpath, 'package.json')
                findings.extend(self._scan_package_json(file_path))

            if 'requirements.txt' in filenames:
                file_path = os.path.join(dirpath, 'requirements.txt')
                findings.extend(self._scan_requirements_txt(file_path))

        return findings

    def _scan_package_json(self, file_path):
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            deps = data.get('dependencies', {})
            dev_deps = data.get('devDependencies', {})
            all_deps = {**deps, **dev_deps}

            for package, version in all_deps.items():
                # Limpiar version (ej. "^1.0.0" -> "1.0.0")
                clean_version = re.sub(r'^[~^><=]+', '', version).strip()
                if clean_version:
                    vulns = self._query_osv(package, clean_version, "npm")
                    findings.extend(self._format_vulns(vulns, package, clean_version, file_path))
        except Exception as e:
            print(f"\033[93m[AuditLens SCA] Error leyendo {file_path}: {e}\033[0m")
            
        return findings

    def _scan_requirements_txt(self, file_path):
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Soporta formato: Django==3.1.0 o requests>=2.0
                    match = re.match(r'^([a-zA-Z0-9_\-]+)[=><~]+(.*)$', line)
                    if match:
                        package = match.group(1).strip()
                        version = match.group(2).strip()
                        
                        vulns = self._query_osv(package, version, "PyPI")
                        formatted = self._format_vulns(vulns, package, version, file_path, line_num)
                        findings.extend(formatted)
        except Exception as e:
            print(f"\033[93m[AuditLens SCA] Error leyendo {file_path}: {e}\033[0m")
            
        return findings

    def _query_osv(self, package, version, ecosystem):
        payload = {
            "version": version,
            "package": {
                "name": package,
                "ecosystem": ecosystem
            }
        }
        try:
            response = requests.post(self.osv_api_url, json=payload, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if "vulns" in data:
                    return data["vulns"]
        except requests.RequestException:
            pass
        return []

    def _format_vulns(self, vulns, package, version, file_path, line_num=1):
        findings = []
        for v in vulns:
            cve = v.get("aliases", ["UNKNOWN-CVE"])[0]
            summary = v.get("summary", "Vulnerabilidad detectada en dependencia de terceros")
            severity = "CRITICAL" # Asumimos crítico por defecto si está en OSV
            
            finding = {
                "rule_id": f"SCA-{cve}",
                "name": f"Dependencia Vulnerable: {package}@{version}",
                "description": f"Se ha detectado {cve} en {package}. Detalle: {summary}",
                "file": file_path,
                "line": line_num,
                "severity": severity,
                "compliance": ["CWE-1104", "OWASP-A6"]
            }
            findings.append(finding)
        return findings
