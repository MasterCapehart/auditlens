import json
import os

class SarifExporter:
    def __init__(self):
        self.sarif_log = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AuditLens Enterprise",
                            "informationUri": "https://github.com/MasterCapehart/auditlens",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        self.rules_added = set()

    def add_finding(self, finding):
        rule_id = finding.get("rule_id", "UNKNOWN-RULE")
        name = finding.get("name", "Unknown vulnerability")
        description = finding.get("description", "")
        file_path = finding.get("file", "")
        line_num = finding.get("line", 1)
        severity = finding.get("severity", "LOW")
        
        # Mapeo de severidad de AuditLens a SARIF
        level_map = {
            "HIGH": "error",
            "CRITICAL": "error",
            "MEDIUM": "warning",
            "LOW": "note"
        }
        sarif_level = level_map.get(severity.upper(), "warning")

        # Asegurar que la regla esté en el driver
        if rule_id not in self.rules_added:
            self.sarif_log["runs"][0]["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "shortDescription": {"text": name},
                "fullDescription": {"text": description},
                "properties": {
                    "tags": finding.get("compliance", [])
                }
            })
            self.rules_added.add(rule_id)

        # Crear el resultado
        result = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": description
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path
                        },
                        "region": {
                            "startLine": line_num
                        }
                    }
                }
            ]
        }
        self.sarif_log["runs"][0]["results"].append(result)

    def export(self, output_path="audit_results.sarif"):
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.sarif_log, f, indent=2)
        print(f"\n\033[92m[DevSecOps]\033[0m Reporte SARIF exportado con éxito a: \033[1m{os.path.abspath(output_path)}\033[0m")
        print("Puedes subir este archivo a GitHub Security, GitLab CI o SonarQube.")
