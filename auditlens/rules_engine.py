"""
AuditLens Rules Engine — loads YAML rule definitions and matches them against code.

Changes vs original:
- CQ-07: invalid regex patterns produce a warning instead of crashing the engine
- MISSING-08: TypeScript (.ts, .tsx) mapped to 'typescript' language tag
"""

from __future__ import annotations

import yaml
import re
import os
from typing import List, Optional


class Rule:
    def __init__(self, data: dict):
        self.id = data.get('id', 'UNKNOWN')
        self.name = data.get('name', 'Unknown Rule')
        self.description = data.get('description', '')
        self.languages = data.get('languages', [])
        self.regex_pattern = data.get('regex_pattern')
        self.compliance = data.get('compliance', [])
        self.severity = data.get('severity', 'LOW')
        self._compiled_regex = None

        if self.regex_pattern:
            # CQ-07 FIX: catch invalid regex at load time with a clear warning
            try:
                self._compiled_regex = re.compile(self.regex_pattern, re.IGNORECASE)
            except re.error as exc:
                print(
                    f"\033[93m[AuditLens] Warning: invalid regex in rule "
                    f"'{self.id}': {exc}. Rule disabled.\033[0m"
                )

    def match_text(self, text: str) -> bool:
        if self._compiled_regex:
            return bool(self._compiled_regex.search(text))
        return False


class RulesEngine:
    def __init__(self, rules_file: str | None = None):
        self.rules: list[Rule] = []
        if not rules_file:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            rules_file = os.path.join(base_dir, 'rules.yaml')
        self._load_rules(rules_file)

    def _load_rules(self, rules_file: str) -> None:
        if not os.path.exists(rules_file):
            print(
                f"\033[93m[AuditLens] Warning: rules file not found at "
                f"{rules_file}. Running with empty rule set.\033[0m"
            )
            return

        try:
            with open(rules_file, 'r', encoding='utf-8') as fh:
                data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            print(f"\033[91m[AuditLens] Error: invalid YAML in rules file: {exc}\033[0m")
            return

        if not data or 'rules' not in data:
            print("\033[93m[AuditLens] Warning: rules file has no 'rules' key.\033[0m")
            return

        for rule_data in data['rules']:
            self.rules.append(Rule(rule_data))

        print(f"\033[90m[AuditLens] Loaded {len(self.rules)} rules.\033[0m")

    def get_rules_for_language(self, ext: str) -> List[Rule]:
        # MISSING-08 FIX: TypeScript mapped properly
        ext_to_lang = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.swift': 'swift',
        }
        lang = ext_to_lang.get(ext)
        if not lang:
            return []
        return [r for r in self.rules if lang in r.languages]
