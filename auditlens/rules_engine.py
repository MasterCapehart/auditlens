import yaml
import re
import os

class Rule:
    def __init__(self, data):
        self.id = data.get('id', 'UNKNOWN')
        self.name = data.get('name', 'Unknown Rule')
        self.description = data.get('description', '')
        self.languages = data.get('languages', [])
        self.regex_pattern = data.get('regex_pattern')
        self.compliance = data.get('compliance', [])
        self.severity = data.get('severity', 'LOW')
        
        if self.regex_pattern:
            self._compiled_regex = re.compile(self.regex_pattern)
        else:
            self._compiled_regex = None

    def match_text(self, text):
        if self._compiled_regex:
            return self._compiled_regex.search(text)
        return False

class RulesEngine:
    def __init__(self, rules_file=None):
        self.rules = []
        if not rules_file:
            # Default to rules.yaml in the module directory
            base_dir = os.path.dirname(os.path.abspath(__file__))
            rules_file = os.path.join(base_dir, 'rules.yaml')
            
        self.load_rules(rules_file)

    def load_rules(self, rules_file):
        if not os.path.exists(rules_file):
            print(f"\033[93m[AuditLens] Advertencia: No se encontró {rules_file}. Se usará un motor vacío.\033[0m")
            return
            
        with open(rules_file, 'r', encoding='utf-8') as f:
            try:
                data = yaml.safe_load(f)
                if 'rules' in data:
                    self.rules = [Rule(r) for r in data['rules']]
            except yaml.YAMLError as e:
                print(f"\033[91m[ERROR] YAML Invalido en las reglas: {e}\033[0m")

    def get_rules_for_language(self, ext):
        ext_to_lang = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.swift': 'swift'
        }
        lang = ext_to_lang.get(ext)
        if not lang:
            return []
            
        return [r for r in self.rules if lang in r.languages]
