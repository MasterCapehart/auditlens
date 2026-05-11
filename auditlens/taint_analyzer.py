"""AuditLens Taint Analyzer — T1-3/T1-4 enhanced."""
from __future__ import annotations
import re
from typing import Dict, List, Optional, Set

class TaintAnalyzer:
    def __init__(self):
        self.source_name_patterns: List[str] = [
            'rut','password','passwd','pwd','token','secret',
            'api_key','apikey','auth_key','private_key','access_key',
            'credential','ssn','credit_card','card_number',
        ]
        self._input_source_patterns: List[re.Pattern] = [
            re.compile(r'request\s*\.\s*(?:args|form|json|data|values|files|cookies|headers)(?:\s*\.\s*get\s*\(|\s*\[)', re.IGNORECASE),
            re.compile(r'request\s*\.\s*get_json\s*\(', re.IGNORECASE),
            re.compile(r'\binput\s*\(', re.IGNORECASE),
            re.compile(r'\bsys\s*\.\s*argv\s*\[', re.IGNORECASE),
            re.compile(r'os\s*\.\s*environ\s*(?:\.\s*get\s*\(|\s*\[)', re.IGNORECASE),
            re.compile(r'os\s*\.\s*getenv\s*\(', re.IGNORECASE),
            re.compile(r'req\s*\.\s*(?:body|params|query|headers)\s*(?:\.\w+|\[)', re.IGNORECASE),
            re.compile(r'process\s*\.\s*env\s*\[', re.IGNORECASE),
        ]
        self.sink_patterns: List[str] = [
            'print','logging.info','logging.debug','logging.warning','logging.error',
            'logger.info','logger.debug','logger.warning','logger.error',
            'db.execute','cursor.execute','connection.execute','session.execute',
            'fetch','requests.post','requests.get','requests.put','requests.patch',
            'requests.delete','urllib.request.urlopen',
            'subprocess.run','subprocess.call','subprocess.Popen',
            'os.system','eval','exec','compile','open',
            'send_file','send_from_directory','redirect','render_template_string',
        ]
        self._source_assign_re = re.compile(
            r'(?:^|[\s\(,])(?:self\.|this\.)?(?:let\s+|const\s+|var\s+)?'
            r'(\w*(?:' + '|'.join(re.escape(p) for p in self.source_name_patterns) + r')\w*)'
            r'\s*(?:=|\[[\'"]\w+[\'"]\]\s*=)',
            re.IGNORECASE,
        )
        self._sink_res: List[re.Pattern] = [
            re.compile(r'(?<!\w)' + re.escape(s) + r'\s*\(', re.IGNORECASE)
            for s in self.sink_patterns
        ]

    def _is_comment_line(self, text: str) -> bool:
        s = text.strip()
        return s.startswith('#') or s.startswith('//') or s.startswith('*') or s.startswith('/*')

    def _strip_inline_comment(self, text: str) -> str:
        return re.split(r'(?<!["\'])#', text)[0]

    def _get_suppress_rules(self, line: str) -> Optional[Set[str]]:
        lower = line.lower()
        if 'auditlens: ignore' not in lower: return None
        after = re.split(r'auditlens:\s*ignore', lower, maxsplit=1, flags=re.IGNORECASE)[-1]
        rule_ids = set(re.findall(r'[A-Z0-9_-]{3,}', after.upper()))
        return rule_ids

    def _is_suppressed(self, line: str, rule_id: str = 'TAINT-01') -> bool:
        suppressed = self._get_suppress_rules(line)
        if suppressed is None: return False
        if len(suppressed) == 0: return True
        return rule_id in suppressed

    def analyze(self, file_path: str, code_lines: List[str]) -> List[dict]:
        findings: List[dict] = []
        tainted_vars: Dict[str, tuple] = {}
        reported: Set[str] = set()

        for line_idx, line in enumerate(code_lines):
            line_num = line_idx + 1
            text = line.rstrip('\n')
            if self._is_comment_line(text): continue
            code_part = self._strip_inline_comment(text)

            # 1. Assignment-based sources (sensitive variable names)
            for match in self._source_assign_re.finditer(code_part):
                var_name = match.group(1).lower()
                tainted_vars[var_name] = (line_num, f"sensitive variable '{var_name}'")

            # 2. T1-3: User-input sources on RHS
            for input_re in self._input_source_patterns:
                if input_re.search(code_part):
                    assign_match = re.match(r'\s*(?:let\s+|const\s+|var\s+)?(\w+)\s*=', code_part)
                    if assign_match:
                        var_name = assign_match.group(1).lower()
                        tainted_vars[var_name] = (line_num, f"user-controlled input assigned to '{var_name}'")

            # 3. Sinks
            for var_name, (source_line, source_desc) in list(tainted_vars.items()):
                if line_num == source_line: continue
                if var_name not in code_part.lower(): continue
                if var_name in reported: continue
                if self._is_suppressed(text, 'TAINT-01'): continue
                for sink_re, sink_name in zip(self._sink_res, self.sink_patterns):
                    if sink_re.search(code_part):
                        findings.append({
                            'rule_id': 'TAINT-01',
                            'name': 'Sensitive Data Flow Vulnerability (Taint)',
                            'description': (
                                f"{source_desc.capitalize()} (line {source_line}) "
                                f"flows into dangerous sink '{sink_name}()' without sanitization."
                            ),
                            'file': file_path, 'line': line_num, 'severity': 'HIGH',
                            'compliance': ['CWE-79','CWE-89','CWE-78','OWASP-A3:2021'],
                        })
                        reported.add(var_name)
                        del tainted_vars[var_name]
                        break
        return findings
