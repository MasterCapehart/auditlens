# Taint Analysis for AuditLens
# Tracks sensitive variable assignments and their subsequent use in dangerous sinks.

import re

class TaintAnalyzer:
    def __init__(self):
        # source_patterns: variable name fragments considered sensitive at birth
        self.source_patterns = [
            'rut', 'password', 'passwd', 'pwd', 'token', 'secret',
            'api_key', 'apikey', 'auth_key', 'private_key', 'access_key',
            'credential', 'ssn', 'credit_card', 'card_number',
        ]

        # sink_patterns: dangerous functions where sensitive data should not flow unobfuscated
        self.sink_patterns = [
            'print', 'logging.info', 'logging.debug', 'logging.warning',
            'logging.error', 'logger.info', 'logger.debug', 'logger.warning',
            'logger.error', 'db.execute', 'cursor.execute', 'connection.execute',
            'fetch', 'requests.post', 'requests.get', 'requests.put',
            'requests.patch', 'requests.delete', 'urllib.request.urlopen',
            'subprocess.run', 'subprocess.call', 'subprocess.Popen',
            'os.system', 'eval', 'exec',
        ]

        # Regex: matches assignments like:
        #   password = "foo", self.token = x, user['secret'] = val,
        #   let password =, const api_key =, var token =
        # Uses word boundaries to avoid matching "last_password_update"
        self._source_re = re.compile(
            r'(?:^|[\s\(,])(?:self\.|this\.)?(?:let\s+|const\s+|var\s+)?'
            r'(\w*(?:' + '|'.join(re.escape(p) for p in self.source_patterns) + r')\w*)'
            r'\s*(?:=|\[[\'"]\w+[\'"]\]\s*=)',
            re.IGNORECASE
        )

        # Precompile sink regexes for efficiency
        self._sink_res = [
            re.compile(r'(?<!\w)' + re.escape(sink) + r'\s*\(', re.IGNORECASE)
            for sink in self.sink_patterns
        ]

    def _is_comment(self, text: str, lang_ext: str = '') -> bool:
        """Best-effort check: is the entire line a comment?"""
        stripped = text.strip()
        return (
            stripped.startswith('#') or
            stripped.startswith('//') or
            stripped.startswith('*') or
            stripped.startswith('/*')
        )

    def analyze(self, file_path: str, code_lines: list) -> list:
        """
        Intra-procedural taint tracking.
        Detects sensitive variable sources and checks if they flow
        into dangerous sinks on subsequent lines without sanitization.
        Returns a list of finding dicts.
        """
        findings = []
        # BUG-01 FIX: use a separate dict so we never mutate while iterating.
        tainted_vars: dict[str, int] = {}  # var_name -> line_number_where_tainted
        reported: set[str] = set()          # avoid duplicate reports per var

        for line_idx, line in enumerate(code_lines):
            line_num = line_idx + 1
            text = line.rstrip('\n')

            # Skip whole-line comments
            if self._is_comment(text):
                continue

            # Strip inline comments (Python # style) for matching purposes only
            code_part = re.split(r'(?<!["\'])#', text)[0]

            # ── 1. Detect Sources ────────────────────────────────────────────
            # CQ-01 FIX: use proper regex with word boundaries
            for match in self._source_re.finditer(code_part):
                var_name = match.group(1).lower()
                tainted_vars[var_name] = line_num

            # ── 2. Detect Sinks ──────────────────────────────────────────────
            # CQ-02 FIX: only match actual function calls (sink_re ends with `\s*(`)
            # and skip the declaration line itself
            # BUG-01 FIX: iterate over a snapshot so deletion is safe
            for var_name, source_line in list(tainted_vars.items()):
                if line_num == source_line:
                    continue
                if var_name not in code_part.lower():
                    continue
                if var_name in reported:
                    continue

                for sink_re, sink_name in zip(self._sink_res, self.sink_patterns):
                    if sink_re.search(code_part):
                        finding = {
                            "rule_id": "TAINT-01",
                            "name": "Sensitive Data Flow Vulnerability (Taint)",
                            "description": (
                                f"Sensitive variable '{var_name}' (declared at line {source_line}) "
                                f"flows into dangerous sink '{sink_name}()' without sanitization."
                            ),
                            "file": file_path,
                            "line": line_num,
                            "severity": "HIGH",
                            "compliance": ["CWE-79", "CWE-89", "OWASP-A3"],
                        }
                        findings.append(finding)
                        reported.add(var_name)
                        # Remove from live tracking to avoid repeat reports
                        del tainted_vars[var_name]
                        break

        return findings
