"""
AuditLens — Static Analysis Orchestrator

Changes vs original:
- BUG-10: file read errors are reported, not silently swallowed
- BUG-11: Tree-sitter AST traversal actually used (string literal scanning)
- PERF-03: parsers cached per language session
- MISSING-01: run_static_analysis returns exit code based on findings severity
- MISSING-04: min_severity filter support
- MISSING-05: inline suppress via '# auditlens: ignore' comment
- MISSING-08: TypeScript / TSX support added
- UX-01: messages in English
- UX-02: summary count printed at end
- CQ-06: removed unused 'import argparse'
"""

import os
import sys
from .rules_engine import RulesEngine
from .taint_analyzer import TaintAnalyzer
from .sca_engine import SCAEngine

# ── Tree-sitter parser cache (PERF-03) ────────────────────────────────────────
_PARSER_CACHE: dict = {}

_SUPPORTED_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.swift'}

_EXT_TO_LANGUAGE = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.swift': 'swift',
}

_SEVERITY_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}

SUPPRESS_COMMENT = 'auditlens: ignore'


def _load_parser(ext: str):
    """
    PERF-03 FIX: cache parsers per language instead of re-initialising on every file.
    PKG-06 FIX: Swift/TypeScript import failures produce a clear warning instead
    of silently returning None.
    """
    if ext in _PARSER_CACHE:
        return _PARSER_CACHE[ext]

    try:
        from tree_sitter import Language, Parser

        if ext == '.py':
            import tree_sitter_python as ts_mod
        elif ext in ('.js', '.jsx'):
            import tree_sitter_javascript as ts_mod
        elif ext in ('.ts', '.tsx'):
            try:
                import tree_sitter_typescript as ts_mod_ts
                # tree_sitter_typescript exposes separate .typescript and .tsx
                ts_mod = ts_mod_ts.typescript if ext in ('.ts',) else ts_mod_ts.tsx
                lang = Language(ts_mod)
                parser = Parser(lang)
                _PARSER_CACHE[ext] = parser
                return parser
            except ImportError:
                print(
                    f"\033[93m[AuditLens] Warning: tree-sitter-typescript not installed. "
                    f"AST analysis disabled for {ext} files.\033[0m"
                )
                _PARSER_CACHE[ext] = None
                return None
            except (ValueError, Exception) as exc:
                print(
                    f"\033[93m[AuditLens] Warning: tree-sitter parser error for {ext}: {exc}. "
                    f"AST analysis disabled.\033[0m"
                )
                _PARSER_CACHE[ext] = None
                return None
        elif ext == '.swift':
            try:
                import tree_sitter_swift as ts_mod
            except ImportError:
                print(
                    "\033[93m[AuditLens] Warning: tree-sitter-swift not installed. "
                    "AST analysis disabled for .swift files.\033[0m"
                )
                _PARSER_CACHE[ext] = None
                return None
        else:
            _PARSER_CACHE[ext] = None
            return None

        lang = Language(ts_mod.language())
        parser = Parser(lang)
        _PARSER_CACHE[ext] = parser
        return parser

    except ImportError:
        _PARSER_CACHE[ext] = None
        return None
    except (ValueError, Exception) as exc:
        # PKG-03 FIX: tree-sitter Language version mismatch (e.g. "Incompatible Language version")
        print(
            f"\033[93m[AuditLens] Warning: tree-sitter parser unavailable for {ext}: {exc}. "
            f"AST analysis disabled for this file type.\033[0m"
        )
        _PARSER_CACHE[ext] = None
        return None


def _ast_scan(file_path: str, code_bytes: bytes, parser, ext: str) -> list:
    """
    BUG-11 FIX: actually traverse the Tree-sitter AST.
    Currently detects hardcoded string literals assigned to sensitive identifiers
    — a structural check that regex alone cannot do reliably.
    """
    findings = []
    try:
        tree = parser.parse(code_bytes)
        root = tree.root_node

        sensitive_names = {
            'password', 'passwd', 'pwd', 'secret', 'token', 'api_key',
            'apikey', 'private_key', 'access_key', 'auth_key',
        }

        def _walk(node):
            """
            Look for assignment nodes where the left side is a sensitive name
            and the right side is a string literal (hardcoded value).
            """
            # Python: assignment_statement / augmented_assignment
            # JS/TS:  variable_declarator, assignment_expression
            # Swift:  value_binding_pattern
            is_assignment = node.type in (
                'assignment',          # Python
                'assignment_statement',
                'augmented_assignment',
                'variable_declarator', # JS / TS
                'assignment_expression',
                'pattern_initializer', # Swift
            )

            if is_assignment and len(node.children) >= 2:
                lhs = node.children[0]
                # Extract identifier text from the left-hand side
                lhs_text = ''
                if lhs.type == 'identifier':
                    lhs_text = lhs.text.decode('utf-8', errors='replace').lower()
                elif lhs.type in ('attribute', 'member_expression'):
                    # e.g. self.password  or  obj.token
                    for child in lhs.children:
                        if child.type == 'identifier':
                            lhs_text = child.text.decode('utf-8', errors='replace').lower()

                if any(s in lhs_text for s in sensitive_names):
                    # Check if the RHS contains a string literal
                    for child in node.children:
                        if child.type in (
                            'string', 'string_literal',  # Python / Swift
                            'template_string',            # JS/TS template literals
                            'string_fragment',
                        ):
                            val = child.text.decode('utf-8', errors='replace')
                            # Ignore empty strings and env var lookups
                            if len(val) > 3 and 'os.environ' not in val and 'process.env' not in val:
                                findings.append({
                                    'rule_id': 'AST-01-HARDCODED-SENSITIVE',
                                    'name': 'Hardcoded Sensitive Value (AST)',
                                    'description': (
                                        f"Identifier '{lhs_text}' is assigned a hardcoded "
                                        f"string literal. Use environment variables or a "
                                        f"secrets manager instead."
                                    ),
                                    'file': file_path,
                                    'line': node.start_point[0] + 1,
                                    'severity': 'HIGH',
                                    'compliance': ['OWASP-A7', 'CWE-798'],
                                })
                            break

            for child in node.children:
                _walk(child)

        _walk(root)
    except Exception as e:
        print(f"\033[93m[AuditLens] AST scan warning for {file_path}: {e}\033[0m")

    return findings


def _should_suppress(line: str) -> bool:
    """
    MISSING-05 FIX: inline suppress — any line containing
    '# auditlens: ignore' (case-insensitive) is excluded from findings.
    """
    return SUPPRESS_COMMENT in line.lower()


def analyze_file(
    file_path: str,
    rules_engine: 'RulesEngine',
    taint_analyzer: 'TaintAnalyzer',
    sarif_exporter=None,
    pdf_exporter=None,
    min_severity: str = 'LOW',
    all_findings_accumulator: list | None = None,
) -> list:
    """
    Analyze a single file. Returns list of findings.
    BUG-10 FIX: errors are printed, not silently swallowed.
    """
    ext = os.path.splitext(file_path)[1].lower()
    rules = rules_engine.get_rules_for_language(ext)
    min_rank = _SEVERITY_RANK.get(min_severity.upper(), 0)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
            code_lines = fh.readlines()
            code_text = ''.join(code_lines)
    except OSError as e:
        # BUG-10 FIX: report, don't swallow
        print(f"\033[93m[AuditLens] Warning: cannot read {file_path}: {e}\033[0m")
        return []

    findings: list = []

    # ── 1. YAML regex rules ───────────────────────────────────────────────────
    for rule in rules:
        for i, line in enumerate(code_lines):
            # MISSING-05 FIX: skip suppressed lines
            if _should_suppress(line):
                continue
            if rule.match_text(line):
                findings.append({
                    'rule_id': rule.id,
                    'name': rule.name,
                    'description': rule.description,
                    'file': file_path,
                    'line': i + 1,
                    'severity': rule.severity,
                    'compliance': rule.compliance,
                })

    # ── 2. Taint analysis ────────────────────────────────────────────────────
    taint_findings = taint_analyzer.analyze(file_path, code_lines)
    findings.extend(taint_findings)

    # ── 3. Tree-sitter AST scan (BUG-11 FIX) ─────────────────────────────────
    parser = _load_parser(ext)
    if parser:
        ast_findings = _ast_scan(file_path, code_text.encode('utf-8'), parser, ext)
        findings.extend(ast_findings)

    # ── 4. Filter by min severity and emit ───────────────────────────────────
    for finding in findings:
        rank = _SEVERITY_RANK.get(finding['severity'].upper(), 0)
        if rank < min_rank:
            continue

        color = (
            '\033[91m'
            if finding['severity'] in ('CRITICAL', 'HIGH')
            else '\033[93m'
        )
        print(
            f"{color}[{finding['rule_id']}] {finding['file']}:{finding['line']} "
            f"— {finding['name']}\033[0m"
        )
        if finding.get('compliance'):
            print(f"   \033[90mCompliance: {', '.join(finding['compliance'])}\033[0m")

        if sarif_exporter:
            sarif_exporter.add_finding(finding)
        if pdf_exporter:
            pdf_exporter.add_finding(finding)
        if all_findings_accumulator is not None:
            all_findings_accumulator.append(finding)

    return findings


def run_static_analysis(
    path: str,
    export_sarif: bool = False,
    export_pdf: bool = False,
    output_path: str | None = None,
    min_severity: str = 'LOW',
    run_sca: bool = True,
) -> int:
    """
    MISSING-01 FIX: returns exit code.
      0 = no findings at or above min_severity
      1 = findings found
      2 = path does not exist
    UX-01: messages in English.
    UX-02: summary at the end.
    """
    print(f"\033[94m[AuditLens]\033[0m Starting scan: {path}\n")

    if not os.path.exists(path):
        print(f"\033[91m[ERROR]\033[0m Path does not exist: {path}")
        return 2

    rules_engine = RulesEngine()
    taint_analyzer = TaintAnalyzer()

    sarif_exporter = None
    if export_sarif:
        from .sarif_exporter import SarifExporter
        sarif_exporter = SarifExporter()

    pdf_exporter = None
    if export_pdf:
        from .pdf_exporter import PdfExporter
        pdf_exporter = PdfExporter()

    all_findings: list = []

    # ── SCA ──────────────────────────────────────────────────────────────────
    if run_sca:
        print("\033[94m[AuditLens]\033[0m Running Software Composition Analysis (SCA)...")
        sca_engine = SCAEngine()
        sca_path = path if os.path.isdir(path) else os.path.dirname(path)
        sca_findings = sca_engine.analyze_directory(sca_path)
        for finding in sca_findings:
            rank = _SEVERITY_RANK.get(finding['severity'].upper(), 0)
            if rank < _SEVERITY_RANK.get(min_severity.upper(), 0):
                continue
            color = '\033[91m'
            print(
                f"{color}[{finding['rule_id']}] {finding['file']}:{finding['line']} "
                f"— {finding['name']}\033[0m"
            )
            if finding.get('compliance'):
                print(f"   \033[90mCompliance: {', '.join(finding['compliance'])}\033[0m")
            if sarif_exporter:
                sarif_exporter.add_finding(finding)
            if pdf_exporter:
                pdf_exporter.add_finding(finding)
            all_findings.append(finding)

    # ── SAST ─────────────────────────────────────────────────────────────────
    print("\033[94m[AuditLens]\033[0m Running Static Analysis (SAST)...")
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        if ext in _SUPPORTED_EXTENSIONS:
            analyze_file(
                path, rules_engine, taint_analyzer,
                sarif_exporter, pdf_exporter, min_severity, all_findings,
            )
    elif os.path.isdir(path):
        exclude_dirs = {
            'venv', 'env', '.env', '.git', '__pycache__',
            'node_modules', 'build', 'dist', '.tox',
        }
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in _SUPPORTED_EXTENSIONS:
                    analyze_file(
                        os.path.join(root, fname),
                        rules_engine, taint_analyzer,
                        sarif_exporter, pdf_exporter, min_severity, all_findings,
                    )

    # ── UX-02: Summary ───────────────────────────────────────────────────────
    total = len(all_findings)
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in all_findings:
        sev = f['severity'].upper()
        if sev in counts:
            counts[sev] += 1

    print(f"\n\033[92m[AuditLens]\033[0m Scan complete.")
    print(
        f"   Total findings: {total}  "
        f"(\033[91mCRITICAL:{counts['CRITICAL']}  HIGH:{counts['HIGH']}\033[0m  "
        f"\033[93mMEDIUM:{counts['MEDIUM']}\033[0m  "
        f"\033[90mLOW:{counts['LOW']}\033[0m)"
    )

    # ── Export ────────────────────────────────────────────────────────────────
    if sarif_exporter:
        out = output_path or 'audit_results.sarif'
        sarif_exporter.export(out)

    if pdf_exporter:
        out = output_path or 'audit_report.pdf'
        pdf_exporter.generate_report(out)

    return 1 if all_findings else 0
