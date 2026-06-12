"""
AuditLens — Static Analysis Orchestrator

New in this version:
- T1-2: --baseline/--diff mode (save/load fingerprint baseline)
- T1-4: rule-specific suppress # auditlens: ignore RULE-ID
- T1-5: .auditlens.yaml project config integration
- T2-3: --format json output
- T3-3: scan history persisted to SQLite
- T3-6: Python 3.9 compat — Optional[X] instead of X | None
"""

from __future__ import annotations

import json
import os
import sys
from typing import Dict, List, Optional

from .rules_engine import RulesEngine
from .taint_analyzer import TaintAnalyzer
from .sca_engine import SCAEngine

# ── Parser cache (PERF-03) ────────────────────────────────────────────────────
_PARSER_CACHE: Dict[str, object] = {}

_SUPPORTED_EXTENSIONS = {
    '.py', '.js', '.jsx', '.ts', '.tsx', '.swift',
    '.go', '.java', '.kt', '.rb', '.php',
    '.tf', '.hcl', '.yaml', '.yml',
}

_IAC_ONLY_FILENAMES = {'dockerfile', 'docker-compose.yml', 'docker-compose.yaml'}

_SEVERITY_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


def _load_parser(ext: str):
    if ext in _PARSER_CACHE:
        return _PARSER_CACHE[ext]

    try:
        from tree_sitter import Language, Parser

        if ext == '.py':
            import tree_sitter_python as ts_mod
            lang = Language(ts_mod.language())
        elif ext in ('.js', '.jsx'):
            import tree_sitter_javascript as ts_mod
            lang = Language(ts_mod.language())
        elif ext in ('.ts', '.tsx'):
            try:
                import tree_sitter_typescript as ts_mod_ts
                ts_lang = ts_mod_ts.typescript if ext == '.ts' else ts_mod_ts.tsx
                lang = Language(ts_lang)
            except ImportError:
                _PARSER_CACHE[ext] = None
                return None
        elif ext == '.swift':
            try:
                import tree_sitter_swift as ts_mod
                lang = Language(ts_mod.language())
            except ImportError:
                _PARSER_CACHE[ext] = None
                return None
        else:
            _PARSER_CACHE[ext] = None
            return None

        parser = Parser(lang)
        _PARSER_CACHE[ext] = parser
        return parser

    except (ImportError, ValueError, Exception) as exc:
        print(
            f'\033[93m[AuditLens] Warning: AST parser unavailable for {ext}: {exc}\033[0m'
        )
        _PARSER_CACHE[ext] = None
        return None


def _ast_scan(file_path: str, code_bytes: bytes, parser) -> List[dict]:
    findings: List[dict] = []
    try:
        tree = parser.parse(code_bytes)
        root = tree.root_node

        sensitive_names = {
            'password', 'passwd', 'pwd', 'secret', 'token', 'api_key',
            'apikey', 'private_key', 'access_key', 'auth_key',
        }

        def _walk(node):
            is_assignment = node.type in (
                'assignment', 'assignment_statement', 'augmented_assignment',
                'variable_declarator', 'assignment_expression', 'pattern_initializer',
            )
            if is_assignment and len(node.children) >= 2:
                lhs = node.children[0]
                lhs_text = ''
                if lhs.type == 'identifier':
                    lhs_text = lhs.text.decode('utf-8', errors='replace').lower()
                elif lhs.type in ('attribute', 'member_expression'):
                    for child in lhs.children:
                        if child.type == 'identifier':
                            lhs_text = child.text.decode('utf-8', errors='replace').lower()

                if any(s in lhs_text for s in sensitive_names):
                    for child in node.children:
                        if child.type in ('string', 'string_literal', 'template_string', 'string_fragment'):
                            val = child.text.decode('utf-8', errors='replace')
                            if (len(val) > 3
                                    and 'os.environ' not in val
                                    and 'process.env' not in val):
                                findings.append({
                                    'rule_id': 'AST-01-HARDCODED-SENSITIVE',
                                    'name': 'Hardcoded Sensitive Value (AST)',
                                    'description': (
                                        f"Identifier '{lhs_text}' is assigned a hardcoded "
                                        "string literal. Use environment variables instead."
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
        print(f'\033[93m[AuditLens] AST scan warning for {file_path}: {e}\033[0m')
    return findings


def _should_suppress(line: str, rule_id: str) -> bool:
    """
    T1-4: Rule-specific suppress.
    # auditlens: ignore          → suppress all rules on this line
    # auditlens: ignore SEC-01   → suppress only SEC-01 on this line
    """
    lower = line.lower()
    if 'auditlens: ignore' not in lower:
        return False
    import re
    after = re.split(r'auditlens:\s*ignore', lower, maxsplit=1, flags=re.IGNORECASE)[-1]
    rule_ids = set(re.findall(r'[A-Z0-9_-]{3,}', after.upper()))
    return len(rule_ids) == 0 or rule_id in rule_ids


def analyze_file(
    file_path: str,
    rules_engine: RulesEngine,
    taint_analyzer: TaintAnalyzer,
    sarif_exporter=None,
    pdf_exporter=None,
    min_severity: str = 'LOW',
    all_findings_accumulator: Optional[List[dict]] = None,
    disabled_rules: Optional[List[str]] = None,
    excluded_paths: Optional[List[str]] = None,
) -> List[dict]:
    """Analyze a single file. Returns list of findings."""
    # T1-5: check config-excluded paths
    if excluded_paths:
        norm = os.path.normpath(file_path)
        for excl in excluded_paths:
            if norm.startswith(os.path.normpath(excl)):
                return []

    ext = os.path.splitext(file_path)[1].lower()
    min_rank = _SEVERITY_RANK.get(min_severity.upper(), 0)
    disabled = set(disabled_rules or [])

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
            code_lines = fh.readlines()
            code_text = ''.join(code_lines)
    except OSError as e:
        print(f'\033[93m[AuditLens] Warning: cannot read {file_path}: {e}\033[0m')
        return []

    findings: List[dict] = []

    rules = rules_engine.get_rules_for_language(ext, filename=file_path)

    # ── 1. YAML regex rules ───────────────────────────────────────────────────
    for rule in rules:
        if rule.id in disabled:
            continue
        for i, line in enumerate(code_lines):
            if _should_suppress(line, rule.id):
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

    # ── 2. Taint analysis ─────────────────────────────────────────────────────
    if 'TAINT-01' not in disabled:
        findings.extend(taint_analyzer.analyze(file_path, code_lines))

    # ── 3. Tree-sitter AST scan ───────────────────────────────────────────────
    if 'AST-01-HARDCODED-SENSITIVE' not in disabled:
        parser = _load_parser(ext)
        if parser:
            findings.extend(_ast_scan(file_path, code_text.encode('utf-8'), parser))

    # ── 4. Entropy-based secret detection ────────────────────────────────────
    if 'ENTROPY-BASE64' not in disabled and 'ENTROPY-HEX' not in disabled:
        try:
            from .entropy_scanner import scan_file_for_secrets
            findings.extend(scan_file_for_secrets(file_path))
        except Exception:
            pass

    # ── 5. Filter, print, accumulate ─────────────────────────────────────────
    for finding in findings:
        rank = _SEVERITY_RANK.get(finding['severity'].upper(), 0)
        if rank < min_rank:
            continue

        color = '\033[91m' if finding['severity'] in ('CRITICAL', 'HIGH') else '\033[93m'
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
    export_json: bool = False,
    export_docx: bool = False,
    export_html: bool = False,
    export_xlsx: bool = False,
    output_path: Optional[str] = None,
    min_severity: str = 'LOW',
    run_sca: bool = True,
    save_baseline: Optional[str] = None,
    diff_baseline: Optional[str] = None,
    record_history: bool = True,
    interprocedural: bool = False,
    empresa: str = 'Empresa',
    sistema: str = 'Sistema de Software',
    auditor: str = '[Auditor por asignar]',
    trimestre: str = 'primer trimestre de 2025',
    ai_fix: bool = False,
    ai_fix_severity: str = 'HIGH',
    ai_fix_output: Optional[str] = None,
) -> int:
    """
    Run full analysis. Returns exit code:
      0 = no findings
      1 = findings found (or new findings vs baseline)
      2 = path does not exist
    """
    from .config import load_config

    # Load project config (.auditlens.yaml)
    search_dir = path if os.path.isdir(path) else os.path.dirname(path)
    cfg = load_config(search_dir)

    # CLI flags override config
    effective_min_severity = min_severity if min_severity != 'LOW' else cfg.min_severity
    effective_sca = run_sca and cfg.sca
    effective_baseline = diff_baseline or cfg.baseline

    print(f'\033[94m[AuditLens]\033[0m Starting scan: {path}\n')

    if not os.path.exists(path):
        print(f'\033[91m[ERROR]\033[0m Path does not exist: {path}')
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

    all_findings: List[dict] = []

    # ── SCA ───────────────────────────────────────────────────────────────────
    if effective_sca:
        print('\033[94m[AuditLens]\033[0m Running Software Composition Analysis (SCA)...')
        sca_engine = SCAEngine()
        sca_path = path if os.path.isdir(path) else os.path.dirname(path)
        sca_findings = sca_engine.analyze_directory(sca_path)
        min_rank = _SEVERITY_RANK.get(effective_min_severity, 0)
        for finding in sca_findings:
            if _SEVERITY_RANK.get(finding['severity'].upper(), 0) < min_rank:
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

    # ── SAST ──────────────────────────────────────────────────────────────────
    print('\033[94m[AuditLens]\033[0m Running Static Analysis (SAST)...')

    common_kwargs: Dict = dict(
        rules_engine=rules_engine,
        taint_analyzer=taint_analyzer,
        sarif_exporter=sarif_exporter,
        pdf_exporter=pdf_exporter,
        min_severity=effective_min_severity,
        all_findings_accumulator=all_findings,
        disabled_rules=cfg.disable_rules,
        excluded_paths=cfg.exclude_paths,
    )

    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        base = os.path.basename(path).lower()
        if ext in _SUPPORTED_EXTENSIONS or base.startswith('dockerfile'):
            analyze_file(path, **common_kwargs)
    elif os.path.isdir(path):
        exclude_dirs = {
            'venv', 'env', '.env', '.venv',
            '.git', '__pycache__',
            'node_modules', 'build', 'dist', '.tox',
            'site-packages', 'lib', 'bin', 'include',
        }
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                base = fname.lower()
                if ext in _SUPPORTED_EXTENSIONS or base.startswith('dockerfile'):
                    analyze_file(os.path.join(root, fname), **common_kwargs)

    # ── Inter-procedural taint (optional, Python only) ────────────────────────
    if interprocedural and os.path.isdir(path):
        print('\033[94m[AuditLens]\033[0m Running Inter-Procedural Taint Analysis...')
        try:
            from .taint_interprocedural import InterProceduralTaintAnalyzer
            ip_analyzer = InterProceduralTaintAnalyzer()
            ip_analyzer.load_directory(path)
            ip_findings = ip_analyzer.analyze()
            min_rank = _SEVERITY_RANK.get(effective_min_severity, 0)
            for finding in ip_findings:
                if _SEVERITY_RANK.get(finding['severity'].upper(), 0) < min_rank:
                    continue
                color = '\033[91m'
                print(
                    f"{color}[{finding['rule_id']}] {finding['file']}:{finding['line']} "
                    f"— {finding['name']}\033[0m"
                )
                if sarif_exporter:
                    sarif_exporter.add_finding(finding)
                if pdf_exporter:
                    pdf_exporter.add_finding(finding)
                all_findings.append(finding)
        except Exception as exc:
            print(f'\033[93m[AuditLens] Inter-procedural taint warning: {exc}\033[0m')

    # ── Suppression (.auditlens-ignore + inline + security-tool whitelist) ──────
    try:
        from .suppression import filter_suppressed
        project_root = path if os.path.isdir(path) else os.path.dirname(path)
        all_findings, suppressed = filter_suppressed(all_findings, project_root)
        if suppressed:
            print(
                f'\033[90m[AuditLens] {len(suppressed)} hallazgo(s) suprimido(s) '
                f'(# auditlens: ignore / .auditlens-ignore / whitelist)\033[0m'
            )
    except Exception:
        pass

    # ── Baseline / diff (T1-2) ────────────────────────────────────────────────
    reported_findings = all_findings

    if save_baseline:
        from .baseline import save_baseline as _save
        _save(all_findings, save_baseline)

    if effective_baseline and not save_baseline:
        from .baseline import load_baseline, diff_against_baseline
        baseline = load_baseline(effective_baseline)
        if baseline is not None:
            new_findings = diff_against_baseline(all_findings, baseline)
            dropped = len(all_findings) - len(new_findings)
            if dropped:
                print(
                    f'\033[90m[AuditLens] Baseline: {dropped} known findings suppressed, '
                    f'{len(new_findings)} new.\033[0m'
                )
            reported_findings = new_findings

    # ── Compliance enrichment ─────────────────────────────────────────────────
    try:
        from .compliance_mapper import enrich_with_compliance
        reported_findings = enrich_with_compliance(reported_findings)
    except Exception:
        pass

    # ── Summary ───────────────────────────────────────────────────────────────
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in reported_findings:
        sev = f['severity'].upper()
        if sev in counts:
            counts[sev] += 1

    total = len(reported_findings)
    print(f'\n\033[92m[AuditLens]\033[0m Scan complete.')
    print(
        f"   Total: {total}  "
        f"(\033[91mCRITICAL:{counts['CRITICAL']}  HIGH:{counts['HIGH']}\033[0m  "
        f"\033[93mMEDIUM:{counts['MEDIUM']}\033[0m  "
        f"\033[90mLOW:{counts['LOW']}\033[0m)"
    )

    # ── Risk table ────────────────────────────────────────────────────────────
    if reported_findings:
        try:
            from .risk_scorer import print_risk_table
            print_risk_table(reported_findings)
        except Exception:
            pass

    # ── Export ────────────────────────────────────────────────────────────────
    if sarif_exporter:
        sarif_exporter.export(output_path or 'audit_results.sarif')

    if pdf_exporter:
        pdf_exporter.generate_report(output_path or 'audit_report.pdf')

    # JSON output
    if export_json:
        json_path = output_path or 'audit_results.json'
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(reported_findings, fh, indent=2, default=str)
        print(f'\033[92m[AuditLens]\033[0m Reporte JSON guardado: \033[1m{os.path.abspath(json_path)}\033[0m')

    # Word/DOCX audit report (full audit document)
    if export_docx:
        docx_path = output_path or 'informe_auditoria.docx'
        try:
            from .docx_exporter import generate_docx_report
            generate_docx_report(
                findings=reported_findings,
                scan_path=path,
                output_path=docx_path,
                empresa=empresa,
                sistema=sistema,
                auditor=auditor,
                trimestre=trimestre,
            )
        except ImportError:
            print(
                '\033[93m[AuditLens]\033[0m python-docx no instalado. '
                'Instala con: pip install python-docx --break-system-packages'
            )

    # HTML report
    if export_html:
        html_path = output_path or 'audit_report.html'
        try:
            from .html_exporter import generate_html_report
            generate_html_report(reported_findings, scan_path=path, output_path=html_path)
        except Exception as exc:
            print(f'\033[93m[AuditLens]\033[0m HTML export error: {exc}')

    # Excel report
    if export_xlsx:
        xlsx_path = output_path or 'audit_report.xlsx'
        try:
            from .xlsx_exporter import generate_xlsx_report
            generate_xlsx_report(reported_findings, scan_path=path, output_path=xlsx_path)
        except Exception as exc:
            print(f'\033[93m[AuditLens]\033[0m XLSX export error: {exc}')

    # AI fix suggestions
    if ai_fix and reported_findings:
        try:
            from .ai_fix import run_ai_fix
            run_ai_fix(
                reported_findings,
                min_severity=ai_fix_severity,
                output_path=ai_fix_output,
            )
        except Exception as exc:
            print(f'\033[93m[AuditLens]\033[0m AI fix error: {exc}')

    # Persist history
    if record_history and all_findings is not None:
        try:
            from .history import record_scan
            record_scan(path, all_findings)
        except Exception:
            pass

    # Dispatch notifications if configured
    if cfg.baseline is None:
        notif_config = getattr(cfg, 'notifications', None)
        if notif_config:
            try:
                from .notifications import dispatch_notifications
                dispatch_notifications(reported_findings, path, notif_config)
            except Exception as exc:
                print(f'\033[93m[AuditLens] Notification error: {exc}\033[0m')

    # Respect fail_on from config
    fail_rank = _SEVERITY_RANK.get(cfg.fail_on, 0)
    has_critical_findings = any(
        _SEVERITY_RANK.get(f['severity'].upper(), 0) >= fail_rank
        for f in reported_findings
    )
    return 1 if has_critical_findings else 0
