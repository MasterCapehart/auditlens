"""
AuditLens Multi-Project Scanner — scan several repos in sequence,
produce a unified summary table and a merged JSON/HTML report.

Usage:
    auditlens multi-scan ./repo1 ./repo2 ./repo3
    auditlens multi-scan ./repo1 ./repo2 --format html -o multi_report.html
    auditlens multi-scan ./repo1 ./repo2 --severity HIGH
"""

from __future__ import annotations

import json
import os
from typing import List, Optional

_SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
_SEVERITY_RANK  = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


def run_multi_scan(
    paths: List[str],
    min_severity: str = 'LOW',
    run_sca: bool = True,
    export_format: str = 'text',
    output_path: Optional[str] = None,
) -> int:
    """
    Scan each path independently, aggregate, print unified summary.
    Returns 0 if no findings, 1 if any findings.
    """
    from .rules_engine import RulesEngine
    from .taint_analyzer import TaintAnalyzer
    from .analyzer import analyze_file, _SUPPORTED_EXTENSIONS
    from .sca_engine import SCAEngine

    rules_engine = RulesEngine()
    taint_analyzer = TaintAnalyzer()
    sca_engine = SCAEngine()
    exclude_dirs = {
        'venv', '.venv', 'env', '.env', 'node_modules', '.git',
        '__pycache__', 'build', 'dist', 'site-packages',
    }

    all_findings: List[dict] = []
    per_project: List[dict] = []

    for path in paths:
        path = os.path.abspath(path)
        if not os.path.exists(path):
            print(f'\033[91m[AuditLens]\033[0m Path not found: {path}')
            continue

        print(f'\n\033[94m[AuditLens Multi-Scan]\033[0m → {path}')
        project_findings: List[dict] = []

        # SCA
        if run_sca:
            sca_dir = path if os.path.isdir(path) else os.path.dirname(path)
            sca_findings = sca_engine.analyze_directory(sca_dir)
            project_findings.extend(sca_findings)

        # SAST
        if os.path.isfile(path):
            ext = os.path.splitext(path)[1].lower()
            if ext in _SUPPORTED_EXTENSIONS:
                analyze_file(
                    path, rules_engine, taint_analyzer,
                    min_severity=min_severity,
                    all_findings_accumulator=project_findings,
                )
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in exclude_dirs]
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in _SUPPORTED_EXTENSIONS:
                        analyze_file(
                            os.path.join(root, fname),
                            rules_engine, taint_analyzer,
                            min_severity=min_severity,
                            all_findings_accumulator=project_findings,
                        )

        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in project_findings:
            sev = f.get('severity', 'LOW').upper()
            if sev in counts:
                counts[sev] += 1

        per_project.append({
            'path': path,
            'name': os.path.basename(path),
            'total': len(project_findings),
            'counts': dict(counts),
            'findings': project_findings,
        })
        all_findings.extend(project_findings)

    # ── Unified summary table ─────────────────────────────────────────────────
    print('\n\033[94m[AuditLens]\033[0m Multi-Scan Summary')
    print(f"  {'Project':<30} {'Total':>6} {'C':>4} {'H':>4} {'M':>5} {'L':>5}")
    print('  ' + '─' * 58)
    for p in sorted(per_project, key=lambda x: -x['total']):
        c = p['counts']
        c_col = f'\033[91m{c["CRITICAL"]:>4}\033[0m' if c['CRITICAL'] else f'{c["CRITICAL"]:>4}'
        h_col = f'\033[93m{c["HIGH"]:>4}\033[0m'     if c['HIGH']     else f'{c["HIGH"]:>4}'
        print(f"  {p['name']:<30} {p['total']:>6} {c_col} {h_col} {c['MEDIUM']:>5} {c['LOW']:>5}")

    total_all = len(all_findings)
    print(f'\n  Total across all projects: {total_all} findings')

    # ── Export ────────────────────────────────────────────────────────────────
    if export_format == 'html':
        from .html_exporter import generate_html_report
        out = output_path or 'multi_audit_report.html'
        generate_html_report(all_findings, scan_path=', '.join(p['name'] for p in per_project), output_path=out)

    elif export_format == 'json':
        out = output_path or 'multi_audit_results.json'
        with open(out, 'w', encoding='utf-8') as fh:
            json.dump({
                'projects': [{k: v for k, v in p.items() if k != 'findings'} for p in per_project],
                'all_findings': all_findings,
            }, fh, indent=2, default=str)
        print(f'\033[92m[AuditLens]\033[0m JSON guardado: {os.path.abspath(out)}')

    elif export_format == 'xlsx':
        from .xlsx_exporter import generate_xlsx_report
        out = output_path or 'multi_audit_report.xlsx'
        generate_xlsx_report(all_findings, scan_path='Multi-project scan', output_path=out)

    return 1 if total_all > 0 else 0
