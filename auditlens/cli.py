"""
AuditLens CLI entry point — complete command set.
"""

from __future__ import annotations

import argparse
import sys
import platform

from . import __version__
from .analyzer import run_static_analysis
from .runner import run_script_with_hook
from .log_watcher import watch_log_file, watch_xcode_simulator


def main():
    parser = argparse.ArgumentParser(
        description='AuditLens — SAST, SCA, Taint Analysis, Auditoría ISO y Post-Mortem.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Ejemplos:\n'
            '  auditlens scan ./proyecto\n'
            '  auditlens scan ./proyecto --format docx -o informe.docx\n'
            '  auditlens scan ./proyecto --format pdf -o reporte.pdf\n'
            '  auditlens scan ./proyecto --format sarif -o results.sarif\n'
            '  auditlens scan ./proyecto --severity HIGH --no-sca\n'
            '  auditlens scan ./proyecto --save-baseline .auditlens-baseline.json\n'
            '  auditlens scan ./proyecto --diff-baseline .auditlens-baseline.json\n'
            '  auditlens plan ./proyecto --empresa "MiEmpresa" --sistema "SistemaX v1.0"\n'
            '  auditlens plan ./proyecto --output plan_auditoria.docx\n'
            '  auditlens serve ./proyecto\n'
            '  auditlens serve ./proyecto --port 8080 --scan-first\n'
            '  auditlens watch-repo ./proyecto\n'
            '  auditlens history ./proyecto\n'
            '  auditlens run script.py\n'
            '  auditlens watch app.log\n'
            '  auditlens watch-xcode\n'
        ),
    )
    parser.add_argument('--version', action='version', version=f'auditlens {__version__}')

    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')

    # ── scan ─────────────────────────────────────────────────────────────────
    sp = subparsers.add_parser('scan', help='Ejecutar SAST + SCA + Taint analysis.')
    sp.add_argument('path', help='Directorio o archivo a escanear.')
    sp.add_argument(
        '--format', choices=['text', 'sarif', 'pdf', 'json', 'docx'], default='text',
        help='Formato de salida (default: text). docx genera informe Word completo.',
    )
    sp.add_argument('--output', '-o', default=None, help='Ruta del archivo de salida.')
    sp.add_argument(
        '--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW',
        help='Severidad mínima a reportar (default: LOW).',
    )
    sp.add_argument('--no-sca', dest='no_sca', action='store_true',
                    help='Omitir SCA — más rápido para escaneos solo SAST.')
    sp.add_argument('--save-baseline', metavar='FILE',
                    help='Guardar hallazgos como baseline.')
    sp.add_argument('--diff-baseline', metavar='FILE',
                    help='Solo reportar hallazgos nuevos vs este baseline.')
    sp.add_argument('--no-history', dest='no_history', action='store_true',
                    help='No persistir este escaneo en la base de datos de historial.')
    sp.add_argument('--interprocedural', action='store_true',
                    help='Habilitar análisis de taint entre archivos (más lento, más preciso).')
    # Audit report metadata
    sp.add_argument('--empresa', default='Empresa', help='Nombre de la empresa (para informe Word).')
    sp.add_argument('--sistema', default='Sistema de Software', help='Nombre del sistema auditado.')
    sp.add_argument('--auditor', default='[Auditor por asignar]', help='Nombre del auditor líder.')
    sp.add_argument('--trimestre', default='primer trimestre de 2025',
                    help='Período de la auditoría.')

    # ── plan ─────────────────────────────────────────────────────────────────
    pp = subparsers.add_parser(
        'plan',
        help='Generar documento de planificación de auditoría (Word/PDF).',
    )
    pp.add_argument('path', help='Directorio del proyecto a planificar.')
    pp.add_argument('--empresa', default='Empresa', help='Nombre de la empresa.')
    pp.add_argument('--sistema', default='Sistema de Software', help='Nombre del sistema.')
    pp.add_argument('--auditor', default='[Auditor por asignar]', help='Auditor líder.')
    pp.add_argument('--trimestre', default='primer trimestre de 2025',
                    help='Período de la auditoría.')
    pp.add_argument('--output', '-o', default='plan_auditoria.docx',
                    help='Archivo de salida (default: plan_auditoria.docx).')
    pp.add_argument('--no-sca', dest='no_sca', action='store_true',
                    help='Omitir SCA en el análisis previo.')

    # ── serve ─────────────────────────────────────────────────────────────────
    svp = subparsers.add_parser('serve', help='Iniciar el dashboard web (requiere flask).')
    svp.add_argument('path', help='Directorio del proyecto a visualizar.')
    svp.add_argument('--port', type=int, default=8080, help='Puerto (default: 8080).')
    svp.add_argument('--host', default='127.0.0.1', help='Host (default: 127.0.0.1).')
    svp.add_argument('--no-browser', dest='no_browser', action='store_true',
                     help='No abrir el browser automáticamente.')
    svp.add_argument('--scan-first', dest='scan_first', action='store_true',
                     help='Ejecutar un escaneo antes de abrir el dashboard.')

    # ── watch-repo ────────────────────────────────────────────────────────────
    wrp = subparsers.add_parser('watch-repo', help='Re-escanear archivos al cambiar.')
    wrp.add_argument('path', help='Directorio del proyecto a monitorear.')
    wrp.add_argument(
        '--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW',
        help='Severidad mínima (default: LOW).',
    )
    wrp.add_argument('--no-sca', dest='no_sca', action='store_true',
                     help='Omitir SCA en cada cambio.')

    # ── run ───────────────────────────────────────────────────────────────────
    rp = subparsers.add_parser('run', help='Ejecutar script Python con diagnóstico Post-Mortem.')
    rp.add_argument('script', help='Script Python a ejecutar.')
    rp.add_argument('args', nargs=argparse.REMAINDER, help='Argumentos para el script.')

    # ── watch ─────────────────────────────────────────────────────────────────
    wp = subparsers.add_parser('watch', help='Monitorear archivo de log en tiempo real.')
    wp.add_argument('logfile', help='Ruta del archivo de log.')

    # ── watch-xcode ───────────────────────────────────────────────────────────
    subparsers.add_parser('watch-xcode', help='Monitorear logs del Simulador iOS (macOS + Xcode).')

    # ── history ───────────────────────────────────────────────────────────────
    hp = subparsers.add_parser('history', help='Mostrar historial de escaneos.')
    hp.add_argument('path', help='Ruta del proyecto.')
    hp.add_argument('--limit', type=int, default=10, help='Número de escaneos a mostrar.')

    args = parser.parse_args()

    if args.command == 'scan':
        exit_code = run_static_analysis(
            args.path,
            export_sarif=(args.format == 'sarif'),
            export_pdf=(args.format == 'pdf'),
            export_json=(args.format == 'json'),
            export_docx=(args.format == 'docx'),
            output_path=args.output,
            min_severity=args.severity,
            run_sca=not args.no_sca,
            save_baseline=args.save_baseline,
            diff_baseline=args.diff_baseline,
            record_history=not args.no_history,
            interprocedural=getattr(args, 'interprocedural', False),
            empresa=getattr(args, 'empresa', 'Empresa'),
            sistema=getattr(args, 'sistema', 'Sistema de Software'),
            auditor=getattr(args, 'auditor', '[Auditor por asignar]'),
            trimestre=getattr(args, 'trimestre', 'primer trimestre de 2025'),
        )
        sys.exit(exit_code)

    elif args.command == 'plan':
        _run_plan_command(args)

    elif args.command == 'serve':
        from .dashboard import serve_dashboard
        serve_dashboard(
            scan_path=args.path,
            port=args.port,
            host=args.host,
            open_browser=not args.no_browser,
            scan_first=args.scan_first,
        )

    elif args.command == 'watch-repo':
        from .watcher import watch_repo
        watch_repo(
            root_path=args.path,
            min_severity=args.severity,
            run_sca=not args.no_sca,
        )

    elif args.command == 'run':
        run_script_with_hook(args.script, args.args)

    elif args.command == 'watch':
        watch_log_file(args.logfile)

    elif args.command == 'watch-xcode':
        if platform.system() != 'Darwin':
            print('\033[91m[ERROR]\033[0m watch-xcode requiere macOS con Xcode instalado.')
            sys.exit(1)
        watch_xcode_simulator()

    elif args.command == 'history':
        from .history import print_history
        print_history(args.path, limit=args.limit)

    else:
        parser.print_help()


def _run_plan_command(args):
    """Execute the 'plan' subcommand."""
    from .analyzer import run_static_analysis
    from .audit_planner import generate_audit_plan
    from .docx_exporter import generate_docx_report

    print(f'\033[94m[AuditLens Plan]\033[0m Iniciando planificación de auditoría...\n')

    # Run a quick scan first to get findings for context
    print('\033[94m[AuditLens Plan]\033[0m Ejecutando análisis previo del proyecto...')
    findings_acc: list = []

    run_static_analysis(
        args.path,
        run_sca=not args.no_sca,
        record_history=False,
        min_severity='LOW',
    )

    # Re-run collecting findings
    from .rules_engine import RulesEngine
    from .taint_analyzer import TaintAnalyzer
    from .analyzer import analyze_file, _SUPPORTED_EXTENSIONS
    import os

    rules_engine = RulesEngine()
    taint_analyzer = TaintAnalyzer()
    exclude_dirs = {'venv', '.venv', 'env', '.env', 'node_modules', '.git', '__pycache__', 'build', 'dist'}

    for dirpath, dirnames, files in os.walk(args.path):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in _SUPPORTED_EXTENSIONS:
                analyze_file(
                    os.path.join(dirpath, fname),
                    rules_engine, taint_analyzer,
                    min_severity='LOW',
                    all_findings_accumulator=findings_acc,
                )

    # Generate plan
    plan = generate_audit_plan(
        root_path=args.path,
        findings=findings_acc,
        empresa=args.empresa,
        sistema=args.sistema,
        trimestre=args.trimestre,
        auditor=args.auditor,
    )

    output = args.output
    if output.endswith('.docx') or not output.endswith('.pdf'):
        if not output.endswith('.docx'):
            output = output + '.docx'
        try:
            generate_docx_report(
                findings=findings_acc,
                scan_path=args.path,
                output_path=output,
                empresa=args.empresa,
                sistema=args.sistema,
                auditor=args.auditor,
                trimestre=args.trimestre,
                plan=plan,
            )
        except ImportError as e:
            print(f'\033[91m[ERROR]\033[0m {e}')
            print('Instala con: pip install python-docx --break-system-packages')
            sys.exit(1)
    else:
        print(f'\033[93m[AuditLens Plan]\033[0m Formato PDF para plan no soportado aún. Usa .docx')

    # Print summary
    print(f'\n\033[92m[AuditLens Plan]\033[0m Planificación completada.')
    print(f'   Proyecto: \033[1m{args.path}\033[0m')
    print(f'   Sistema: {args.sistema}')
    print(f'   Empresa: {args.empresa}')
    print(f'   Hallazgos analizados: {len(findings_acc)}')
    print(f'   Módulos detectados: {len(plan.get("resumen_proyecto", {}).get("modulos", []))}')


if __name__ == '__main__':
    main()
