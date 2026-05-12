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
        description='AuditLens — SAST, SCA, Taint Analysis and Post-Mortem diagnostics.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  auditlens scan ./src\n'
            '  auditlens scan ./src --format sarif -o results.sarif\n'
            '  auditlens scan ./src --format json -o results.json\n'
            '  auditlens scan ./src --severity HIGH --no-sca\n'
            '  auditlens scan ./src --save-baseline .auditlens-baseline.json\n'
            '  auditlens scan ./src --diff-baseline .auditlens-baseline.json\n'
            '  auditlens scan ./src --interprocedural\n'
            '  auditlens serve ./src\n'
            '  auditlens serve ./src --port 8080 --scan-first\n'
            '  auditlens watch-repo ./src\n'
            '  auditlens watch-repo ./src --severity HIGH\n'
            '  auditlens history ./src\n'
            '  auditlens run script.py\n'
            '  auditlens watch app.log\n'
            '  auditlens watch-xcode\n'
        ),
    )
    parser.add_argument('--version', action='version', version=f'auditlens {__version__}')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # ── scan ─────────────────────────────────────────────────────────────────
    sp = subparsers.add_parser('scan', help='Run SAST + SCA + Taint analysis.')
    sp.add_argument('path', help='Directory or file to scan.')
    sp.add_argument(
        '--format', choices=['text', 'sarif', 'pdf', 'json'], default='text',
        help='Output format (default: text).',
    )
    sp.add_argument('--output', '-o', default=None, help='Output file path.')
    sp.add_argument(
        '--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW',
        help='Minimum severity to report (default: LOW).',
    )
    sp.add_argument('--no-sca', dest='no_sca', action='store_true',
                    help='Skip SCA — faster for SAST-only scans.')
    sp.add_argument('--save-baseline', metavar='FILE',
                    help='Save findings as baseline.')
    sp.add_argument('--diff-baseline', metavar='FILE',
                    help='Only report new findings vs this baseline.')
    sp.add_argument('--no-history', dest='no_history', action='store_true',
                    help='Do not persist this scan to the history database.')
    sp.add_argument('--interprocedural', action='store_true',
                    help='Enable cross-file taint analysis (slower, more accurate).')

    # ── serve ─────────────────────────────────────────────────────────────────
    svp = subparsers.add_parser('serve', help='Start the web dashboard (requires flask).')
    svp.add_argument('path', help='Project path to visualize.')
    svp.add_argument('--port', type=int, default=8080, help='Port to listen on (default: 8080).')
    svp.add_argument('--host', default='127.0.0.1', help='Host to bind (default: 127.0.0.1).')
    svp.add_argument('--no-browser', dest='no_browser', action='store_true',
                     help='Do not open browser automatically.')
    svp.add_argument('--scan-first', dest='scan_first', action='store_true',
                     help='Run a fresh scan before opening the dashboard.')

    # ── watch-repo ────────────────────────────────────────────────────────────
    wrp = subparsers.add_parser('watch-repo', help='Re-scan files on change.')
    wrp.add_argument('path', help='Project directory to watch.')
    wrp.add_argument(
        '--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW',
        help='Minimum severity to report (default: LOW).',
    )
    wrp.add_argument('--no-sca', dest='no_sca', action='store_true',
                     help='Skip SCA on each file change.')

    # ── run ───────────────────────────────────────────────────────────────────
    rp = subparsers.add_parser('run', help='Run a Python script with Post-Mortem diagnostics.')
    rp.add_argument('script', help='Python script to execute.')
    rp.add_argument('args', nargs=argparse.REMAINDER, help='Arguments for the script.')

    # ── watch ─────────────────────────────────────────────────────────────────
    wp = subparsers.add_parser('watch', help='Monitor a log file in real time.')
    wp.add_argument('logfile', help='Path to the log file.')

    # ── watch-xcode ───────────────────────────────────────────────────────────
    subparsers.add_parser('watch-xcode', help='Monitor iOS Simulator logs (macOS + Xcode).')

    # ── history ───────────────────────────────────────────────────────────────
    hp = subparsers.add_parser('history', help='Show scan history trend for a path.')
    hp.add_argument('path', help='Project path to show history for.')
    hp.add_argument('--limit', type=int, default=10, help='Number of past scans (default: 10).')

    args = parser.parse_args()

    if args.command == 'scan':
        exit_code = run_static_analysis(
            args.path,
            export_sarif=(args.format == 'sarif'),
            export_pdf=(args.format == 'pdf'),
            export_json=(args.format == 'json'),
            output_path=args.output,
            min_severity=args.severity,
            run_sca=not args.no_sca,
            save_baseline=args.save_baseline,
            diff_baseline=args.diff_baseline,
            record_history=not args.no_history,
            interprocedural=getattr(args, 'interprocedural', False),
        )
        sys.exit(exit_code)

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
            print('\033[91m[ERROR]\033[0m watch-xcode requires macOS with Xcode installed.')
            sys.exit(1)
        watch_xcode_simulator()

    elif args.command == 'history':
        from .history import print_history
        print_history(args.path, limit=args.limit)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
