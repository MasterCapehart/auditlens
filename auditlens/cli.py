"""
AuditLens CLI entry point.

New flags:
- --format json (T2-3)
- --save-baseline / --diff-baseline (T1-2)
- --config (T1-5)
- history subcommand (T3-3)
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
    sp.add_argument(
        '--save-baseline', metavar='FILE',
        help='Save current findings as baseline for future --diff-baseline runs.',
    )
    sp.add_argument(
        '--diff-baseline', metavar='FILE',
        help='Only report findings NOT in this baseline (new findings only).',
    )
    sp.add_argument(
        '--no-history', dest='no_history', action='store_true',
        help='Do not persist this scan to the history database.',
    )

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
    hp.add_argument('--limit', type=int, default=10, help='Number of past scans to show.')

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
        )
        sys.exit(exit_code)

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
