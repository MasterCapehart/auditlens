"""
AuditLens CLI entry point.

Changes vs original:
- MISSING-01: propagates exit code from run_static_analysis
- MISSING-02: --output flag for SARIF/PDF
- MISSING-04: --severity filter
- MISSING-06: --version flag
- UX-04: platform guard for watch-xcode
"""

import argparse
import sys
import platform
from . import __version__
from .analyzer import run_static_analysis
from .runner import run_script_with_hook
from .log_watcher import watch_log_file, watch_xcode_simulator


def main():
    parser = argparse.ArgumentParser(
        description="AuditLens — SAST, SCA, Taint Analysis and Post-Mortem diagnostics.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  auditlens scan ./my_project\n"
            "  auditlens scan ./my_project --format sarif --output results.sarif\n"
            "  auditlens scan ./my_project --severity HIGH\n"
            "  auditlens scan ./my_project --no-sca\n"
            "  auditlens run script.py\n"
            "  auditlens watch app.log\n"
            "  auditlens watch-xcode\n"
        ),
    )

    # MISSING-06 FIX: --version flag
    parser.add_argument(
        '--version', action='version',
        version=f'auditlens {__version__}',
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # ── scan ──────────────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser(
        'scan',
        help='Run static analysis (SAST + SCA + Taint) on a directory or file.',
    )
    scan_parser.add_argument(
        'path', type=str,
        help='Path to the directory or file to scan.',
    )
    scan_parser.add_argument(
        '--format', type=str,
        choices=['text', 'sarif', 'pdf'],
        default='text',
        help='Output report format (default: text).',
    )
    # MISSING-02 FIX: --output flag
    scan_parser.add_argument(
        '--output', '-o', type=str, default=None,
        help='Output file path for SARIF or PDF reports.',
    )
    # MISSING-04 FIX: --severity filter
    scan_parser.add_argument(
        '--severity', type=str,
        choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        default='LOW',
        help='Minimum severity level to report (default: LOW).',
    )
    # PERF-01 FIX: opt-out of SCA for fast scans
    scan_parser.add_argument(
        '--no-sca', dest='no_sca', action='store_true',
        help='Skip Software Composition Analysis (SCA) — faster for SAST-only scans.',
    )

    # ── run ───────────────────────────────────────────────────────────────────
    run_parser = subparsers.add_parser(
        'run',
        help='Execute a Python script with Post-Mortem diagnostics.',
    )
    run_parser.add_argument(
        'script', type=str,
        help='Path to the Python script to execute.',
    )
    run_parser.add_argument(
        'args', nargs=argparse.REMAINDER,
        help='Additional arguments forwarded to the script.',
    )

    # ── watch ─────────────────────────────────────────────────────────────────
    watch_parser = subparsers.add_parser(
        'watch',
        help='Monitor a log file in real time for error signatures.',
    )
    watch_parser.add_argument(
        'logfile', type=str,
        help='Path to the log file to watch.',
    )

    # ── watch-xcode ───────────────────────────────────────────────────────────
    subparsers.add_parser(
        'watch-xcode',
        help='Monitor the active iOS Simulator log stream (macOS + Xcode only).',
    )

    args = parser.parse_args()

    if args.command == 'scan':
        export_sarif = args.format == 'sarif'
        export_pdf = args.format == 'pdf'
        exit_code = run_static_analysis(
            args.path,
            export_sarif=export_sarif,
            export_pdf=export_pdf,
            output_path=args.output,
            min_severity=args.severity,
            run_sca=not args.no_sca,
        )
        sys.exit(exit_code)

    elif args.command == 'run':
        run_script_with_hook(args.script, args.args)

    elif args.command == 'watch':
        watch_log_file(args.logfile)

    elif args.command == 'watch-xcode':
        # UX-04 FIX: platform guard
        if platform.system() != 'Darwin':
            print(
                '\033[91m[ERROR]\033[0m watch-xcode is only available on macOS '
                'with Xcode installed.'
            )
            sys.exit(1)
        watch_xcode_simulator()

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
