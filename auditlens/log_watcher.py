"""
AuditLens Log Watcher — real-time log monitoring with forensic correlation.

Changes vs original:
- BUG-03: NameError when Popen fails before process is assigned
- DOC-02: removed hardcoded 'EcoAlerta' reference
- CQ-09: log file opened with explicit encoding
- UX-04: macOS guard now handled by cli.py before calling watch_xcode_simulator()
"""

import time
import re
import os
import subprocess

# Matches error signatures in Swift/iOS logs, e.g.:
#   fatal error: ... MyFile.swift line 42
#   exception in Foo.py:88
SWIFT_ERROR_REGEX = re.compile(
    r'(?i)(?:fatal error|exception|error|crash).*?'
    r'([a-zA-Z0-9_/\.-]+?\.(?:swift|py|js|ts))'
    r'.*?(?:line|:)\s*(\d+)'
)


def _find_file_in_project(filename: str, search_path: str = '.') -> str | None:
    """Resolve a bare filename or absolute path to a local project file."""
    if os.path.isabs(filename) and os.path.exists(filename):
        return filename

    base_name = os.path.basename(filename)
    for root, _, files in os.walk(search_path):
        if base_name in files:
            return os.path.join(root, base_name)
    return None


def _print_forensic_report(log_line: str, filepath: str, line_num: str):
    """Print a Post-Mortem style report extracted from a log entry."""
    print('\n' + '=' * 80)
    print('\033[91m[AuditLens] RUNTIME ERROR DETECTED IN LOGS\033[0m')
    print('=' * 80)

    print(f'\n\033[1mLog Message:\033[0m')
    print(f'   \033[93m{log_line.strip()}\033[0m')

    print(f'\n\033[1mLocation:\033[0m')
    print(f'   File: \033[96m{filepath}\033[0m')
    print(f'   Line: \033[96m{line_num}\033[0m')

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
        idx = int(line_num) - 1
        if 0 <= idx < len(lines):
            print(f'\n\033[1mCode Context:\033[0m')
            if idx > 0:
                print(f'   \033[90m{idx}: {lines[idx - 1].rstrip()}\033[0m')
            print(f'   \033[91m>> {idx + 1}: {lines[idx].rstrip()}\033[0m')
            if idx < len(lines) - 1:
                print(f'   \033[90m{idx + 2}: {lines[idx + 1].rstrip()}\033[0m')
    except Exception as exc:
        print(f'\n   \033[90m(Could not read source file: {exc})\033[0m')

    print('\n' + '=' * 80 + '\n')


def _process_log_line(line: str):
    """Scan a single log line for error signatures and correlate with source."""
    match = SWIFT_ERROR_REGEX.search(line)
    if match:
        filename = match.group(1)
        line_num = match.group(2)
        actual_path = _find_file_in_project(filename)
        if actual_path:
            _print_forensic_report(line, actual_path, line_num)
        else:
            print(
                f'\033[93m[AuditLens Watcher]\033[0m Error detected, but source file '
                f"'{filename}' was not found locally."
            )


def watch_log_file(filepath: str):
    """Python equivalent of 'tail -f' with AuditLens forensic parsing."""
    if not os.path.exists(filepath):
        print(f'\033[91m[ERROR]\033[0m Log file not found: {filepath}')
        return

    print(f'\033[94m[AuditLens Watcher]\033[0m Watching {filepath} for errors...\n')
    # CQ-09 FIX: explicit encoding
    with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
        fh.seek(0, 2)  # seek to end
        try:
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                _process_log_line(line)
        except KeyboardInterrupt:
            print('\n\033[92m[AuditLens Watcher]\033[0m Watch stopped.')


def watch_xcode_simulator():
    """
    Connect to the active iOS Simulator log stream via xcrun.
    BUG-03 FIX: process variable guarded so KeyboardInterrupt handler
    never references an unbound name.
    """
    print('\033[94m[AuditLens Xcode Watcher]\033[0m Connecting to iOS Simulator logs...')
    print('Open your app in the Simulator. Crashes will be detected in real time.\n')

    cmd = ['xcrun', 'simctl', 'spawn', 'booted', 'log', 'stream']
    process = None  # BUG-03 FIX: initialize before try block

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in iter(process.stdout.readline, ''):
            if any(
                marker in line
                for marker in ('xcrun: error:', 'No devices are booted', 'An error was encountered:')
            ):
                print(f'\033[91m[XCODE ERROR]\033[0m {line.strip()}')
            _process_log_line(line)

        process.wait()
        if process.returncode != 0:
            print(
                '\n\033[93m[AuditLens]\033[0m Watcher closed '
                '(iOS Simulator not running or was shut down).'
            )

    except FileNotFoundError:
        print(
            '\033[91m[ERROR]\033[0m xcrun not found. '
            'Make sure Xcode is installed and xcode-select --install has been run.'
        )
    except KeyboardInterrupt:
        # BUG-03 FIX: safe guard — process may be None if Popen failed
        if process is not None:
            process.terminate()
        print('\n\033[92m[AuditLens Xcode Watcher]\033[0m Watch stopped.')
