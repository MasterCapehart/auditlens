"""
AuditLens Repo Watcher — continuous re-scan on file changes.

Usage:
    auditlens watch-repo ./my_project
    auditlens watch-repo ./my_project --severity HIGH --no-sca

Uses watchdog (if available) or falls back to polling.
Re-scans only the changed file, then updates the running summary.
"""

from __future__ import annotations

import os
import sys
import time
import threading
from typing import Optional, Set

_SUPPORTED_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.swift', '.go', '.java', '.kt', '.rb'}


def _scan_file(file_path: str, min_severity: str = 'LOW', run_sca: bool = False) -> list:
    """Run a quick single-file scan and return findings."""
    from .rules_engine import RulesEngine
    from .taint_analyzer import TaintAnalyzer
    from .analyzer import analyze_file

    rules_engine = RulesEngine()
    taint = TaintAnalyzer()
    accumulator: list = []

    analyze_file(
        file_path,
        rules_engine,
        taint,
        min_severity=min_severity,
        all_findings_accumulator=accumulator,
    )
    return accumulator


class _WatchState:
    """Shared mutable state for the watcher."""

    def __init__(self):
        self.findings_by_file: dict = {}
        self.lock = threading.Lock()
        self.last_event: Optional[str] = None

    def update(self, file_path: str, findings: list):
        with self.lock:
            if findings:
                self.findings_by_file[file_path] = findings
            else:
                self.findings_by_file.pop(file_path, None)

    @property
    def total(self) -> int:
        with self.lock:
            return sum(len(v) for v in self.findings_by_file.values())

    def summary(self) -> dict:
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        with self.lock:
            for findings in self.findings_by_file.values():
                for f in findings:
                    sev = f['severity'].upper()
                    if sev in counts:
                        counts[sev] += 1
        return counts


def _print_status(state: _WatchState, changed_file: Optional[str] = None):
    counts = state.summary()
    if changed_file:
        short = '/'.join(changed_file.split('/')[-2:])
        print(f'\r\033[94m[AuditLens Watch]\033[0m Changed: \033[1m{short}\033[0m', end='  ')
    crit_c = f'\033[91m{counts["CRITICAL"]}\033[0m' if counts['CRITICAL'] else '0'
    high_c = f'\033[91m{counts["HIGH"]}\033[0m' if counts['HIGH'] else '0'
    med_c  = f'\033[93m{counts["MEDIUM"]}\033[0m' if counts['MEDIUM'] else '0'
    print(
        f'\r\033[94m[AuditLens Watch]\033[0m Total: {state.total}  '
        f'CRIT:{crit_c}  HIGH:{high_c}  MED:{med_c}  LOW:{counts["LOW"]}     ',
        end='',
    )
    sys.stdout.flush()


def _handle_change(file_path: str, state: _WatchState, min_severity: str):
    """Called when a file is created or modified."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in _SUPPORTED_EXTENSIONS:
        return

    try:
        findings = _scan_file(file_path, min_severity=min_severity)
        state.update(file_path, findings)

        # Print new findings inline
        if findings:
            print()  # new line after status bar
            for f in findings:
                color = '\033[91m' if f['severity'] in ('CRITICAL', 'HIGH') else '\033[93m'
                short = '/'.join(f['file'].split('/')[-2:])
                print(f"  {color}[{f['rule_id']}] {short}:{f['line']} — {f['name']}\033[0m")

        _print_status(state, file_path)
    except Exception as exc:
        print(f'\n\033[93m[AuditLens Watch] Error scanning {file_path}: {exc}\033[0m')


# ── Watchdog-based watcher ────────────────────────────────────────────────────

def _watch_with_watchdog(
    root_path: str,
    state: _WatchState,
    min_severity: str,
    exclude_dirs: Set[str],
):
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    class _Handler(FileSystemEventHandler):
        def _process(self, event):
            if event.is_directory:
                return
            parts = event.src_path.split(os.sep)
            if any(d in exclude_dirs for d in parts):
                return
            _handle_change(event.src_path, state, min_severity)

        def on_modified(self, event): self._process(event)
        def on_created(self, event):  self._process(event)

    observer = Observer()
    observer.schedule(_Handler(), root_path, recursive=True)
    observer.start()
    return observer


# ── Polling fallback ──────────────────────────────────────────────────────────

def _watch_with_polling(
    root_path: str,
    state: _WatchState,
    min_severity: str,
    exclude_dirs: Set[str],
    interval: float = 1.5,
):
    """Pure-Python polling watcher — no dependencies."""
    mtimes: dict = {}

    def _collect():
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext in _SUPPORTED_EXTENSIONS:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        yield fpath, os.path.getmtime(fpath)
                    except OSError:
                        pass

    # Initial snapshot
    for fpath, mtime in _collect():
        mtimes[fpath] = mtime

    while True:
        time.sleep(interval)
        for fpath, mtime in _collect():
            old = mtimes.get(fpath)
            if old is None or mtime > old:
                mtimes[fpath] = mtime
                _handle_change(fpath, state, min_severity)


# ── Public entry point ────────────────────────────────────────────────────────

def watch_repo(
    root_path: str,
    min_severity: str = 'LOW',
    run_sca: bool = False,
    poll_interval: float = 1.5,
):
    """
    Watch a project directory and re-scan files on change.
    Uses watchdog if installed, otherwise falls back to polling.
    """
    abs_path = os.path.abspath(root_path)
    if not os.path.isdir(abs_path):
        print(f'\033[91m[ERROR]\033[0m Not a directory: {abs_path}')
        sys.exit(1)

    exclude_dirs = {
        'venv', 'env', '.env', '.git', '__pycache__',
        'node_modules', 'build', 'dist', '.tox',
    }

    state = _WatchState()

    print(f'\033[94m[AuditLens Watch]\033[0m Watching: \033[1m{abs_path}\033[0m')
    print(f'\033[94m[AuditLens Watch]\033[0m Min severity: {min_severity} | Press Ctrl+C to stop\n')

    # Initial full scan
    print('\033[90mRunning initial scan...\033[0m')
    for dirpath, dirnames, filenames in os.walk(abs_path):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in _SUPPORTED_EXTENSIONS:
                fpath = os.path.join(dirpath, fname)
                findings = _scan_file(fpath, min_severity=min_severity)
                state.update(fpath, findings)

    _print_status(state)

    try:
        try:
            from watchdog.observers import Observer  # noqa: F401
            print(f'\n\033[90m(using watchdog — real-time events)\033[0m')
            observer = _watch_with_watchdog(abs_path, state, min_severity, exclude_dirs)
            try:
                while True:
                    time.sleep(1)
            finally:
                observer.stop()
                observer.join()
        except ImportError:
            print(f'\n\033[90m(watchdog not installed — using polling every {poll_interval}s)\033[0m')
            print('\033[90mTip: pip install watchdog  for real-time file events\033[0m\n')
            _watch_with_polling(abs_path, state, min_severity, exclude_dirs, poll_interval)

    except KeyboardInterrupt:
        print(f'\n\n\033[92m[AuditLens Watch]\033[0m Stopped. Final: {state.total} findings.')
