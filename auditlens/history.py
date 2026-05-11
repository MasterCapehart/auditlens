"""
AuditLens Scan History — SQLite-backed persistent scan records.

Enables trend tracking, diff-by-commit, and executive dashboards.

Usage:
    auditlens history ./my_project          # show trend over last 10 scans
    auditlens history ./my_project --limit 5
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import List, Optional

_DEFAULT_DB = os.path.join(os.path.expanduser('~'), '.auditlens', 'history.db')

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at  TEXT    NOT NULL,
    scan_path   TEXT    NOT NULL,
    git_commit  TEXT,
    total       INTEGER NOT NULL DEFAULT 0,
    critical    INTEGER NOT NULL DEFAULT 0,
    high        INTEGER NOT NULL DEFAULT 0,
    medium      INTEGER NOT NULL DEFAULT 0,
    low         INTEGER NOT NULL DEFAULT 0,
    findings_json TEXT  NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_scan_path ON scans(scan_path);
"""


def _db_path() -> str:
    return os.environ.get('AUDITLENS_DB', _DEFAULT_DB)


def _get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = db_path or _db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def _git_commit(scan_path: str) -> Optional[str]:
    """Try to get the current HEAD commit hash for the scan path."""
    try:
        import subprocess
        result = subprocess.run(
            ['git', 'rev-parse', '--short', 'HEAD'],
            cwd=scan_path if os.path.isdir(scan_path) else os.path.dirname(scan_path),
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def record_scan(
    scan_path: str,
    findings: List[dict],
    db_path: Optional[str] = None,
) -> int:
    """
    Persist a completed scan to the history database.
    Returns the new scan ID.
    """
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.get('severity', 'LOW').upper()
        if sev in counts:
            counts[sev] += 1

    conn = _get_connection(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO scans
              (scanned_at, scan_path, git_commit, total, critical, high, medium, low, findings_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                os.path.abspath(scan_path),
                _git_commit(scan_path),
                len(findings),
                counts['CRITICAL'],
                counts['HIGH'],
                counts['MEDIUM'],
                counts['LOW'],
                json.dumps(findings),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_history(
    scan_path: str,
    limit: int = 10,
    db_path: Optional[str] = None,
) -> List[dict]:
    """Return the last `limit` scans for the given path."""
    conn = _get_connection(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, scanned_at, git_commit, total, critical, high, medium, low
            FROM scans
            WHERE scan_path = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (os.path.abspath(scan_path), limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def print_history(scan_path: str, limit: int = 10, db_path: Optional[str] = None) -> None:
    """Pretty-print scan history for a project path."""
    rows = get_history(scan_path, limit, db_path)
    if not rows:
        print(f"\033[93m[AuditLens] No scan history for: {scan_path}\033[0m")
        return

    print(f"\n\033[94m[AuditLens]\033[0m Scan history for: \033[1m{scan_path}\033[0m")
    print(f"  {'#':<4} {'Date':<20} {'Commit':<10} {'Total':>6} {'CRIT':>6} {'HIGH':>6} {'MED':>6} {'LOW':>6}")
    print("  " + "─" * 68)

    for r in reversed(rows):  # oldest first for trend reading
        commit = r['git_commit'] or '─' * 7
        crit = r['critical']
        high = r['high']
        total = r['total']
        crit_color = '\033[91m' if crit > 0 else '\033[0m'
        high_color = '\033[91m' if high > 0 else '\033[0m'
        print(
            f"  {r['id']:<4} {r['scanned_at'][:19]:<20} {commit:<10} "
            f"{total:>6} "
            f"{crit_color}{crit:>6}\033[0m "
            f"{high_color}{high:>6}\033[0m "
            f"\033[93m{r['medium']:>6}\033[0m "
            f"\033[90m{r['low']:>6}\033[0m"
        )
    print()
