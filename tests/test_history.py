"""
Tests for scan history engine (T3-3).
"""
from __future__ import annotations

import os
import pytest
from auditlens.history import record_scan, get_history, print_history

_DB = '/var/folders/3l/6nldfwpx5nnc0wgms3cv24lh0000gn/T/opencode/test_history.db'


def _clean():
    try: os.unlink(_DB)
    except OSError: pass


def test_record_scan_creates_entry(tmp_path):
    findings = [
        {'severity': 'HIGH', 'rule_id': 'SEC-01', 'file': 'f.py', 'line': 1,
         'name': 'n', 'description': 'd', 'compliance': []},
        {'severity': 'CRITICAL', 'rule_id': 'INJ-01', 'file': 'f.py', 'line': 5,
         'name': 'n', 'description': 'd', 'compliance': []},
    ]
    db = str(tmp_path / 'hist.db')
    scan_id = record_scan('/fake/project', findings, db_path=db)
    assert scan_id == 1

    rows = get_history('/fake/project', db_path=db)
    assert len(rows) == 1
    assert rows[0]['total'] == 2
    assert rows[0]['critical'] == 1
    assert rows[0]['high'] == 1


def test_get_history_returns_newest_first(tmp_path):
    db = str(tmp_path / 'hist.db')
    record_scan('/p', [{'severity': 'HIGH', 'rule_id': 'R1', 'file': 'f', 'line': 1,
                        'name': '', 'description': '', 'compliance': []}], db_path=db)
    record_scan('/p', [], db_path=db)

    rows = get_history('/p', db_path=db)
    assert rows[0]['id'] > rows[1]['id']  # newest first


def test_get_history_respects_limit(tmp_path):
    db = str(tmp_path / 'hist.db')
    for _ in range(5):
        record_scan('/p', [], db_path=db)
    rows = get_history('/p', limit=3, db_path=db)
    assert len(rows) == 3


def test_get_history_empty_for_new_path(tmp_path):
    db = str(tmp_path / 'hist.db')
    rows = get_history('/nonexistent/path', db_path=db)
    assert rows == []


def test_print_history_no_crash(tmp_path, capsys):
    db = str(tmp_path / 'hist.db')
    record_scan('/p', [], db_path=db)
    print_history('/p', db_path=db)
    captured = capsys.readouterr()
    assert 'AuditLens' in captured.out
