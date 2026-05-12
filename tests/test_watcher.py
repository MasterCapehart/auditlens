"""
Tests for the watcher module (watch-repo).
"""
from __future__ import annotations
import os
import pytest
from auditlens.watcher import _SUPPORTED_EXTENSIONS, _WatchState


def test_supported_extensions_include_new_languages():
    assert '.go' in _SUPPORTED_EXTENSIONS
    assert '.java' in _SUPPORTED_EXTENSIONS
    assert '.kt' in _SUPPORTED_EXTENSIONS
    assert '.rb' in _SUPPORTED_EXTENSIONS
    assert '.py' in _SUPPORTED_EXTENSIONS
    assert '.ts' in _SUPPORTED_EXTENSIONS


def test_watch_state_update_and_total():
    state = _WatchState()
    findings = [
        {'severity': 'HIGH', 'rule_id': 'SEC-01', 'file': 'f.py', 'line': 1,
         'name': '', 'description': '', 'compliance': []},
        {'severity': 'CRITICAL', 'rule_id': 'INJ-01', 'file': 'f.py', 'line': 5,
         'name': '', 'description': '', 'compliance': []},
    ]
    state.update('/project/app.py', findings)
    assert state.total == 2


def test_watch_state_update_clears_on_empty():
    state = _WatchState()
    findings = [{'severity': 'HIGH', 'rule_id': 'R1', 'file': 'f.py', 'line': 1,
                 'name': '', 'description': '', 'compliance': []}]
    state.update('/project/app.py', findings)
    assert state.total == 1
    state.update('/project/app.py', [])
    assert state.total == 0


def test_watch_state_summary_counts():
    state = _WatchState()
    state.update('a.py', [
        {'severity': 'CRITICAL', 'rule_id': 'R1', 'file': 'a.py', 'line': 1,
         'name': '', 'description': '', 'compliance': []},
        {'severity': 'HIGH', 'rule_id': 'R2', 'file': 'a.py', 'line': 2,
         'name': '', 'description': '', 'compliance': []},
    ])
    state.update('b.py', [
        {'severity': 'MEDIUM', 'rule_id': 'R3', 'file': 'b.py', 'line': 1,
         'name': '', 'description': '', 'compliance': []},
    ])
    summary = state.summary()
    assert summary['CRITICAL'] == 1
    assert summary['HIGH'] == 1
    assert summary['MEDIUM'] == 1
    assert summary['LOW'] == 0


def test_watch_state_multiple_files_independent():
    state = _WatchState()
    f1 = [{'severity': 'HIGH', 'rule_id': 'R1', 'file': 'a.py', 'line': 1,
            'name': '', 'description': '', 'compliance': []}]
    f2 = [{'severity': 'CRITICAL', 'rule_id': 'R2', 'file': 'b.py', 'line': 1,
            'name': '', 'description': '', 'compliance': []}]
    state.update('a.py', f1)
    state.update('b.py', f2)
    assert state.total == 2
    # Clear one file, other remains
    state.update('a.py', [])
    assert state.total == 1
