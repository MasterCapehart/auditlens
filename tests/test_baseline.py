"""
Tests for the Baseline engine (T1-2).
"""
from __future__ import annotations

import json
import os
import pytest
from auditlens.baseline import save_baseline, load_baseline, diff_against_baseline, _fingerprint


def _make_finding(rule_id='SEC-01', file='app.py', line=5, severity='HIGH', line_content='password = "secret"'):
    return {
        'rule_id': rule_id, 'name': 'Test', 'description': 'desc',
        'file': file, 'line': line, 'severity': severity,
        'compliance': [], 'line_content': line_content,
    }


def test_fingerprint_is_stable():
    f = _make_finding()
    assert _fingerprint(f) == _fingerprint(f)


def test_fingerprint_differs_by_rule():
    f1 = _make_finding(rule_id='SEC-01')
    f2 = _make_finding(rule_id='SEC-02')
    assert _fingerprint(f1) != _fingerprint(f2)


def test_fingerprint_differs_by_content():
    f1 = _make_finding(line_content='password = "abc"')
    f2 = _make_finding(line_content='password = "xyz"')
    assert _fingerprint(f1) != _fingerprint(f2)


def test_save_and_load_baseline(tmp_path):
    findings = [_make_finding()]
    path = str(tmp_path / 'baseline.json')
    save_baseline(findings, path)
    assert os.path.exists(path)
    loaded = load_baseline(path)
    assert loaded is not None
    assert len(loaded) == 1


def test_load_nonexistent_baseline_returns_none(tmp_path):
    result = load_baseline(str(tmp_path / 'nonexistent.json'))
    assert result is None


def test_diff_filters_known_findings(tmp_path):
    f1 = _make_finding(rule_id='SEC-01', line_content='password = "a"')
    f2 = _make_finding(rule_id='SEC-02', line_content='token = "b"')

    path = str(tmp_path / 'baseline.json')
    save_baseline([f1], path)
    baseline = load_baseline(path)

    new_findings = diff_against_baseline([f1, f2], baseline)
    assert len(new_findings) == 1
    assert new_findings[0]['rule_id'] == 'SEC-02'


def test_diff_all_new_when_baseline_empty(tmp_path):
    f1 = _make_finding()
    baseline = {}
    result = diff_against_baseline([f1], baseline)
    assert len(result) == 1


def test_diff_all_suppressed_when_all_known(tmp_path):
    f1 = _make_finding(line_content='known = "x"')
    path = str(tmp_path / 'b.json')
    save_baseline([f1], path)
    baseline = load_baseline(path)
    result = diff_against_baseline([f1], baseline)
    assert result == []
