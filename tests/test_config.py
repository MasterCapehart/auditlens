"""
Tests for project config (.auditlens.yaml) loading (T1-5).
"""
from __future__ import annotations

import os
import tempfile
import pytest
from auditlens.config import load_config, AuditLensConfig, _DEFAULTS


def _write_config(tmp_path, content: str) -> str:
    cfg_path = tmp_path / '.auditlens.yaml'
    cfg_path.write_text(content)
    return str(tmp_path)


def test_defaults_when_no_config_file(tmp_path):
    cfg = load_config(str(tmp_path))
    assert cfg.min_severity == _DEFAULTS['min_severity'].upper()
    assert cfg.sca == _DEFAULTS['sca']


def test_loads_min_severity(tmp_path):
    d = _write_config(tmp_path, 'min_severity: HIGH\n')
    cfg = load_config(d)
    assert cfg.min_severity == 'HIGH'


def test_loads_exclude_paths(tmp_path):
    d = _write_config(tmp_path, 'exclude_paths:\n  - tests/\n  - migrations/\n')
    cfg = load_config(d)
    assert 'tests/' in cfg.exclude_paths


def test_loads_disable_rules(tmp_path):
    d = _write_config(tmp_path, 'disable_rules:\n  - DATA-02-HARDCODED-IP\n')
    cfg = load_config(d)
    assert 'DATA-02-HARDCODED-IP' in cfg.disable_rules


def test_is_rule_disabled(tmp_path):
    d = _write_config(tmp_path, 'disable_rules:\n  - SEC-01\n')
    cfg = load_config(d)
    assert cfg.is_rule_disabled('SEC-01')
    assert not cfg.is_rule_disabled('SEC-02')


def test_is_path_excluded(tmp_path):
    d = _write_config(tmp_path, 'exclude_paths:\n  - tests/\n')
    cfg = load_config(d)
    assert cfg.is_path_excluded('tests/foo.py')
    assert not cfg.is_path_excluded('src/foo.py')


def test_fail_on_config(tmp_path):
    d = _write_config(tmp_path, 'fail_on: CRITICAL\n')
    cfg = load_config(d)
    assert cfg.fail_on == 'CRITICAL'


def test_baseline_config(tmp_path):
    d = _write_config(tmp_path, 'baseline: .auditlens-baseline.json\n')
    cfg = load_config(d)
    assert cfg.baseline == '.auditlens-baseline.json'


def test_invalid_yaml_returns_defaults(tmp_path):
    bad = tmp_path / '.auditlens.yaml'
    bad.write_text(': invalid: yaml: :\n')
    cfg = load_config(str(tmp_path))
    assert cfg.min_severity == _DEFAULTS['min_severity'].upper()
