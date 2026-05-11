"""
Tests for RulesEngine.
Covers CQ-07 (invalid regex), rule loading, language filtering.
"""
import os
import tempfile
import pytest
from auditlens.rules_engine import RulesEngine, Rule


def _make_rules_file(content: str) -> str:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as fh:
        fh.write(content)
    return fh.name


# ── Basic rule loading ────────────────────────────────────────────────────────
def test_loads_valid_rules():
    yaml_content = (
        "rules:\n"
        "  - id: \"TEST-01\"\n"
        "    name: \"Test Rule\"\n"
        "    description: \"A test rule\"\n"
        "    languages: [\"python\"]\n"
        "    regex_pattern: \"bad_function\\\\(\"\n"
        "    compliance: [\"CWE-123\"]\n"
        "    severity: \"HIGH\"\n"
    )
    path = _make_rules_file(yaml_content)
    try:
        engine = RulesEngine(rules_file=path)
        assert len(engine.rules) == 1
        assert engine.rules[0].id == 'TEST-01'
    finally:
        os.unlink(path)


def test_rule_matches_text():
    rule = Rule({
        'id': 'T1', 'name': 'T', 'description': '', 'languages': ['python'],
        'regex_pattern': r'password\s*=', 'compliance': [], 'severity': 'HIGH',
    })
    assert rule.match_text('password = "foo"')
    assert not rule.match_text('username = "foo"')


# ── CQ-07: invalid regex does NOT crash engine ────────────────────────────────
def test_invalid_regex_does_not_crash(capsys):
    yaml_content = (
        "rules:\n"
        "  - id: \"BAD-REGEX\"\n"
        "    name: \"Bad Regex\"\n"
        "    description: \"has invalid regex\"\n"
        "    languages: [\"python\"]\n"
        "    regex_pattern: \"(?P<invalid\"\n"
        "    compliance: []\n"
        "    severity: \"LOW\"\n"
        "  - id: \"GOOD-01\"\n"
        "    name: \"Good\"\n"
        "    description: \"\"\n"
        "    languages: [\"python\"]\n"
        "    regex_pattern: \"print\\\\(\"\n"
        "    compliance: []\n"
        "    severity: \"LOW\"\n"
    )
    path = _make_rules_file(yaml_content)
    try:
        engine = RulesEngine(rules_file=path)
        # Bad regex rule loads but its _compiled_regex is None — should be disabled
        bad = next(r for r in engine.rules if r.id == 'BAD-REGEX')
        assert bad._compiled_regex is None
        # Good rule still works
        good = next(r for r in engine.rules if r.id == 'GOOD-01')
        assert good.match_text('print("hello")')
    finally:
        os.unlink(path)


# ── Language filtering ────────────────────────────────────────────────────────
def test_get_rules_for_language():
    yaml_content = (
        "rules:\n"
        "  - id: \"PY-01\"\n"
        "    name: \"Python only\"\n"
        "    description: \"\"\n"
        "    languages: [\"python\"]\n"
        "    regex_pattern: \"foo\"\n"
        "    compliance: []\n"
        "    severity: \"LOW\"\n"
        "  - id: \"JS-01\"\n"
        "    name: \"JS only\"\n"
        "    description: \"\"\n"
        "    languages: [\"javascript\"]\n"
        "    regex_pattern: \"bar\"\n"
        "    compliance: []\n"
        "    severity: \"LOW\"\n"
    )
    path = _make_rules_file(yaml_content)
    try:
        engine = RulesEngine(rules_file=path)
        py_rules = engine.get_rules_for_language('.py')
        js_rules = engine.get_rules_for_language('.js')
        assert all(r.id == 'PY-01' for r in py_rules)
        assert all(r.id == 'JS-01' for r in js_rules)
    finally:
        os.unlink(path)


def test_missing_rules_file_returns_empty_engine():
    engine = RulesEngine(rules_file='/nonexistent/path/rules.yaml')
    assert engine.rules == []
