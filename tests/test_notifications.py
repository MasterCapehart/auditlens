"""
Tests for notifications module (Slack/JIRA).
"""
from __future__ import annotations
import pytest
from auditlens.notifications import (
    _resolve_env,
    _build_slack_payload,
    _jira_priority,
    _build_jira_description,
)


def _finding(severity='HIGH', rule_id='SEC-01'):
    return {
        'rule_id': rule_id, 'name': 'Test Finding',
        'description': 'A test vulnerability description.',
        'file': '/project/app.py', 'line': 42,
        'severity': severity, 'compliance': ['OWASP-A7:2021', 'CWE-798'],
    }


# ── _resolve_env ──────────────────────────────────────────────────────────────
def test_resolve_env_replaces_env_var(monkeypatch):
    monkeypatch.setenv('MY_SECRET', 'abc123')
    assert _resolve_env('${MY_SECRET}') == 'abc123'


def test_resolve_env_leaves_unknown_as_is():
    result = _resolve_env('${NONEXISTENT_12345}')
    assert result == '${NONEXISTENT_12345}'


def test_resolve_env_plain_string():
    assert _resolve_env('https://hooks.slack.com/xxx') == 'https://hooks.slack.com/xxx'


# ── Slack payload ─────────────────────────────────────────────────────────────
def test_slack_payload_returns_none_when_no_findings():
    result = _build_slack_payload([], '/project', 'HIGH')
    assert result is None


def test_slack_payload_returns_none_below_threshold():
    findings = [_finding('LOW')]
    result = _build_slack_payload(findings, '/project', 'HIGH')
    assert result is None


def test_slack_payload_returns_blocks_for_matching():
    findings = [_finding('CRITICAL'), _finding('HIGH')]
    result = _build_slack_payload(findings, '/project', 'HIGH')
    assert result is not None
    assert 'blocks' in result
    assert len(result['blocks']) >= 3  # header + section + divider


def test_slack_payload_limits_to_5_findings():
    findings = [_finding('CRITICAL')] * 10
    result = _build_slack_payload(findings, '/project', 'CRITICAL')
    assert result is not None
    # Should have a "...and N more" context block
    block_types = [b['type'] for b in result['blocks']]
    assert 'context' in block_types


# ── JIRA priority ─────────────────────────────────────────────────────────────
def test_jira_priority_mapping():
    assert _jira_priority('CRITICAL') == 'Highest'
    assert _jira_priority('HIGH') == 'High'
    assert _jira_priority('MEDIUM') == 'Medium'
    assert _jira_priority('LOW') == 'Low'
    assert _jira_priority('UNKNOWN') == 'Medium'  # fallback


# ── JIRA description ─────────────────────────────────────────────────────────
def test_jira_description_contains_key_fields():
    f = _finding()
    desc = _build_jira_description(f)
    assert 'SEC-01' in desc
    assert 'app.py' in desc
    assert 'AuditLens' in desc
    assert 'OWASP-A7:2021' in desc
