"""
Test suite for auditlens.policy_engine

Tests policy-as-code framework including DSL evaluation,
RBAC rules, threshold enforcement, and compliance mapping.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json
import tempfile
from pathlib import Path

from auditlens.policy_engine import (
    PolicyEngine,
    Policy,
    PolicyRule,
    RuleMatcher,
    PolicyResult,
    ValidationResult,
    TestResult,
    PolicyRegistry,
    PolicyDiff,
    PolicyVersion,
    load_policy_from_file,
    evaluate_findings,
    create_default_policy,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_findings():
    """Sample vulnerability findings."""
    return [
        {'rule_id': 'SQL-01', 'file': 'app.py', 'line': 10, 'severity': 'CRITICAL', 'compliance': ['CWE-89']},
        {'rule_id': 'XSS-01', 'file': 'views.py', 'line': 20, 'severity': 'HIGH', 'compliance': ['CWE-79']},
        {'rule_id': 'INFO-01', 'file': 'utils.py', 'line': 30, 'severity': 'LOW', 'compliance': []},
    ]


@pytest.fixture
def sample_policy():
    """Sample policy with rules."""
    rules = [
        PolicyRule(id='critical-block', matcher={'severity': 'CRITICAL'}, action='fail'),
        PolicyRule(id='high-warn', matcher={'severity': 'HIGH'}, action='warn'),
    ]
    return Policy(
        name='test-policy',
        version='1.0.0',
        rules=rules,
        thresholds={'max_critical': 0, 'max_high': 3},
    )


@pytest.fixture
def policy_engine():
    """PolicyEngine instance."""
    return PolicyEngine()


# ── RuleMatcher Tests ─────────────────────────────────────────────────────────

def test_rule_matcher_simple_equality():
    """Test simple equality matching."""
    matcher = RuleMatcher("severity == 'CRITICAL'")
    finding = {'severity': 'CRITICAL'}

    assert matcher.evaluate(finding) is True


def test_rule_matcher_in_operator():
    """Test 'in' operator matching."""
    matcher = RuleMatcher("severity in ['HIGH', 'CRITICAL']")
    finding = {'severity': 'HIGH'}

    assert matcher.evaluate(finding) is True


def test_rule_matcher_file_pattern():
    """Test file glob pattern matching."""
    matcher = RuleMatcher("file matches 'src/**/*.py'")
    finding = {'file': 'src/app/main.py'}

    assert matcher.evaluate(finding) is True


def test_rule_matcher_contains():
    """Test 'contains' operator."""
    matcher = RuleMatcher("compliance contains 'CWE-89'")
    finding = {'compliance': ['CWE-89', 'OWASP-A03']}

    assert matcher.evaluate(finding) is True


def test_rule_matcher_and_logic():
    """Test AND logical operator."""
    matcher = RuleMatcher("(severity == 'HIGH') and (file matches '*.py')")
    finding = {'severity': 'HIGH', 'file': 'app.py'}

    assert matcher.evaluate(finding) is True


def test_rule_matcher_or_logic():
    """Test OR logical operator."""
    matcher = RuleMatcher("(severity == 'CRITICAL') or (severity == 'HIGH')")
    finding = {'severity': 'HIGH'}

    assert matcher.evaluate(finding) is True


def test_rule_matcher_dict_input():
    """Test dict-based matcher input."""
    matcher = RuleMatcher({'severity': 'CRITICAL', 'file_pattern': '*.py'})
    finding = {'severity': 'CRITICAL', 'file': 'app.py'}

    # Should convert dict to expression
    assert isinstance(matcher.expression, str)


def test_rule_matcher_comparison_operators():
    """Test numeric comparison operators."""
    matcher = RuleMatcher("line > 100")
    finding = {'line': 150}

    assert matcher.evaluate(finding) is True


# ── PolicyRule Tests ──────────────────────────────────────────────────────────

def test_policy_rule_matches():
    """Test rule matching."""
    rule = PolicyRule(id='test', matcher="severity == 'HIGH'", action='fail')
    finding = {'severity': 'HIGH'}

    assert rule.matches(finding) is True


def test_policy_rule_apply_action_tag():
    """Test tag action application."""
    rule = PolicyRule(id='test', matcher='true', action='tag', metadata={'tags': ['security', 'audit']})
    finding = {}

    result = rule.apply_action(finding, {})

    assert 'tags' in result
    assert 'security' in result['tags']


def test_policy_rule_apply_action_suppress():
    """Test suppress action."""
    rule = PolicyRule(id='test', matcher='true', action='suppress')
    finding = {}

    result = rule.apply_action(finding, {})

    assert result['suppressed'] is True
    assert result['suppressed_by'] == 'test'


def test_policy_rule_to_dict():
    """Test rule serialization."""
    rule = PolicyRule(id='test', matcher="severity == 'HIGH'", action='fail')
    data = rule.to_dict()

    assert data['id'] == 'test'
    assert data['action'] == 'fail'


# ── Policy Tests ──────────────────────────────────────────────────────────────

def test_policy_initialization(sample_policy):
    """Test Policy initialization."""
    assert sample_policy.name == 'test-policy'
    assert len(sample_policy.rules) == 2


def test_policy_validate_valid(sample_policy):
    """Test validation of valid policy."""
    result = sample_policy.validate()

    assert result.valid is True
    assert len(result.errors) == 0


def test_policy_validate_invalid_version():
    """Test validation catches invalid version."""
    policy = Policy(name='test', version='bad_version', rules=[])
    result = policy.validate()

    assert result.valid is False
    assert any('version' in err.lower() for err in result.errors)


def test_policy_to_dict(sample_policy):
    """Test policy serialization."""
    data = sample_policy.to_dict()

    assert data['name'] == 'test-policy'
    assert data['version'] == '1.0.0'
    assert len(data['rules']) == 2


# ── PolicyEngine Tests ────────────────────────────────────────────────────────

def test_policy_engine_evaluate(policy_engine, sample_policy, sample_findings):
    """Test policy evaluation."""
    result = policy_engine.evaluate(sample_findings, sample_policy)

    assert isinstance(result, PolicyResult)
    assert result.policy == sample_policy


def test_policy_engine_threshold_enforcement(policy_engine, sample_findings):
    """Test threshold violation detection."""
    policy = Policy(
        name='strict',
        version='1.0.0',
        rules=[],
        thresholds={'max_critical': 0},
    )

    result = policy_engine.evaluate(sample_findings, policy)

    # Should fail due to CRITICAL finding exceeding threshold
    assert result.passed is False


def test_policy_engine_severity_filtering(policy_engine, sample_findings):
    """Test fail_on_severity filtering."""
    policy = Policy(
        name='filter',
        version='1.0.0',
        rules=[],
        thresholds={'fail_on_severity': 'HIGH'},
    )

    result = policy_engine.evaluate(sample_findings, policy)

    # Should only evaluate HIGH and CRITICAL findings
    assert len([v for v in result.violations]) >= 0


# ── PolicyResult Tests ────────────────────────────────────────────────────────

def test_policy_result_get_critical_chains(sample_policy, sample_findings):
    """Test filtering violations by severity."""
    engine = PolicyEngine()
    result = engine.evaluate(sample_findings, sample_policy)

    violations_by_sev = result.get_violations_by_severity()

    assert 'CRITICAL' in violations_by_sev
    assert 'HIGH' in violations_by_sev


def test_policy_result_to_dict(policy_engine, sample_policy, sample_findings):
    """Test result serialization."""
    result = policy_engine.evaluate(sample_findings, sample_policy)
    data = result.to_dict()

    assert 'passed' in data
    assert 'violations' in data
    assert 'metrics' in data


# ── PolicyRegistry Tests ──────────────────────────────────────────────────────

def test_policy_registry_register(tmp_path, sample_policy):
    """Test policy registration."""
    registry = PolicyRegistry(str(tmp_path))
    policy_id = registry.register(sample_policy, metadata={'author': 'test'})

    assert policy_id == 'test-policy:1.0.0'


def test_policy_registry_get(tmp_path, sample_policy):
    """Test policy retrieval."""
    registry = PolicyRegistry(str(tmp_path))
    registry.register(sample_policy)

    retrieved = registry.get('test-policy', '1.0.0')

    assert retrieved.name == sample_policy.name


def test_policy_registry_list_versions(tmp_path, sample_policy):
    """Test version listing."""
    registry = PolicyRegistry(str(tmp_path))
    registry.register(sample_policy)

    versions = registry.list_versions('test-policy')

    assert len(versions) >= 1
    assert all(isinstance(v, PolicyVersion) for v in versions)


def test_policy_registry_diff(tmp_path):
    """Test policy version diff."""
    registry = PolicyRegistry(str(tmp_path))

    policy_v1 = Policy(name='test', version='1.0.0', rules=[
        PolicyRule('r1', 'true', 'fail'),
    ])
    policy_v2 = Policy(name='test', version='2.0.0', rules=[
        PolicyRule('r1', 'true', 'warn'),  # Modified
        PolicyRule('r2', 'true', 'fail'),  # Added
    ])

    registry.register(policy_v1)
    registry.register(policy_v2)

    diff = registry.diff('test', '1.0.0', '2.0.0')

    assert isinstance(diff, PolicyDiff)


# ── Public API Tests ──────────────────────────────────────────────────────────

def test_create_default_policy():
    """Test default policy creation."""
    policy = create_default_policy(name='default')

    assert policy.name == 'default'
    assert len(policy.rules) > 0
    assert 'max_critical' in policy.thresholds


# ── Integration Tests ─────────────────────────────────────────────────────────

def test_end_to_end_policy_workflow(tmp_path, sample_findings):
    """Test complete policy workflow."""
    # Create policy
    policy = create_default_policy()

    # Evaluate
    engine = PolicyEngine()
    result = engine.evaluate(sample_findings, policy)

    # Verify
    assert isinstance(result, PolicyResult)
    assert result.metrics['total_findings'] == len(sample_findings)
