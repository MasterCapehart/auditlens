"""
Test suite for auditlens.remediation_engine

Tests automated fix generation, validation, and PR workflow.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, mock_open
from datetime import datetime, timezone, timedelta
from pathlib import Path

from auditlens.remediation_engine import (
    RemediationEngine,
    RemediationConfig,
    FixGenerator,
    SafetyValidator,
    TestOrchestrator,
    PRManager,
    RollbackManager,
    RemediationTracker,
    FixProposal,
    ValidationResult,
    TestResult,
    PRMetadata,
    VCSType,
    RemediationMode,
    FixStatus,
    RiskLevel,
    finding_key,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_finding():
    """Sample vulnerability finding."""
    return {
        'rule_id': 'SQL-01-INJECTION',
        'name': 'SQL Injection',
        'description': 'Potential SQL injection in query',
        'file': '/path/to/app.py',
        'line': 42,
        'severity': 'CRITICAL',
        'compliance': ['CWE-89'],
    }


@pytest.fixture
def remediation_config():
    """Sample remediation configuration."""
    return RemediationConfig(
        vcs_type=VCSType.GITHUB,
        repo='owner/repo',
        base_branch='main',
        auto_merge=False,
        require_review=True,
    )


@pytest.fixture
def fix_generator():
    """FixGenerator with mocked API."""
    return FixGenerator(api_key='test_key')


@pytest.fixture
def test_orchestrator():
    """Test orchestrator instance."""
    return TestOrchestrator()


@pytest.fixture
def pr_manager():
    """PR manager instance."""
    return PRManager(VCSType.GITHUB, 'test_token', 'owner/repo')


@pytest.fixture
def rollback_manager(tmp_path):
    """Rollback manager with temp storage."""
    return RollbackManager(snapshot_dir=str(tmp_path / 'snapshots'))


@pytest.fixture
def remediation_tracker(tmp_path):
    """Remediation tracker with temp DB."""
    return RemediationTracker(db_path=str(tmp_path / 'remediation.db'))


# ── finding_key Tests ─────────────────────────────────────────────────────────

def test_finding_key_generation(sample_finding):
    """Test stable finding key generation."""
    key1 = finding_key(sample_finding)
    key2 = finding_key(sample_finding)

    assert key1 == key2
    assert len(key1) == 16  # SHA256 truncated to 16 chars


def test_finding_key_different_findings():
    """Test different findings produce different keys."""
    f1 = {'rule_id': 'A', 'file': 'a.py', 'line': 1, 'description': 'Test'}
    f2 = {'rule_id': 'B', 'file': 'b.py', 'line': 2, 'description': 'Other'}

    assert finding_key(f1) != finding_key(f2)


# ── FixGenerator Tests ────────────────────────────────────────────────────────

@patch('auditlens.remediation_engine.FixGenerator._call_ai_api')
def test_fix_generator_generate_fix(mock_api, fix_generator, sample_finding, tmp_path):
    """Test fix generation."""
    # Create temp file
    test_file = tmp_path / 'app.py'
    test_file.write_text("def query(user_id):\n    sql = f'SELECT * FROM users WHERE id={user_id}'\n")
    sample_finding['file'] = str(test_file)

    mock_api.return_value = """```diff
--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def query(user_id):
-    sql = f'SELECT * FROM users WHERE id={user_id}'
+    sql = 'SELECT * FROM users WHERE id=?'
```
CONFIDENCE: 0.85
EXPLANATION: Use parameterized query"""

    proposal = fix_generator.generate_fix(sample_finding)

    assert proposal is not None
    assert isinstance(proposal, FixProposal)
    assert '---' in proposal.diff
    assert proposal.confidence_score > 0


def test_fix_generator_build_prompt(fix_generator, sample_finding):
    """Test prompt construction."""
    prompt = fix_generator._build_prompt(sample_finding, "sample code")

    assert 'SQL-01-INJECTION' in prompt
    assert 'CRITICAL' in prompt
    assert 'sample code' in prompt


def test_fix_generator_extract_confidence(fix_generator):
    """Test confidence score extraction."""
    response = "Some text\nCONFIDENCE: 0.92\nMore text"
    confidence = fix_generator._extract_confidence(response)

    assert confidence == 0.92


def test_fix_generator_estimate_risk(fix_generator, sample_finding):
    """Test risk estimation."""
    diff = """--- a/file.py
+++ b/file.py
@@ -1,5 +1,5 @@
-old line
+new line"""

    risk = fix_generator._estimate_risk(sample_finding, diff)

    assert isinstance(risk, RiskLevel)


# ── SafetyValidator Tests ─────────────────────────────────────────────────────

def test_safety_validator_initialization(test_orchestrator):
    """Test SafetyValidator initialization."""
    validator = SafetyValidator(test_orchestrator)

    assert validator.test_orchestrator == test_orchestrator
    assert isinstance(validator._validation_cache, dict)


@patch('auditlens.remediation_engine.SafetyValidator._apply_patch_temp')
@patch('auditlens.remediation_engine.SafetyValidator._scan_patched_code')
def test_safety_validator_validate_pre_merge(mock_scan, mock_patch, test_orchestrator, sample_finding):
    """Test pre-merge validation."""
    mock_patch.return_value = ['/path/to/file.py']
    mock_scan.return_value = []

    validator = SafetyValidator(test_orchestrator)
    result = validator.validate_pre_merge('diff content', sample_finding, '/project')

    assert isinstance(result, ValidationResult)
    assert result.tests_run >= 0


def test_safety_validator_verify_finding_resolved(test_orchestrator, sample_finding):
    """Test finding resolution verification."""
    validator = SafetyValidator(test_orchestrator)

    new_findings = [{'rule_id': 'OTHER', 'file': 'other.py', 'line': 1, 'description': 'different'}]
    resolved = validator._verify_finding_resolved(sample_finding, new_findings)

    assert resolved is True


# ── TestOrchestrator Tests ────────────────────────────────────────────────────

def test_test_orchestrator_detect_pytest(test_orchestrator, tmp_path):
    """Test pytest detection."""
    # Create pytest.ini
    (tmp_path / 'pytest.ini').touch()

    suite = test_orchestrator.detect_test_suite(str(tmp_path))

    assert suite is not None
    assert suite.runner == 'pytest'


def test_test_orchestrator_detect_jest(test_orchestrator, tmp_path):
    """Test jest detection."""
    (tmp_path / 'jest.config.js').write_text('module.exports = {};')

    suite = test_orchestrator.detect_test_suite(str(tmp_path))

    assert suite is not None
    assert suite.runner == 'jest'


def test_test_orchestrator_parse_pytest_output(test_orchestrator):
    """Test pytest output parsing."""
    output = "5 passed, 2 failed in 1.23s"
    metrics = test_orchestrator._parse_test_output(output, 'pytest')

    assert metrics.passed == 5
    assert metrics.failed == 2


# ── PRManager Tests ───────────────────────────────────────────────────────────

def test_pr_manager_initialization(pr_manager):
    """Test PRManager initialization."""
    assert pr_manager.vcs_type == VCSType.GITHUB
    assert pr_manager.repo == 'owner/repo'


def test_pr_manager_create_fix_branch(pr_manager):
    """Test branch creation."""
    with patch('auditlens.remediation_engine._run_command') as mock_cmd:
        mock_cmd.return_value = (0, '', '')

        branch = pr_manager.create_fix_branch('main', 'finding123')

        assert 'auditlens/fix-finding123' in branch
        mock_cmd.assert_called_once()


@patch('requests.post')
def test_pr_manager_create_github_pr(mock_post, pr_manager):
    """Test GitHub PR creation."""
    mock_post.return_value.json.return_value = {
        'number': 42,
        'html_url': 'https://github.com/owner/repo/pull/42',
        'head': {'sha': 'abc123'},
    }

    metadata = pr_manager._create_github_pr('fix-branch', 'Fix title', 'Fix body', 'main')

    assert isinstance(metadata, PRMetadata)
    assert metadata.pr_id == '42'
    assert 'github.com' in metadata.pr_url


# ── RollbackManager Tests ─────────────────────────────────────────────────────

def test_rollback_manager_initialization(rollback_manager):
    """Test RollbackManager initialization."""
    assert rollback_manager.snapshot_dir.exists()


def test_rollback_manager_create_snapshot(rollback_manager, sample_finding):
    """Test snapshot creation."""
    file_state = {'/path/to/file.py': 'hash123'}

    with patch('auditlens.remediation_engine._run_command') as mock_cmd:
        mock_cmd.return_value = (0, 'stash_ref_123', '')

        snapshot_id = rollback_manager.create_snapshot(sample_finding, file_state)

        assert snapshot_id.id
        assert isinstance(snapshot_id.timestamp, datetime)


# ── RemediationTracker Tests ──────────────────────────────────────────────────

def test_remediation_tracker_initialization(remediation_tracker):
    """Test tracker database initialization."""
    assert Path(remediation_tracker.db_path).exists()


def test_remediation_tracker_record_fix(remediation_tracker, sample_finding):
    """Test fix record creation."""
    pr_metadata = PRMetadata(
        pr_id='1',
        pr_url='https://example.com/pr/1',
        branch='fix-branch',
        commit_sha='abc123',
        created_at=datetime.now(timezone.utc),
        status=pytest.importorskip('auditlens.remediation_engine').PRStatus.OPEN,
        finding_id='f1',
    )

    record_id = remediation_tracker.record_fix(sample_finding, pr_metadata, FixStatus.SUCCESS)

    assert record_id > 0


def test_remediation_tracker_get_success_rate(remediation_tracker, sample_finding):
    """Test success rate calculation."""
    # Record some fixes
    for _ in range(5):
        remediation_tracker.record_fix(sample_finding, None, FixStatus.SUCCESS)

    rate = remediation_tracker.get_success_rate(time_window_days=30)

    assert 0 <= rate <= 1.0


# ── RemediationEngine Tests ───────────────────────────────────────────────────

@patch('auditlens.remediation_engine.FixGenerator')
@patch('auditlens.remediation_engine.PRManager')
def test_remediation_engine_initialization(mock_pr, mock_fix, remediation_config):
    """Test RemediationEngine initialization."""
    engine = RemediationEngine(remediation_config, api_key='test_key')

    assert engine.config == remediation_config
    assert engine.api_key == 'test_key'


@patch('auditlens.remediation_engine.RemediationEngine._remediate_single')
def test_remediation_engine_remediate(mock_single, remediation_config):
    """Test batch remediation."""
    mock_single.return_value = {'success': True, 'pr_metadata': None}

    engine = RemediationEngine(remediation_config, api_key='test_key')
    findings = [{'rule_id': 'T1', 'file': 'f.py', 'line': 1, 'severity': 'HIGH', 'description': 'Test'}]

    report = engine.remediate(findings, RemediationMode.SAFE)

    assert report.fixes_attempted > 0
    assert report.success_rate >= 0


def test_remediation_engine_filter_by_mode(remediation_config):
    """Test finding filtering by remediation mode."""
    engine = RemediationEngine(remediation_config)

    findings = [
        {'severity': 'CRITICAL'},
        {'severity': 'HIGH'},
        {'severity': 'MEDIUM'},
        {'severity': 'LOW'},
    ]

    safe = engine._filter_by_mode(findings, RemediationMode.SAFE)
    assert len(safe) == 2  # CRITICAL, HIGH

    moderate = engine._filter_by_mode(findings, RemediationMode.MODERATE)
    assert len(moderate) == 3  # CRITICAL, HIGH, MEDIUM

    aggressive = engine._filter_by_mode(findings, RemediationMode.AGGRESSIVE)
    assert len(aggressive) == 4  # All


# ── Integration Tests ─────────────────────────────────────────────────────────

@patch('auditlens.remediation_engine.FixGenerator.generate_fix')
@patch('auditlens.remediation_engine.SafetyValidator.validate_pre_merge')
@patch('auditlens.remediation_engine.PRManager.create_fix_branch')
def test_remediation_full_workflow(mock_branch, mock_validate, mock_generate, remediation_config, sample_finding):
    """Test complete remediation workflow."""
    # Mock successful fix generation
    mock_generate.return_value = FixProposal(
        finding=sample_finding,
        diff='--- a/file\n+++ b/file',
        explanation='Fixed',
        confidence_score=0.85,
        affected_files=['/path/to/file.py'],
        estimated_risk=RiskLevel.LOW,
    )

    # Mock successful validation
    mock_validate.return_value = ValidationResult(
        passed=True,
        tests_run=10,
        tests_failed=0,
        new_findings=[],
        original_finding_resolved=True,
        execution_time_ms=1000,
    )

    mock_branch.return_value = 'fix-branch'

    engine = RemediationEngine(remediation_config, api_key='test_key')
    result = engine._remediate_single(sample_finding)

    assert 'success' in result
