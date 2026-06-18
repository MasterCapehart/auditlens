"""
Test suite for auditlens.security_test_generator

Tests automated security test generation from vulnerability findings.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from auditlens.security_test_generator import (
    SecurityTestGenerator,
    TestContext,
    FixProposal,
    ValidationResult,
    PytestStrategy,
    JestStrategy,
    AITestEnhancer,
    TestValidator,
    TestCoverageMapper,
    generate_security_tests,
    generate_test_for_finding,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_finding():
    """Sample vulnerability finding."""
    return {
        'rule_id': 'SQL-01-INJECTION',
        'name': 'SQL Injection',
        'description': 'Potential SQL injection',
        'file': 'app.py',
        'line': 42,
        'severity': 'CRITICAL',
        'compliance': ['CWE-89'],
    }


@pytest.fixture
def test_context(sample_finding, tmp_path):
    """Test context with temp file."""
    test_file = tmp_path / 'app.py'
    test_file.write_text('def query(user_id):\n    sql = f"SELECT * FROM users WHERE id={user_id}"\n')

    sample_finding['file'] = str(test_file)
    return TestContext(sample_finding, str(tmp_path))


@pytest.fixture
def pytest_strategy():
    """Pytest strategy instance."""
    return PytestStrategy()


# ── TestContext Tests ─────────────────────────────────────────────────────────

def test_test_context_initialization(test_context):
    """Test TestContext initialization."""
    assert test_context.target_file
    assert test_context.vulnerable_line == 42


def test_test_context_get_test_file_path(test_context, tmp_path):
    """Test test file path generation."""
    test_path = test_context.get_test_file_path(str(tmp_path / 'tests'))

    assert 'test_' in test_path
    assert test_path.endswith('.py')


# ── PytestStrategy Tests ──────────────────────────────────────────────────────

def test_pytest_strategy_generate_header(pytest_strategy):
    """Test pytest test file header generation."""
    header = pytest_strategy.generate_test_file_header('test_module')

    assert 'import pytest' in header
    assert 'unittest.mock' in header


def test_pytest_strategy_generate_sql_injection_test(pytest_strategy, sample_finding, test_context):
    """Test SQL injection test generation."""
    test_code = pytest_strategy._generate_sql_injection_test(sample_finding, test_context)

    assert 'def test_' in test_code
    assert 'SQL injection' in test_code.lower()
    assert "' OR '1'='1" in test_code  # SQL injection payload


def test_pytest_strategy_generate_xss_test(pytest_strategy, test_context):
    """Test XSS test generation."""
    finding = {'rule_id': 'XSS-01', 'file': 'app.py', 'line': 10, 'severity': 'HIGH', 'compliance': ['CWE-79']}

    test_code = pytest_strategy._generate_xss_test(finding, test_context)

    assert 'def test_xss' in test_code
    assert '<script>' in test_code  # XSS payload


def test_pytest_strategy_generate_auth_bypass_test(pytest_strategy, test_context):
    """Test authentication bypass test generation."""
    finding = {'rule_id': 'AUTH-01', 'file': 'app.py', 'line': 10, 'severity': 'HIGH', 'compliance': []}

    test_code = pytest_strategy._generate_auth_bypass_test(finding, test_context)

    assert 'def test_auth_bypass' in test_code
    assert 'authentication' in test_code.lower()


def test_pytest_strategy_generate_hardcoded_secret_test(pytest_strategy, sample_finding, test_context):
    """Test hardcoded secret test generation."""
    finding = {'rule_id': 'SEC-01-HARDCODED', 'file': 'app.py', 'line': 10, 'severity': 'HIGH', 'compliance': []}

    test_code = pytest_strategy._generate_hardcoded_secret_test(finding, test_context)

    assert 'def test_no_hardcoded_secrets' in test_code
    assert 'os.environ' in test_code


# ── JestStrategy Tests ────────────────────────────────────────────────────────

def test_jest_strategy_generate_header():
    """Test Jest test file header generation."""
    strategy = JestStrategy()
    header = strategy.generate_test_file_header('test_module')

    assert 'import' in header
    assert '@jest/globals' in header


# ── AITestEnhancer Tests ──────────────────────────────────────────────────────

@patch('auditlens.security_test_generator.AITestEnhancer._get_client')
def test_ai_test_enhancer_enhance_test(mock_client, sample_finding, test_context):
    """Test AI-powered test enhancement."""
    enhancer = AITestEnhancer(api_key='test_key')

    # Mock AI API response
    mock_response = Mock()
    mock_response.content = [Mock(text='```python\ndef test_improved(): assert True\n```')]
    mock_client.return_value.messages.create.return_value = mock_response

    test_code = 'def test_basic(): pass'
    enhanced = enhancer.enhance_test(test_code, sample_finding, test_context)

    assert 'def test_' in enhanced


# ── TestValidator Tests ───────────────────────────────────────────────────────

def test_test_validator_validate_syntax():
    """Test Python syntax validation."""
    validator = TestValidator()

    valid_code = 'def test_example():\n    assert True'
    result = validator.validate_syntax(valid_code, 'python')

    assert result.is_valid is True


def test_test_validator_validate_invalid_syntax():
    """Test invalid syntax detection."""
    validator = TestValidator()

    invalid_code = 'def test_example(\n    assert True'
    result = validator.validate_syntax(invalid_code, 'python')

    assert result.is_valid is False
    assert len(result.syntax_errors) > 0


# ── TestCoverageMapper Tests ──────────────────────────────────────────────────

def test_test_coverage_mapper_add_mapping():
    """Test coverage mapping."""
    mapper = TestCoverageMapper()

    mapper.add_mapping('finding_1', 'test_file.py', 'test_sql_injection')

    assert 'finding_1' in mapper._mappings


def test_test_coverage_mapper_get_coverage_report():
    """Test coverage report generation."""
    mapper = TestCoverageMapper()
    findings = [
        {'rule_id': 'SQL-01', 'file': 'app.py', 'line': 10, 'severity': 'HIGH', 'description': 'Test'},
    ]

    mapper.add_mapping('SQL-01:app.py:10', 'test_app.py', 'test_sql')

    report = mapper.get_coverage_report(findings)

    assert report.total_findings == 1
    assert report.covered_findings == 1
    assert report.coverage_percentage == 100.0


# ── SecurityTestGenerator Tests ───────────────────────────────────────────────

def test_security_test_generator_initialization(tmp_path):
    """Test SecurityTestGenerator initialization."""
    generator = SecurityTestGenerator(str(tmp_path), framework='pytest')

    assert generator.framework == 'pytest'
    assert isinstance(generator.strategy, PytestStrategy)


def test_security_test_generator_generate_from_findings(tmp_path):
    """Test test generation from findings list."""
    findings = [
        {'rule_id': 'SQL-01', 'file': str(tmp_path / 'app.py'), 'line': 10, 'severity': 'HIGH', 'description': 'Test'},
    ]

    # Create source file
    (tmp_path / 'app.py').write_text('def query(): pass')

    generator = SecurityTestGenerator(str(tmp_path), framework='pytest', use_ai=False)

    with patch.object(generator, '_generate_single_test', return_value=('test code', 'test.py', 'test_func')):
        result = generator.generate_from_findings(findings, str(tmp_path / 'tests'))

        assert result.tests_created >= 0


# ── Public API Tests ──────────────────────────────────────────────────────────

def test_generate_security_tests_api(tmp_path):
    """Test public API for test generation."""
    findings = [
        {'rule_id': 'TEST', 'file': str(tmp_path / 'app.py'), 'line': 1, 'severity': 'HIGH', 'description': 'Test'},
    ]

    (tmp_path / 'app.py').write_text('code')

    with patch('auditlens.security_test_generator.SecurityTestGenerator.generate_from_findings') as mock_gen:
        mock_gen.return_value = Mock(tests_created=1, files_written=[], framework='pytest')

        result = generate_security_tests(findings, str(tmp_path), str(tmp_path / 'tests'))

        assert 'tests_created' in result


def test_generate_test_for_finding_api(tmp_path, sample_finding):
    """Test single test generation API."""
    sample_finding['file'] = str(tmp_path / 'app.py')
    (tmp_path / 'app.py').write_text('code')

    test_code = generate_test_for_finding(sample_finding, str(tmp_path))

    assert isinstance(test_code, str)
    assert len(test_code) > 0


# ── Integration Tests ─────────────────────────────────────────────────────────

def test_end_to_end_test_generation(tmp_path):
    """Test complete test generation workflow."""
    # Create source file
    app_file = tmp_path / 'app.py'
    app_file.write_text('''
def query(user_id):
    sql = f"SELECT * FROM users WHERE id={user_id}"
    return execute(sql)
''')

    findings = [
        {
            'rule_id': 'SQL-01-INJECTION',
            'file': str(app_file),
            'line': 2,
            'severity': 'CRITICAL',
            'description': 'SQL injection vulnerability',
            'compliance': ['CWE-89'],
        }
    ]

    output_dir = tmp_path / 'tests'
    output_dir.mkdir()

    generator = SecurityTestGenerator(str(tmp_path), framework='pytest', use_ai=False)
    result = generator.generate_from_findings(findings, str(output_dir))

    assert result.tests_created >= 0
    assert result.execution_time >= 0
