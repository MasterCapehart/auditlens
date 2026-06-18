"""
Test suite for auditlens.ml_classifier

Tests ML-based false positive reduction.
"""

import pytest
from auditlens.ml_classifier import calculate_fp_score, classify_findings


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def test_finding():
    """Base test finding."""
    return {
        'file': 'src/app.py',
        'line': 42,
        'snippet': 'password = "test123"',
        'rule_id': 'SEC-01-HARDCODED-SECRET',
    }


@pytest.fixture
def findings_list():
    """List of test findings."""
    return [
        {'file': 'src/app.py', 'line': 10, 'snippet': 'sql = "SELECT *"', 'rule_id': 'sql-injection', 'severity': 'HIGH'},
        {'file': 'tests/test_app.py', 'line': 20, 'snippet': 'password = "test"', 'rule_id': 'secret', 'severity': 'MEDIUM'},
        {'file': 'docs/example.py', 'line': 5, 'snippet': 'api_key = "your_key_here"', 'rule_id': 'secret', 'severity': 'HIGH'},
    ]


# ── calculate_fp_score Tests ──────────────────────────────────────────────────

def test_calculate_fp_score_test_file():
    """Test files should have higher FP score."""
    finding = {
        'file': 'tests/test_app.py',
        'line': 10,
        'snippet': 'code',
        'rule_id': 'test-rule',
    }

    score = calculate_fp_score(finding)
    assert score >= 0.4  # Test file boost


def test_calculate_fp_score_example_file():
    """Example/demo files should have higher FP score."""
    finding = {
        'file': 'examples/demo.py',
        'line': 10,
        'snippet': 'code',
        'rule_id': 'test-rule',
    }

    score = calculate_fp_score(finding)
    assert score >= 0.3  # Example file boost


def test_calculate_fp_score_comment():
    """Code in comments should have higher FP score."""
    finding = {
        'file': 'src/app.py',
        'line': 10,
        'snippet': '# password = "test123"',
        'rule_id': 'secret',
    }

    score = calculate_fp_score(finding)
    assert score >= 0.5  # Comment boost


def test_calculate_fp_score_long_line():
    """Very long lines (likely generated) should have higher FP score."""
    finding = {
        'file': 'src/generated.py',
        'line': 10,
        'snippet': 'x = ' + 'a' * 400,
        'rule_id': 'test-rule',
    }

    score = calculate_fp_score(finding)
    assert score >= 0.2  # Long line boost


def test_calculate_fp_score_example_secret():
    """Example/placeholder secrets should have high FP score."""
    finding = {
        'file': 'src/app.py',
        'line': 10,
        'snippet': 'password = "your_password_here"',
        'rule_id': 'hardcoded-password',
    }

    score = calculate_fp_score(finding)
    assert score >= 0.6  # Example value boost


def test_calculate_fp_score_production_code():
    """Production code with no indicators should have low FP score."""
    finding = {
        'file': 'src/core/auth.py',
        'line': 10,
        'snippet': 'sql = "SELECT * FROM users WHERE id=" + user_id',
        'rule_id': 'sql-injection',
    }

    score = calculate_fp_score(finding)
    assert score < 0.5  # Should be low for real vulnerabilities


def test_calculate_fp_score_static_serving():
    """Path traversal in static file serving might be intentional."""
    finding = {
        'file': 'src/static_server.py',
        'line': 10,
        'snippet': 'open(path)',
        'rule_id': 'path-traversal',
    }

    score = calculate_fp_score(finding)
    assert score >= 0.15  # Static file boost


def test_calculate_fp_score_orm_query():
    """SQL injection in ORM context is often safe."""
    finding = {
        'file': 'src/models.py',
        'line': 10,
        'snippet': 'User.query(name=username)',
        'rule_id': 'sql-injection',
    }

    score = calculate_fp_score(finding)
    assert score >= 0.2  # ORM boost


def test_calculate_fp_score_caps_at_one():
    """FP score should be capped at 1.0."""
    # Maximize all indicators
    finding = {
        'file': 'tests/examples/demo_test.py',
        'line': 10,
        'snippet': '# ' + 'a' * 500 + ' password = "example_password_123"',
        'rule_id': 'secret',
    }

    score = calculate_fp_score(finding)
    assert score == 1.0  # Capped at maximum


# ── classify_findings Tests ───────────────────────────────────────────────────

def test_classify_findings_empty_list():
    """Test classification with empty findings list."""
    result = classify_findings([])

    assert result['total'] == 0
    assert result['likely_true_positives'] == 0
    assert result['likely_false_positives'] == 0


def test_classify_findings_basic(findings_list):
    """Test basic classification functionality."""
    result = classify_findings(findings_list)

    assert result['total'] == 3
    assert 'likely_true_positives' in result
    assert 'likely_false_positives' in result
    assert 'uncertain' in result
    assert 'metrics' in result
    assert 'findings' in result


def test_classify_findings_adds_fp_score(findings_list):
    """Test that FP score is added to findings."""
    result = classify_findings(findings_list)

    for finding in result['findings']:
        assert 'fp_score' in finding
        assert 0 <= finding['fp_score'] <= 1.0


def test_classify_findings_adds_classification(findings_list):
    """Test that classification label is added."""
    result = classify_findings(findings_list)

    valid_classifications = {'LIKELY_TRUE_POSITIVE', 'LIKELY_FALSE_POSITIVE', 'UNCERTAIN'}

    for finding in result['findings']:
        assert 'ml_classification' in finding
        assert finding['ml_classification'] in valid_classifications


def test_classify_findings_classification_thresholds():
    """Test classification threshold logic."""
    findings = [
        {'file': 'src/app.py', 'snippet': 'code', 'rule_id': 'test', 'severity': 'HIGH'},  # Low FP score
        {'file': 'tests/test.py', 'snippet': '# example', 'rule_id': 'test', 'severity': 'HIGH'},  # High FP score
    ]

    result = classify_findings(findings)

    # At least one should be TP, one should be FP or uncertain
    assert result['likely_true_positives'] + result['likely_false_positives'] + result['uncertain'] == 2


def test_classify_findings_metrics():
    """Test metrics calculation."""
    findings = [
        {'file': 'src/app.py', 'snippet': 'real_code', 'rule_id': 'vuln', 'severity': 'HIGH'},
        {'file': 'tests/test.py', 'snippet': 'test_code', 'rule_id': 'vuln', 'severity': 'HIGH'},
    ]

    result = classify_findings(findings)

    assert 'metrics' in result
    assert 'precision' in result['metrics']
    assert 'recall' in result['metrics']
    assert 'f1_score' in result['metrics']
    assert 'accuracy' in result['metrics']


def test_classify_findings_count_totals(findings_list):
    """Test that classification counts match total."""
    result = classify_findings(findings_list)

    total_classified = (
        result['likely_true_positives'] +
        result['likely_false_positives'] +
        result['uncertain']
    )

    assert total_classified == result['total']


def test_classify_findings_preserves_original_data(findings_list):
    """Test that original finding data is preserved."""
    result = classify_findings(findings_list)

    for i, classified in enumerate(result['findings']):
        original = findings_list[i]
        assert classified['file'] == original['file']
        assert classified['rule_id'] == original['rule_id']


# ── Edge Cases ────────────────────────────────────────────────────────────────

def test_calculate_fp_score_missing_fields():
    """Test FP calculation with missing fields."""
    finding = {}

    score = calculate_fp_score(finding)
    assert 0 <= score <= 1.0  # Should not crash


def test_calculate_fp_score_none_values():
    """Test FP calculation with None values."""
    finding = {
        'file': None,
        'snippet': None,
        'rule_id': None,
    }

    score = calculate_fp_score(finding)
    assert 0 <= score <= 1.0


def test_classify_findings_single_finding():
    """Test classification with single finding."""
    findings = [{'file': 'test.py', 'snippet': 'code', 'rule_id': 'test', 'severity': 'HIGH'}]

    result = classify_findings(findings)

    assert result['total'] == 1
    assert len(result['findings']) == 1


# ── Integration Tests ─────────────────────────────────────────────────────────

def test_end_to_end_classification():
    """Test complete classification workflow."""
    # Mix of real and false positive indicators
    findings = [
        # Real vulnerability in production code
        {
            'file': 'src/database.py',
            'line': 100,
            'snippet': 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
            'rule_id': 'sql-injection',
            'severity': 'CRITICAL',
        },
        # Test code (likely FP)
        {
            'file': 'tests/test_db.py',
            'line': 50,
            'snippet': '# Example: cursor.execute("DELETE FROM users")',
            'rule_id': 'sql-injection',
            'severity': 'HIGH',
        },
        # Example documentation (likely FP)
        {
            'file': 'docs/examples/api.py',
            'line': 20,
            'snippet': 'api_key = "your_api_key_here"',
            'rule_id': 'hardcoded-secret',
            'severity': 'HIGH',
        },
    ]

    result = classify_findings(findings)

    # Should identify at least one TP and one FP
    assert result['likely_true_positives'] >= 1
    assert result['likely_false_positives'] >= 1
    assert result['total'] == 3
