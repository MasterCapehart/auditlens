"""
Test suite for auditlens.predictive_dashboard

Tests trend forecasting, fix time estimation, and risk predictions.
"""

import pytest
from datetime import datetime, timedelta

from auditlens.predictive_dashboard import (
    predict_trends,
    estimate_fix_time,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def historical_scans():
    """Sample historical scan data."""
    base_date = datetime.now() - timedelta(days=90)
    scans = []

    for i in range(10):
        scans.append({
            'scanned_at': (base_date + timedelta(days=i*7)).isoformat(),
            'critical': 5 + i,
            'high': 10 + i*2,
            'medium': 20 + i,
            'low': 30 - i,
        })

    return scans


@pytest.fixture
def sample_findings():
    """Sample findings for fix time estimation."""
    return [
        {'severity': 'CRITICAL'},
        {'severity': 'CRITICAL'},
        {'severity': 'HIGH'},
        {'severity': 'HIGH'},
        {'severity': 'HIGH'},
        {'severity': 'MEDIUM'},
        {'severity': 'LOW'},
    ]


# ── predict_trends Tests ──────────────────────────────────────────────────────

def test_predict_trends_insufficient_data():
    """Test prediction with insufficient historical data."""
    result = predict_trends([])

    assert result['status'] == 'insufficient_data'


def test_predict_trends_basic(historical_scans):
    """Test basic trend prediction."""
    result = predict_trends(historical_scans)

    assert result['status'] == 'success'
    assert 'current_state' in result
    assert 'trends' in result
    assert 'predictions' in result
    assert 'debt_analysis' in result


def test_predict_trends_current_state(historical_scans):
    """Test current state extraction."""
    result = predict_trends(historical_scans)

    current = result['current_state']
    assert 'critical' in current
    assert 'high' in current
    assert 'medium' in current
    assert 'low' in current


def test_predict_trends_trend_calculation(historical_scans):
    """Test trend slope calculation."""
    result = predict_trends(historical_scans)

    trends = result['trends']
    assert 'critical_trend' in trends
    assert 'overall_trend' in trends
    assert trends['overall_trend'] in ['INCREASING', 'STABLE', 'DECREASING']


def test_predict_trends_predictions_timeframes(historical_scans):
    """Test prediction timeframes (7, 30, 90 days)."""
    result = predict_trends(historical_scans)

    predictions = result['predictions']
    assert len(predictions) == 3

    days_ahead = [p['days_ahead'] for p in predictions]
    assert 7 in days_ahead
    assert 30 in days_ahead
    assert 90 in days_ahead


def test_predict_trends_risk_levels(historical_scans):
    """Test risk level assignment in predictions."""
    result = predict_trends(historical_scans)

    valid_risk_levels = {'LOW', 'MEDIUM', 'HIGH'}

    for prediction in result['predictions']:
        assert 'risk_level' in prediction
        assert prediction['risk_level'] in valid_risk_levels


def test_predict_trends_debt_growth(historical_scans):
    """Test technical debt growth calculation."""
    result = predict_trends(historical_scans)

    debt = result['debt_analysis']
    assert 'current_debt' in debt
    assert 'projected_debt_90d' in debt
    assert 'growth_percentage' in debt
    assert 'recommended_action' in debt


def test_predict_trends_increasing_trend():
    """Test detection of increasing trend."""
    scans = [
        {'scanned_at': datetime.now().isoformat(), 'critical': i, 'high': i*2, 'medium': i*3, 'low': i}
        for i in range(1, 6)
    ]

    result = predict_trends(scans)

    assert result['trends']['overall_trend'] == 'INCREASING'


def test_predict_trends_stable_trend():
    """Test detection of stable trend."""
    scans = [
        {'scanned_at': datetime.now().isoformat(), 'critical': 5, 'high': 10, 'medium': 20, 'low': 30}
        for _ in range(5)
    ]

    result = predict_trends(scans)

    assert result['trends']['overall_trend'] == 'STABLE'


def test_predict_trends_decreasing_trend():
    """Test detection of decreasing trend."""
    scans = [
        {'scanned_at': datetime.now().isoformat(), 'critical': 10-i, 'high': 20-i*2, 'medium': 30-i, 'low': 40-i}
        for i in range(1, 6)
    ]

    result = predict_trends(scans)

    # Should detect decreasing critical/high
    assert result['trends']['critical_trend'] < 0


# ── estimate_fix_time Tests ───────────────────────────────────────────────────

def test_estimate_fix_time_empty_list():
    """Test fix time estimation with no findings."""
    result = estimate_fix_time([])

    assert result['total_findings'] == 0
    assert result['estimated_hours'] == 0
    assert result['estimated_days'] == 0


def test_estimate_fix_time_basic(sample_findings):
    """Test basic fix time estimation."""
    result = estimate_fix_time(sample_findings)

    assert result['total_findings'] == len(sample_findings)
    assert result['estimated_hours'] > 0
    assert result['estimated_days'] >= 0
    assert result['estimated_weeks'] >= 0


def test_estimate_fix_time_severity_breakdown(sample_findings):
    """Test severity breakdown calculation."""
    result = estimate_fix_time(sample_findings)

    breakdown = result['severity_breakdown_hours']
    assert 'CRITICAL' in breakdown
    assert 'HIGH' in breakdown
    assert 'MEDIUM' in breakdown
    assert 'LOW' in breakdown


def test_estimate_fix_time_critical_takes_longer():
    """Test that CRITICAL findings take more time than LOW."""
    critical_findings = [{'severity': 'CRITICAL'}]
    low_findings = [{'severity': 'LOW'}]

    critical_result = estimate_fix_time(critical_findings)
    low_result = estimate_fix_time(low_findings)

    assert critical_result['estimated_hours'] > low_result['estimated_hours']


def test_estimate_fix_time_hours_to_days_conversion():
    """Test hours to days conversion (8-hour workday)."""
    findings = [{'severity': 'CRITICAL'}] * 4  # 4 * 4 hours = 16 hours = 2 days

    result = estimate_fix_time(findings)

    assert result['estimated_days'] == 2.0


def test_estimate_fix_time_weeks_calculation():
    """Test weeks calculation (5-day workweek)."""
    findings = [{'severity': 'CRITICAL'}] * 10  # 40 hours = 5 days = 1 week

    result = estimate_fix_time(findings)

    assert result['estimated_weeks'] == 1.0


def test_estimate_fix_time_severity_time_mapping():
    """Test severity to time hour mapping."""
    # CRITICAL: 4h, HIGH: 2h, MEDIUM: 1h, LOW: 0.5h
    findings = [
        {'severity': 'CRITICAL'},  # 4
        {'severity': 'HIGH'},      # 2
        {'severity': 'MEDIUM'},    # 1
        {'severity': 'LOW'},       # 0.5
    ]  # Total: 7.5 hours

    result = estimate_fix_time(findings)

    assert result['estimated_hours'] == 7.5


def test_estimate_fix_time_unknown_severity():
    """Test handling of unknown severity (defaults to LOW)."""
    findings = [{'severity': 'UNKNOWN'}]

    result = estimate_fix_time(findings)

    assert result['estimated_hours'] == 0.5  # Same as LOW


def test_estimate_fix_time_mixed_severities():
    """Test estimation with mixed severity findings."""
    findings = [
        {'severity': 'CRITICAL'},
        {'severity': 'CRITICAL'},
        {'severity': 'HIGH'},
        {'severity': 'MEDIUM'},
        {'severity': 'LOW'},
    ]

    result = estimate_fix_time(findings)

    expected_hours = 4 + 4 + 2 + 1 + 0.5  # 11.5
    assert result['estimated_hours'] == expected_hours


# ── Integration Tests ─────────────────────────────────────────────────────────

def test_end_to_end_prediction_workflow(historical_scans, sample_findings):
    """Test complete prediction workflow."""
    # Predict trends
    trends = predict_trends(historical_scans)
    assert trends['status'] == 'success'

    # Estimate fix time
    fix_time = estimate_fix_time(sample_findings)
    assert fix_time['estimated_hours'] > 0

    # Combined analysis
    projected_debt = trends['debt_analysis']['projected_debt_90d']
    current_findings = fix_time['total_findings']

    # Validate consistency
    assert projected_debt >= 0
    assert current_findings > 0


def test_realistic_project_scenario():
    """Test with realistic project data."""
    # Simulate 3 months of weekly scans with increasing issues
    scans = []
    base_date = datetime.now() - timedelta(days=90)

    for week in range(12):
        scans.append({
            'scanned_at': (base_date + timedelta(days=week*7)).isoformat(),
            'critical': 2 + week,
            'high': 5 + week*2,
            'medium': 15 + week,
            'low': 25,
        })

    trends = predict_trends(scans)

    # Should detect increasing trend
    assert trends['trends']['overall_trend'] == 'INCREASING'

    # Should recommend action
    assert trends['debt_analysis']['recommended_action'] in ['URGENT', 'MONITOR', 'MAINTAIN']

    # Predictions should show growth
    assert trends['predictions'][-1]['total'] > trends['current_state']['critical'] + trends['current_state']['high']
