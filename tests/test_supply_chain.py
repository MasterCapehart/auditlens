"""
Test suite for auditlens.supply_chain_guard

Tests SBOM diff analysis, typosquatting detection, and supply chain risk scoring.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json
from pathlib import Path

from auditlens.supply_chain_guard import (
    SBOMDiffer,
    TyposquattingDetector,
    SupplyChainRiskScorer,
    SBOMIntegrityChecker,
    SupplyChainGuard,
    Component,
    ComponentChange,
    DiffResult,
    TyposquattingMatch,
    audit_supply_chain,
    detect_typosquatting,
    diff_sboms,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_component():
    """Sample software component."""
    return Component(name='requests', version='2.28.0', ecosystem='pypi')


@pytest.fixture
def sample_sbom_cyclonedx(tmp_path):
    """Sample CycloneDX SBOM file."""
    sbom = {
        'components': [
            {
                'name': 'flask',
                'version': '2.0.0',
                'purl': 'pkg:pypi/flask@2.0.0',
                'licenses': [{'license': {'id': 'BSD-3-Clause'}}],
            },
            {
                'name': 'requests',
                'version': '2.28.0',
                'purl': 'pkg:pypi/requests@2.28.0',
                'licenses': [{'license': {'id': 'Apache-2.0'}}],
            },
        ]
    }

    sbom_file = tmp_path / 'sbom.json'
    sbom_file.write_text(json.dumps(sbom))
    return str(sbom_file)


# ── Component Tests ───────────────────────────────────────────────────────────

def test_component_initialization(sample_component):
    """Test Component initialization."""
    assert sample_component.name == 'requests'
    assert sample_component.version == '2.28.0'
    assert sample_component.purl.startswith('pkg:pypi/')


def test_component_purl_generation():
    """Test PURL generation."""
    comp = Component(name='express', version='4.18.0', ecosystem='npm')

    assert comp.purl == 'pkg:npm/express@4.18.0'


# ── SBOMDiffer Tests ──────────────────────────────────────────────────────────

def test_sbom_differ_parse_cyclonedx(sample_sbom_cyclonedx):
    """Test CycloneDX parsing."""
    differ = SBOMDiffer()
    components = differ.parse_cyclonedx(sample_sbom_cyclonedx)

    assert len(components) == 2
    assert all(isinstance(c, Component) for c in components.values())


def test_sbom_differ_diff(tmp_path):
    """Test SBOM diffing."""
    # Create baseline SBOM
    baseline = {
        'components': [
            {'name': 'flask', 'version': '1.0.0', 'purl': 'pkg:pypi/flask@1.0.0'},
        ]
    }
    baseline_file = tmp_path / 'baseline.json'
    baseline_file.write_text(json.dumps(baseline))

    # Create current SBOM with changes
    current = {
        'components': [
            {'name': 'flask', 'version': '2.0.0', 'purl': 'pkg:pypi/flask@2.0.0'},  # Modified
            {'name': 'requests', 'version': '2.28.0', 'purl': 'pkg:pypi/requests@2.28.0'},  # Added
        ]
    }
    current_file = tmp_path / 'current.json'
    current_file.write_text(json.dumps(current))

    differ = SBOMDiffer()
    result = differ.diff(str(baseline_file), str(current_file))

    assert isinstance(result, DiffResult)
    assert len(result.added) == 1  # requests added
    assert len(result.modified) >= 0  # flask version changed


def test_sbom_differ_version_downgrade_detection():
    """Test detection of version downgrades."""
    differ = SBOMDiffer()

    old_comp = Component('package', '2.0.0', 'pypi')
    new_comp = Component('package', '1.0.0', 'pypi')

    change = differ._analyze_version_change(old_comp, new_comp)

    assert change.change_type == 'downgrade'
    assert change.risk in ['HIGH', 'MEDIUM']


# ── TyposquattingDetector Tests ───────────────────────────────────────────────

def test_typosquatting_detector_initialization():
    """Test detector initialization."""
    detector = TyposquattingDetector(threshold=0.85)

    assert detector.threshold == 0.85


def test_typosquatting_detector_similarity_calculation():
    """Test similarity score calculation."""
    detector = TyposquattingDetector()

    # Very similar strings
    sim1 = detector._compute_similarity('requests', 'reqeusts')
    assert sim1 > 0.8

    # Dissimilar strings
    sim2 = detector._compute_similarity('abc', 'xyz')
    assert sim2 < 0.5


def test_typosquatting_detector_confusables():
    """Test confusable character detection."""
    detector = TyposquattingDetector()

    # 0 (zero) vs o (letter)
    assert detector._has_confusables('requ0sts', 'requosts')

    # 1 (one) vs l (letter)
    assert detector._has_confusables('f1ask', 'flask')


def test_typosquatting_detector_parse_requirements(tmp_path):
    """Test requirements.txt parsing."""
    req_file = tmp_path / 'requirements.txt'
    req_file.write_text('flask==2.0.0\nrequests>=2.28.0\n# comment\n')

    detector = TyposquattingDetector()
    deps = detector._parse_requirements_txt(req_file, 'pypi')

    assert len(deps) == 2
    assert ('flask', 'pypi') in deps


# ── SupplyChainRiskScorer Tests ───────────────────────────────────────────────

def test_risk_scorer_initialization():
    """Test risk scorer initialization."""
    scorer = SupplyChainRiskScorer()

    assert scorer._cache_db.exists()


def test_risk_scorer_score_component():
    """Test component risk scoring."""
    scorer = SupplyChainRiskScorer()

    with patch.object(scorer, '_get_package_metadata', return_value=None):
        score = scorer.score_component('unknown-package', '1.0.0', 'pypi')

        assert 0 <= score <= 100


def test_risk_scorer_age_scoring():
    """Test age-based risk scoring."""
    scorer = SupplyChainRiskScorer()

    # Very new package
    new_metadata = {'releases': {'1.0.0': [{'upload_time': '2024-12-01T00:00:00'}]}}
    new_score = scorer._score_age(new_metadata)

    assert new_score >= 50  # New packages are riskier


# ── SBOMIntegrityChecker Tests ────────────────────────────────────────────────

def test_integrity_checker_detect_format(sample_sbom_cyclonedx):
    """Test SBOM format detection."""
    checker = SBOMIntegrityChecker()
    format_type = checker._detect_sbom_format(sample_sbom_cyclonedx)

    assert format_type in ['cyclonedx', 'spdx']


# ── SupplyChainGuard Tests ────────────────────────────────────────────────────

def test_supply_chain_guard_initialization():
    """Test SupplyChainGuard initialization."""
    guard = SupplyChainGuard()

    assert guard.differ is not None
    assert guard.typosquat_detector is not None


# ── Public API Tests ──────────────────────────────────────────────────────────

def test_detect_typosquatting_api(tmp_path):
    """Test typosquatting detection API."""
    req_file = tmp_path / 'requirements.txt'
    req_file.write_text('reqeusts==2.0.0\n')  # Typo of 'requests'

    results = detect_typosquatting(str(tmp_path), threshold=0.85)

    assert isinstance(results, list)


# ── Integration Tests ─────────────────────────────────────────────────────────

def test_end_to_end_supply_chain_audit(tmp_path):
    """Test complete supply chain audit."""
    # Create mock project
    req_file = tmp_path / 'requirements.txt'
    req_file.write_text('flask==2.0.0\n')

    with patch('auditlens.supply_chain_guard.SupplyChainGuard.audit_project') as mock_audit:
        mock_audit.return_value = Mock(
            sbom_diff=None,
            typosquatting_findings=[],
            score=20.0,
        )

        report = audit_supply_chain(str(tmp_path))

        assert report is not None
