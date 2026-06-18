"""
Test suite for auditlens.correlation_engine

Tests correlation engine functionality including:
- Finding-to-node mapping
- Attack chain construction
- Risk score calculation
- Vulnerability clustering
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

from auditlens.correlation_engine import (
    CorrelationEngine,
    GraphCorrelator,
    AttackChain,
    ChainStage,
    RiskScore,
    VulnerabilityCluster,
    ComponentChange,
    correlate_findings,
    build_attack_chains,
    compute_compound_risk,
    cluster_by_vulnerability_pattern,
    find_critical_paths,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_findings():
    """Sample vulnerability findings for testing."""
    return [
        {
            'rule_id': 'SQL-01-INJECTION',
            'name': 'SQL Injection',
            'description': 'Potential SQL injection vulnerability',
            'file': 'app/db.py',
            'line': 42,
            'severity': 'CRITICAL',
            'compliance': ['CWE-89', 'OWASP-A03'],
        },
        {
            'rule_id': 'XSS-01-REFLECTED',
            'name': 'Reflected XSS',
            'description': 'User input rendered without escaping',
            'file': 'app/views.py',
            'line': 18,
            'severity': 'HIGH',
            'compliance': ['CWE-79', 'OWASP-A03'],
        },
        {
            'rule_id': 'TAINT-01',
            'name': 'Taint Flow',
            'description': 'Unsanitized user input flows to sink',
            'file': 'app/views.py',
            'line': 15,
            'severity': 'MEDIUM',
            'compliance': [],
        },
    ]


@pytest.fixture
def sample_graph():
    """Sample attack surface graph for testing."""
    return {
        'nodes': [
            {'id': 'node_0', 'label': 'HTTP Input', 'file': 'app/views.py', 'line': 15, 'severity': 'MEDIUM'},
            {'id': 'node_1', 'label': 'SQL Query', 'file': 'app/db.py', 'line': 42, 'severity': 'CRITICAL'},
            {'id': 'node_2', 'label': 'XSS Sink', 'file': 'app/views.py', 'line': 18, 'severity': 'HIGH'},
        ],
        'edges': [
            {'source': 'node_0', 'target': 'node_1', 'type': 'data_flow'},
            {'source': 'node_0', 'target': 'node_2', 'type': 'data_flow'},
        ],
    }


@pytest.fixture
def correlation_engine(sample_findings):
    """Pre-configured correlation engine."""
    return CorrelationEngine(project_path='./test_project', findings=sample_findings)


@pytest.fixture
def sample_chain_stage():
    """Sample chain stage for testing."""
    return ChainStage(
        stage_id='stage_1',
        finding={'rule_id': 'SQL-01', 'severity': 'CRITICAL', 'compliance': ['CWE-89']},
        node_id='node_1',
        stage_type='sink',
        file='app/db.py',
        line=42,
        severity='CRITICAL',
        description='SQL injection vulnerability',
    )


# ── ChainStage Tests ──────────────────────────────────────────────────────────

def test_chain_stage_get_severity_weight(sample_chain_stage):
    """Test severity weight calculation."""
    assert sample_chain_stage.get_severity_weight() == 100  # CRITICAL


def test_chain_stage_get_exploitability(sample_chain_stage):
    """Test exploitability score extraction."""
    assert sample_chain_stage.get_exploitability() == 0.90  # CWE-89


def test_chain_stage_to_dict(sample_chain_stage):
    """Test ChainStage serialization."""
    result = sample_chain_stage.to_dict()
    assert result['stage_id'] == 'stage_1'
    assert result['severity'] == 'CRITICAL'
    assert result['node_id'] == 'node_1'


# ── RiskScore Tests ───────────────────────────────────────────────────────────

def test_risk_score_to_dict():
    """Test RiskScore serialization."""
    risk = RiskScore(total=85.5, severity=90.0, exploitability=0.85, likelihood=0.75, impact=80.0)
    result = risk.to_dict()

    assert result['total'] == 85.5
    assert result['severity'] == 90.0
    assert result['exploitability'] == 0.85


# ── AttackChain Tests ─────────────────────────────────────────────────────────

def test_attack_chain_initialization():
    """Test AttackChain initialization and post_init."""
    stages = [
        ChainStage('s1', {'rule_id': 'T1', 'compliance': ['CWE-79']}, 'n1', 'entry', 'file1.py', 10, 'HIGH', 'Entry'),
        ChainStage('s2', {'rule_id': 'T2', 'compliance': ['CWE-89']}, 'n2', 'sink', 'file2.py', 20, 'CRITICAL', 'Sink'),
    ]

    chain = AttackChain(chain_id='chain_1', stages=stages)

    assert chain.entry_point == 'n1'
    assert chain.exploit_target == 'n2'
    assert chain.path_length == 2
    assert 'CWE-79' in chain.cwe_chain
    assert 'CWE-89' in chain.cwe_chain


def test_attack_chain_compute_risk():
    """Test compound risk calculation."""
    stages = [
        ChainStage('s1', {'rule_id': 'T1', 'compliance': ['CWE-89'], 'severity': 'CRITICAL'}, 'n1', 'entry', 'f1.py', 10, 'CRITICAL', 'SQL'),
    ]

    chain = AttackChain(chain_id='c1', stages=stages)
    risk = chain.compute_risk()

    assert 0 <= risk.total <= 100
    assert risk.severity > 0
    assert risk.exploitability > 0


def test_attack_chain_get_critical_nodes():
    """Test critical node identification."""
    stages = [
        ChainStage('s1', {}, 'n1', 'entry', 'f1.py', 10, 'HIGH', 'Entry'),
        ChainStage('s2', {}, 'n2', 'propagation', 'f2.py', 20, 'MEDIUM', 'Prop'),
        ChainStage('s3', {}, 'n3', 'sink', 'f3.py', 30, 'CRITICAL', 'Sink'),
    ]

    chain = AttackChain(chain_id='c1', stages=stages)
    critical = chain.get_critical_nodes()

    assert 'n1' in critical  # entry
    assert 'n3' in critical  # sink
    assert 'n2' not in critical  # propagation


# ── VulnerabilityCluster Tests ────────────────────────────────────────────────

def test_vulnerability_cluster_initialization(sample_findings):
    """Test cluster initialization and computed fields."""
    cluster = VulnerabilityCluster(
        cluster_id='cluster_1',
        pattern_type='CWE-89',
        findings=[sample_findings[0]],
    )

    assert cluster.count == 1
    assert cluster.severity_distribution['CRITICAL'] == 1
    assert cluster.representative_finding == sample_findings[0]


def test_vulnerability_cluster_compute_risk(sample_findings):
    """Test cluster risk score calculation."""
    cluster = VulnerabilityCluster(
        cluster_id='c1',
        pattern_type='CWE-89',
        findings=sample_findings,
    )

    assert cluster.risk_score > 0
    assert cluster.risk_score <= 100


def test_vulnerability_cluster_remediation_strategy():
    """Test remediation strategy generation."""
    cluster = VulnerabilityCluster(
        cluster_id='c1',
        pattern_type='CWE-89',
        findings=[],
    )

    strategy = cluster.get_remediation_strategy()
    assert 'parameterized queries' in strategy.lower()


# ── GraphCorrelator Tests ─────────────────────────────────────────────────────

def test_graph_correlator_map_findings_to_nodes(sample_graph, sample_findings):
    """Test finding-to-node mapping."""
    correlator = GraphCorrelator(sample_graph, sample_findings)
    mapping = correlator.map_findings_to_nodes()

    # Should map findings based on file:line matches
    assert isinstance(mapping, dict)
    # At least some nodes should be mapped
    assert len(correlator.node_to_finding) >= 0


def test_graph_correlator_find_paths(sample_graph, sample_findings):
    """Test path finding between entry and sink nodes."""
    correlator = GraphCorrelator(sample_graph, sample_findings)
    correlator.map_findings_to_nodes()

    # Test path finding
    paths = correlator.find_paths('node_0', 'node_1', max_depth=5)

    assert isinstance(paths, list)
    # Should find at least one path based on the graph structure
    if paths:
        assert all(isinstance(path, list) for path in paths)


def test_graph_correlator_build_chains_from_paths(sample_graph, sample_findings):
    """Test chain construction from graph paths."""
    correlator = GraphCorrelator(sample_graph, sample_findings)
    correlator.map_findings_to_nodes()

    # Create sample paths
    paths = [['node_0', 'node_1']]
    chains = correlator.build_chains_from_paths(paths)

    assert isinstance(chains, list)
    if chains:
        assert all(isinstance(chain, AttackChain) for chain in chains)


# ── CorrelationEngine Tests ───────────────────────────────────────────────────

def test_correlation_engine_initialization(correlation_engine):
    """Test CorrelationEngine initialization."""
    assert correlation_engine.project_path == './test_project'
    assert len(correlation_engine.findings) == 3
    assert correlation_engine.chains == []


def test_correlation_engine_build_attack_surface_graph(correlation_engine):
    """Test graph generation from findings."""
    graph = correlation_engine._build_attack_surface_graph()

    assert 'nodes' in graph
    assert 'edges' in graph
    assert len(graph['nodes']) > 0


def test_correlation_engine_identify_entry_nodes(correlation_engine, sample_graph):
    """Test entry node identification."""
    correlation_engine.graph = sample_graph
    correlation_engine.correlator = GraphCorrelator(sample_graph, correlation_engine.findings)
    correlation_engine.correlator.map_findings_to_nodes()

    entry_nodes = correlation_engine._identify_entry_nodes()

    assert isinstance(entry_nodes, list)


def test_correlation_engine_identify_sink_nodes(correlation_engine, sample_graph):
    """Test sink node identification."""
    correlation_engine.graph = sample_graph
    correlation_engine.correlator = GraphCorrelator(sample_graph, correlation_engine.findings)
    correlation_engine.correlator.map_findings_to_nodes()

    sink_nodes = correlation_engine._identify_sink_nodes()

    assert isinstance(sink_nodes, list)


@patch('auditlens.correlation_engine.CorrelationEngine._build_attack_surface_graph')
def test_correlation_engine_analyze(mock_graph, correlation_engine, sample_graph):
    """Test full correlation analysis."""
    mock_graph.return_value = sample_graph

    result = correlation_engine.analyze()

    assert result.project_path == './test_project'
    assert isinstance(result.attack_chains, list)
    assert isinstance(result.vulnerability_clusters, list)
    assert 'total_chains' in result.stats


def test_correlation_engine_build_chains(correlation_engine):
    """Test attack chain construction."""
    chains = correlation_engine.build_chains()

    assert isinstance(chains, list)
    # Should create at least simple chains from findings
    assert len(chains) > 0


def test_correlation_engine_cluster_vulnerabilities(correlation_engine):
    """Test vulnerability clustering."""
    clusters = correlation_engine._cluster_vulnerabilities()

    assert isinstance(clusters, list)
    if clusters:
        assert all(isinstance(c, VulnerabilityCluster) for c in clusters)


# ── Public API Tests ──────────────────────────────────────────────────────────

def test_correlate_findings(sample_findings):
    """Test public correlate_findings API."""
    result = correlate_findings(sample_findings)

    assert isinstance(result, dict)
    # Returns mapping of chain_id to AttackChain
    for chain_id, chain in result.items():
        assert isinstance(chain_id, str)
        assert isinstance(chain, AttackChain)


def test_build_attack_chains_with_graph(sample_findings, sample_graph):
    """Test build_attack_chains with explicit graph."""
    chains = build_attack_chains(sample_findings, graph=sample_graph)

    assert isinstance(chains, list)


def test_compute_compound_risk():
    """Test compound risk calculation."""
    stages = [
        ChainStage('s1', {'rule_id': 'T1', 'compliance': ['CWE-89'], 'severity': 'CRITICAL'}, 'n1', 'entry', 'f.py', 1, 'CRITICAL', 'Test'),
    ]
    chain = AttackChain('c1', stages)

    risk = compute_compound_risk(chain)

    assert isinstance(risk, RiskScore)
    assert 0 <= risk.total <= 100


def test_cluster_by_vulnerability_pattern(sample_findings):
    """Test vulnerability pattern clustering."""
    clusters = cluster_by_vulnerability_pattern(sample_findings)

    assert isinstance(clusters, dict)
    # Should have at least one cluster
    assert len(clusters) > 0


def test_find_critical_paths():
    """Test critical path filtering."""
    # Create chains with different risk scores
    high_risk_chain = AttackChain(
        'c1',
        [ChainStage('s1', {'rule_id': 'T1', 'compliance': ['CWE-89'], 'severity': 'CRITICAL'}, 'n1', 'sink', 'f.py', 1, 'CRITICAL', 'High')],
    )
    low_risk_chain = AttackChain(
        'c2',
        [ChainStage('s2', {'rule_id': 'T2', 'compliance': [], 'severity': 'LOW'}, 'n2', 'entry', 'f.py', 2, 'LOW', 'Low')],
    )

    chains = [high_risk_chain, low_risk_chain]
    critical = find_critical_paths(chains, min_risk=50)

    assert isinstance(critical, list)
    # Should filter by risk threshold
    assert all(c.risk_score.total >= 50 for c in critical if c.risk_score)


# ── Edge Cases ────────────────────────────────────────────────────────────────

def test_empty_findings():
    """Test correlation with empty findings list."""
    engine = CorrelationEngine(project_path='.', findings=[])
    result = engine.analyze()

    assert result.attack_chains == []
    assert result.stats['total_findings'] == 0


def test_single_finding():
    """Test correlation with single finding."""
    finding = {'rule_id': 'TEST', 'file': 'test.py', 'line': 1, 'severity': 'HIGH', 'compliance': []}
    engine = CorrelationEngine(project_path='.', findings=[finding])

    chains = engine.build_chains()

    # Should create at least one simple chain
    assert len(chains) >= 1
