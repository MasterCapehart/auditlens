"""
AuditLens Correlation Engine — Multi-Stage Attack Chain Analysis

Correlates independent findings into exploitable attack chains by:
1. Mapping findings to attack surface graph nodes
2. Discovering entry→function→sink paths
3. Computing compound risk scores based on chain severity, exploitability, and impact
4. Clustering related vulnerabilities for pattern-based remediation

Usage:
    from auditlens.correlation_engine import CorrelationEngine

    engine = CorrelationEngine(project_path="./my_app", findings=scan_results)
    result = engine.analyze()

    # Export correlation report
    result.export(output_path="correlation_report.html", format="html")

    # Get critical chains only
    critical = result.get_critical_chains(threshold=70)
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Type Aliases ──────────────────────────────────────────────────────────────
NodeID = str
ChainID = str
FindingID = str

# ── Severity Mappings ─────────────────────────────────────────────────────────
_SEVERITY_WEIGHTS = {'LOW': 25, 'MEDIUM': 50, 'HIGH': 75, 'CRITICAL': 100}
_SEVERITY_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}

# ── CWE to Exploitability Mapping ─────────────────────────────────────────────
_CWE_EXPLOITABILITY = {
    'CWE-78': 0.95,   # OS Command Injection
    'CWE-79': 0.85,   # XSS
    'CWE-89': 0.90,   # SQL Injection
    'CWE-22': 0.80,   # Path Traversal
    'CWE-352': 0.75,  # CSRF
    'CWE-434': 0.85,  # Unrestricted Upload
    'CWE-502': 0.90,  # Deserialization
    'CWE-611': 0.75,  # XXE
    'CWE-918': 0.80,  # SSRF
    'CWE-798': 0.70,  # Hardcoded Credentials
    'CWE-327': 0.65,  # Weak Crypto
    'CWE-285': 0.70,  # Improper Authorization
}

# ── MITRE ATT&CK Tactic Mapping ──────────────────────────────────────────────
_CWE_TO_MITRE = {
    'CWE-78': ['TA0002', 'TA0004'],   # Execution, Privilege Escalation
    'CWE-79': ['TA0001'],              # Initial Access
    'CWE-89': ['TA0009'],              # Collection
    'CWE-22': ['TA0009'],              # Collection
    'CWE-352': ['TA0001'],             # Initial Access
    'CWE-434': ['TA0002', 'TA0003'],  # Execution, Persistence
    'CWE-502': ['TA0002'],             # Execution
    'CWE-611': ['TA0009'],             # Collection
    'CWE-918': ['TA0009', 'TA0007'],  # Collection, Discovery
    'CWE-798': ['TA0006'],             # Credential Access
    'CWE-327': ['TA0006'],             # Credential Access
    'CWE-285': ['TA0005'],             # Defense Evasion
}


# ══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ChainStage:
    """Single stage in an attack chain (entry→taint→exploit)."""

    stage_id: str
    finding: dict
    node_id: str
    stage_type: str  # 'entry' | 'propagation' | 'sink' | 'exploit'
    file: str
    line: int
    severity: str
    description: str

    def get_severity_weight(self) -> int:
        """Returns numeric weight for severity (0-100)."""
        return _SEVERITY_WEIGHTS.get(self.severity.upper(), 25)

    def get_exploitability(self) -> float:
        """Returns exploitability score (0-1) based on CWE."""
        compliance = self.finding.get('compliance', [])
        for cwe in compliance:
            if cwe.startswith('CWE-'):
                exploitability = _CWE_EXPLOITABILITY.get(cwe, 0.5)
                return exploitability
        return 0.5  # default

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            'stage_id': self.stage_id,
            'finding': self.finding,
            'node_id': self.node_id,
            'stage_type': self.stage_type,
            'file': self.file,
            'line': self.line,
            'severity': self.severity,
            'description': self.description,
        }


@dataclass
class RiskScore:
    """Encapsulates compound risk calculation with breakdown by dimension."""

    total: float = 0.0
    severity: float = 0.0
    exploitability: float = 0.0
    likelihood: float = 0.0
    impact: float = 0.0
    cvss_vector: str = ''
    breakdown: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            'total': round(self.total, 2),
            'severity': round(self.severity, 2),
            'exploitability': round(self.exploitability, 2),
            'likelihood': round(self.likelihood, 2),
            'impact': round(self.impact, 2),
            'cvss_vector': self.cvss_vector,
            'breakdown': {k: round(v, 2) for k, v in self.breakdown.items()},
        }


@dataclass
class AttackChain:
    """Represents a multi-stage attack path from entry point to exploit."""

    chain_id: ChainID
    stages: List[ChainStage]
    entry_point: str = ''
    exploit_target: str = ''
    risk_score: Optional[RiskScore] = None
    path_length: int = 0
    attack_vector: str = ''
    affected_files: List[str] = field(default_factory=list)
    cwe_chain: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Initialize computed fields."""
        if not self.entry_point and self.stages:
            self.entry_point = self.stages[0].node_id
        if not self.exploit_target and self.stages:
            self.exploit_target = self.stages[-1].node_id
        if not self.path_length:
            self.path_length = len(self.stages)
        if not self.affected_files:
            self.affected_files = list(set(s.file for s in self.stages))
        if not self.cwe_chain:
            self._extract_cwes()
        if not self.mitre_tactics:
            self._extract_mitre_tactics()
        if not self.attack_vector:
            self._build_attack_vector()
        if self.risk_score is None:
            self.risk_score = self.compute_risk()

    def _extract_cwes(self) -> None:
        """Extract CWE identifiers from stage findings."""
        cwes = []
        for stage in self.stages:
            compliance = stage.finding.get('compliance', [])
            cwes.extend([c for c in compliance if c.startswith('CWE-')])
        self.cwe_chain = list(dict.fromkeys(cwes))  # preserve order, remove dupes

    def _extract_mitre_tactics(self) -> None:
        """Map CWEs to MITRE ATT&CK tactics."""
        tactics = []
        for cwe in self.cwe_chain:
            tactics.extend(_CWE_TO_MITRE.get(cwe, []))
        self.mitre_tactics = list(dict.fromkeys(tactics))

    def _build_attack_vector(self) -> None:
        """Build human-readable attack vector string."""
        vectors = []
        for stage in self.stages:
            rule_id = stage.finding.get('rule_id', 'UNKNOWN')
            if 'SQL' in rule_id or 'CWE-89' in str(stage.finding.get('compliance', [])):
                vectors.append('SQL')
            elif 'XSS' in rule_id or 'CWE-79' in str(stage.finding.get('compliance', [])):
                vectors.append('XSS')
            elif 'CMD' in rule_id or 'CWE-78' in str(stage.finding.get('compliance', [])):
                vectors.append('RCE')
            elif 'PATH' in rule_id or 'CWE-22' in str(stage.finding.get('compliance', [])):
                vectors.append('PATH_TRAV')
            elif 'TAINT' in rule_id:
                vectors.append('TAINT')
            else:
                vectors.append(rule_id.split('-')[0])
        self.attack_vector = '→'.join(list(dict.fromkeys(vectors)))

    def add_stage(self, stage: ChainStage) -> AttackChain:
        """Add a stage to the chain (returns new chain, immutable pattern)."""
        new_stages = self.stages + [stage]
        return AttackChain(
            chain_id=self.chain_id,
            stages=new_stages,
            entry_point=self.entry_point,
        )

    def compute_risk(self) -> RiskScore:
        """
        Calculates compound risk score (0-100) based on:
        - Chain severity (weighted average)
        - Exploitability (from CWE)
        - Likelihood (path length, input exposure)
        - Impact (data loss, RCE, privilege escalation)
        """
        if not self.stages:
            return RiskScore()

        # 1. Severity: weighted average of all stages
        severity_sum = sum(s.get_severity_weight() for s in self.stages)
        avg_severity = severity_sum / len(self.stages)

        # 2. Exploitability: max exploitability in chain
        exploitability = max(s.get_exploitability() for s in self.stages)

        # 3. Likelihood: inversely proportional to path length (shorter = more likely)
        # Normalized: 1-hop = 1.0, 5-hop = 0.2
        likelihood = max(0.2, 1.0 - (self.path_length - 1) * 0.2)

        # 4. Impact: based on CWE severity and blast radius
        impact_scores = []
        for cwe in self.cwe_chain:
            if cwe in ['CWE-78', 'CWE-502', 'CWE-434']:  # RCE-class
                impact_scores.append(1.0)
            elif cwe in ['CWE-89', 'CWE-22', 'CWE-611']:  # Data exfil
                impact_scores.append(0.85)
            elif cwe in ['CWE-79', 'CWE-352', 'CWE-918']:  # Client-side/SSRF
                impact_scores.append(0.70)
            else:
                impact_scores.append(0.50)
        impact = max(impact_scores) if impact_scores else 0.5

        # 5. Compound risk: weighted formula
        # Base: severity (40%) + exploitability (30%) + impact (30%)
        base_risk = (avg_severity * 0.4) + (exploitability * 100 * 0.3) + (impact * 100 * 0.3)

        # Adjusted by likelihood
        total_risk = base_risk * (0.5 + 0.5 * likelihood)

        # CVSS-like vector (simplified)
        cvss_vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        return RiskScore(
            total=min(100.0, total_risk),
            severity=avg_severity,
            exploitability=exploitability,
            likelihood=likelihood,
            impact=impact * 100,
            cvss_vector=cvss_vector,
            breakdown={
                'severity_contribution': avg_severity * 0.4,
                'exploitability_contribution': exploitability * 100 * 0.3,
                'impact_contribution': impact * 100 * 0.3,
                'likelihood_multiplier': 0.5 + 0.5 * likelihood,
            },
        )

    def get_critical_nodes(self) -> List[str]:
        """Returns list of node IDs that are critical (entry or sink)."""
        return [s.node_id for s in self.stages if s.stage_type in ('entry', 'sink', 'exploit')]

    def get_attack_vector_summary(self) -> str:
        """Returns human-readable summary of attack chain."""
        return f"{self.attack_vector} ({self.path_length} stages, risk={self.risk_score.total:.1f})"

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            'chain_id': self.chain_id,
            'stages': [s.to_dict() for s in self.stages],
            'entry_point': self.entry_point,
            'exploit_target': self.exploit_target,
            'risk_score': self.risk_score.to_dict() if self.risk_score else None,
            'path_length': self.path_length,
            'attack_vector': self.attack_vector,
            'affected_files': self.affected_files,
            'cwe_chain': self.cwe_chain,
            'mitre_tactics': self.mitre_tactics,
        }


@dataclass
class VulnerabilityCluster:
    """Groups related findings by CWE, OWASP category, or file."""

    cluster_id: str
    pattern_type: str  # 'CWE-89', 'OWASP-A01', 'file-based'
    findings: List[dict]
    count: int = 0
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    representative_finding: Optional[dict] = None
    risk_score: float = 0.0
    remediation_strategy: str = ''

    def __post_init__(self):
        """Initialize computed fields."""
        if not self.count:
            self.count = len(self.findings)
        if not self.severity_distribution:
            self._compute_severity_distribution()
        if not self.representative_finding:
            self.representative_finding = self.get_representative_finding()
        if not self.risk_score:
            self.risk_score = self.compute_cluster_risk()
        if not self.remediation_strategy:
            self.remediation_strategy = self.get_remediation_strategy()

    def _compute_severity_distribution(self) -> None:
        """Count findings by severity."""
        dist = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in self.findings:
            sev = f.get('severity', 'LOW').upper()
            if sev in dist:
                dist[sev] += 1
        self.severity_distribution = dist

    def get_representative_finding(self) -> dict:
        """Returns the most severe finding as representative."""
        if not self.findings:
            return {}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: _SEVERITY_RANK.get(f.get('severity', 'LOW').upper(), 0),
            reverse=True,
        )
        return sorted_findings[0]

    def compute_cluster_risk(self) -> float:
        """Compute aggregate risk for the cluster."""
        if not self.findings:
            return 0.0

        # Weight by severity
        total_weight = 0.0
        for sev, count in self.severity_distribution.items():
            total_weight += _SEVERITY_WEIGHTS.get(sev, 25) * count

        # Average + frequency multiplier
        avg = total_weight / self.count
        freq_multiplier = min(1.5, 1.0 + (self.count - 1) * 0.05)  # cap at 1.5x

        return min(100.0, avg * freq_multiplier)

    def get_remediation_strategy(self) -> str:
        """Returns remediation guidance based on pattern type."""
        if self.pattern_type.startswith('CWE-89'):
            return 'Use parameterized queries or prepared statements. Avoid string concatenation in SQL.'
        elif self.pattern_type.startswith('CWE-79'):
            return 'Sanitize user input. Use context-aware output encoding (HTML entities, JS escaping).'
        elif self.pattern_type.startswith('CWE-78'):
            return 'Avoid shell execution with user input. Use subprocess with argument arrays.'
        elif self.pattern_type.startswith('CWE-22'):
            return 'Validate file paths against whitelist. Use os.path.normpath() and reject "..".'
        elif self.pattern_type.startswith('CWE-'):
            return f'Address {self.pattern_type} vulnerabilities according to OWASP guidelines.'
        elif self.pattern_type.startswith('file-based'):
            return 'Review all vulnerabilities in affected file(s) for common root cause.'
        else:
            return 'Apply secure coding practices and input validation.'

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            'cluster_id': self.cluster_id,
            'pattern_type': self.pattern_type,
            'findings': self.findings,
            'count': self.count,
            'severity_distribution': self.severity_distribution,
            'representative_finding': self.representative_finding,
            'risk_score': round(self.risk_score, 2),
            'remediation_strategy': self.remediation_strategy,
        }


@dataclass
class CorrelationResult:
    """Container for correlation analysis output."""

    timestamp: str
    project_path: str
    attack_chains: List[AttackChain]
    vulnerability_clusters: List[VulnerabilityCluster]
    stats: dict

    def get_critical_chains(self, threshold: int = 70) -> List[AttackChain]:
        """Returns chains with risk score above threshold."""
        return [
            chain for chain in self.attack_chains
            if chain.risk_score and chain.risk_score.total >= threshold
        ]

    def get_top_chains(self, n: int = 10) -> List[AttackChain]:
        """Returns top N chains by risk score."""
        sorted_chains = sorted(
            self.attack_chains,
            key=lambda c: c.risk_score.total if c.risk_score else 0,
            reverse=True,
        )
        return sorted_chains[:n]

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            'timestamp': self.timestamp,
            'project_path': self.project_path,
            'attack_chains': [c.to_dict() for c in self.attack_chains],
            'vulnerability_clusters': [vc.to_dict() for vc in self.vulnerability_clusters],
            'stats': self.stats,
        }

    def export(self, output_path: str, format: str = 'html') -> None:
        """Export correlation report to file."""
        if format == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(self.to_json())
        elif format == 'html':
            export_correlation_report(self.attack_chains, output_path, format='html')
        else:
            raise ValueError(f'Unsupported format: {format}')


# ══════════════════════════════════════════════════════════════════════════════
# Graph Correlation
# ══════════════════════════════════════════════════════════════════════════════

class GraphCorrelator:
    """
    Bridges findings with attack surface graph.
    Performs BFS/DFS to find entry→sink paths.
    """

    def __init__(self, graph: Dict[str, Any], findings: List[dict]):
        self.graph = graph
        self.findings = findings
        self.node_to_finding: Dict[NodeID, dict] = {}
        self.finding_to_node: Dict[FindingID, NodeID] = {}

    def map_findings_to_nodes(self) -> Dict[NodeID, dict]:
        """
        Map findings to graph nodes based on file:line.
        Returns dict: node_id → finding
        """
        # Build lookup: (file, line) → finding
        location_map: Dict[Tuple[str, int], dict] = {}
        for finding in self.findings:
            file_path = finding.get('file', '')
            line = finding.get('line', 0)
            key = (file_path, line)
            location_map[key] = finding

        # Map nodes to findings
        nodes = self.graph.get('nodes', [])
        for node in nodes:
            node_id = node.get('id', '')
            file_path = node.get('file', '')
            line = node.get('line', 0)
            key = (file_path, line)

            if key in location_map:
                self.node_to_finding[node_id] = location_map[key]
                finding_id = self._finding_id(location_map[key])
                self.finding_to_node[finding_id] = node_id

        return self.node_to_finding

    def _finding_id(self, finding: dict) -> FindingID:
        """Generate unique ID for a finding."""
        key = f"{finding.get('file', '')}:{finding.get('line', 0)}:{finding.get('rule_id', '')}"
        return hashlib.md5(key.encode()).hexdigest()[:12]

    def find_paths(
        self,
        entry_id: NodeID,
        sink_id: NodeID,
        max_depth: int = 5,
    ) -> List[List[NodeID]]:
        """
        Find all paths from entry to sink using BFS.
        Returns list of paths, where each path is a list of node IDs.
        """
        if entry_id == sink_id:
            return [[entry_id]]

        # Build adjacency list
        adj: Dict[NodeID, List[NodeID]] = defaultdict(list)
        edges = self.graph.get('edges', [])
        for edge in edges:
            source = edge.get('source', '')
            target = edge.get('target', '')
            if source and target:
                adj[source].append(target)

        # BFS with path tracking
        paths: List[List[NodeID]] = []
        queue: deque = deque([(entry_id, [entry_id])])
        visited: Set[Tuple[NodeID, ...]] = set()

        while queue:
            node, path = queue.popleft()

            if len(path) > max_depth:
                continue

            # Check if we've seen this path state before
            path_tuple = tuple(path)
            if path_tuple in visited:
                continue
            visited.add(path_tuple)

            for neighbor in adj[node]:
                if neighbor == sink_id:
                    paths.append(path + [neighbor])
                elif neighbor not in path:  # avoid cycles
                    queue.append((neighbor, path + [neighbor]))

        return paths

    def build_chains_from_paths(self, paths: List[List[NodeID]]) -> List[AttackChain]:
        """Convert graph paths to AttackChain objects."""
        chains = []

        for path in paths:
            stages = []
            for i, node_id in enumerate(path):
                finding = self.node_to_finding.get(node_id)
                if not finding:
                    # Intermediate node without finding (propagation)
                    node_info = self._get_node_info(node_id)
                    finding = {
                        'rule_id': 'PROPAGATION',
                        'name': 'Data Flow Propagation',
                        'description': f'Taint propagates through {node_info.get("label", "unknown")}',
                        'file': node_info.get('file', ''),
                        'line': node_info.get('line', 0),
                        'severity': 'MEDIUM',
                        'compliance': [],
                    }

                stage_type = 'entry' if i == 0 else ('sink' if i == len(path) - 1 else 'propagation')

                stage = ChainStage(
                    stage_id=f'{node_id}_{i}',
                    finding=finding,
                    node_id=node_id,
                    stage_type=stage_type,
                    file=finding.get('file', ''),
                    line=finding.get('line', 0),
                    severity=finding.get('severity', 'MEDIUM'),
                    description=finding.get('description', ''),
                )
                stages.append(stage)

            if stages:
                chain = AttackChain(
                    chain_id=str(uuid.uuid4())[:8],
                    stages=stages,
                )
                chains.append(chain)

        return chains

    def _get_node_info(self, node_id: NodeID) -> dict:
        """Get node metadata from graph."""
        nodes = self.graph.get('nodes', [])
        for node in nodes:
            if node.get('id') == node_id:
                return node
        return {}

    def get_tainted_subgraph(self) -> Dict[str, Any]:
        """Extract subgraph containing only tainted nodes."""
        tainted_nodes = set(self.node_to_finding.keys())

        filtered_nodes = [
            node for node in self.graph.get('nodes', [])
            if node.get('id') in tainted_nodes
        ]

        filtered_edges = [
            edge for edge in self.graph.get('edges', [])
            if edge.get('source') in tainted_nodes and edge.get('target') in tainted_nodes
        ]

        return {
            'nodes': filtered_nodes,
            'edges': filtered_edges,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Correlation Engine
# ══════════════════════════════════════════════════════════════════════════════

class CorrelationEngine:
    """
    Orchestrates finding correlation, attack chain construction, and risk scoring.
    Main facade for the module.
    """

    def __init__(self, project_path: str, findings: List[dict]):
        self.project_path = project_path
        self.findings = findings
        self.graph: Optional[Dict[str, Any]] = None
        self.correlator: Optional[GraphCorrelator] = None
        self.chains: List[AttackChain] = []
        self.clusters: List[VulnerabilityCluster] = []

    def analyze(self) -> CorrelationResult:
        """
        Run full correlation analysis.
        Returns CorrelationResult with chains, clusters, and stats.
        """
        print(f'\033[94m[CorrelationEngine]\033[0m Analyzing {len(self.findings)} findings...')

        # 1. Build or load attack surface graph
        self.graph = self._build_attack_surface_graph()

        # 2. Build attack chains
        self.chains = self.build_chains()

        # 3. Cluster vulnerabilities
        self.clusters = self._cluster_vulnerabilities()

        # 4. Compute stats
        stats = self._compute_stats()

        result = CorrelationResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            project_path=self.project_path,
            attack_chains=self.chains,
            vulnerability_clusters=self.clusters,
            stats=stats,
        )

        print(f'\033[92m[CorrelationEngine]\033[0m Found {len(self.chains)} attack chains, '
              f'{len(self.clusters)} vulnerability clusters.')

        return result

    def build_chains(self) -> List[AttackChain]:
        """Constructs multi-stage attack chains by traversing graph paths."""
        if not self.graph:
            print('\033[93m[CorrelationEngine] Warning: No attack surface graph available.\033[0m')
            return self._build_simple_chains()

        self.correlator = GraphCorrelator(self.graph, self.findings)
        self.correlator.map_findings_to_nodes()

        # Find entry and sink nodes
        entry_nodes = self._identify_entry_nodes()
        sink_nodes = self._identify_sink_nodes()

        print(f'\033[94m[CorrelationEngine]\033[0m Found {len(entry_nodes)} entry points, '
              f'{len(sink_nodes)} sinks.')

        all_chains = []

        # For each entry→sink pair, find paths
        for entry_id in entry_nodes:
            for sink_id in sink_nodes:
                if entry_id == sink_id:
                    continue

                paths = self.correlator.find_paths(entry_id, sink_id, max_depth=5)
                chains = self.correlator.build_chains_from_paths(paths)
                all_chains.extend(chains)

        # If no chains found, create simple chains
        if not all_chains:
            all_chains = self._build_simple_chains()

        return all_chains

    def _build_simple_chains(self) -> List[AttackChain]:
        """
        Fallback: Create single-stage chains from findings when no graph available.
        """
        chains = []
        for finding in self.findings:
            stage = ChainStage(
                stage_id=str(uuid.uuid4())[:8],
                finding=finding,
                node_id=f"node_{finding.get('file', '')}_{finding.get('line', 0)}",
                stage_type='exploit',
                file=finding.get('file', ''),
                line=finding.get('line', 0),
                severity=finding.get('severity', 'MEDIUM'),
                description=finding.get('description', ''),
            )
            chain = AttackChain(
                chain_id=str(uuid.uuid4())[:8],
                stages=[stage],
            )
            chains.append(chain)
        return chains

    def _build_attack_surface_graph(self) -> Dict[str, Any]:
        """
        Build attack surface graph from project.
        Uses simplified graph structure.
        """
        # Simplified graph: each finding is a node
        nodes = []
        for i, finding in enumerate(self.findings):
            node_id = f"node_{i}"
            nodes.append({
                'id': node_id,
                'label': finding.get('name', 'Unknown'),
                'file': finding.get('file', ''),
                'line': finding.get('line', 0),
                'severity': finding.get('severity', 'MEDIUM'),
            })

        # Connect findings in same file (simple heuristic)
        edges = []
        file_nodes: Dict[str, List[str]] = defaultdict(list)
        for node in nodes:
            file_nodes[node['file']].append(node['id'])

        for file_path, node_ids in file_nodes.items():
            for i in range(len(node_ids) - 1):
                edges.append({
                    'source': node_ids[i],
                    'target': node_ids[i + 1],
                    'type': 'data_flow',
                })

        return {'nodes': nodes, 'edges': edges}

    def _identify_entry_nodes(self) -> List[NodeID]:
        """Identify entry points (user input sources)."""
        if not self.correlator:
            return []

        entry_nodes = []
        for node_id, finding in self.correlator.node_to_finding.items():
            rule_id = finding.get('rule_id', '')
            description = finding.get('description', '').lower()

            if 'TAINT' in rule_id or 'input' in description or 'user' in description:
                entry_nodes.append(node_id)

        return entry_nodes

    def _identify_sink_nodes(self) -> List[NodeID]:
        """Identify sink points (dangerous operations)."""
        if not self.correlator:
            return []

        sink_nodes = []
        for node_id, finding in self.correlator.node_to_finding.items():
            rule_id = finding.get('rule_id', '')
            compliance = finding.get('compliance', [])

            # High/Critical severity findings are sinks
            if finding.get('severity', '').upper() in ('HIGH', 'CRITICAL'):
                sink_nodes.append(node_id)
            # Or specific dangerous patterns
            elif any(cwe in compliance for cwe in ['CWE-78', 'CWE-89', 'CWE-502']):
                sink_nodes.append(node_id)

        return sink_nodes

    def _cluster_vulnerabilities(self) -> List[VulnerabilityCluster]:
        """Group findings by CWE, OWASP, or file."""
        clusters_dict = cluster_by_vulnerability_pattern(self.findings)

        clusters = []
        for pattern_type, findings_list in clusters_dict.items():
            cluster = VulnerabilityCluster(
                cluster_id=str(uuid.uuid4())[:8],
                pattern_type=pattern_type,
                findings=findings_list,
            )
            clusters.append(cluster)

        return clusters

    def _compute_stats(self) -> dict:
        """Compute correlation statistics."""
        total_chains = len(self.chains)
        critical_chains = len([c for c in self.chains if c.risk_score and c.risk_score.total >= 70])

        correlated_findings = set()
        for chain in self.chains:
            for stage in chain.stages:
                finding_id = self._finding_id(stage.finding)
                correlated_findings.add(finding_id)

        avg_chain_length = sum(c.path_length for c in self.chains) / total_chains if total_chains else 0
        max_risk = max((c.risk_score.total for c in self.chains if c.risk_score), default=0.0)

        return {
            'total_chains': total_chains,
            'critical_chains': critical_chains,
            'total_findings': len(self.findings),
            'correlated_findings': len(correlated_findings),
            'uncorrelated_findings': len(self.findings) - len(correlated_findings),
            'avg_chain_length': round(avg_chain_length, 2),
            'max_risk_score': round(max_risk, 2),
        }

    def _finding_id(self, finding: dict) -> FindingID:
        """Generate unique ID for a finding."""
        key = f"{finding.get('file', '')}:{finding.get('line', 0)}:{finding.get('rule_id', '')}"
        return hashlib.md5(key.encode()).hexdigest()[:12]

    def rank_chains(self) -> List[AttackChain]:
        """Returns chains sorted by risk score (high to low)."""
        return sorted(
            self.chains,
            key=lambda c: c.risk_score.total if c.risk_score else 0,
            reverse=True,
        )

    def export(self, output_path: str, format: str = 'html') -> None:
        """Export correlation analysis to file."""
        result = self.analyze() if not self.chains else CorrelationResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            project_path=self.project_path,
            attack_chains=self.chains,
            vulnerability_clusters=self.clusters,
            stats=self._compute_stats(),
        )
        result.export(output_path, format)


# ══════════════════════════════════════════════════════════════════════════════
# Public API Functions
# ══════════════════════════════════════════════════════════════════════════════

def correlate_findings(findings: List[dict]) -> Dict[ChainID, AttackChain]:
    """
    Main entry point. Takes raw findings list and returns dict of attack chain IDs
    mapped to AttackChain objects.
    """
    engine = CorrelationEngine(project_path='.', findings=findings)
    result = engine.analyze()
    return {chain.chain_id: chain for chain in result.attack_chains}


def build_attack_chains(
    findings: List[dict],
    graph: Optional[Dict[str, Any]] = None,
) -> List[AttackChain]:
    """
    Constructs multi-stage attack chains by traversing entry→function→sink paths
    in the attack surface graph.
    """
    engine = CorrelationEngine(project_path='.', findings=findings)
    if graph:
        engine.graph = graph
    return engine.build_chains()


def compute_compound_risk(chain: AttackChain) -> RiskScore:
    """
    Calculates compound risk score (0-100) based on chain length, severity,
    exploitability, and business impact.
    """
    return chain.compute_risk()


def export_correlation_report(
    chains: List[AttackChain],
    output_path: str,
    format: str = 'html',
) -> None:
    """
    Exports correlation analysis to HTML, JSON, or XLSX format with
    interactive visualization.
    """
    if format == 'json':
        data = {
            'chains': [c.to_dict() for c in chains],
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    elif format == 'html':
        html = _generate_html_report(chains)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

    else:
        raise ValueError(f'Unsupported format: {format}')


def find_critical_paths(
    chains: List[AttackChain],
    min_risk: int = 70,
) -> List[AttackChain]:
    """
    Filters and ranks attack chains by compound risk score, returns chains
    above threshold.
    """
    critical = [c for c in chains if c.risk_score and c.risk_score.total >= min_risk]
    return sorted(critical, key=lambda c: c.risk_score.total, reverse=True)


def cluster_by_vulnerability_pattern(findings: List[dict]) -> Dict[str, List[dict]]:
    """
    Groups findings by vulnerability pattern (SQLI, XSS, IDOR, etc.) for
    correlation analysis.
    """
    clusters: Dict[str, List[dict]] = defaultdict(list)

    # Cluster by CWE
    for finding in findings:
        compliance = finding.get('compliance', [])
        for item in compliance:
            if item.startswith('CWE-'):
                clusters[item].append(finding)
                break
        else:
            # Cluster by rule family
            rule_id = finding.get('rule_id', 'UNKNOWN')
            family = rule_id.split('-')[0] if '-' in rule_id else rule_id
            clusters[f'rule-{family}'].append(finding)

    # Also cluster by file (for file-based remediation)
    file_clusters: Dict[str, List[dict]] = defaultdict(list)
    for finding in findings:
        file_path = finding.get('file', '')
        if file_path:
            file_clusters[f'file-{os.path.basename(file_path)}'].append(finding)

    # Merge file clusters (only if 3+ findings in same file)
    for file_key, file_findings in file_clusters.items():
        if len(file_findings) >= 3:
            clusters[file_key] = file_findings

    return dict(clusters)


def _generate_html_report(chains: List[AttackChain]) -> str:
    """Generate interactive HTML report for attack chains."""
    critical_chains = [c for c in chains if c.risk_score and c.risk_score.total >= 70]

    chains_html = []
    for chain in sorted(chains, key=lambda c: c.risk_score.total if c.risk_score else 0, reverse=True)[:20]:
        risk = chain.risk_score.total if chain.risk_score else 0
        color = 'red' if risk >= 70 else 'orange' if risk >= 50 else 'gray'

        stages_html = '<ol>'
        for stage in chain.stages:
            stages_html += f'<li><code>{stage.file}:{stage.line}</code> — {stage.description[:80]}</li>'
        stages_html += '</ol>'

        chains_html.append(f'''
        <div class="chain" style="border-left: 4px solid {color};">
            <h3>{chain.attack_vector} <span style="color: {color};">Risk: {risk:.1f}</span></h3>
            <p><strong>Path:</strong> {chain.entry_point} → {chain.exploit_target} ({chain.path_length} stages)</p>
            <p><strong>CWEs:</strong> {', '.join(chain.cwe_chain) or 'N/A'}</p>
            <p><strong>MITRE Tactics:</strong> {', '.join(chain.mitre_tactics) or 'N/A'}</p>
            <details>
                <summary>Show stages</summary>
                {stages_html}
            </details>
        </div>
        ''')

    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Attack Chain Correlation Report</title>
        <style>
            body {{ font-family: -apple-system, sans-serif; margin: 2em; background: #f5f5f5; }}
            h1 {{ color: #333; }}
            .stats {{ background: white; padding: 1em; border-radius: 8px; margin-bottom: 1em; }}
            .chain {{ background: white; padding: 1em; margin: 1em 0; border-radius: 4px; }}
            code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }}
            details {{ margin-top: 0.5em; }}
            summary {{ cursor: pointer; color: #007bff; }}
        </style>
    </head>
    <body>
        <h1>🔗 Attack Chain Correlation Report</h1>
        <div class="stats">
            <p><strong>Total Chains:</strong> {len(chains)} | <strong>Critical:</strong> {len(critical_chains)}</p>
            <p><strong>Generated:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
        </div>
        <h2>Top Attack Chains</h2>
        {''.join(chains_html)}
    </body>
    </html>
    '''
