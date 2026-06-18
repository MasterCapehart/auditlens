# AuditLens API Reference

**Version**: 0.10.0  
**Last Updated**: 2026-06-17

Comprehensive API documentation for all public modules, classes, and functions in AuditLens.

---

## Table of Contents

1. [Motor de Correlación Inteligente](#1-motor-de-correlación-inteligente)
2. [Sistema de Remediación Automatizada](#2-sistema-de-remediación-automatizada)
3. [ML para Reducción de Falsos Positivos](#3-ml-para-reducción-de-falsos-positivos)
4. [Arquitectura de Escaneo Distribuido](#4-arquitectura-de-escaneo-distribuido)
5. [Policy-as-Code Framework](#5-policy-as-code-framework)
6. [Language Server Protocol](#6-language-server-protocol)
7. [Dashboard Predictivo](#7-dashboard-predictivo)
8. [Supply Chain Security Suite](#8-supply-chain-security-suite)
9. [Security Test Generator](#9-security-test-generator)
10. [Multi-Tenancy Architecture](#10-multi-tenancy-architecture)

---

## 1. Motor de Correlación Inteligente

**Module**: `auditlens.correlation_engine`

Detects attack chains by correlating findings to identify exploitable multi-step attack paths.

### Functions

#### `correlate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]`

Analyze findings to detect exploitable attack chains.

**Parameters:**
- `findings` (List[Dict[str, Any]]): List of security findings from scan results. Each finding should contain:
  - `rule_id` (str): Identifier of the security rule
  - `file` (str): File path where finding was detected
  - `line` (int): Line number
  - `severity` (str): Severity level (LOW, MEDIUM, HIGH, CRITICAL)

**Returns:**
- List[Dict[str, Any]]: List of detected attack chains, each containing:
  - `name` (str): Attack chain name (e.g., "XSS to Session Hijacking")
  - `severity` (str): Overall chain severity
  - `impact` (str): Description of attack impact
  - `nodes` (List[str]): Rule IDs involved in the chain
  - `edges` (List[Dict]): Graph edges showing attack flow
  - `findings` (List[Dict]): Actual findings for each node
  - `likelihood` (str): HIGH if full chain matched, MEDIUM for partial

**Example:**
```python
from auditlens.correlation_engine import correlate_findings

findings = [
    {"rule_id": "xss-reflected", "file": "app.py", "line": 42, "severity": "HIGH"},
    {"rule_id": "insecure-cookie", "file": "config.py", "line": 12, "severity": "MEDIUM"}
]

chains = correlate_findings(findings)
for chain in chains:
    print(f"Attack chain: {chain['name']}")
    print(f"Impact: {chain['impact']}")
    print(f"Likelihood: {chain['likelihood']}")
```

**Raises:**
- None (returns empty list on error)

---

#### `export_attack_graph_json(chains: List[Dict[str, Any]], output_path: str) -> None`

Export attack chains as JSON for visualization.

**Parameters:**
- `chains` (List[Dict[str, Any]]): Output from `correlate_findings()`
- `output_path` (str): Path to write JSON file

**Returns:**
- None

**Example:**
```python
export_attack_graph_json(chains, "attack_graph.json")
```

---

#### `run_correlation(findings: List[Dict[str, Any]]) -> Dict[str, Any]`

Main entry point for correlation analysis with summary statistics.

**Parameters:**
- `findings` (List[Dict[str, Any]]): Security findings

**Returns:**
- Dict[str, Any]: Summary containing:
  - `total_chains` (int): Number of detected chains
  - `critical_chains` (int): Count of CRITICAL severity chains
  - `high_chains` (int): Count of HIGH severity chains
  - `chains` (List[Dict]): Full chain details

**Example:**
```python
summary = run_correlation(findings)
print(f"Detected {summary['critical_chains']} critical attack chains")
```

---

## 2. Sistema de Remediación Automatizada

**Module**: `auditlens.remediation_tracker`

Tracks remediation progress by comparing baseline and current findings.

### Functions

#### `compare_findings(baseline: List[dict], current: List[dict]) -> Dict[str, Any]`

Compare two findings lists to track remediation progress.

**Parameters:**
- `baseline` (List[dict]): Findings from previous scan
- `current` (List[dict]): Findings from current scan

**Returns:**
- Dict[str, Any]: Comparison result containing:
  - `resolved` (List[dict]): Findings fixed since baseline
  - `new` (List[dict]): New findings not in baseline
  - `persistent` (List[dict]): Findings present in both scans
  - `improved` (List[dict]): Findings with reduced severity
  - `worsened` (List[dict]): Findings with increased severity
  - `stats` (Dict): Summary statistics:
    - `total_before` (int): Baseline finding count
    - `total_after` (int): Current finding count
    - `resolved_count` (int)
    - `new_count` (int)
    - `persistent_count` (int)
    - `resolution_rate` (int): Percentage of findings resolved
    - `score_before` (int): Baseline security score (0-100)
    - `score_after` (int): Current security score (0-100)
    - `score_delta` (int): Score change

**Example:**
```python
from auditlens.remediation_tracker import compare_findings

baseline = load_findings("baseline.json")
current = load_findings("current.json")

result = compare_findings(baseline, current)
print(f"Resolved: {result['stats']['resolved_count']}")
print(f"New issues: {result['stats']['new_count']}")
print(f"Score improved by: {result['stats']['score_delta']} points")
```

---

#### `print_remediation_summary(result: Dict[str, Any]) -> None`

Print formatted remediation summary to console.

**Parameters:**
- `result` (Dict[str, Any]): Output from `compare_findings()`

**Returns:**
- None

**Example:**
```python
print_remediation_summary(result)
# Outputs:
# ========================================================
#  REMEDIATION TRACKER — PROGRESO ENTRE AUDITORÍAS
# ========================================================
#
#   Hallazgos anteriores:  45
#   Hallazgos actuales:    32
#   ✓ Resueltos:   18
#   ✗ Nuevos:      5
```

---

#### `generate_tracker_html(result: Dict[str, Any], output_path: str) -> str`

Generate HTML report for remediation tracking.

**Parameters:**
- `result` (Dict[str, Any]): Output from `compare_findings()`
- `output_path` (str): Path to write HTML file

**Returns:**
- str: Path to generated HTML file

**Example:**
```python
html_path = generate_tracker_html(result, "remediation_report.html")
```

---

## 3. ML para Reducción de Falsos Positivos

**Module**: `auditlens.ml_classifier`

Machine Learning-based false positive reduction using heuristic classification.

### Functions

#### `calculate_fp_score(finding: Dict[str, Any]) -> float`

Calculate false positive probability for a single finding.

**Parameters:**
- `finding` (Dict[str, Any]): Finding to analyze, containing:
  - `file` (str): File path
  - `line` (int): Line number
  - `snippet` (str): Code snippet
  - `rule_id` (str): Rule identifier

**Returns:**
- float: False positive score (0.0 - 1.0). Higher = more likely to be false positive.

**Heuristics:**
- Test files: +0.4
- Example/demo files: +0.3
- Comments: +0.5
- Very long lines (>300 chars): +0.2
- SQL injection in ORM: +0.2
- Example secrets: +0.6
- Path traversal in static serving: +0.15

**Example:**
```python
from auditlens.ml_classifier import calculate_fp_score

finding = {
    "file": "tests/test_auth.py",
    "line": 42,
    "snippet": "password = 'test123'",
    "rule_id": "hardcoded-password"
}

fp_score = calculate_fp_score(finding)
print(f"False positive probability: {fp_score:.2f}")
# Output: False positive probability: 1.00 (test file + example password)
```

**Raises:**
- None

---

#### `classify_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]`

Run ML classifier on all findings.

**Parameters:**
- `findings` (List[Dict[str, Any]]): List of findings to classify

**Returns:**
- Dict[str, Any]: Classification results containing:
  - `total` (int): Total findings processed
  - `likely_true_positives` (int): Count of likely TP
  - `likely_false_positives` (int): Count of likely FP
  - `uncertain` (int): Count of uncertain findings
  - `metrics` (Dict): Performance metrics:
    - `precision` (float): Estimated precision %
    - `recall` (float): Estimated recall %
    - `f1_score` (float): F1 score
    - `accuracy` (float): Accuracy %
  - `findings` (List[Dict]): Original findings with added fields:
    - `fp_score` (float): False positive score
    - `ml_classification` (str): LIKELY_TRUE_POSITIVE | LIKELY_FALSE_POSITIVE | UNCERTAIN

**Example:**
```python
from auditlens.ml_classifier import classify_findings

result = classify_findings(all_findings)
print(f"True positives: {result['likely_true_positives']}")
print(f"False positives: {result['likely_false_positives']}")
print(f"Precision: {result['metrics']['precision']}%")

# Filter out likely false positives
real_issues = [
    f for f in result['findings']
    if f['ml_classification'] != 'LIKELY_FALSE_POSITIVE'
]
```

---

## 4. Arquitectura de Escaneo Distribuido

**Module**: `auditlens.multi_scan`

Multi-project scanning with unified reporting and parallel execution support.

### Functions

#### `run_multi_scan(paths: List[str], min_severity: str = 'LOW', run_sca: bool = True, export_format: str = 'text', output_path: Optional[str] = None) -> int`

Scan multiple projects and aggregate results.

**Parameters:**
- `paths` (List[str]): List of file or directory paths to scan
- `min_severity` (str): Minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL). Default: 'LOW'
- `run_sca` (bool): Enable Software Composition Analysis. Default: True
- `export_format` (str): Output format ('text', 'html', 'json', 'xlsx'). Default: 'text'
- `output_path` (Optional[str]): Path for output file. Default: auto-generated

**Returns:**
- int: Exit code (0 if no findings, 1 if findings detected)

**Example:**
```python
from auditlens.multi_scan import run_multi_scan

exit_code = run_multi_scan(
    paths=['./backend', './frontend', './mobile'],
    min_severity='HIGH',
    export_format='html',
    output_path='multi_audit.html'
)

# Console output:
# [AuditLens Multi-Scan] → ./backend
# [AuditLens Multi-Scan] → ./frontend
# [AuditLens Multi-Scan] → ./mobile
#
# Multi-Scan Summary
#   Project                        Total    C    H     M     L
#   ──────────────────────────────────────────────────────────
#   backend                           45    3   12    20    10
#   frontend                          28    1    8    15     4
#   mobile                            12    0    3     7     2
#
#   Total across all projects: 85 findings
```

**Raises:**
- None (prints error for invalid paths)

---

## 5. Policy-as-Code Framework

**Module**: `auditlens.rules_engine`

YAML-based security rules engine with regex pattern matching.

### Classes

#### `class Rule`

Represents a single security rule.

**Attributes:**
- `id` (str): Unique rule identifier
- `name` (str): Human-readable rule name
- `description` (str): Detailed description
- `languages` (List[str]): Applicable languages
- `regex_pattern` (str): Detection regex pattern
- `compliance` (List[str]): Compliance frameworks (ISO, OWASP, etc.)
- `severity` (str): Severity level

**Methods:**

##### `__init__(self, data: dict)`

Initialize rule from dictionary.

**Parameters:**
- `data` (dict): Rule configuration

**Raises:**
- Prints warning if regex is invalid (rule will be disabled)

##### `match_text(self, text: str) -> bool`

Test if text matches this rule.

**Parameters:**
- `text` (str): Code text to analyze

**Returns:**
- bool: True if match found

**Example:**
```python
rule_data = {
    "id": "SEC-01",
    "name": "Hardcoded Secret",
    "regex_pattern": r"password\s*=\s*['\"].*['\"]",
    "languages": ["python"],
    "severity": "HIGH"
}
rule = Rule(rule_data)
if rule.match_text("password = 'admin123'"):
    print("Vulnerability detected!")
```

---

#### `class RulesEngine`

Loads and manages security rules.

**Methods:**

##### `__init__(self, rules_file: str | None = None)`

Initialize rules engine.

**Parameters:**
- `rules_file` (str | None): Path to YAML rules file. Default: `./auditlens/rules.yaml`

**Raises:**
- Prints warning if rules file not found or invalid

**Example:**
```python
from auditlens.rules_engine import RulesEngine

# Load default rules
engine = RulesEngine()

# Load custom rules
custom_engine = RulesEngine("custom_rules.yaml")
```

##### `get_rules_for_language(self, ext: str, filename: str = '') -> List[Rule]`

Get applicable rules for a file.

**Parameters:**
- `ext` (str): File extension (e.g., '.py', '.js')
- `filename` (str): Full filename for disambiguation (e.g., 'Dockerfile')

**Returns:**
- List[Rule]: Rules applicable to this language

**Supported Languages:**
- Python (.py)
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- Swift (.swift)
- Go (.go)
- Java (.java)
- Kotlin (.kt)
- Ruby (.rb)
- PHP (.php)
- Terraform (.tf, .hcl)
- Docker (Dockerfile)
- YAML (.yaml, .yml) - with K8s/Docker Compose detection

**Example:**
```python
engine = RulesEngine()
python_rules = engine.get_rules_for_language('.py')
print(f"Found {len(python_rules)} Python rules")

# With filename for disambiguation
k8s_rules = engine.get_rules_for_language('.yaml', 'deployment.yaml')
```

---

## 6. Language Server Protocol

**Module**: `lsp-server.server`

Real-time security analysis in IDEs via Language Server Protocol.

### Classes

#### `LanguageServer`

LSP server implementation using `pygls`.

**Global Instance:**
```python
server = LanguageServer("auditlens-server", "v0.2")
```

### Functions

#### `validate_code(ls: LanguageServer, uri: str, text: str) -> None`

Validate code and publish diagnostics.

**Parameters:**
- `ls` (LanguageServer): Server instance
- `uri` (str): Document URI
- `text` (str): Document text content

**Returns:**
- None (publishes diagnostics to client)

---

#### `did_open(ls: LanguageServer, params: DidOpenTextDocumentParams) -> None`

Handler for document open events.

**Parameters:**
- `ls` (LanguageServer): Server instance
- `params` (DidOpenTextDocumentParams): Open event parameters

**Decorator:**
- `@server.feature(TEXT_DOCUMENT_DID_OPEN)`

---

#### `did_change(ls: LanguageServer, params: DidChangeTextDocumentParams) -> None`

Handler for document change events.

**Parameters:**
- `ls` (LanguageServer): Server instance
- `params` (DidChangeTextDocumentParams): Change event parameters

**Decorator:**
- `@server.feature(TEXT_DOCUMENT_DID_CHANGE)`

---

**Usage:**

Start the LSP server:
```bash
cd lsp-server
python server.py
```

VSCode integration (`settings.json`):
```json
{
  "auditlens.lsp.enabled": true,
  "auditlens.lsp.serverCommand": "python /path/to/lsp-server/server.py"
}
```

**Features:**
- Real-time security diagnostics as you type
- Inline warnings for vulnerabilities
- Severity-based diagnostic levels
- File-based caching for performance

---

## 7. Dashboard Predictivo

**Module**: `auditlens.predictive_dashboard`

Trend forecasting and risk predictions based on historical scan data.

### Functions

#### `predict_trends(history: List[Dict[str, Any]]) -> Dict[str, Any]`

Analyze historical scan data and predict future vulnerability trends.

**Parameters:**
- `history` (List[Dict[str, Any]]): Historical scan records, each containing:
  - `scanned_at` (str): ISO timestamp
  - `critical` (int): Critical finding count
  - `high` (int): High finding count
  - `medium` (int): Medium finding count
  - `low` (int): Low finding count

**Returns:**
- Dict[str, Any]: Predictions containing:
  - `status` (str): "success" or "insufficient_data"
  - `current_state` (Dict): Current severity counts
  - `trends` (Dict): Linear regression trends per severity
    - `critical_trend` (float): Growth rate
    - `high_trend` (float)
    - `medium_trend` (float)
    - `low_trend` (float)
    - `overall_trend` (str): INCREASING | STABLE | DECREASING
  - `predictions` (List[Dict]): Forecasts for 7, 30, 90 days:
    - `days_ahead` (int)
    - `predicted_date` (str)
    - `critical` (int): Predicted count
    - `high` (int)
    - `medium` (int)
    - `low` (int)
    - `total` (int)
    - `risk_level` (str): HIGH | MEDIUM | LOW
  - `debt_analysis` (Dict): Technical debt metrics
    - `current_debt` (int): Current total findings
    - `projected_debt_90d` (int): 90-day projection
    - `growth_percentage` (float): Growth rate
    - `recommended_action` (str): URGENT | MONITOR | MAINTAIN

**Example:**
```python
from auditlens.predictive_dashboard import predict_trends

history = [
    {"scanned_at": "2026-01-01", "critical": 5, "high": 12, "medium": 28, "low": 45},
    {"scanned_at": "2026-02-01", "critical": 6, "high": 15, "medium": 30, "low": 42},
    {"scanned_at": "2026-03-01", "critical": 8, "high": 18, "medium": 35, "low": 40}
]

forecast = predict_trends(history)
if forecast['status'] == 'success':
    for pred in forecast['predictions']:
        print(f"{pred['days_ahead']} days: {pred['total']} findings (Risk: {pred['risk_level']})")
    
    print(f"\nTechnical debt growth: {forecast['debt_analysis']['growth_percentage']:.1f}%")
    print(f"Action required: {forecast['debt_analysis']['recommended_action']}")
```

**Raises:**
- None (returns `insufficient_data` status if < 2 scans)

---

#### `estimate_fix_time(findings: List[Dict[str, Any]]) -> Dict[str, Any]`

Estimate time required to fix all findings based on severity.

**Parameters:**
- `findings` (List[Dict[str, Any]]): Security findings

**Returns:**
- Dict[str, Any]: Time estimates:
  - `total_findings` (int)
  - `estimated_hours` (float): Total hours
  - `estimated_days` (float): Person-days (8-hour workday)
  - `estimated_weeks` (float): Person-weeks
  - `severity_breakdown_hours` (Dict): Hours per severity

**Time Assumptions:**
- CRITICAL: 4 hours average
- HIGH: 2 hours average
- MEDIUM: 1 hour average
- LOW: 0.5 hours average

**Example:**
```python
from auditlens.predictive_dashboard import estimate_fix_time

estimates = estimate_fix_time(findings)
print(f"Total time to fix: {estimates['estimated_days']} person-days")
print(f"  ({estimates['estimated_weeks']} weeks)")
print(f"\nBreakdown:")
for sev, hours in estimates['severity_breakdown_hours'].items():
    print(f"  {sev}: {hours} hours")
```

---

## 8. Supply Chain Security Suite

**Module**: `auditlens.supply_chain_guard`

SBOM generation and dependency vulnerability tracking.

### Functions

#### `parse_requirements_txt(path: str) -> List[Dict[str, str]]`

Parse Python requirements.txt file.

**Parameters:**
- `path` (str): Path to requirements.txt

**Returns:**
- List[Dict[str, str]]: List of dependencies, each containing:
  - `name` (str): Package name
  - `version` (str): Version number or "unknown"
  - `constraint` (str): Version constraint (==, >=, etc.)

**Example:**
```python
from auditlens.supply_chain_guard import parse_requirements_txt

deps = parse_requirements_txt("requirements.txt")
for dep in deps:
    print(f"{dep['name']} {dep['constraint']} {dep['version']}")
```

---

#### `parse_package_json(path: str) -> List[Dict[str, str]]`

Parse Node.js package.json file.

**Parameters:**
- `path` (str): Path to package.json

**Returns:**
- List[Dict[str, str]]: List of dependencies with:
  - `name` (str)
  - `version` (str): Clean version (^ and ~ removed)
  - `constraint` (str): "dependencies" or "devDependencies"

---

#### `check_known_vulns(deps: List[Dict[str, str]]) -> List[Dict[str, Any]]`

Check dependencies against known vulnerabilities.

**Parameters:**
- `deps` (List[Dict[str, str]]): Dependencies from parse functions

**Returns:**
- List[Dict[str, Any]]: Vulnerabilities found, each containing:
  - `package` (str): Vulnerable package name
  - `installed_version` (str)
  - `vulnerable_range` (str): Version range with vulnerability
  - `cve_id` (str): CVE identifier
  - `severity` (str): Vulnerability severity
  - `fixed_version` (str): Version with fix

**Example:**
```python
from auditlens.supply_chain_guard import parse_requirements_txt, check_known_vulns

deps = parse_requirements_txt("requirements.txt")
vulns = check_known_vulns(deps)

for vuln in vulns:
    print(f"[{vuln['severity']}] {vuln['package']} {vuln['installed_version']}")
    print(f"  CVE: {vuln['cve_id']}")
    print(f"  Fix: Upgrade to {vuln['fixed_version']}")
```

**Known Vulnerability Database:**
- Flask, Django, Requests, urllib3 (Python)
- lodash, axios, express, moment (JavaScript)

**Note:** In production, this should query real CVE databases (OSV, NVD, Snyk).

---

#### `generate_sbom(scan_path: str) -> Dict[str, Any]`

Generate Software Bill of Materials (SBOM) for a project.

**Parameters:**
- `scan_path` (str): Root directory of the project

**Returns:**
- Dict[str, Any]: SBOM containing:
  - `format` (str): "AuditLens-SBOM-1.0"
  - `generated_at` (str): ISO timestamp
  - `project_path` (str)
  - `total_dependencies` (int)
  - `dependencies` (List[Dict]): All dependencies
  - `vulnerabilities` (Dict): Vulnerability summary
    - `total` (int)
    - `critical`, `high`, `medium`, `low` (int): Counts per severity
    - `details` (List[Dict]): Full vulnerability details
  - `risk_score` (Dict): Supply chain risk assessment

**Example:**
```python
from auditlens.supply_chain_guard import generate_sbom, export_sbom_json

sbom = generate_sbom("./my_project")
print(f"Total dependencies: {sbom['total_dependencies']}")
print(f"Vulnerabilities found: {sbom['vulnerabilities']['total']}")
print(f"Risk level: {sbom['risk_score']['level']}")

# Export to JSON
export_sbom_json(sbom, "sbom.json")
```

---

#### `calculate_supply_chain_risk(deps: List[Dict[str, str]], vulns: List[Dict[str, Any]]) -> Dict[str, Any]`

Calculate overall supply chain risk score.

**Parameters:**
- `deps` (List[Dict[str, str]]): All dependencies
- `vulns` (List[Dict[str, Any]]): Known vulnerabilities

**Returns:**
- Dict[str, Any]: Risk assessment:
  - `score` (int): Numeric risk score
  - `level` (str): CRITICAL | HIGH | MEDIUM | LOW | NONE
  - `total_dependencies` (int)
  - `vulnerable_dependencies` (int): Unique packages with vulnerabilities
  - `message` (str): Summary message

**Scoring Formula:**
```
score = (critical_vulns × 10) + (high_vulns × 5) + (total_vulns × 1)

Risk Levels:
- CRITICAL: score >= 50 or critical >= 3
- HIGH: score >= 20 or high >= 5
- MEDIUM: score >= 5
- LOW: score < 5
```

---

#### `export_sbom_json(sbom: Dict[str, Any], output_path: str) -> None`

Export SBOM to JSON file.

**Parameters:**
- `sbom` (Dict[str, Any]): SBOM from `generate_sbom()`
- `output_path` (str): Output file path

**Returns:**
- None

---

## 9. Security Test Generator

**Module**: `auditlens.test_analyzer`

Test coverage analysis and ISO 12207 compliance scoring.

### Functions

#### `analyze_test_coverage(root_path: str) -> Dict`

Scan a project directory and return test coverage analysis.

**Parameters:**
- `root_path` (str): Root directory of the project to analyze

**Returns:**
- Dict: Test coverage metrics containing:
  - `total_archivos_fuente` (int): Total source files
  - `total_archivos_test` (int): Total test files
  - `ratio_cobertura_estimado` (float): Estimated coverage ratio (0-100)
  - `archivos_sin_tests` (List[str]): Files without tests (max 20)
  - `total_sin_tests` (int): Count of untested files
  - `tiene_config_tests` (bool): Has test configuration
  - `tipos_pruebas` (Dict): Test types detected:
    - `unitarias` (bool): Has unit tests
    - `seguridad` (bool): Has security tests
    - `integracion` (bool): Has integration tests
  - `tests_seguridad` (List[str]): Security test files (max 5)
  - `tests_integracion` (List[str]): Integration test files (max 5)
  - `puntuacion_iso12207` (int): ISO 12207 V&V compliance score (0-100)
  - `brechas_identificadas` (List[Dict]): Testing gaps with recommendations

**ISO 12207 Scoring (0-100):**
- Has any tests: +30
- Reasonable test ratio (≥1.0): +30 (or +20 for ≥0.5, +10 for ≥0.2)
- Security tests present: +20
- Integration tests present: +10
- Test configuration present: +10

**Example:**
```python
from auditlens.test_analyzer import analyze_test_coverage
import json

coverage = analyze_test_coverage("./backend")

print(f"Source files: {coverage['total_archivos_fuente']}")
print(f"Test files: {coverage['total_archivos_test']}")
print(f"Coverage ratio: {coverage['ratio_cobertura_estimado']:.1f}%")
print(f"ISO 12207 score: {coverage['puntuacion_iso12207']}/100")

print("\nTest types:")
for test_type, present in coverage['tipos_pruebas'].items():
    status = "✓" if present else "✗"
    print(f"  {status} {test_type}")

print(f"\nGaps identified: {len(coverage['brechas_identificadas'])}")
for gap in coverage['brechas_identificadas']:
    print(f"\n[{gap['impacto']}] {gap['brecha']}")
    print(f"  Recommendation: {gap['recomendacion']}")
    print(f"  Timeframe: {gap['plazo']}")
```

**Detected Test Patterns:**
- Python: `test_*.py`, `*_test.py`
- JavaScript/TypeScript: `*.test.js`, `*.spec.ts`, `*.test.tsx`
- Java: `*Test.java`
- Go: `*_test.go`
- Ruby: `*_spec.rb`

**Test Directories:**
- `tests/`, `test/`, `__tests__/`, `spec/`, `specs/`, `e2e/`

**Security Test Detection:**
- Keywords: security, pentest, injection, xss, sql, csrf, auth
- Patterns: test_password, test_token, test_secret

**Integration Test Detection:**
- Keywords: integration, e2e, end-to-end, api_test, functional

**Raises:**
- None (handles errors gracefully)

---

## 10. Multi-Tenancy Architecture

**Module**: `auditlens.dashboard`

Web dashboard with multi-user support and scan history tracking.

### Functions

#### `serve_dashboard(scan_path: str, port: int = 8080, scan_first: bool = False, host: str = '127.0.0.1') -> None`

Launch interactive web dashboard for scan visualization.

**Parameters:**
- `scan_path` (str): Project directory to scan/analyze
- `port` (int): HTTP server port. Default: 8080
- `scan_first` (bool): Run a fresh scan before opening dashboard. Default: False
- `host` (str): Server host address. Default: '127.0.0.1'

**Returns:**
- None (blocks until server is stopped with Ctrl+C)

**Features:**
- Real-time severity trend charts (Chart.js)
- Filterable findings table
- File vulnerability heatmap
- Compliance framework breakdown
- Scan comparison (baseline vs current)
- Historical scan timeline
- Export to JSON/HTML/PDF

**Example:**
```python
from auditlens.dashboard import serve_dashboard

# Launch dashboard on default port
serve_dashboard("./my_project")

# Launch with fresh scan
serve_dashboard("./my_project", scan_first=True)

# Custom port
serve_dashboard("./my_project", port=9000)
```

**CLI Usage:**
```bash
# Basic usage
auditlens serve ./my_project

# Custom port
auditlens serve ./my_project --port 8080

# Scan before opening
auditlens serve ./my_project --scan-first

# Allow external access
auditlens serve ./my_project --host 0.0.0.0
```

**Dashboard Routes:**
- `GET /` - Main dashboard UI
- `GET /api/scan` - Get scan results
- `GET /api/history` - Get scan history
- `GET /api/stats` - Get statistics
- `POST /api/rescan` - Trigger new scan
- `GET /api/export` - Export results

**Browser Opens:**
```
http://localhost:8080
```

**Raises:**
- OSError: If port is already in use
- PermissionError: If insufficient permissions for port < 1024

---

### Internal Functions

#### `_build_app(scan_path: str, db_path: Optional[str] = None) -> Flask`

Build Flask application instance.

**Parameters:**
- `scan_path` (str): Project root path
- `db_path` (Optional[str]): SQLite database path for history. Default: `.auditlens/history.db`

**Returns:**
- Flask: Configured Flask app

**Note:** This is an internal function. Use `serve_dashboard()` instead.

---

## Remediation AI (AI Auto-Patch)

**Module**: `auditlens.ai_fix`

Automated vulnerability remediation using AI API.

### Functions

#### `suggest_fix(finding: dict, api_key: Optional[str] = None, model: str = 'ai-model-latest', patch_mode: bool = False) -> Optional[str]`

Generate AI-powered fix suggestion for a vulnerability.

**Parameters:**
- `finding` (dict): Finding to fix, containing:
  - `rule_id` (str)
  - `name` (str)
  - `severity` (str)
  - `file` (str): Path to vulnerable file
  - `line` (int): Vulnerable line number
  - `compliance` (List[str])
  - `description` (str)
- `api_key` (Optional[str]): AI API key. Default: `ANTHROPIC_API_KEY` env var
- `model` (str): AI model to use. Default: 'ai-model-latest'
- `patch_mode` (bool): Return unified diff instead of explanation. Default: False

**Returns:**
- Optional[str]: Fix suggestion text or unified diff, None on error

**Example:**
```python
from auditlens.ai_fix import suggest_fix
import os

os.environ['ANTHROPIC_API_KEY'] = 'sk-...'

finding = {
    "rule_id": "SEC-01-HARDCODED-SECRET",
    "name": "Hardcoded Secret",
    "severity": "CRITICAL",
    "file": "config.py",
    "line": 42,
    "compliance": ["OWASP A02"],
    "description": "Hardcoded credentials detected"
}

# Get explanation and fix
suggestion = suggest_fix(finding)
print(suggestion)

# Get unified diff for auto-patching
diff = suggest_fix(finding, patch_mode=True)
if diff:
    print(diff)
```

**Raises:**
- ImportError: If anthropic package not installed
- Prints error message if API key not set or API request fails

---

#### `apply_patch(diff_text: str, base_dir: str, dry_run: bool = False) -> Tuple[bool, str]`

Apply a unified diff patch to the filesystem.

**Parameters:**
- `diff_text` (str): Unified diff patch text
- `base_dir` (str): Base directory for patch application
- `dry_run` (bool): Test patch without writing. Default: False

**Returns:**
- Tuple[bool, str]: (success, message)
  - success (bool): True if patch applied successfully
  - message (str): Result message or error details

**Example:**
```python
from auditlens.ai_fix import suggest_fix, apply_patch

# Generate AI patch
diff = suggest_fix(finding, patch_mode=True)

# Test patch (dry-run)
success, msg = apply_patch(diff, "./project", dry_run=True)
if success:
    print("Patch can be applied")
    # Apply for real
    success, msg = apply_patch(diff, "./project")
    print(msg)
```

**Requires:**
- `patch` command must be available on system

**Raises:**
- FileNotFoundError: If `patch` command not found
- Exception: For other patch application errors

---

#### `run_ai_fix(findings: List[dict], min_severity: str = 'HIGH', rule_filter: Optional[str] = None, api_key: Optional[str] = None, model: str = 'ai-model-latest', output_path: Optional[str] = None, apply_patches: bool = False, dry_run: bool = False, project_root: Optional[str] = None) -> None`

Batch process findings with AI-powered fixes.

**Parameters:**
- `findings` (List[dict]): All findings to process
- `min_severity` (str): Minimum severity to fix. Default: 'HIGH'
- `rule_filter` (Optional[str]): Filter by specific rule ID
- `api_key` (Optional[str]): AI API key
- `model` (str): AI model. Default: 'ai-model-latest'
- `output_path` (Optional[str]): Save results to JSON file
- `apply_patches` (bool): Auto-apply patches to files. Default: False
- `dry_run` (bool): Test patches without writing. Default: False
- `project_root` (Optional[str]): Project root directory. Default: current directory

**Returns:**
- None (prints results to console, optionally saves to file)

**Example:**
```python
from auditlens.ai_fix import run_ai_fix
import json

# Load findings
with open("audit_results.json") as f:
    findings = json.load(f)

# Get suggestions (safe mode)
run_ai_fix(
    findings,
    min_severity='HIGH',
    output_path='fix_suggestions.json'
)

# Auto-fix mode (test first with dry_run)
run_ai_fix(
    findings,
    min_severity='CRITICAL',
    apply_patches=True,
    dry_run=True,
    project_root='./backend'
)

# Apply patches for real (use with caution!)
run_ai_fix(
    findings,
    rule_filter='SEC-01-HARDCODED-SECRET',
    apply_patches=True,
    project_root='./backend'
)
```

**CLI Usage:**
```bash
# Get fix suggestions
auditlens fix ./project --severity HIGH

# Auto-patch (dry-run first)
auditlens fix ./project --severity CRITICAL --apply --dry-run

# Apply patches for specific rule
auditlens fix ./project --rule SEC-01 --apply

# Save suggestions to file
auditlens fix ./project -o fixes.json
```

**Raises:**
- None (prints errors for individual failures)

---

## Exception Classes

AuditLens uses standard Python exceptions and prints error messages to console. No custom exception classes are currently exposed in the public API.

**Common Error Patterns:**

```python
# File not found
if not os.path.exists(path):
    print(f"\033[91m[AuditLens]\033[0m Path not found: {path}")
    return

# Invalid configuration
if not config.get('api_key'):
    print(f"\033[91m[AuditLens]\033[0m API key not configured")
    return None

# Regex compilation error (rules_engine)
try:
    regex = re.compile(pattern)
except re.error as exc:
    print(f"\033[93m[AuditLens] Warning: invalid regex: {exc}\033[0m")
```

---

## Type Definitions

Common type structures used across the API:

### Finding

```python
{
    "rule_id": str,           # e.g., "SEC-01-HARDCODED-SECRET"
    "name": str,              # Human-readable rule name
    "severity": str,          # LOW | MEDIUM | HIGH | CRITICAL
    "file": str,              # Absolute or relative file path
    "line": int,              # Line number (1-indexed)
    "snippet": str,           # Code snippet (optional)
    "description": str,       # Vulnerability description
    "compliance": List[str],  # e.g., ["OWASP A02", "ISO 27001 A.14"]
    "cwe": Optional[str],     # CWE identifier (optional)
    "recommendation": str     # Fix recommendation (optional)
}
```

### Scan History Entry

```python
{
    "scanned_at": str,        # ISO 8601 timestamp
    "scan_path": str,         # Root path scanned
    "total_findings": int,
    "critical": int,
    "high": int,
    "medium": int,
    "low": int,
    "files_scanned": int,
    "scan_duration_ms": int,
    "findings": List[Finding]
}
```

### Dependency

```python
{
    "name": str,              # Package name
    "version": str,           # Version number or "unknown"
    "constraint": str         # Version constraint or dependency type
}
```

### Vulnerability

```python
{
    "package": str,
    "installed_version": str,
    "vulnerable_range": str,  # e.g., "<2.20.0"
    "cve_id": str,           # e.g., "CVE-2023-12345"
    "severity": str,
    "fixed_version": str
}
```

---

## Configuration

### Environment Variables

```bash
# AI Fix Engine
export ANTHROPIC_API_KEY="sk-..."

# Dashboard (optional)
export AUDITLENS_PORT="8080"
export AUDITLENS_HOST="127.0.0.1"

# Rules Engine (optional)
export AUDITLENS_RULES="/path/to/custom_rules.yaml"
```

### Rules File Format (YAML)

```yaml
rules:
  - id: SEC-01-HARDCODED-SECRET
    name: Hardcoded Secret
    description: Hardcoded credentials detected in source code
    languages:
      - python
      - javascript
      - typescript
    regex_pattern: '(password|secret|api[_-]?key)\s*=\s*[''"][\w\-]{8,}[''"]'
    severity: CRITICAL
    compliance:
      - OWASP A02
      - ISO 27001 A.9
      - NIST 800-53 IA-5

  - id: SEC-02-SQL-INJECTION
    name: SQL Injection
    description: Potential SQL injection vulnerability
    languages:
      - python
      - java
      - php
    regex_pattern: 'execute\(.*\+.*\)'
    severity: CRITICAL
    compliance:
      - OWASP A03
      - CWE-89
```

---

## Performance Notes

### Optimization Tips

1. **Large Codebases**: Use `--exclude` to skip vendor directories:
   ```bash
   auditlens scan . --exclude node_modules,venv,build
   ```

2. **ML Classifier**: Reduces false positives by ~30-40%:
   ```python
   classified = classify_findings(findings)
   real_issues = [
       f for f in classified['findings']
       if f['ml_classification'] != 'LIKELY_FALSE_POSITIVE'
   ]
   ```

3. **Multi-Scan**: Use `--min-severity HIGH` for faster initial scans:
   ```bash
   auditlens multi-scan ./repo1 ./repo2 --severity HIGH
   ```

4. **Dashboard**: SQLite history DB is auto-indexed. For large projects (>10k findings), consider periodic cleanup:
   ```bash
   sqlite3 .auditlens/history.db "DELETE FROM scans WHERE created_at < date('now', '-90 days');"
   ```

---

## Version Compatibility

**AuditLens 0.10.0 Requirements:**
- Python 3.9+
- anthropic >= 0.21.0 (for AI Fix)
- pygls >= 1.1.0 (for LSP)
- Flask >= 2.3.0 (for Dashboard)
- PyYAML >= 6.0

**Optional Dependencies:**
- openpyxl >= 3.1.0 (Excel export)
- python-docx >= 0.8.11 (Word export)
- reportlab >= 4.0.0 (PDF export)

---

## Support & Documentation

- **Full Documentation**: `README.md`, `ARCHITECTURE.md`
- **CLI Reference**: `auditlens --help`
- **Rule Writing Guide**: `docs/RULES.md`
- **API Examples**: `examples/` directory
- **Issue Tracker**: GitHub Issues

---

**End of API Reference**

Last updated: 2026-06-17  
AuditLens v0.10.0
