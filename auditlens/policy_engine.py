"""
AuditLens Policy-as-Code Framework

Evaluate scan findings against declarative policies for CI/CD enforcement,
compliance validation, and custom security gates.

Features:
- YAML/JSON policy definitions with versioning
- DSL for expressive rule matching (severity, files, compliance, CWE/OWASP)
- Threshold enforcement (max critical/high, fail_on_severity)
- Policy registry with semantic versioning and diffing
- Unit testing for policies with fixture-based test cases
- Compliance framework mapping (PCI-DSS, ISO27001, GDPR, etc.)
- Action system (fail, warn, suppress, tag, notify)
"""

from __future__ import annotations

import json
import os
import re
import hashlib
import fnmatch
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# ── Data Structures ───────────────────────────────────────────────────────────


class PolicyViolation:
    """Single policy violation with finding reference and remediation guidance."""

    def __init__(self, finding: dict, rule: 'PolicyRule', message: str):
        self.finding = finding
        self.rule = rule
        self.message = message
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            'finding': self.finding,
            'rule_id': self.rule.id,
            'message': self.message,
            'timestamp': self.timestamp,
            'severity': self.finding.get('severity', 'UNKNOWN'),
            'file': self.finding.get('file', 'unknown'),
            'line': self.finding.get('line', 0),
        }


class PolicyResult:
    """Result of policy evaluation with pass/fail status and violations."""

    def __init__(self, policy: 'Policy', passed: bool, violations: List[PolicyViolation],
                 context: Optional[dict] = None):
        self.policy = policy
        self.passed = passed
        self.violations = violations
        self.context = context or {}
        self.evaluation_time = 0.0
        self.metrics = self._compute_metrics()

    def _compute_metrics(self) -> dict:
        by_severity: Dict[str, int] = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        by_rule: Dict[str, int] = {}

        for violation in self.violations:
            sev = violation.finding.get('severity', 'UNKNOWN').upper()
            if sev in by_severity:
                by_severity[sev] += 1

            rule_id = violation.rule.id
            by_rule[rule_id] = by_rule.get(rule_id, 0) + 1

        return {
            'total_findings': len(set(id(v.finding) for v in self.violations)),
            'total_violations': len(self.violations),
            'by_severity': by_severity,
            'by_rule': by_rule,
        }

    def to_dict(self) -> dict:
        return {
            'passed': self.passed,
            'policy': {
                'name': self.policy.name,
                'version': self.policy.version,
                'description': self.policy.metadata.get('description', ''),
            },
            'violations': [v.to_dict() for v in self.violations],
            'metrics': self.metrics,
            'evaluation_time': self.evaluation_time,
            'context': self.context,
        }

    def to_json(self, path: str) -> None:
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(self.to_dict(), fh, indent=2, default=str)

    def print_summary(self) -> None:
        status = '\033[92mPASSED\033[0m' if self.passed else '\033[91mFAILED\033[0m'
        print(f'\n\033[1m[Policy Evaluation]\033[0m {status}')
        print(f'  Policy: {self.policy.name} v{self.policy.version}')
        print(f'  Violations: {len(self.violations)}')
        print(f'  Metrics:')
        print(f'    CRITICAL: {self.metrics["by_severity"]["CRITICAL"]}')
        print(f'    HIGH:     {self.metrics["by_severity"]["HIGH"]}')
        print(f'    MEDIUM:   {self.metrics["by_severity"]["MEDIUM"]}')
        print(f'    LOW:      {self.metrics["by_severity"]["LOW"]}')
        print(f'  Evaluation time: {self.evaluation_time:.3f}s')

    def get_violations_by_severity(self) -> dict:
        result: Dict[str, List[PolicyViolation]] = {
            'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []
        }
        for v in self.violations:
            sev = v.finding.get('severity', 'LOW').upper()
            if sev in result:
                result[sev].append(v)
        return result


class ValidationResult:
    """Policy validation result with errors, warnings, and suggestions."""

    def __init__(self, valid: bool, errors: List[str], warnings: List[str]):
        self.valid = valid
        self.errors = errors
        self.warnings = warnings

    def to_dict(self) -> dict:
        return {
            'valid': self.valid,
            'errors': self.errors,
            'warnings': self.warnings,
        }

    def print_summary(self) -> None:
        if self.valid:
            print('\033[92m[Policy Validation] VALID\033[0m')
        else:
            print('\033[91m[Policy Validation] INVALID\033[0m')

        if self.errors:
            print('\n  Errors:')
            for err in self.errors:
                print(f'    - {err}')

        if self.warnings:
            print('\n  Warnings:')
            for warn in self.warnings:
                print(f'    - {warn}')


class PolicyVersion:
    """Metadata for a versioned policy in the registry."""

    def __init__(self, version: str, hash_value: str, created_at: str,
                 author: str, changelog: str):
        self.version = version
        self.hash = hash_value
        self.created_at = created_at
        self.author = author
        self.changelog = changelog

    def to_dict(self) -> dict:
        return {
            'version': self.version,
            'hash': self.hash,
            'created_at': self.created_at,
            'author': self.author,
            'changelog': self.changelog,
        }


class PolicyDiff:
    """Semantic diff between two policy versions."""

    def __init__(self, v1: str, v2: str, added_rules: List[str],
                 removed_rules: List[str], modified_rules: List[str],
                 threshold_changes: dict):
        self.v1 = v1
        self.v2 = v2
        self.added_rules = added_rules
        self.removed_rules = removed_rules
        self.modified_rules = modified_rules
        self.threshold_changes = threshold_changes

    def to_dict(self) -> dict:
        return {
            'v1': self.v1,
            'v2': self.v2,
            'added_rules': self.added_rules,
            'removed_rules': self.removed_rules,
            'modified_rules': self.modified_rules,
            'threshold_changes': self.threshold_changes,
        }

    def __str__(self) -> str:
        lines = [f'Policy Diff: {self.v1} → {self.v2}']
        if self.added_rules:
            lines.append(f'  + Added rules: {", ".join(self.added_rules)}')
        if self.removed_rules:
            lines.append(f'  - Removed rules: {", ".join(self.removed_rules)}')
        if self.modified_rules:
            lines.append(f'  ~ Modified rules: {", ".join(self.modified_rules)}')
        if self.threshold_changes:
            lines.append(f'  Threshold changes: {self.threshold_changes}')
        return '\n'.join(lines)


class PolicyTestCase:
    """Unit test definition for policies with expected violations."""

    def __init__(self, name: str, description: str, findings: List[dict],
                 expected: dict, context: Optional[dict] = None):
        self.name = name
        self.description = description
        self.findings = findings
        self.expected = expected
        self.context = context or {}

    @staticmethod
    def from_yaml(path: str) -> List['PolicyTestCase']:
        if not _YAML_AVAILABLE:
            raise ImportError('PyYAML is required for loading test cases from YAML')

        with open(path, 'r', encoding='utf-8') as fh:
            data = yaml.safe_load(fh)

        test_cases = []
        for tc_data in data.get('test_cases', []):
            test_cases.append(PolicyTestCase(
                name=tc_data['name'],
                description=tc_data.get('description', ''),
                findings=tc_data['input']['findings'],
                expected=tc_data['expected'],
                context=tc_data['input'].get('context', {}),
            ))

        return test_cases

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'description': self.description,
            'input': {
                'findings': self.findings,
                'context': self.context,
            },
            'expected': self.expected,
        }


class TestResult:
    """Result of running policy tests."""

    def __init__(self, passed: int, failed: int, failures: List[dict]):
        self.passed = passed
        self.failed = failed
        self.failures = failures

    def to_dict(self) -> dict:
        return {
            'passed': self.passed,
            'failed': self.failed,
            'total': self.passed + self.failed,
            'failures': self.failures,
        }

    def print_summary(self) -> None:
        total = self.passed + self.failed
        if self.failed == 0:
            print(f'\033[92m[Policy Tests] PASSED {self.passed}/{total}\033[0m')
        else:
            print(f'\033[91m[Policy Tests] FAILED {self.failed}/{total}\033[0m')

        for failure in self.failures:
            print(f'\n  Test: {failure["test_name"]}')
            print(f'    Expected: {failure["expected"]}')
            print(f'    Got: {failure["actual"]}')


# ── Policy DSL and Matcher ────────────────────────────────────────────────────


class RuleMatcher:
    """
    DSL expression engine for matching findings.

    Supported syntax:
      - rule_id == 'SEC-01-HARDCODED-SECRET'
      - severity in ['HIGH', 'CRITICAL']
      - file matches 'src/**/*.py'
      - compliance contains 'PCI-DSS'
      - (severity == 'CRITICAL') and (file not matches 'tests/**')
      - count(findings where severity == 'HIGH') > 10
    """

    _OPERATORS = {'==', '!=', 'in', 'not in', 'matches', 'not matches',
                  'contains', '>', '<', '>=', '<=', 'and', 'or'}

    def __init__(self, expression: str | dict):
        if isinstance(expression, dict):
            self.expression = self._dict_to_expression(expression)
        else:
            self.expression = expression

        self._compiled_patterns: Dict[str, re.Pattern] = {}

    def _dict_to_expression(self, d: dict) -> str:
        """Convert dict-based matcher to DSL expression."""
        parts = []
        if 'rule_id' in d:
            parts.append(f"rule_id == '{d['rule_id']}'")
        if 'severity' in d:
            if isinstance(d['severity'], list):
                parts.append(f"severity in {d['severity']}")
            else:
                parts.append(f"severity == '{d['severity']}'")
        if 'file_pattern' in d:
            parts.append(f"file matches '{d['file_pattern']}'")
        if 'compliance' in d:
            if isinstance(d['compliance'], list):
                for tag in d['compliance']:
                    parts.append(f"compliance contains '{tag}'")
            else:
                parts.append(f"compliance contains '{d['compliance']}'")

        return ' and '.join(parts) if parts else 'true'

    @lru_cache(maxsize=128)
    def _compile_pattern(self, pattern: str) -> re.Pattern:
        """Convert glob pattern to regex."""
        regex = fnmatch.translate(pattern)
        return re.compile(regex, re.IGNORECASE)

    def evaluate(self, finding: dict) -> bool:
        """Evaluate matcher against a finding."""
        try:
            return self._eval_expression(self.expression, finding)
        except Exception as e:
            print(f'\033[93m[PolicyEngine] Matcher evaluation error: {e}\033[0m')
            return False

    def _eval_expression(self, expr: str, finding: dict) -> bool:
        """Recursively evaluate DSL expression."""
        expr = expr.strip()

        if expr == 'true':
            return True
        if expr == 'false':
            return False

        # Handle parentheses
        if expr.startswith('(') and expr.endswith(')'):
            return self._eval_expression(expr[1:-1], finding)

        # Logical operators (process outermost first)
        for op in [' or ', ' and ']:
            if op in expr:
                parts = self._split_logical(expr, op.strip())
                if len(parts) > 1:
                    if op.strip() == 'or':
                        return any(self._eval_expression(p, finding) for p in parts)
                    else:
                        return all(self._eval_expression(p, finding) for p in parts)

        # Comparison operators
        if ' == ' in expr:
            field, value = self._parse_comparison(expr, '==')
            return self._get_field(finding, field) == self._parse_value(value)

        if ' != ' in expr:
            field, value = self._parse_comparison(expr, '!=')
            return self._get_field(finding, field) != self._parse_value(value)

        if ' in ' in expr and ' not in ' not in expr:
            field, value = self._parse_comparison(expr, 'in')
            return self._get_field(finding, field) in self._parse_list(value)

        if ' not in ' in expr:
            field, value = self._parse_comparison(expr, 'not in')
            return self._get_field(finding, field) not in self._parse_list(value)

        if ' matches ' in expr and ' not matches ' not in expr:
            return self._match_file_pattern(finding, expr, negate=False)

        if ' not matches ' in expr:
            return self._match_file_pattern(finding, expr, negate=True)

        if ' contains ' in expr:
            field, value = self._parse_comparison(expr, 'contains')
            field_val = self._get_field(finding, field)
            search_val = self._parse_value(value)
            if isinstance(field_val, list):
                return search_val in field_val
            return search_val in str(field_val)

        # Numeric comparisons
        for op in ['>=', '<=', '>', '<']:
            if f' {op} ' in expr:
                field, value = self._parse_comparison(expr, op)
                field_num = float(self._get_field(finding, field) or 0)
                value_num = float(self._parse_value(value))
                if op == '>':
                    return field_num > value_num
                elif op == '<':
                    return field_num < value_num
                elif op == '>=':
                    return field_num >= value_num
                elif op == '<=':
                    return field_num <= value_num

        return False

    def _split_logical(self, expr: str, op: str) -> List[str]:
        """Split expression by logical operator, respecting parentheses."""
        parts = []
        depth = 0
        current = []

        tokens = expr.split()
        for token in tokens:
            if token == '(':
                depth += 1
                current.append(token)
            elif token == ')':
                depth -= 1
                current.append(token)
            elif token == op and depth == 0:
                parts.append(' '.join(current))
                current = []
            else:
                current.append(token)

        if current:
            parts.append(' '.join(current))

        return parts

    def _parse_comparison(self, expr: str, op: str) -> Tuple[str, str]:
        """Parse 'field OP value' into (field, value)."""
        parts = expr.split(f' {op} ', 1)
        if len(parts) != 2:
            raise ValueError(f'Invalid comparison: {expr}')
        return parts[0].strip(), parts[1].strip()

    def _get_field(self, finding: dict, field: str) -> Any:
        """Get field value from finding (supports dot notation)."""
        if '.' in field:
            keys = field.split('.')
            val = finding
            for key in keys:
                val = val.get(key, '')
            return val
        return finding.get(field, '')

    def _parse_value(self, value: str) -> Any:
        """Parse value from DSL (remove quotes, parse numbers)."""
        value = value.strip()
        if (value.startswith("'") and value.endswith("'")) or \
           (value.startswith('"') and value.endswith('"')):
            return value[1:-1]
        if value.isdigit():
            return int(value)
        try:
            return float(value)
        except ValueError:
            return value

    def _parse_list(self, value: str) -> List[Any]:
        """Parse list literal ['a', 'b', 'c']."""
        value = value.strip()
        if not (value.startswith('[') and value.endswith(']')):
            return [self._parse_value(value)]

        content = value[1:-1]
        items = [item.strip() for item in content.split(',')]
        return [self._parse_value(item) for item in items]

    def _match_file_pattern(self, finding: dict, expr: str, negate: bool) -> bool:
        """Match file path against glob pattern."""
        op = 'not matches' if negate else 'matches'
        field, pattern_str = self._parse_comparison(expr, op)
        pattern = self._parse_value(pattern_str)

        file_path = self._get_field(finding, field)
        if not file_path:
            return negate

        if pattern not in self._compiled_patterns:
            self._compiled_patterns[pattern] = self._compile_pattern(pattern)

        match = bool(self._compiled_patterns[pattern].match(str(file_path)))
        return not match if negate else match


# ── Policy and Rules ──────────────────────────────────────────────────────────


class PolicyRule:
    """Individual rule within a policy with matcher, action, and metadata."""

    def __init__(self, id: str, matcher: RuleMatcher | dict | str,
                 action: str = 'fail', metadata: Optional[dict] = None):
        self.id = id
        self.action = action
        self.metadata = metadata or {}

        if isinstance(matcher, RuleMatcher):
            self.matcher = matcher
        else:
            self.matcher = RuleMatcher(matcher)

    def matches(self, finding: dict) -> bool:
        return self.matcher.evaluate(finding)

    def apply_action(self, finding: dict, context: dict) -> dict:
        """Apply rule action to finding (modify tags, suppress, etc.)."""
        result = finding.copy()

        if self.action == 'tag':
            tags = result.get('tags', [])
            tags.extend(self.metadata.get('tags', []))
            result['tags'] = tags

        elif self.action == 'suppress':
            result['suppressed'] = True
            result['suppressed_by'] = self.id

        elif self.action == 'notify':
            result['notify'] = True
            result['notification_channels'] = self.metadata.get('channels', [])

        return result

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'matcher': self.matcher.expression,
            'action': self.action,
            'metadata': self.metadata,
        }

    @staticmethod
    def from_dict(data: dict) -> 'PolicyRule':
        return PolicyRule(
            id=data['id'],
            matcher=data.get('matcher', 'true'),
            action=data.get('action', 'fail'),
            metadata=data.get('metadata', {}),
        )


class Policy:
    """Immutable policy definition with rules, thresholds, and compliance mappings."""

    def __init__(self, name: str, version: str, rules: List[PolicyRule],
                 metadata: Optional[dict] = None, thresholds: Optional[dict] = None,
                 compliance: Optional[dict] = None, notifications: Optional[dict] = None):
        self.name = name
        self.version = version
        self.rules = rules
        self.metadata = metadata or {}
        self.thresholds = thresholds or {}
        self.compliance = compliance or {}
        self.notifications = notifications or {}

    @staticmethod
    def from_yaml(path: str) -> 'Policy':
        if not _YAML_AVAILABLE:
            raise ImportError('PyYAML is required for loading policies from YAML')

        with open(path, 'r', encoding='utf-8') as fh:
            data = yaml.safe_load(fh)

        return Policy.from_dict(data)

    @staticmethod
    def from_dict(data: dict) -> 'Policy':
        rules = [PolicyRule.from_dict(r) for r in data.get('rules', [])]

        return Policy(
            name=data['name'],
            version=data.get('version', '1.0.0'),
            rules=rules,
            metadata={
                'description': data.get('description', ''),
                'author': data.get('author', ''),
                'created_at': data.get('created_at', ''),
                'tags': data.get('tags', []),
            },
            thresholds=data.get('thresholds', {}),
            compliance=data.get('compliance', {}),
            notifications=data.get('notifications', {}),
        )

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'version': self.version,
            'description': self.metadata.get('description', ''),
            'author': self.metadata.get('author', ''),
            'created_at': self.metadata.get('created_at', ''),
            'tags': self.metadata.get('tags', []),
            'rules': [r.to_dict() for r in self.rules],
            'thresholds': self.thresholds,
            'compliance': self.compliance,
            'notifications': self.notifications,
        }

    def to_yaml(self, path: str) -> None:
        if not _YAML_AVAILABLE:
            raise ImportError('PyYAML is required for saving policies to YAML')

        with open(path, 'w', encoding='utf-8') as fh:
            yaml.dump(self.to_dict(), fh, default_flow_style=False, sort_keys=False)

    def get_rule(self, rule_id: str) -> Optional[PolicyRule]:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def validate(self) -> ValidationResult:
        errors = []
        warnings = []

        # Validate version format
        if not re.match(r'^\d+\.\d+\.\d+$', self.version):
            errors.append(f'Invalid version format: {self.version} (expected X.Y.Z)')

        # Validate rule IDs are unique
        rule_ids = [r.id for r in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            errors.append('Duplicate rule IDs found')

        # Validate threshold keys
        valid_threshold_keys = {'max_critical', 'max_high', 'max_medium', 'max_low',
                                'total_max', 'fail_on_severity'}
        invalid_keys = set(self.thresholds.keys()) - valid_threshold_keys
        if invalid_keys:
            warnings.append(f'Unknown threshold keys: {invalid_keys}')

        # Validate fail_on_severity value
        if 'fail_on_severity' in self.thresholds:
            valid_severities = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
            if self.thresholds['fail_on_severity'].upper() not in valid_severities:
                errors.append(f'Invalid fail_on_severity: {self.thresholds["fail_on_severity"]}')

        # Validate actions
        valid_actions = {'fail', 'warn', 'notify', 'suppress', 'tag'}
        for rule in self.rules:
            if rule.action not in valid_actions:
                warnings.append(f'Rule {rule.id}: unknown action {rule.action}')

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)


# ── Policy Engine ─────────────────────────────────────────────────────────────


class PolicyEngine:
    """
    Core orchestrator for loading, validating, and evaluating policies against
    scan findings. Manages policy lifecycle and execution context.
    """

    _SEVERITY_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}

    def __init__(self, config: Optional[Any] = None):
        self.config = config
        self._policy_cache: Dict[str, Policy] = {}

    def load_policy(self, policy_path: str, version: Optional[str] = None) -> Policy:
        """Load policy from YAML/JSON file. Supports versioned policies."""
        cache_key = f'{policy_path}:{version or "latest"}'

        if cache_key in self._policy_cache:
            return self._policy_cache[cache_key]

        if policy_path.endswith('.yaml') or policy_path.endswith('.yml'):
            policy = Policy.from_yaml(policy_path)
        elif policy_path.endswith('.json'):
            with open(policy_path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            policy = Policy.from_dict(data)
        else:
            raise ValueError(f'Unsupported policy format: {policy_path}')

        self._policy_cache[cache_key] = policy
        return policy

    def validate_policy(self, policy: Policy) -> ValidationResult:
        """Validate policy syntax and semantics."""
        return policy.validate()

    def evaluate(self, findings: List[dict], policy: Policy,
                 context: Optional[dict] = None) -> PolicyResult:
        """
        Evaluate findings against policy. Returns pass/fail status, violations,
        and metadata.
        """
        import time
        start_time = time.time()

        context = context or {}
        violations: List[PolicyViolation] = []

        # Pre-filter findings by severity if specified in policy
        effective_findings = findings
        if 'fail_on_severity' in policy.thresholds:
            min_sev = policy.thresholds['fail_on_severity'].upper()
            min_rank = self._SEVERITY_RANK.get(min_sev, 0)
            effective_findings = [
                f for f in findings
                if self._SEVERITY_RANK.get(f.get('severity', 'LOW').upper(), 0) >= min_rank
            ]

        # Evaluate rules
        violations.extend(self._apply_rule_matchers(effective_findings, policy.rules, context))

        # Evaluate thresholds
        threshold_violations = self._evaluate_thresholds(effective_findings, policy.thresholds)
        for msg in threshold_violations:
            violations.append(PolicyViolation(
                finding={'severity': 'POLICY', 'description': msg},
                rule=PolicyRule(id='THRESHOLD', matcher='true', action='fail'),
                message=msg,
            ))

        # Determine pass/fail
        passed = len(violations) == 0

        result = PolicyResult(policy, passed, violations, context)
        result.evaluation_time = time.time() - start_time

        return result

    def _apply_rule_matchers(self, findings: List[dict], rules: List[PolicyRule],
                             context: dict) -> List[PolicyViolation]:
        """Apply rule matchers to findings and collect violations."""
        violations: List[PolicyViolation] = []

        for finding in findings:
            for rule in rules:
                if rule.matches(finding):
                    if rule.action == 'fail':
                        message = rule.metadata.get('message', f'Rule {rule.id} violated')
                        violations.append(PolicyViolation(finding, rule, message))

                    # Apply side effects (tagging, suppression)
                    if rule.action in ('tag', 'suppress', 'notify'):
                        rule.apply_action(finding, context)

        return violations

    def _evaluate_thresholds(self, findings: List[dict], thresholds: dict) -> List[str]:
        """Evaluate threshold constraints and return violation messages."""
        violations = []

        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            sev = f.get('severity', 'LOW').upper()
            if sev in counts:
                counts[sev] += 1

        total = len(findings)

        if 'max_critical' in thresholds and counts['CRITICAL'] > thresholds['max_critical']:
            violations.append(
                f"Threshold exceeded: {counts['CRITICAL']} CRITICAL findings "
                f"(max: {thresholds['max_critical']})"
            )

        if 'max_high' in thresholds and counts['HIGH'] > thresholds['max_high']:
            violations.append(
                f"Threshold exceeded: {counts['HIGH']} HIGH findings "
                f"(max: {thresholds['max_high']})"
            )

        if 'max_medium' in thresholds and counts['MEDIUM'] > thresholds['max_medium']:
            violations.append(
                f"Threshold exceeded: {counts['MEDIUM']} MEDIUM findings "
                f"(max: {thresholds['max_medium']})"
            )

        if 'max_low' in thresholds and counts['LOW'] > thresholds['max_low']:
            violations.append(
                f"Threshold exceeded: {counts['LOW']} LOW findings "
                f"(max: {thresholds['max_low']})"
            )

        if 'total_max' in thresholds and total > thresholds['total_max']:
            violations.append(
                f"Threshold exceeded: {total} total findings "
                f"(max: {thresholds['total_max']})"
            )

        return violations

    def test_policy(self, policy: Policy, test_cases: List[PolicyTestCase]) -> TestResult:
        """Run unit tests against policy using test fixtures."""
        passed = 0
        failed = 0
        failures = []

        for tc in test_cases:
            result = self.evaluate(tc.findings, policy, tc.context)

            expected_passed = tc.expected.get('passed', True)
            expected_count = tc.expected.get('violation_count', 0)
            expected_rules = set(tc.expected.get('violated_rules', []))

            actual_passed = result.passed
            actual_count = len(result.violations)
            actual_rules = set(v.rule.id for v in result.violations)

            test_passed = True

            if actual_passed != expected_passed:
                test_passed = False
                failures.append({
                    'test_name': tc.name,
                    'field': 'passed',
                    'expected': expected_passed,
                    'actual': actual_passed,
                })

            if expected_count > 0 and actual_count != expected_count:
                test_passed = False
                failures.append({
                    'test_name': tc.name,
                    'field': 'violation_count',
                    'expected': expected_count,
                    'actual': actual_count,
                })

            if expected_rules and actual_rules != expected_rules:
                test_passed = False
                failures.append({
                    'test_name': tc.name,
                    'field': 'violated_rules',
                    'expected': list(expected_rules),
                    'actual': list(actual_rules),
                })

            if test_passed:
                passed += 1
            else:
                failed += 1

        return TestResult(passed, failed, failures)


# ── Policy Registry ───────────────────────────────────────────────────────────


class PolicyRegistry:
    """Versioned policy storage and retrieval with semantic versioning and diffs."""

    def __init__(self, registry_path: str):
        self.registry_path = registry_path
        os.makedirs(registry_path, exist_ok=True)
        self._index_path = os.path.join(registry_path, 'index.json')
        self._index = self._load_index()

    def _load_index(self) -> dict:
        if os.path.exists(self._index_path):
            with open(self._index_path, 'r', encoding='utf-8') as fh:
                return json.load(fh)
        return {}

    def _save_index(self) -> None:
        with open(self._index_path, 'w', encoding='utf-8') as fh:
            json.dump(self._index, fh, indent=2)

    def register(self, policy: Policy, metadata: Optional[dict] = None) -> str:
        """Register policy in versioned registry. Returns policy ID."""
        policy_id = f'{policy.name}:{policy.version}'
        policy_hash = self._compute_hash(policy)

        policy_dir = os.path.join(self.registry_path, policy.name)
        os.makedirs(policy_dir, exist_ok=True)

        policy_file = os.path.join(policy_dir, f'{policy.version}.yaml')
        policy.to_yaml(policy_file)

        version_info = PolicyVersion(
            version=policy.version,
            hash_value=policy_hash,
            created_at=datetime.utcnow().isoformat(),
            author=metadata.get('author', 'unknown') if metadata else 'unknown',
            changelog=metadata.get('changelog', '') if metadata else '',
        )

        if policy.name not in self._index:
            self._index[policy.name] = []

        self._index[policy.name].append(version_info.to_dict())
        self._save_index()

        return policy_id

    def get(self, policy_name: str, version: Optional[str] = None) -> Policy:
        """Get policy by name and optional version (latest if not specified)."""
        if policy_name not in self._index:
            raise ValueError(f'Policy not found: {policy_name}')

        versions = self._index[policy_name]
        if not versions:
            raise ValueError(f'No versions found for policy: {policy_name}')

        if version is None:
            version = versions[-1]['version']

        policy_file = os.path.join(self.registry_path, policy_name, f'{version}.yaml')
        return Policy.from_yaml(policy_file)

    def list_versions(self, policy_name: str) -> List[PolicyVersion]:
        """List all versions of a named policy."""
        if policy_name not in self._index:
            return []

        return [PolicyVersion(**v) for v in self._index[policy_name]]

    def diff(self, policy_name: str, v1: str, v2: str) -> PolicyDiff:
        """Compare two policy versions and return semantic diff."""
        p1 = self.get(policy_name, v1)
        p2 = self.get(policy_name, v2)

        rules1 = {r.id: r for r in p1.rules}
        rules2 = {r.id: r for r in p2.rules}

        added = [rid for rid in rules2 if rid not in rules1]
        removed = [rid for rid in rules1 if rid not in rules2]

        modified = []
        for rid in rules1:
            if rid in rules2:
                if rules1[rid].to_dict() != rules2[rid].to_dict():
                    modified.append(rid)

        threshold_changes = {}
        for key in set(p1.thresholds.keys()) | set(p2.thresholds.keys()):
            val1 = p1.thresholds.get(key)
            val2 = p2.thresholds.get(key)
            if val1 != val2:
                threshold_changes[key] = {'old': val1, 'new': val2}

        return PolicyDiff(v1, v2, added, removed, modified, threshold_changes)

    def _compute_hash(self, policy: Policy) -> str:
        """Compute SHA-256 hash of policy content."""
        content = json.dumps(policy.to_dict(), sort_keys=True)
        return hashlib.sha256(content.encode('utf-8')).hexdigest()


# ── Policy DSL Parser (Advanced) ──────────────────────────────────────────────


class PolicyDSL:
    """
    Parser and evaluator for advanced policy expressions with logical operators,
    quantifiers, and custom functions.

    Supports:
      - count(findings where severity == 'HIGH') > 10
      - any(findings where severity == 'CRITICAL')
      - all(findings where file matches 'src/**')
    """

    @staticmethod
    def parse(expression: str) -> dict:
        """Parse DSL expression into abstract syntax tree."""
        # Simplified AST for now - full parser would use proper tokenization
        return {'type': 'expression', 'value': expression}

    @staticmethod
    def evaluate(ast: dict, context: dict) -> bool:
        """Evaluate parsed AST against context."""
        # Placeholder for full AST evaluation
        return True


# ── Public API ────────────────────────────────────────────────────────────────


def load_policy_from_file(path: str) -> Policy:
    """Convenience function to load a policy from file."""
    engine = PolicyEngine()
    return engine.load_policy(path)


def evaluate_findings(findings: List[dict], policy_path: str,
                      context: Optional[dict] = None) -> PolicyResult:
    """Convenience function to evaluate findings against a policy file."""
    engine = PolicyEngine()
    policy = engine.load_policy(policy_path)
    return engine.evaluate(findings, policy, context)


def create_default_policy(name: str = 'default', output_path: Optional[str] = None) -> Policy:
    """Create a default policy with common rules and thresholds."""
    rules = [
        PolicyRule(
            id='critical-findings',
            matcher={'severity': 'CRITICAL'},
            action='fail',
            metadata={'message': 'Critical findings must be resolved'},
        ),
        PolicyRule(
            id='high-findings',
            matcher={'severity': 'HIGH'},
            action='fail',
            metadata={'message': 'High severity findings must be resolved'},
        ),
    ]

    policy = Policy(
        name=name,
        version='1.0.0',
        rules=rules,
        metadata={
            'description': 'Default policy with critical/high enforcement',
            'author': 'AuditLens',
            'created_at': datetime.utcnow().isoformat(),
        },
        thresholds={
            'max_critical': 0,
            'max_high': 5,
            'fail_on_severity': 'HIGH',
        },
    )

    if output_path:
        policy.to_yaml(output_path)

    return policy
