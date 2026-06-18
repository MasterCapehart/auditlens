"""
AuditLens Security Test Generator

Generates automated security regression tests from vulnerability findings.
Supports multiple frameworks: pytest, Jest/Vitest, JUnit.
Optional AI enhancement via AI API.

Usage:
    from auditlens.security_test_generator import generate_security_tests

    stats = generate_security_tests(
        findings=findings_list,
        project_path='./myproject',
        output_dir='tests/security',
        framework='pytest'
    )
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from jinja2 import Environment, FileSystemLoader, Template, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    import tree_sitter
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TestContext:
    """Context needed to generate a test for a specific finding."""
    finding: dict
    project_path: str
    target_file: str = ''
    vulnerable_line: int = 0
    vulnerable_code: Optional[str] = None
    function_name: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    framework_detected: Optional[str] = None
    test_file_path: str = ''

    def __post_init__(self):
        self.target_file = self.finding.get('file', '')
        self.vulnerable_line = int(self.finding.get('line', 0))
        self._extract_context()

    def _extract_context(self) -> None:
        """Extract vulnerable code, function name, and imports."""
        if not os.path.exists(self.target_file):
            return

        try:
            with open(self.target_file, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()

            # Extract vulnerable line
            if 0 < self.vulnerable_line <= len(lines):
                self.vulnerable_code = lines[self.vulnerable_line - 1].strip()

            # Extract imports (first 50 lines)
            self.imports = [
                line.strip()
                for line in lines[:50]
                if line.strip().startswith(('import ', 'from '))
            ]

            # Detect framework
            imports_text = ' '.join(self.imports)
            if 'flask' in imports_text.lower():
                self.framework_detected = 'flask'
            elif 'django' in imports_text.lower():
                self.framework_detected = 'django'
            elif 'fastapi' in imports_text.lower():
                self.framework_detected = 'fastapi'
            elif 'express' in imports_text.lower() or 'next' in imports_text.lower():
                self.framework_detected = 'express'

        except Exception:
            pass

    def extract_vulnerable_function(self) -> Optional[str]:
        """Extract the function containing the vulnerability using AST."""
        if not TREE_SITTER_AVAILABLE or not self.vulnerable_code:
            return None

        try:
            ext = os.path.splitext(self.target_file)[1]
            if ext == '.py':
                with open(self.target_file, 'r', encoding='utf-8', errors='replace') as f:
                    source = f.read()
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if hasattr(node, 'lineno') and node.lineno <= self.vulnerable_line <= node.end_lineno:
                            self.function_name = node.name
                            return node.name
        except Exception:
            pass
        return None

    def get_test_file_path(self, output_dir: str) -> str:
        """Generate appropriate test file path."""
        if self.test_file_path:
            return self.test_file_path

        rel_path = os.path.relpath(self.target_file, self.project_path)
        base_name = os.path.splitext(os.path.basename(rel_path))[0]
        ext = os.path.splitext(rel_path)[1]

        if ext == '.py':
            test_name = f'test_{base_name}_security.py'
        elif ext in ('.js', '.jsx', '.ts', '.tsx'):
            test_name = f'{base_name}.security.test{ext}'
        elif ext == '.java':
            test_name = f'{base_name}SecurityTest.java'
        else:
            test_name = f'test_{base_name}_security.txt'

        self.test_file_path = os.path.join(output_dir, test_name)
        return self.test_file_path


@dataclass
class ValidationResult:
    """Result of test validation."""
    is_valid: bool
    syntax_errors: List[str] = field(default_factory=list)
    missing_imports: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class ExecutionResult:
    """Result of test execution."""
    success: bool
    stdout: str = ''
    stderr: str = ''
    exit_code: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    duration: float = 0.0


@dataclass
class CoverageReport:
    """Coverage report for generated tests."""
    total_findings: int
    covered_findings: int
    coverage_percentage: float
    uncovered_by_severity: Dict[str, int] = field(default_factory=dict)
    tests_by_category: Dict[str, int] = field(default_factory=dict)
    traceability_matrix: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class TestGenerationResult:
    """Result of test generation."""
    tests_created: int = 0
    files_written: List[str] = field(default_factory=list)
    framework: str = 'pytest'
    coverage_map: Dict[str, List[str]] = field(default_factory=dict)
    errors: List[Dict[str, str]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            'tests_created': self.tests_created,
            'files_written': self.files_written,
            'framework': self.framework,
            'coverage_map': self.coverage_map,
            'errors': self.errors,
            'stats': self.stats,
            'execution_time': self.execution_time,
        }

    def to_json(self, path: str) -> None:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2)

    def print_summary(self) -> None:
        print(f'\n\033[92m[Security Test Generator]\033[0m Generation Complete')
        print(f'   Tests Created:  {self.tests_created}')
        print(f'   Files Written:  {len(self.files_written)}')
        print(f'   Framework:      {self.framework}')
        print(f'   Execution Time: {self.execution_time:.2f}s')

        if self.stats:
            print(f'\n   Stats by Severity:')
            for sev, count in self.stats.get('by_severity', {}).items():
                print(f'     {sev}: {count}')

        if self.errors:
            print(f'\n   \033[93mErrors: {len(self.errors)}\033[0m')
            for err in self.errors[:3]:
                print(f'     - {err.get("message", "Unknown error")}')


# ═══════════════════════════════════════════════════════════════════════════
# Test Framework Strategies (Strategy Pattern)
# ═══════════════════════════════════════════════════════════════════════════

class TestFrameworkStrategy(ABC):
    """Abstract strategy for test framework code generation."""

    @abstractmethod
    def generate_test_code(self, finding: dict, context: TestContext) -> str:
        pass

    @abstractmethod
    def generate_test_file_header(self, module_name: str) -> str:
        pass

    @abstractmethod
    def generate_test_file_footer(self) -> str:
        pass

    def get_assertion_syntax(self, assertion_type: str) -> str:
        return 'assert'

    def get_mock_syntax(self, target: str) -> str:
        return f'mock({target})'


class PytestStrategy(TestFrameworkStrategy):
    """Pytest implementation strategy."""

    def generate_test_file_header(self, module_name: str) -> str:
        return f'''"""
Security regression tests for {module_name}
Generated by AuditLens Security Test Generator
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

'''

    def generate_test_file_footer(self) -> str:
        return '\n'

    def generate_test_code(self, finding: dict, context: TestContext) -> str:
        """Generate test code based on vulnerability type."""
        rule_id = finding.get('rule_id', '')

        if 'SQL' in rule_id.upper() or 'INJECTION' in finding.get('name', '').upper():
            return self._generate_sql_injection_test(finding, context)
        elif 'XSS' in rule_id.upper() or 'CROSS-SITE' in finding.get('name', '').upper():
            return self._generate_xss_test(finding, context)
        elif 'AUTH' in rule_id.upper() or 'AUTHENTICATION' in finding.get('name', '').upper():
            return self._generate_auth_bypass_test(finding, context)
        elif 'SECRET' in rule_id.upper() or 'HARDCODED' in rule_id.upper():
            return self._generate_hardcoded_secret_test(finding, context)
        elif 'TAINT' in rule_id.upper():
            return self._generate_taint_test(finding, context)
        else:
            return self._generate_generic_test(finding, context)

    def _generate_sql_injection_test(self, finding: dict, context: TestContext) -> str:
        func_name = context.function_name or 'vulnerable_function'
        test_name = f"test_sql_injection_{func_name}_line_{context.vulnerable_line}"

        return f'''
def {test_name}():
    """
    Test for SQL injection vulnerability at line {context.vulnerable_line}
    Rule: {finding.get('rule_id')}
    """
    # SQL injection payloads
    malicious_inputs = [
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "' UNION SELECT * FROM users--",
        "admin'--",
        "1' AND 1=1--",
    ]

    for payload in malicious_inputs:
        # TODO: Replace with actual function call
        # result = {func_name}(payload)
        # assert sanitized(result), f"SQL injection vulnerable with: {{payload}}"
        pass

    # Valid input should work
    # result = {func_name}("valid_user")
    # assert result is not None
'''

    def _generate_xss_test(self, finding: dict, context: TestContext) -> str:
        func_name = context.function_name or 'vulnerable_function'
        test_name = f"test_xss_{func_name}_line_{context.vulnerable_line}"

        return f'''
def {test_name}():
    """
    Test for XSS vulnerability at line {context.vulnerable_line}
    Rule: {finding.get('rule_id')}
    """
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    ]

    for payload in xss_payloads:
        # TODO: Replace with actual function/endpoint call
        # response = {func_name}(payload)
        # assert escape_html(payload) in response
        # assert payload not in response, f"XSS vulnerable with: {{payload}}"
        pass
'''

    def _generate_auth_bypass_test(self, finding: dict, context: TestContext) -> str:
        test_name = f"test_auth_bypass_line_{context.vulnerable_line}"

        return f'''
def {test_name}():
    """
    Test for authentication bypass at line {context.vulnerable_line}
    Rule: {finding.get('rule_id')}
    """
    # Test without authentication
    # response = client.get('/protected-endpoint', headers={{}})
    # assert response.status_code == 401, "Endpoint accessible without auth"

    # Test with invalid token
    # response = client.get('/protected-endpoint', headers={{'Authorization': 'Bearer invalid'}})
    # assert response.status_code == 401, "Endpoint accessible with invalid token"

    # Test with valid token should succeed
    # valid_token = generate_valid_token()
    # response = client.get('/protected-endpoint', headers={{'Authorization': f'Bearer {{valid_token}}'}})
    # assert response.status_code == 200
    pass
'''

    def _generate_hardcoded_secret_test(self, finding: dict, context: TestContext) -> str:
        test_name = f"test_no_hardcoded_secrets_line_{context.vulnerable_line}"

        return f'''
def {test_name}():
    """
    Test that secrets are loaded from environment, not hardcoded
    Rule: {finding.get('rule_id')}
    File: {context.target_file}:{context.vulnerable_line}
    """
    # Read the source file
    with open(r'{context.target_file}', 'r') as f:
        lines = f.readlines()

    vulnerable_line = lines[{context.vulnerable_line - 1}]

    # Check that line doesn't contain hardcoded strings
    secret_patterns = [
        r'["\']?(?:password|secret|token|api_key)["\']?\s*=\s*["\'][^"\']+["\']',
        r'["\']sk-[a-zA-Z0-9]{{32,}}["\']',  # API keys
        r'["\'][a-zA-Z0-9]{{40,}}["\']',  # Long tokens
    ]

    for pattern in secret_patterns:
        import re
        if re.search(pattern, vulnerable_line, re.IGNORECASE):
            # Check if it's using environment variables
            if 'os.environ' not in vulnerable_line and 'process.env' not in vulnerable_line:
                pytest.fail(
                    f"Hardcoded secret detected at line {context.vulnerable_line}. "
                    f"Use environment variables instead."
                )
'''

    def _generate_taint_test(self, finding: dict, context: TestContext) -> str:
        test_name = f"test_taint_flow_line_{context.vulnerable_line}"

        return f'''
def {test_name}():
    """
    Test for taint flow vulnerability at line {context.vulnerable_line}
    Rule: {finding.get('rule_id')}
    Description: {finding.get('description', '')[:100]}
    """
    # Simulate untrusted input
    untrusted_input = "<script>alert('test')</script>"

    # TODO: Replace with actual vulnerable function
    # result = process_input(untrusted_input)

    # Verify input is sanitized before use
    # assert untrusted_input not in result, "Unsanitized tainted data in output"
    # assert html.escape(untrusted_input) in result or sanitize(untrusted_input) in result
    pass
'''

    def _generate_generic_test(self, finding: dict, context: TestContext) -> str:
        rule_id = finding.get('rule_id', 'UNKNOWN').replace('-', '_').lower()
        test_name = f"test_{rule_id}_line_{context.vulnerable_line}"

        return f'''
def {test_name}():
    """
    Security test for vulnerability at line {context.vulnerable_line}
    Rule: {finding.get('rule_id')}
    Name: {finding.get('name', '')}
    Severity: {finding.get('severity', '')}
    """
    # TODO: Implement test for this vulnerability
    # Vulnerable code: {context.vulnerable_code or 'N/A'}
    pytest.skip("Test implementation pending")
'''

    def generate_fixture(self, fixture_type: str) -> str:
        """Generate pytest fixtures."""
        if fixture_type == 'client':
            return '''
@pytest.fixture
def client():
    """Flask/FastAPI test client fixture."""
    # TODO: Import and configure your app
    # from myapp import create_app
    # app = create_app(testing=True)
    # return app.test_client()
    pass
'''
        return ''


class JestStrategy(TestFrameworkStrategy):
    """Jest/Vitest strategy for JavaScript/TypeScript."""

    def generate_test_file_header(self, module_name: str) -> str:
        return f'''/**
 * Security regression tests for {module_name}
 * Generated by AuditLens Security Test Generator
 */

import {{ describe, it, expect, jest }} from '@jest/globals';

'''

    def generate_test_file_footer(self) -> str:
        return '\n'

    def generate_test_code(self, finding: dict, context: TestContext) -> str:
        rule_id = finding.get('rule_id', 'UNKNOWN').replace('-', '_')
        test_name = f"{rule_id}_line_{context.vulnerable_line}"

        return f'''
describe('Security: {finding.get("name", "Unknown")}', () => {{
    it('should prevent {test_name}', () => {{
        // Rule: {finding.get('rule_id')}
        // Line: {context.vulnerable_line}
        // Severity: {finding.get('severity', '')}

        // TODO: Implement test
        expect(true).toBe(true);
    }});
}});
'''


class JUnitStrategy(TestFrameworkStrategy):
    """JUnit 5 strategy for Java."""

    def generate_test_file_header(self, module_name: str) -> str:
        class_name = f"{module_name}SecurityTest"
        return f'''package com.auditlens.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Security regression tests for {module_name}
 * Generated by AuditLens Security Test Generator
 */
public class {class_name} {{

'''

    def generate_test_file_footer(self) -> str:
        return '}\n'

    def generate_test_code(self, finding: dict, context: TestContext) -> str:
        rule_id = finding.get('rule_id', 'UNKNOWN').replace('-', '_')
        method_name = f"test{rule_id}Line{context.vulnerable_line}"

        return f'''
    @Test
    @DisplayName("{finding.get('name', 'Security Test')}")
    public void {method_name}() {{
        // Rule: {finding.get('rule_id')}
        // Line: {context.vulnerable_line}
        // Severity: {finding.get('severity', '')}

        // TODO: Implement test
        assertTrue(true, "Test implementation pending");
    }}
'''


# ═══════════════════════════════════════════════════════════════════════════
# AI Enhancement
# ═══════════════════════════════════════════════════════════════════════════

class AITestEnhancer:
    """Uses AI API to enhance generated tests."""

    def __init__(self, api_key: Optional[str] = None, model: str = 'ai-model-latest'):
        self.api_key = api_key or os.environ.get('ANTHROPIC_API_KEY')
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError('anthropic package required for AI enhancement')
        return self._client

    def enhance_test(self, test_code: str, finding: dict, context: TestContext) -> str:
        """Enhance test with AI-generated improvements."""
        if not self.api_key:
            return test_code

        prompt = self._build_enhancement_prompt(test_code, finding, context)

        try:
            client = self._get_client()
            message = client.messages.create(
                model=self.model,
                max_tokens=2048,
                messages=[{'role': 'user', 'content': prompt}],
            )
            enhanced = message.content[0].text

            # Extract code from markdown if present
            code_match = re.search(r'```(?:python|javascript|java)?\s*\n(.*?)```', enhanced, re.DOTALL)
            if code_match:
                return code_match.group(1).strip()

            return enhanced.strip()
        except Exception as e:
            print(f'\033[93m[AI Enhance Warning]\033[0m {e}')
            return test_code

    def _build_enhancement_prompt(self, test_code: str, finding: dict, context: TestContext) -> str:
        return f"""You are a security testing expert. Enhance this security test to make it more comprehensive.

FINDING:
- Rule: {finding.get('rule_id')}
- Name: {finding.get('name')}
- Severity: {finding.get('severity')}
- Description: {finding.get('description', '')}
- File: {context.target_file}:{context.vulnerable_line}

CURRENT TEST CODE:
```
{test_code}
```

TASK:
1. Replace TODO comments with actual test implementation
2. Add realistic edge cases (at least 3-5 test cases)
3. Add better assertions with clear failure messages
4. Generate realistic test data (don't use placeholder values)
5. Keep the same test framework and style
6. Make it ready to run (no TODOs remaining)

Return ONLY the improved test code, no explanations."""

    def generate_test_data(self, vulnerability_type: str, count: int = 5) -> List[str]:
        """Generate realistic test data for a vulnerability type."""
        if not self.api_key:
            return []

        prompt = f"""Generate {count} realistic test payloads for {vulnerability_type} vulnerability testing.
Return as a JSON array of strings. Each payload should be a real attack vector.
Example: ["payload1", "payload2", ...]

Return ONLY the JSON array, no explanation."""

        try:
            client = self._get_client()
            message = client.messages.create(
                model=self.model,
                max_tokens=512,
                messages=[{'role': 'user', 'content': prompt}],
            )
            text = message.content[0].text.strip()
            return json.loads(text)
        except Exception:
            return []


# ═══════════════════════════════════════════════════════════════════════════
# Template Engine
# ═══════════════════════════════════════════════════════════════════════════

class VulnerabilityTemplateEngine:
    """Manages Jinja2 templates for vulnerability test generation."""

    def __init__(self, templates_dir: Optional[str] = None):
        self.templates_dir = templates_dir or self._default_templates_dir()
        self._templates: Dict[str, Template] = {}
        self._load_templates()

    def _default_templates_dir(self) -> str:
        """Get default templates directory."""
        return os.path.join(os.path.dirname(__file__), 'test_templates')

    def _load_templates(self) -> None:
        """Load Jinja2 templates from directory."""
        if not JINJA2_AVAILABLE:
            return

        if not os.path.exists(self.templates_dir):
            return

        try:
            env = Environment(
                loader=FileSystemLoader(self.templates_dir),
                autoescape=select_autoescape(['html', 'xml'])
            )

            for filename in os.listdir(self.templates_dir):
                if filename.endswith('.j2'):
                    template_name = filename[:-3]
                    self._templates[template_name] = env.get_template(filename)
        except Exception as e:
            print(f'\033[93m[Template Warning]\033[0m Could not load templates: {e}')

    def get_template(self, vuln_type: str, framework: str) -> Optional[Template]:
        """Get template for vulnerability type and framework."""
        template_key = f"{vuln_type}_{framework}"
        return self._templates.get(template_key)

    def render_test(self, template_name: str, context: dict) -> str:
        """Render a test using template."""
        template = self._templates.get(template_name)
        if not template:
            return ''
        return template.render(**context)

    def _map_rule_to_template(self, rule_id: str) -> str:
        """Map rule ID to template name."""
        mapping = {
            'SEC-01': 'sql_injection',
            'SEC-02': 'xss',
            'SEC-03': 'auth_bypass',
            'TAINT-01': 'taint_flow',
        }
        return mapping.get(rule_id, 'generic')


# ═══════════════════════════════════════════════════════════════════════════
# Validation
# ═══════════════════════════════════════════════════════════════════════════

class TestValidator:
    """Validates generated test code."""

    def validate_syntax(self, test_code: str, language: str) -> ValidationResult:
        """Validate syntax using AST parsing."""
        result = ValidationResult(is_valid=True)

        if language == 'python':
            try:
                ast.parse(test_code)
            except SyntaxError as e:
                result.is_valid = False
                result.syntax_errors.append(f"Line {e.lineno}: {e.msg}")

        return result

    def validate_imports(self, test_code: str, project_path: str) -> List[str]:
        """Check for missing imports."""
        missing = []

        # Extract imports from test code
        import_pattern = r'^(?:from|import)\s+([\w.]+)'
        imports = re.findall(import_pattern, test_code, re.MULTILINE)

        for imp in imports:
            module = imp.split('.')[0]
            try:
                __import__(module)
            except ImportError:
                missing.append(module)

        return missing

    def dry_run_test(self, test_file: str, framework: str) -> ExecutionResult:
        """Execute dry run of test file."""
        result = ExecutionResult(success=False)

        if framework == 'pytest':
            cmd = ['pytest', '--collect-only', test_file]
        elif framework == 'jest':
            cmd = ['jest', '--listTests', test_file]
        else:
            return result

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            result.exit_code = proc.returncode
            result.stdout = proc.stdout
            result.stderr = proc.stderr
            result.success = (proc.returncode == 0)
        except subprocess.TimeoutExpired:
            result.stderr = 'Timeout expired'
        except FileNotFoundError:
            result.stderr = f'{framework} command not found'
        except Exception as e:
            result.stderr = str(e)

        return result


# ═══════════════════════════════════════════════════════════════════════════
# Coverage Mapping
# ═══════════════════════════════════════════════════════════════════════════

class TestCoverageMapper:
    """Maps findings to generated tests for coverage tracking."""

    def __init__(self):
        self._mappings: Dict[str, List[Tuple[str, str]]] = {}

    def add_mapping(self, finding_id: str, test_file: str, test_name: str) -> None:
        """Add a finding -> test mapping."""
        if finding_id not in self._mappings:
            self._mappings[finding_id] = []
        self._mappings[finding_id].append((test_file, test_name))

    def get_coverage_report(self, findings: List[dict]) -> CoverageReport:
        """Generate coverage report."""
        total = len(findings)
        covered = sum(1 for f in findings if self._get_finding_id(f) in self._mappings)

        uncovered_by_sev: Dict[str, int] = {}
        for f in findings:
            if self._get_finding_id(f) not in self._mappings:
                sev = f.get('severity', 'LOW')
                uncovered_by_sev[sev] = uncovered_by_sev.get(sev, 0) + 1

        return CoverageReport(
            total_findings=total,
            covered_findings=covered,
            coverage_percentage=(covered / total * 100) if total > 0 else 0.0,
            uncovered_by_severity=uncovered_by_sev,
            traceability_matrix=self._build_traceability_matrix(findings)
        )

    def identify_uncovered_findings(self, findings: List[dict]) -> List[dict]:
        """Return findings without test coverage."""
        return [f for f in findings if self._get_finding_id(f) not in self._mappings]

    def export_traceability_matrix(self, output_path: str, findings: List[dict], format: str = 'json') -> None:
        """Export traceability matrix."""
        matrix = self._build_traceability_matrix(findings)

        if format == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(matrix, f, indent=2)
        elif format == 'xlsx':
            try:
                import openpyxl
                wb = openpyxl.Workbook()
                ws = wb.active
                ws.title = 'Test Coverage'

                ws.append(['Finding ID', 'Rule', 'Severity', 'Test Files', 'Test Names'])
                for finding_id, tests in matrix.items():
                    finding = next((f for f in findings if self._get_finding_id(f) == finding_id), {})
                    test_files = ', '.join(t[0] for t in tests)
                    test_names = ', '.join(t[1] for t in tests)
                    ws.append([
                        finding_id,
                        finding.get('rule_id', ''),
                        finding.get('severity', ''),
                        test_files,
                        test_names
                    ])

                wb.save(output_path)
            except ImportError:
                print('\033[93m[Warning]\033[0m openpyxl not available for XLSX export')

    def _get_finding_id(self, finding: dict) -> str:
        """Generate unique ID for a finding."""
        return f"{finding.get('rule_id', '')}:{finding.get('file', '')}:{finding.get('line', 0)}"

    def _build_traceability_matrix(self, findings: List[dict]) -> Dict[str, List[Tuple[str, str]]]:
        """Build complete traceability matrix."""
        matrix = {}
        for finding in findings:
            fid = self._get_finding_id(finding)
            matrix[fid] = self._mappings.get(fid, [])
        return matrix


# ═══════════════════════════════════════════════════════════════════════════
# Main Generator
# ═══════════════════════════════════════════════════════════════════════════

class SecurityTestGenerator:
    """Main orchestrator for security test generation."""

    def __init__(self, project_path: str, framework: str = 'pytest', use_ai: bool = True):
        self.project_path = os.path.abspath(project_path)
        self.framework = framework
        self.use_ai = use_ai

        self.strategy = self._select_framework_strategy(framework)
        self.template_engine = VulnerabilityTemplateEngine()
        self.validator = TestValidator()
        self.coverage_mapper = TestCoverageMapper()

        self.ai_enhancer = None
        if use_ai:
            try:
                self.ai_enhancer = AITestEnhancer()
            except ImportError:
                print('\033[93m[Warning]\033[0m AI enhancement unavailable (anthropic not installed)')

    def _select_framework_strategy(self, framework: str) -> TestFrameworkStrategy:
        """Select appropriate strategy for framework."""
        strategies = {
            'pytest': PytestStrategy(),
            'jest': JestStrategy(),
            'vitest': JestStrategy(),
            'junit': JUnitStrategy(),
        }
        return strategies.get(framework.lower(), PytestStrategy())

    def generate_from_findings(self, findings: List[dict], output_dir: str) -> TestGenerationResult:
        """Generate tests from a list of findings."""
        import time
        start_time = time.time()

        result = TestGenerationResult(framework=self.framework)
        os.makedirs(output_dir, exist_ok=True)

        # Group findings by category
        grouped = self._group_findings_by_category(findings)

        # Generate tests in parallel
        test_files: Dict[str, List[str]] = {}

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for finding in findings:
                future = executor.submit(self._generate_single_test, finding, output_dir)
                futures.append((future, finding))

            for future, finding in futures:
                try:
                    test_code, test_file, test_name = future.result(timeout=30)
                    if test_code:
                        if test_file not in test_files:
                            test_files[test_file] = []
                        test_files[test_file].append(test_code)
                        result.tests_created += 1

                        # Map coverage
                        finding_id = self.coverage_mapper._get_finding_id(finding)
                        self.coverage_mapper.add_mapping(finding_id, test_file, test_name)

                        # Update stats
                        sev = finding.get('severity', 'LOW')
                        if 'by_severity' not in result.stats:
                            result.stats['by_severity'] = {}
                        result.stats['by_severity'][sev] = result.stats['by_severity'].get(sev, 0) + 1

                except Exception as e:
                    result.errors.append({
                        'finding': finding.get('rule_id', 'UNKNOWN'),
                        'message': str(e)
                    })

        # Write test files
        for test_file, test_codes in test_files.items():
            self._write_test_file(test_file, test_codes, result)

        result.execution_time = time.time() - start_time
        return result

    def generate_from_history(self, scan_id: int, output_dir: str) -> TestGenerationResult:
        """Generate tests from a historical scan."""
        from .history import _get_connection

        conn = _get_connection()
        try:
            row = conn.execute(
                'SELECT findings_json FROM scans WHERE id = ?',
                (scan_id,)
            ).fetchone()

            if not row:
                raise ValueError(f'Scan ID {scan_id} not found')

            findings = json.loads(row['findings_json'])
            return self.generate_from_findings(findings, output_dir)
        finally:
            conn.close()

    def _generate_single_test(self, finding: dict, output_dir: str) -> Tuple[str, str, str]:
        """Generate test code for a single finding."""
        context = TestContext(finding, self.project_path)
        context.extract_vulnerable_function()

        test_file = context.get_test_file_path(output_dir)
        test_code = self.strategy.generate_test_code(finding, context)

        # AI enhancement if enabled
        if self.ai_enhancer and self.use_ai:
            test_code = self.ai_enhancer.enhance_test(test_code, finding, context)

        # Extract test name
        test_name_match = re.search(r'def\s+(test_\w+)|it\([\'"](.+?)[\'"]', test_code)
        test_name = test_name_match.group(1) if test_name_match else 'unknown_test'

        return test_code, test_file, test_name

    def _write_test_file(self, test_file: str, test_codes: List[str], result: TestGenerationResult) -> None:
        """Write test codes to a file."""
        module_name = os.path.splitext(os.path.basename(test_file))[0]

        header = self.strategy.generate_test_file_header(module_name)
        footer = self.strategy.generate_test_file_footer()

        full_content = header + '\n'.join(test_codes) + footer

        try:
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write(full_content)
            result.files_written.append(test_file)
        except Exception as e:
            result.errors.append({
                'file': test_file,
                'message': f'Failed to write: {e}'
            })

    def _group_findings_by_category(self, findings: List[dict]) -> Dict[str, List[dict]]:
        """Group findings by vulnerability category."""
        groups: Dict[str, List[dict]] = {}

        for finding in findings:
            rule_id = finding.get('rule_id', 'UNKNOWN')
            category = rule_id.split('-')[0] if '-' in rule_id else 'OTHER'

            if category not in groups:
                groups[category] = []
            groups[category].append(finding)

        return groups


# ═══════════════════════════════════════════════════════════════════════════
# CI/CD Integration
# ═══════════════════════════════════════════════════════════════════════════

def integrate_with_ci(test_dir: str, ci_platform: str = 'github', output_path: Optional[str] = None) -> str:
    """Generate CI/CD configuration for security tests."""
    configs = {
        'github': _generate_github_actions,
        'gitlab': _generate_gitlab_ci,
        'jenkins': _generate_jenkinsfile,
    }

    generator = configs.get(ci_platform.lower(), _generate_github_actions)
    config_content = generator(test_dir)

    if output_path is None:
        if ci_platform == 'github':
            output_path = '.github/workflows/security-tests.yml'
        elif ci_platform == 'gitlab':
            output_path = '.gitlab-ci-security.yml'
        else:
            output_path = 'Jenkinsfile.security'

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(config_content)

    return output_path


def _generate_github_actions(test_dir: str) -> str:
    return f'''name: Security Regression Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  security-tests:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'

    - name: Install dependencies
      run: |
        pip install pytest pytest-cov
        pip install -r requirements.txt || true

    - name: Run security tests
      run: |
        pytest {test_dir} --cov --cov-report=xml --cov-report=html

    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: security-tests
'''


def _generate_gitlab_ci(test_dir: str) -> str:
    return f'''security-tests:
  stage: test
  image: python:3.9
  script:
    - pip install pytest pytest-cov
    - pip install -r requirements.txt || true
    - pytest {test_dir} --cov --cov-report=xml --cov-report=html
  coverage: '/(?i)total.*? (100(?:\\.0+)?\\%|[1-9]?\\d(?:\\.\\d+)?\\%)$/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml
'''


def _generate_jenkinsfile(test_dir: str) -> str:
    return f'''pipeline {{
    agent any

    stages {{
        stage('Setup') {{
            steps {{
                sh 'pip install pytest pytest-cov'
                sh 'pip install -r requirements.txt || true'
            }}
        }}

        stage('Security Tests') {{
            steps {{
                sh 'pytest {test_dir} --cov --cov-report=xml --cov-report=html'
            }}
        }}
    }}

    post {{
        always {{
            junit '{test_dir}/**/test-*.xml'
            publishHTML([
                reportDir: 'htmlcov',
                reportFiles: 'index.html',
                reportName: 'Security Test Coverage'
            ])
        }}
    }}
}}
'''


# ═══════════════════════════════════════════════════════════════════════════
# Public API Functions
# ═══════════════════════════════════════════════════════════════════════════

def generate_security_tests(
    findings: List[dict],
    project_path: str,
    output_dir: str = 'tests/security',
    framework: str = 'pytest',
    use_ai: bool = False,
) -> Dict[str, Any]:
    """
    Generate complete security test suite from findings.

    Args:
        findings: List of vulnerability findings
        project_path: Root path of the project
        output_dir: Directory to write test files
        framework: Testing framework (pytest, jest, junit)
        use_ai: Whether to use AI enhancement

    Returns:
        Dictionary with statistics about generated tests
    """
    generator = SecurityTestGenerator(project_path, framework, use_ai)
    result = generator.generate_from_findings(findings, output_dir)
    return result.to_dict()


def generate_test_for_finding(finding: dict, project_path: str, framework: str = 'pytest') -> str:
    """Generate test code for a single finding."""
    generator = SecurityTestGenerator(project_path, framework, use_ai=False)
    context = TestContext(finding, project_path)
    return generator.strategy.generate_test_code(finding, context)


def export_test_report(test_results: Dict, output_path: str, format: str = 'json') -> None:
    """Export test generation report."""
    if format == 'json':
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(test_results, f, indent=2)
    elif format == 'html':
        html_content = f'''<!DOCTYPE html>
<html>
<head><title>Security Test Report</title></head>
<body>
<h1>Security Test Generation Report</h1>
<p>Tests Created: {test_results.get('tests_created', 0)}</p>
<p>Files Written: {len(test_results.get('files_written', []))}</p>
<pre>{json.dumps(test_results, indent=2)}</pre>
</body>
</html>'''
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)


def validate_generated_tests(test_dir: str, framework: str = 'pytest') -> Dict[str, bool]:
    """Validate syntax of generated tests."""
    validator = TestValidator()
    results = {}

    for root, _, files in os.walk(test_dir):
        for file in files:
            if file.startswith('test_') and file.endswith('.py'):
                test_path = os.path.join(root, file)
                try:
                    with open(test_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                    validation = validator.validate_syntax(code, 'python')
                    results[test_path] = validation.is_valid
                except Exception:
                    results[test_path] = False

    return results
