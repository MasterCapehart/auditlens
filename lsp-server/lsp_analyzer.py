"""
AuditLens LSP Analyzer — Python AST-based diagnostics for the language server.

This module is intentionally separate from the CLI analyzer so the LSP server
has no runtime dependency on tree-sitter or the CLI package.
"""

import ast
from lsprotocol.types import Diagnostic, Range, Position, DiagnosticSeverity

_SENSITIVE_NAMES = frozenset([
    'password', 'passwd', 'pwd', 'secret', 'token',
    'api_key', 'apikey', 'private_key', 'access_key', 'auth_key',
])


class SecurityVisitor(ast.NodeVisitor):
    """Detects hardcoded sensitive values in Python AST assignments."""

    def __init__(self):
        self.diagnostics: list[Diagnostic] = []

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(s in var_name for s in _SENSITIVE_NAMES):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if node.value.value:  # ignore empty strings
                            self.diagnostics.append(Diagnostic(
                                range=Range(
                                    start=Position(line=node.lineno - 1, character=node.col_offset),
                                    end=Position(
                                        line=(node.end_lineno or node.lineno) - 1,
                                        character=node.end_col_offset or 0,
                                    ),
                                ),
                                message=(
                                    f"[AuditLens] Hardcoded secret in '{target.id}'. "
                                    "Use environment variables or a secrets manager. "
                                    "(OWASP-A7, CWE-798)"
                                ),
                                source='AuditLens SAST',
                                severity=DiagnosticSeverity.Warning,
                            ))
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        """Also check augmented assignments: token += '...'"""
        if isinstance(node.target, ast.Name):
            var_name = node.target.id.lower()
            if any(s in var_name for s in _SENSITIVE_NAMES):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self.diagnostics.append(Diagnostic(
                        range=Range(
                            start=Position(line=node.lineno - 1, character=node.col_offset),
                            end=Position(
                                line=(node.end_lineno or node.lineno) - 1,
                                character=node.end_col_offset or 0,
                            ),
                        ),
                        message=(
                            f"[AuditLens] Hardcoded secret in '{node.target.id}'. "
                            "Use environment variables or a secrets manager."
                        ),
                        source='AuditLens SAST',
                        severity=DiagnosticSeverity.Warning,
                    ))
        self.generic_visit(node)


class ComplianceVisitor(ast.NodeVisitor):
    """Flags sensitive PII variable handling (RUT, SSN, etc.) per Ley 19.628 / GDPR."""

    _PII_PATTERNS = frozenset(['rut', 'ssn', 'nid', 'cedula', 'dni'])

    def __init__(self):
        self.diagnostics: list[Diagnostic] = []

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                matched = next((p for p in self._PII_PATTERNS if p in var_name), None)
                if matched:
                    self.diagnostics.append(Diagnostic(
                        range=Range(
                            start=Position(line=node.lineno - 1, character=node.col_offset),
                            end=Position(
                                line=(node.end_lineno or node.lineno) - 1,
                                character=node.end_col_offset or 0,
                            ),
                        ),
                        message=(
                            f"[AuditLens Compliance] Sensitive PII variable '{target.id}' "
                            "detected. Ensure this value is encrypted/hashed if persisted. "
                            "(Ley N° 19.628, GDPR Art. 5)"
                        ),
                        source='AuditLens Compliance',
                        severity=DiagnosticSeverity.Information,
                    ))
        self.generic_visit(node)


def analyze_code_with_ast(code: str, uri: str = '') -> list[Diagnostic]:
    """
    Parse Python source with stdlib ast and return LSP Diagnostic objects.
    Non-Python files (detected via URI extension) are skipped gracefully.
    """
    if uri and not uri.endswith('.py'):
        return []

    diagnostics: list[Diagnostic] = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        # The user's own Python linter will handle syntax errors.
        return diagnostics

    for visitor_cls in (SecurityVisitor, ComplianceVisitor):
        visitor = visitor_cls()
        visitor.visit(tree)
        diagnostics.extend(visitor.diagnostics)

    return diagnostics
