"""
Test suite for auditlens.lsp_server

Tests LSP server, incremental analysis, code actions, and hover providers.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime

# Skip if LSP not available
pytest.importorskip('pygls')

from auditlens.lsp_server import (
    AuditLensLanguageServer,
    IncrementalAnalyzer,
    DiagnosticConverter,
    CodeActionProvider,
    ComplianceHoverProvider,
    BackgroundScanner,
    CachedDocument,
    ProjectConfig,
    start_lsp_server,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return [
        {'rule_id': 'SQL-01', 'file': 'app.py', 'line': 10, 'severity': 'CRITICAL',
         'description': 'SQL injection', 'compliance': ['CWE-89']},
        {'rule_id': 'XSS-01', 'file': 'views.py', 'line': 20, 'severity': 'HIGH',
         'description': 'XSS vulnerability', 'compliance': ['CWE-79']},
    ]


@pytest.fixture
def cached_document():
    """Cached document for testing."""
    return CachedDocument(
        uri='file:///test/app.py',
        version=1,
        text='def main():\n    pass\n'
    )


# ── CachedDocument Tests ──────────────────────────────────────────────────────

def test_cached_document_initialization():
    """Test CachedDocument initialization."""
    doc = CachedDocument('file:///test.py', 1, 'code')

    assert doc.uri == 'file:///test.py'
    assert doc.version == 1
    assert doc.line_count == 1


# ── DiagnosticConverter Tests ─────────────────────────────────────────────────

def test_diagnostic_converter_severity_mapping():
    """Test severity conversion to LSP."""
    converter = DiagnosticConverter()

    from lsprotocol.types import DiagnosticSeverity

    assert converter.severity_to_lsp('CRITICAL') == DiagnosticSeverity.Error
    assert converter.severity_to_lsp('HIGH') == DiagnosticSeverity.Error
    assert converter.severity_to_lsp('MEDIUM') == DiagnosticSeverity.Warning
    assert converter.severity_to_lsp('LOW') == DiagnosticSeverity.Information


def test_diagnostic_converter_findings_to_diagnostics(sample_findings):
    """Test finding to diagnostic conversion."""
    converter = DiagnosticConverter()
    diagnostics = converter.findings_to_diagnostics(sample_findings, 'file:///test.py')

    assert len(diagnostics) == 2
    assert all(d.source == 'auditlens' for d in diagnostics)


# ── ComplianceHoverProvider Tests ─────────────────────────────────────────────

def test_hover_provider_get_hover(sample_findings):
    """Test hover content generation."""
    provider = ComplianceHoverProvider()

    from lsprotocol.types import Position

    hover = provider.get_hover('file:///test.py', Position(line=10, character=0), [sample_findings[0]])

    assert hover is not None
    assert 'CWE-89' in hover.contents.value


def test_hover_provider_remediation_guidance():
    """Test remediation guidance generation."""
    provider = ComplianceHoverProvider()
    guidance = provider.get_remediation_guidance('SQL-01')

    assert 'parameterized' in guidance.lower()


# ── CodeActionProvider Tests ──────────────────────────────────────────────────

@patch('auditlens.lsp_server.AuditLensLanguageServer')
def test_code_action_provider_suppress_action(mock_server, cached_document):
    """Test suppression code action generation."""
    mock_server.documents = {'file:///test.py': cached_document}

    provider = CodeActionProvider(mock_server)
    action = provider.create_suppress_action('file:///test.py', 0, 'SQL-01')

    assert action is not None
    assert 'Suppress SQL-01' in action.title


# ── BackgroundScanner Tests ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_background_scanner_scan_file(tmp_path):
    """Test single file scanning."""
    scanner = BackgroundScanner(max_workers=2)

    test_file = tmp_path / 'test.py'
    test_file.write_text('def main(): pass')

    findings = await scanner.scan_file(str(test_file))

    assert isinstance(findings, list)


# ── Integration Tests ─────────────────────────────────────────────────────────

def test_lsp_server_initialization():
    """Test LSP server initialization."""
    server = AuditLensLanguageServer()

    assert server.name == 'auditlens-lsp'
    assert server.documents == {}
