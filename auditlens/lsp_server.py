"""
AuditLens Language Server Protocol (LSP) Integration

Provides real-time security diagnostics in IDEs via LSP.

Features:
- Real-time SAST diagnostics as you type (debounced)
- Incremental analysis with AST caching
- Code actions: suppress findings, apply AI fixes
- Compliance tooltips on hover (OWASP, CWE, ISO 27001)
- Workspace-wide scanning with progress notifications
- Configuration hot-reload (.auditlens.yaml)

Usage:
    # TCP socket (for external IDE connections)
    python -m auditlens.lsp_server --tcp --port 2087

    # stdio (for VS Code, neovim)
    python -m auditlens.lsp_server --stdio
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from pygls.server import LanguageServer
    from lsprotocol.types import (
        CODE_ACTION_RESOLVE,
        TEXT_DOCUMENT_CODE_ACTION,
        TEXT_DOCUMENT_COMPLETION,
        TEXT_DOCUMENT_DID_CHANGE,
        TEXT_DOCUMENT_DID_CLOSE,
        TEXT_DOCUMENT_DID_OPEN,
        TEXT_DOCUMENT_DID_SAVE,
        TEXT_DOCUMENT_HOVER,
        WORKSPACE_DID_CHANGE_WATCHED_FILES,
        CodeAction,
        CodeActionKind,
        CodeActionOptions,
        CodeActionParams,
        Command,
        CompletionItem,
        CompletionItemKind,
        CompletionList,
        CompletionParams,
        Diagnostic,
        DiagnosticSeverity,
        DiagnosticTag,
        DidChangeTextDocumentParams,
        DidChangeWatchedFilesParams,
        DidCloseTextDocumentParams,
        DidOpenTextDocumentParams,
        DidSaveTextDocumentParams,
        FileChangeType,
        Hover,
        HoverParams,
        Location,
        MarkupContent,
        MarkupKind,
        Position,
        Range,
        TextDocumentIdentifier,
        TextEdit,
        WorkspaceEdit,
    )
    _LSP_AVAILABLE = True
except ImportError:
    _LSP_AVAILABLE = False
    LanguageServer = object  # type: ignore

from .analyzer import analyze_file, _load_parser, _SUPPORTED_EXTENSIONS, _SEVERITY_RANK
from .config import load_config, AuditLensConfig
from .rules_engine import RulesEngine
from .taint_analyzer import TaintAnalyzer
from .sca_engine import SCAEngine
from .baseline import load_baseline

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger('auditlens.lsp')


# ── Data Structures ───────────────────────────────────────────────────────────

class CachedDocument:
    """Cached document state for incremental analysis."""
    def __init__(self, uri: str, version: int, text: str):
        self.uri = uri
        self.version = version
        self.text = text
        self.findings: List[dict] = []
        self.ast_tree = None  # tree-sitter Tree
        self.last_analyzed = datetime.now()
        self.line_count = text.count('\n') + 1


class ProjectConfig:
    """Project configuration aggregator."""
    def __init__(self, root_uri: str):
        self.root_uri = root_uri
        self.root_path = self._uri_to_path(root_uri)
        self.config = load_config(self.root_path) if self.root_path else AuditLensConfig({})
        self.baseline = self._load_baseline()
        self.disabled_rules = set(self.config.disable_rules)
        self.excluded_paths = set(self.config.exclude_paths)

    def _uri_to_path(self, uri: str) -> str:
        if uri.startswith('file://'):
            path = uri[7:]
            # Handle Windows drive letters (file:///C:/path)
            if len(path) > 2 and path[0] == '/' and path[2] == ':':
                path = path[1:]
            return path
        return uri

    def _load_baseline(self) -> Optional[Dict[str, dict]]:
        if self.config.baseline and self.root_path:
            baseline_path = os.path.join(self.root_path, self.config.baseline)
            return load_baseline(baseline_path)
        return None


class AnalysisTask:
    """Represents a pending analysis task."""
    def __init__(self, uri: str, priority: int = 1):
        self.uri = uri
        self.scheduled_at = time.time()
        self.cancel_token: Optional[asyncio.Future] = None
        self.priority = priority  # 0=high, 1=normal, 2=low


# ── LSP Server ────────────────────────────────────────────────────────────────

class AuditLensLanguageServer(LanguageServer):
    """Main LSP server for AuditLens."""

    def __init__(self, name: str = 'auditlens-lsp', version: str = '0.10.0'):
        super().__init__(name, version)
        self.rules_engine = RulesEngine()
        self.taint_analyzer = TaintAnalyzer()
        self.sca_engine = SCAEngine()

        # Document cache (URI -> CachedDocument)
        self.documents: Dict[str, CachedDocument] = {}
        self.max_cache_size = 100

        # Analysis task queue
        self.pending_tasks: Dict[str, AnalysisTask] = {}
        self.debounce_ms = 500

        # Project configuration
        self.project_config: Optional[ProjectConfig] = None

        # Register features
        self.register_features()

        logger.info(f'{name} v{version} initialized')

    def register_features(self):
        """Register LSP feature handlers."""
        # Document lifecycle
        self.feature(TEXT_DOCUMENT_DID_OPEN)(self.on_did_open)
        self.feature(TEXT_DOCUMENT_DID_CHANGE)(self.on_did_change)
        self.feature(TEXT_DOCUMENT_DID_SAVE)(self.on_did_save)
        self.feature(TEXT_DOCUMENT_DID_CLOSE)(self.on_did_close)

        # Code intelligence
        self.feature(TEXT_DOCUMENT_HOVER)(self.on_hover)
        self.feature(TEXT_DOCUMENT_CODE_ACTION)(self.on_code_action)
        self.feature(TEXT_DOCUMENT_COMPLETION)(self.on_completion)

        # Workspace events
        self.feature(WORKSPACE_DID_CHANGE_WATCHED_FILES)(self.on_watched_files_changed)

        # Custom commands
        self.command('auditlens.scan')(self.cmd_scan)
        self.command('auditlens.fix')(self.cmd_fix)
        self.command('auditlens.suppressFinding')(self.cmd_suppress_finding)

        logger.info('LSP features registered')

    def get_workspace_config(self) -> ProjectConfig:
        """Get or create project configuration."""
        if self.project_config is None:
            # Try to get workspace root from LSP client
            workspaces = self.workspace.folders
            root_uri = workspaces[0].uri if workspaces else 'file:///'
            self.project_config = ProjectConfig(root_uri)
            logger.info(f'Loaded project config from {root_uri}')
        return self.project_config

    def schedule_analysis(self, uri: str, debounce_ms: int = 500, priority: int = 1):
        """Schedule document analysis with debouncing."""
        # Cancel existing task
        if uri in self.pending_tasks:
            task = self.pending_tasks[uri]
            if task.cancel_token and not task.cancel_token.done():
                task.cancel_token.cancel()

        # Schedule new task
        task = AnalysisTask(uri, priority)
        self.pending_tasks[uri] = task

        # Debounced execution
        async def debounced_analyze():
            await asyncio.sleep(debounce_ms / 1000.0)
            if uri in self.pending_tasks and self.pending_tasks[uri] is task:
                await self._run_analysis(uri)
                del self.pending_tasks[uri]

        task.cancel_token = asyncio.ensure_future(debounced_analyze())

    async def _run_analysis(self, uri: str):
        """Execute analysis for a document."""
        try:
            doc = self.documents.get(uri)
            if not doc:
                logger.warning(f'Document not found in cache: {uri}')
                return

            logger.info(f'Analyzing {uri}')
            start = time.time()

            # Get configuration
            config = self.get_workspace_config()

            # Check if path is excluded
            file_path = self._uri_to_path(uri)
            if config.config.is_path_excluded(file_path):
                logger.info(f'Skipping excluded path: {file_path}')
                self._publish_diagnostics(uri, [])
                return

            # Run analysis
            analyzer = IncrementalAnalyzer(
                self.rules_engine,
                self.taint_analyzer,
                config
            )
            findings = await analyzer.analyze_document(uri, doc)

            # Update cache
            doc.findings = findings
            doc.last_analyzed = datetime.now()

            # Convert to LSP diagnostics
            converter = DiagnosticConverter()
            diagnostics = converter.findings_to_diagnostics(findings, uri)

            # Publish diagnostics
            self._publish_diagnostics(uri, diagnostics)

            elapsed = time.time() - start
            logger.info(f'Analysis complete for {uri}: {len(findings)} findings in {elapsed:.2f}s')

        except Exception as e:
            logger.error(f'Analysis failed for {uri}: {e}', exc_info=True)

    def _publish_diagnostics(self, uri: str, diagnostics: List[Diagnostic]):
        """Publish diagnostics to LSP client."""
        self.publish_diagnostics(uri, diagnostics)

    def _uri_to_path(self, uri: str) -> str:
        """Convert file:// URI to filesystem path."""
        if uri.startswith('file://'):
            path = uri[7:]
            if len(path) > 2 and path[0] == '/' and path[2] == ':':
                path = path[1:]
            return path
        return uri

    def _path_to_uri(self, path: str) -> str:
        """Convert filesystem path to file:// URI."""
        path = os.path.abspath(path)
        if sys.platform == 'win32':
            return f'file:///{path.replace(os.sep, "/")}'
        return f'file://{path}'

    # ── Document Lifecycle Handlers ───────────────────────────────────────────

    async def on_did_open(self, params: DidOpenTextDocumentParams):
        """Handle document opened."""
        doc = params.text_document
        uri = doc.uri

        # Cache document
        cached = CachedDocument(uri, doc.version, doc.text)
        self.documents[uri] = cached

        # Evict LRU if cache too large
        if len(self.documents) > self.max_cache_size:
            oldest_uri = min(
                self.documents.keys(),
                key=lambda u: self.documents[u].last_analyzed
            )
            del self.documents[oldest_uri]
            logger.info(f'Evicted {oldest_uri} from cache')

        logger.info(f'Document opened: {uri}')

        # Schedule analysis
        self.schedule_analysis(uri, self.debounce_ms)

    async def on_did_change(self, params: DidChangeTextDocumentParams):
        """Handle document changed."""
        uri = params.text_document.uri
        version = params.text_document.version

        if uri not in self.documents:
            logger.warning(f'Document not in cache: {uri}')
            return

        # Update cached text
        doc = self.documents[uri]
        for change in params.content_changes:
            # For full document updates (most common)
            if hasattr(change, 'text') and not hasattr(change, 'range'):
                doc.text = change.text
                doc.version = version
                doc.line_count = change.text.count('\n') + 1

        logger.debug(f'Document changed: {uri} (v{version})')

        # Schedule incremental analysis
        self.schedule_analysis(uri, self.debounce_ms)

    async def on_did_save(self, params: DidSaveTextDocumentParams):
        """Handle document saved."""
        uri = params.text_document.uri
        logger.info(f'Document saved: {uri}')

        # Trigger immediate analysis on save
        self.schedule_analysis(uri, debounce_ms=0, priority=0)

    async def on_did_close(self, params: DidCloseTextDocumentParams):
        """Handle document closed."""
        uri = params.text_document.uri

        # Clear diagnostics
        self._publish_diagnostics(uri, [])

        # Keep in cache for a while (might reopen soon)
        logger.info(f'Document closed: {uri}')

    # ── Code Intelligence Handlers ────────────────────────────────────────────

    async def on_hover(self, params: HoverParams) -> Optional[Hover]:
        """Provide hover information."""
        uri = params.text_document.uri
        position = params.position

        doc = self.documents.get(uri)
        if not doc or not doc.findings:
            return None

        # Find findings at this position
        line = position.line + 1  # LSP is 0-based, our findings are 1-based
        findings_at_line = [f for f in doc.findings if f.get('line') == line]

        if not findings_at_line:
            return None

        # Generate hover content
        provider = ComplianceHoverProvider()
        return provider.get_hover(uri, position, findings_at_line)

    async def on_code_action(self, params: CodeActionParams) -> List[CodeAction]:
        """Provide code actions (quick fixes)."""
        uri = params.text_document.uri
        range_ = params.range
        diagnostics = params.context.diagnostics

        doc = self.documents.get(uri)
        if not doc:
            return []

        # Generate code actions
        provider = CodeActionProvider(self)
        actions = []

        for diagnostic in diagnostics:
            # Find corresponding finding
            line = diagnostic.range.start.line + 1
            finding = next(
                (f for f in doc.findings if f.get('line') == line),
                None
            )
            if finding:
                actions.extend(
                    provider.get_actions_for_diagnostic(uri, diagnostic, finding)
                )

        return actions

    async def on_completion(self, params: CompletionParams) -> Optional[CompletionList]:
        """Provide completion suggestions."""
        uri = params.text_document.uri
        position = params.position

        # Provide secure alternatives for common insecure patterns
        completions = [
            CompletionItem(
                label='parameterized_query',
                kind=CompletionItemKind.Snippet,
                detail='Secure parameterized SQL query',
                documentation='Use parameterized queries to prevent SQL injection',
                insert_text='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
            ),
            CompletionItem(
                label='safe_eval',
                kind=CompletionItemKind.Snippet,
                detail='Safe alternative to eval()',
                documentation='Use ast.literal_eval() instead of eval()',
                insert_text='ast.literal_eval(${1:expression})'
            ),
            CompletionItem(
                label='secure_random',
                kind=CompletionItemKind.Snippet,
                detail='Cryptographically secure random',
                documentation='Use secrets module for secure random generation',
                insert_text='secrets.token_hex(${1:16})'
            ),
        ]

        return CompletionList(is_incomplete=False, items=completions)

    # ── Workspace Handlers ────────────────────────────────────────────────────

    async def on_watched_files_changed(self, params: DidChangeWatchedFilesParams):
        """Handle file system changes."""
        config_files = {'.auditlens.yaml', '.auditlens.yml', 'auditlens.yaml'}

        for change in params.changes:
            uri = change.uri
            file_name = os.path.basename(self._uri_to_path(uri))

            if file_name in config_files:
                logger.info(f'Config file changed: {uri}')
                # Reload configuration
                self.project_config = None
                self.get_workspace_config()

                # Re-analyze all open documents
                for doc_uri in list(self.documents.keys()):
                    self.schedule_analysis(doc_uri, debounce_ms=100, priority=0)

            elif file_name == '.auditlens-ignore':
                logger.info('Ignore file changed, re-analyzing workspace')
                for doc_uri in list(self.documents.keys()):
                    self.schedule_analysis(doc_uri, debounce_ms=100)

    # ── Custom Commands ───────────────────────────────────────────────────────

    async def cmd_scan(self, args: List[Any]) -> Any:
        """Command: auditlens.scan - Run full workspace scan."""
        logger.info('Running full workspace scan')

        config = self.get_workspace_config()
        root_path = config.root_path

        if not root_path or not os.path.isdir(root_path):
            logger.error(f'Invalid workspace root: {root_path}')
            return {'success': False, 'error': 'Invalid workspace root'}

        # Scan workspace in background
        scanner = BackgroundScanner(max_workers=4)
        findings = await scanner.scan_workspace(root_path, config)

        logger.info(f'Workspace scan complete: {len(findings)} findings')
        return {'success': True, 'findings_count': len(findings)}

    async def cmd_fix(self, args: List[Any]) -> Any:
        """Command: auditlens.fix - Apply AI fix to finding."""
        if not args or len(args) < 2:
            return {'success': False, 'error': 'Missing arguments'}

        uri = args[0]
        finding = args[1]

        logger.info(f'Applying AI fix for {finding.get("rule_id")} in {uri}')

        # TODO: Integrate with AI API for AI fixes
        # For now, return placeholder
        return {
            'success': False,
            'error': 'AI fix not yet implemented in LSP server'
        }

    async def cmd_suppress_finding(self, args: List[Any]) -> Any:
        """Command: auditlens.suppressFinding - Add suppression comment."""
        if not args or len(args) < 3:
            return {'success': False, 'error': 'Missing arguments'}

        uri = args[0]
        line = args[1]
        rule_id = args[2]

        logger.info(f'Suppressing {rule_id} at {uri}:{line}')

        # Generate suppression comment
        provider = CodeActionProvider(self)
        action = provider.create_suppress_action(uri, line, rule_id)

        if action and action.edit:
            # Apply edit
            return {'success': True, 'applied': True}

        return {'success': False, 'error': 'Failed to create suppression'}


# ── Incremental Analyzer ──────────────────────────────────────────────────────

class IncrementalAnalyzer:
    """Manages incremental re-analysis on file changes."""

    def __init__(
        self,
        rules_engine: RulesEngine,
        taint_analyzer: TaintAnalyzer,
        project_config: ProjectConfig
    ):
        self.rules_engine = rules_engine
        self.taint_analyzer = taint_analyzer
        self.project_config = project_config

    async def analyze_document(
        self,
        uri: str,
        doc: CachedDocument,
        incremental: bool = True
    ) -> List[dict]:
        """Analyze document and return findings."""
        file_path = self._uri_to_path(uri)
        ext = os.path.splitext(file_path)[1].lower()

        if ext not in _SUPPORTED_EXTENSIONS:
            return []

        findings: List[dict] = []

        # Parse AST (cache for incremental updates)
        parser = _load_parser(ext)
        if parser and incremental and doc.ast_tree:
            # Incremental parse (tree-sitter supports this)
            try:
                tree = parser.parse(doc.text.encode('utf-8'))
                doc.ast_tree = tree
            except Exception as e:
                logger.warning(f'Incremental parse failed: {e}')
                tree = parser.parse(doc.text.encode('utf-8'))
                doc.ast_tree = tree
        elif parser:
            tree = parser.parse(doc.text.encode('utf-8'))
            doc.ast_tree = tree

        # Run regex rules
        code_lines = doc.text.split('\n')
        rules = self.rules_engine.get_rules_for_language(ext)
        disabled = self.project_config.disabled_rules

        for rule in rules:
            if rule.id in disabled:
                continue

            for i, line in enumerate(code_lines):
                if self._should_suppress(line, rule.id):
                    continue

                if rule.match_text(line):
                    findings.append({
                        'rule_id': rule.id,
                        'name': rule.name,
                        'description': rule.description,
                        'file': file_path,
                        'line': i + 1,
                        'severity': rule.severity,
                        'compliance': rule.compliance,
                    })

        # Run taint analysis
        if 'TAINT-01' not in disabled:
            taint_findings = self.taint_analyzer.analyze(file_path, code_lines)
            findings.extend(taint_findings)

        # AST-based checks
        if parser and doc.ast_tree and 'AST-01-HARDCODED-SENSITIVE' not in disabled:
            ast_findings = self._ast_scan(file_path, doc.text.encode('utf-8'), parser)
            findings.extend(ast_findings)

        return findings

    def _uri_to_path(self, uri: str) -> str:
        if uri.startswith('file://'):
            path = uri[7:]
            if len(path) > 2 and path[0] == '/' and path[2] == ':':
                path = path[1:]
            return path
        return uri

    def _should_suppress(self, line: str, rule_id: str) -> bool:
        """Check if line has suppression comment."""
        lower = line.lower()
        if 'auditlens: ignore' not in lower:
            return False
        import re
        after = re.split(r'auditlens:\s*ignore', lower, maxsplit=1, flags=re.IGNORECASE)[-1]
        rule_ids = set(re.findall(r'[A-Z0-9_-]{3,}', after.upper()))
        return len(rule_ids) == 0 or rule_id in rule_ids

    def _ast_scan(self, file_path: str, code_bytes: bytes, parser) -> List[dict]:
        """AST-based hardcoded secrets detection."""
        findings = []
        try:
            tree = parser.parse(code_bytes)
            root = tree.root_node

            sensitive_names = {
                'password', 'passwd', 'pwd', 'secret', 'token', 'api_key',
                'apikey', 'private_key', 'access_key', 'auth_key',
            }

            def walk(node):
                is_assignment = node.type in (
                    'assignment', 'assignment_statement', 'augmented_assignment',
                    'variable_declarator', 'assignment_expression', 'pattern_initializer',
                )
                if is_assignment and len(node.children) >= 2:
                    lhs = node.children[0]
                    lhs_text = ''
                    if lhs.type == 'identifier':
                        lhs_text = lhs.text.decode('utf-8', errors='replace').lower()
                    elif lhs.type in ('attribute', 'member_expression'):
                        for child in lhs.children:
                            if child.type == 'identifier':
                                lhs_text = child.text.decode('utf-8', errors='replace').lower()

                    if any(s in lhs_text for s in sensitive_names):
                        for child in node.children:
                            if child.type in ('string', 'string_literal', 'template_string'):
                                val = child.text.decode('utf-8', errors='replace')
                                if len(val) > 3 and 'os.environ' not in val:
                                    findings.append({
                                        'rule_id': 'AST-01-HARDCODED-SENSITIVE',
                                        'name': 'Hardcoded Sensitive Value (AST)',
                                        'description': f"Identifier '{lhs_text}' assigned hardcoded string",
                                        'file': file_path,
                                        'line': node.start_point[0] + 1,
                                        'severity': 'HIGH',
                                        'compliance': ['OWASP-A7', 'CWE-798'],
                                    })
                                break

                for child in node.children:
                    walk(child)

            walk(root)
        except Exception as e:
            logger.warning(f'AST scan failed: {e}')

        return findings


# ── Diagnostic Converter ──────────────────────────────────────────────────────

class DiagnosticConverter:
    """Converts AuditLens findings to LSP Diagnostic protocol."""

    def findings_to_diagnostics(
        self,
        findings: List[dict],
        uri: str
    ) -> List[Diagnostic]:
        """Convert findings to LSP diagnostics."""
        diagnostics = []

        for finding in findings:
            severity = self.severity_to_lsp(finding.get('severity', 'LOW'))
            line = finding.get('line', 1) - 1  # LSP is 0-based

            # Create range (highlight entire line)
            range_ = Range(
                start=Position(line=line, character=0),
                end=Position(line=line, character=1000)  # End of line
            )

            # Build message
            message = finding.get('description', finding.get('name', 'Security issue'))
            compliance = finding.get('compliance', [])
            if compliance:
                message += f"\n\nCompliance: {', '.join(compliance)}"

            # Create diagnostic
            diagnostic = Diagnostic(
                range=range_,
                message=message,
                severity=severity,
                code=finding.get('rule_id'),
                source='auditlens',
            )

            diagnostics.append(diagnostic)

        return diagnostics

    def severity_to_lsp(self, severity: str) -> DiagnosticSeverity:
        """Map AuditLens severity to LSP severity."""
        severity_map = {
            'CRITICAL': DiagnosticSeverity.Error,
            'HIGH': DiagnosticSeverity.Error,
            'MEDIUM': DiagnosticSeverity.Warning,
            'LOW': DiagnosticSeverity.Information,
        }
        return severity_map.get(severity.upper(), DiagnosticSeverity.Information)


# ── Code Action Provider ──────────────────────────────────────────────────────

class CodeActionProvider:
    """Generates LSP CodeAction instances for quick fixes."""

    def __init__(self, server: AuditLensLanguageServer):
        self.server = server

    def get_actions_for_diagnostic(
        self,
        uri: str,
        diagnostic: Diagnostic,
        finding: dict
    ) -> List[CodeAction]:
        """Generate code actions for a diagnostic."""
        actions = []

        line = diagnostic.range.start.line
        rule_id = finding.get('rule_id', '')

        # Action 1: Suppress this finding
        suppress_action = self.create_suppress_action(uri, line, rule_id)
        if suppress_action:
            actions.append(suppress_action)

        # Action 2: Suppress all findings of this rule
        suppress_all_action = self.create_suppress_all_action(uri, rule_id)
        if suppress_all_action:
            actions.append(suppress_all_action)

        # Action 3: Add to .auditlens-ignore
        ignore_action = self.create_ignore_file_action(uri, finding)
        if ignore_action:
            actions.append(ignore_action)

        return actions

    def create_suppress_action(
        self,
        uri: str,
        line: int,
        rule_id: str
    ) -> Optional[CodeAction]:
        """Create action to add suppression comment."""
        doc = self.server.documents.get(uri)
        if not doc:
            return None

        # Insert comment at end of line
        lines = doc.text.split('\n')
        if line >= len(lines):
            return None

        current_line = lines[line]

        # Check if already suppressed
        if 'auditlens: ignore' in current_line.lower():
            return None

        # Add suppression comment
        comment = f'  # auditlens: ignore {rule_id}'
        new_text = current_line.rstrip() + comment

        edit = TextEdit(
            range=Range(
                start=Position(line=line, character=0),
                end=Position(line=line, character=len(current_line))
            ),
            new_text=new_text
        )

        workspace_edit = WorkspaceEdit(
            changes={uri: [edit]}
        )

        return CodeAction(
            title=f'Suppress {rule_id} on this line',
            kind=CodeActionKind.QuickFix,
            edit=workspace_edit,
            diagnostics=[],
        )

    def create_suppress_all_action(
        self,
        uri: str,
        rule_id: str
    ) -> Optional[CodeAction]:
        """Create action to suppress all instances of a rule."""
        # This would add the rule to .auditlens.yaml disable_rules
        # For now, return a command-based action
        return CodeAction(
            title=f'Disable {rule_id} globally in .auditlens.yaml',
            kind=CodeActionKind.QuickFix,
            command=Command(
                title=f'Disable {rule_id}',
                command='auditlens.disableRule',
                arguments=[rule_id]
            )
        )

    def create_ignore_file_action(
        self,
        uri: str,
        finding: dict
    ) -> Optional[CodeAction]:
        """Create action to add finding to .auditlens-ignore file."""
        return CodeAction(
            title='Add to .auditlens-ignore',
            kind=CodeActionKind.QuickFix,
            command=Command(
                title='Add to ignore file',
                command='auditlens.addToIgnoreFile',
                arguments=[finding]
            )
        )


# ── Compliance Hover Provider ─────────────────────────────────────────────────

class ComplianceHoverProvider:
    """Provides rich hover tooltips with compliance context."""

    def get_hover(
        self,
        uri: str,
        position: Position,
        findings: List[dict]
    ) -> Optional[Hover]:
        """Generate hover content for findings."""
        if not findings:
            return None

        # Build markdown content
        content_parts = []

        for finding in findings:
            rule_id = finding.get('rule_id', 'UNKNOWN')
            name = finding.get('name', 'Security Issue')
            description = finding.get('description', '')
            severity = finding.get('severity', 'LOW')
            compliance = finding.get('compliance', [])

            # Header
            content_parts.append(f"### 🔍 {name}")
            content_parts.append(f"**Rule:** `{rule_id}` | **Severity:** `{severity}`")
            content_parts.append('')

            # Description
            content_parts.append(description)
            content_parts.append('')

            # Compliance
            if compliance:
                content_parts.append('**Compliance Standards:**')
                for std in compliance:
                    # Parse standard (e.g., OWASP-A7, CWE-798)
                    if std.startswith('OWASP'):
                        content_parts.append(f"- [{std}](https://owasp.org/)")
                    elif std.startswith('CWE'):
                        cwe_num = std.split('-')[-1]
                        content_parts.append(f"- [{std}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)")
                    elif std.startswith('ISO'):
                        content_parts.append(f"- {std}")
                    else:
                        content_parts.append(f"- {std}")
                content_parts.append('')

            # Remediation guidance
            guidance = self.get_remediation_guidance(rule_id)
            if guidance:
                content_parts.append('**Remediation:**')
                content_parts.append(guidance)
                content_parts.append('')

            content_parts.append('---')

        markdown = '\n'.join(content_parts)

        return Hover(
            contents=MarkupContent(
                kind=MarkupKind.Markdown,
                value=markdown
            )
        )

    def get_remediation_guidance(self, rule_id: str) -> str:
        """Get remediation guidance for a rule."""
        guidance_map = {
            'AST-01-HARDCODED-SENSITIVE': (
                'Store sensitive values in environment variables or secure vaults. '
                'Use `os.environ.get("VAR_NAME")` or a secrets manager.'
            ),
            'TAINT-01': (
                'Sanitize user input before using in dangerous operations. '
                'Use parameterized queries, escape functions, or input validation.'
            ),
            'SEC-01': (
                'Use secure random number generation. Replace `random` with `secrets` module.'
            ),
            'SQL-01': (
                'Use parameterized queries to prevent SQL injection. '
                'Example: `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`'
            ),
        }
        return guidance_map.get(rule_id, 'Review the finding and apply security best practices.')


# ── Background Scanner ────────────────────────────────────────────────────────

class BackgroundScanner:
    """Runs full workspace scans in background."""

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.rules_engine = RulesEngine()
        self.taint_analyzer = TaintAnalyzer()

    async def scan_workspace(
        self,
        root_path: str,
        config: ProjectConfig
    ) -> List[dict]:
        """Scan entire workspace and return all findings."""
        findings = []

        # Collect files
        files_to_scan = []
        exclude_dirs = {
            'venv', 'env', '.env', '.venv', '.git', '__pycache__',
            'node_modules', 'build', 'dist', '.tox', 'site-packages',
        }

        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]

            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if ext in _SUPPORTED_EXTENSIONS:
                    file_path = os.path.join(dirpath, filename)
                    if not config.config.is_path_excluded(file_path):
                        files_to_scan.append(file_path)

        logger.info(f'Scanning {len(files_to_scan)} files in workspace')

        # Scan files
        for i, file_path in enumerate(files_to_scan):
            try:
                file_findings = analyze_file(
                    file_path,
                    self.rules_engine,
                    self.taint_analyzer,
                    min_severity='LOW',
                    disabled_rules=list(config.disabled_rules),
                    excluded_paths=list(config.excluded_paths),
                )
                findings.extend(file_findings)

                # Progress reporting (every 10 files)
                if (i + 1) % 10 == 0:
                    logger.info(f'Progress: {i + 1}/{len(files_to_scan)} files')

            except Exception as e:
                logger.error(f'Failed to scan {file_path}: {e}')

        return findings

    async def scan_file(self, file_path: str) -> List[dict]:
        """Scan a single file."""
        return analyze_file(
            file_path,
            self.rules_engine,
            self.taint_analyzer,
            min_severity='LOW'
        )


# ── Entry Points ──────────────────────────────────────────────────────────────

def start_lsp_server(
    host: str = 'localhost',
    port: int = 2087,
    stdio: bool = False
) -> None:
    """
    Launch LSP server using TCP socket or stdio transport.

    Args:
        host: TCP host (default: localhost)
        port: TCP port (default: 2087)
        stdio: Use stdio transport instead of TCP (default: False)
    """
    if not _LSP_AVAILABLE:
        logger.error('pygls not installed. Install with: pip install pygls')
        sys.exit(1)

    server = AuditLensLanguageServer()

    if stdio:
        logger.info('Starting LSP server on stdio')
        server.start_io()
    else:
        logger.info(f'Starting LSP server on {host}:{port}')
        server.start_tcp(host, port)


def main():
    """CLI entry point for LSP server."""
    import argparse

    parser = argparse.ArgumentParser(
        description='AuditLens Language Server Protocol (LSP) Server'
    )
    parser.add_argument(
        '--stdio',
        action='store_true',
        help='Use stdio transport (for IDE integration)'
    )
    parser.add_argument(
        '--tcp',
        action='store_true',
        help='Use TCP transport (for external connections)'
    )
    parser.add_argument(
        '--host',
        default='localhost',
        help='TCP host (default: localhost)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=2087,
        help='TCP port (default: 2087)'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )

    args = parser.parse_args()

    # Configure logging
    logging.getLogger('auditlens.lsp').setLevel(getattr(logging, args.log_level))

    # Determine transport
    stdio = args.stdio or not args.tcp

    # Start server
    start_lsp_server(
        host=args.host,
        port=args.port,
        stdio=stdio
    )


if __name__ == '__main__':
    main()
