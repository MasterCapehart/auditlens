"""
AuditLens Language Server Protocol (LSP) Server.

Changes vs original:
- BUG-02: import path fixed — uses absolute package import instead of bare 'analyzer'
  so the server can be started from any working directory.
"""

import sys
import os

# Ensure the lsp-server directory is on sys.path so relative imports resolve.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from pygls.server import LanguageServer
from lsp_analyzer import analyze_code_with_ast  # BUG-02 FIX: renamed to lsp_analyzer.py
from lsprotocol.types import (
    TEXT_DOCUMENT_DID_OPEN,
    TEXT_DOCUMENT_DID_CHANGE,
    DidOpenTextDocumentParams,
    DidChangeTextDocumentParams,
    Diagnostic,
    Position,
    Range,
    DiagnosticSeverity,
)

server = LanguageServer("auditlens-server", "v0.2")


def validate_code(ls: LanguageServer, uri: str, text: str):
    diagnostics = analyze_code_with_ast(text, uri)
    ls.publish_diagnostics(uri, diagnostics)


@server.feature(TEXT_DOCUMENT_DID_OPEN)
def did_open(ls: LanguageServer, params: DidOpenTextDocumentParams):
    text_doc = ls.workspace.get_document(params.text_document.uri)
    validate_code(ls, params.text_document.uri, text_doc.source)


@server.feature(TEXT_DOCUMENT_DID_CHANGE)
def did_change(ls: LanguageServer, params: DidChangeTextDocumentParams):
    text_doc = ls.workspace.get_document(params.text_document.uri)
    validate_code(ls, params.text_document.uri, text_doc.source)


if __name__ == '__main__':
    server.start_io()
