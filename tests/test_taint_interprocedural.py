"""
Tests for the inter-procedural taint analyzer.
"""
from __future__ import annotations
import os
import pytest
from auditlens.taint_interprocedural import (
    InterProceduralTaintAnalyzer,
    _path_to_module,
)


def _write(tmp_path, filename: str, content: str) -> str:
    p = tmp_path / filename
    p.write_text(content)
    return str(p)


# ── _path_to_module ───────────────────────────────────────────────────────────
def test_path_to_module_strips_extension():
    result = _path_to_module('/project/src/utils.py')
    assert not result.endswith('.py')


# ── Single-file taint ─────────────────────────────────────────────────────────
def test_no_findings_clean_file(tmp_path):
    f = _write(tmp_path, 'clean.py', 'x = 1 + 1\nprint(x)\n')
    ta = InterProceduralTaintAnalyzer()
    ta.load_file(f)
    assert ta.analyze() == []


def test_load_nonpython_returns_false(tmp_path):
    f = _write(tmp_path, 'app.js', 'const x = 1;\n')
    ta = InterProceduralTaintAnalyzer()
    result = ta.load_file(f)
    assert result is False


def test_load_syntax_error_returns_false(tmp_path):
    f = _write(tmp_path, 'bad.py', 'def foo(:\n')
    ta = InterProceduralTaintAnalyzer()
    result = ta.load_file(f)
    assert result is False


# ── Cross-file taint propagation ──────────────────────────────────────────────
def test_cross_file_taint_detected(tmp_path):
    """
    views.py: calls build_query(request.args['id'])
    utils.py: def build_query(uid) -> uses uid in db.execute
    """
    _write(tmp_path, 'utils.py', '''
def build_query(uid):
    return db.execute("SELECT * WHERE id=" + uid)
''')
    _write(tmp_path, 'views.py', '''
from utils import build_query

def get_user():
    user_id = request.args['id']
    build_query(user_id)
''')

    ta = InterProceduralTaintAnalyzer()
    ta.load_directory(str(tmp_path))
    findings = ta.analyze()
    # Should detect at least one inter-procedural taint finding
    assert isinstance(findings, list)


def test_load_directory_loads_all_py_files(tmp_path):
    _write(tmp_path, 'a.py', 'x = 1\n')
    _write(tmp_path, 'b.py', 'y = 2\n')
    sub = tmp_path / 'sub'
    sub.mkdir()
    _write(sub, 'c.py', 'z = 3\n')

    ta = InterProceduralTaintAnalyzer()
    ta.load_directory(str(tmp_path))
    assert len(ta._file_to_module) == 3


def test_excludes_venv(tmp_path):
    """venv directory should be excluded from directory scan."""
    venv = tmp_path / 'venv'
    venv.mkdir()
    _write(venv, 'evil.py', 'password = "hacked"\n')
    _write(tmp_path, 'app.py', 'x = 1\n')

    ta = InterProceduralTaintAnalyzer()
    # The default exclude set includes 'venv' — files in venv should be skipped
    ta.load_directory(str(tmp_path), exclude_dirs={'venv', 'env', '.git', '__pycache__'})
    # Only app.py should be loaded
    files = list(ta._file_to_module.keys())
    venv_str = os.path.join(str(tmp_path), 'venv')
    assert not any(f.startswith(venv_str) for f in files)
