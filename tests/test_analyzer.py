"""
Tests for the static analysis orchestrator (analyzer.py).
Covers BUG-10 (silent errors), MISSING-01 (exit codes), MISSING-04 (severity filter),
MISSING-05 (suppress), and general integration.
"""
import os
import tempfile
import pytest
from auditlens.analyzer import run_static_analysis, _should_suppress, analyze_file
from auditlens.rules_engine import RulesEngine
from auditlens.taint_analyzer import TaintAnalyzer


# ── Suppress mechanism (MISSING-05) ──────────────────────────────────────────
def test_suppress_comment_detected():
    assert _should_suppress('password = "foo"  # auditlens: ignore', 'SEC-01')
    assert _should_suppress('  # auditlens: ignore', 'ANY-RULE')
    assert not _should_suppress('password = "foo"', 'SEC-01')
    # Rule-specific: only suppress the named rule
    assert _should_suppress('x  # auditlens: ignore SEC-01', 'SEC-01')
    assert not _should_suppress('x  # auditlens: ignore SEC-01', 'SEC-02')


def test_suppress_prevents_finding(tmp_path):
    f = tmp_path / "script.py"
    f.write_text('password = "hardcoded"  # auditlens: ignore\n')

    engine = RulesEngine()
    ta = TaintAnalyzer()
    findings = analyze_file(str(f), engine, ta)
    # The suppress comment should prevent any finding on that line
    assert all(
        finding['line'] != 1
        for finding in findings
    )


# ── Exit codes (MISSING-01) ───────────────────────────────────────────────────
def test_exit_code_0_when_no_findings(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text("x = 1 + 1\nprint(x)\n")
    code = run_static_analysis(str(f), run_sca=False)
    assert code == 0


def test_exit_code_1_when_findings(tmp_path):
    f = tmp_path / "vuln.py"
    f.write_text('password = "s3cr3t"\nprint(password)\n')
    code = run_static_analysis(str(f), run_sca=False)
    assert code == 1


def test_exit_code_2_for_nonexistent_path():
    code = run_static_analysis("/nonexistent/path", run_sca=False)
    assert code == 2


# ── Severity filter (MISSING-04) ─────────────────────────────────────────────
def test_severity_filter_excludes_low(tmp_path):
    """Findings below min_severity must not be reported."""
    f = tmp_path / "script.py"
    # Write a file whose only finding would be LOW (DATA-02-HARDCODED-IP)
    f.write_text("server = '192.168.1.1'\n")

    accumulator = []
    engine = RulesEngine()
    ta = TaintAnalyzer()
    analyze_file(str(f), engine, ta, min_severity='HIGH', all_findings_accumulator=accumulator)
    # No HIGH+ findings expected for a plain IP address
    assert all(
        finding['severity'].upper() in ('HIGH', 'CRITICAL')
        for finding in accumulator
    )


# ── BUG-10: unreadable file does not crash ────────────────────────────────────
def test_unreadable_file_does_not_crash(tmp_path):
    """BUG-10 FIX: binary/unreadable files produce a warning, not a crash."""
    f = tmp_path / "binary.py"
    f.write_bytes(b'\x00\x01\x02\x03\xff\xfe')

    engine = RulesEngine()
    ta = TaintAnalyzer()
    # Should not raise — errors='replace' handles binary content
    findings = analyze_file(str(f), engine, ta)
    assert isinstance(findings, list)


# ── Directory scanning ────────────────────────────────────────────────────────
def test_directory_scan_recurses(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "app.py").write_text('token = "abc"\nrequests.post("x", data=token)\n')
    (tmp_path / "main.py").write_text('x = 1\n')

    code = run_static_analysis(str(tmp_path), run_sca=False)
    assert code == 1


def test_directory_scan_excludes_node_modules(tmp_path):
    nm = tmp_path / "node_modules"
    nm.mkdir()
    (nm / "vuln.py").write_text('password = "secret"\n')

    code = run_static_analysis(str(tmp_path), run_sca=False)
    assert code == 0  # node_modules excluded


# ── SARIF output (MISSING-02) ─────────────────────────────────────────────────
def test_sarif_export_creates_file(tmp_path):
    f = tmp_path / "vuln.py"
    f.write_text('password = "hardcoded"\n')
    out = str(tmp_path / "out.sarif")

    run_static_analysis(str(f), export_sarif=True, output_path=out, run_sca=False)
    assert os.path.exists(out)

    import json
    with open(out) as fh:
        data = json.load(fh)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) >= 1
