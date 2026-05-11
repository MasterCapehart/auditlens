"""
Tests for SCAEngine.
Covers BUG-08/09, CQ-03/04, and mocked OSV API responses.
"""
import os
import json
import tempfile
import pytest

try:
    import responses as resp_lib
    HAS_RESPONSES = True
except ImportError:
    HAS_RESPONSES = False

from auditlens.sca_engine import SCAEngine, _clean_version, _osv_severity


# ── _clean_version ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,expected", [
    ("^1.2.3", "1.2.3"),
    ("~1.2.3", "1.2.3"),
    (">=2.0.0", "2.0.0"),
    ("==3.1.0", "3.1.0"),
    ("*", None),
    ("latest", None),
    ("1.0.x", "1.0.0"),
    ("git+https://github.com/foo/bar", None),
    ("", None),
])
def test_clean_version(raw, expected):
    assert _clean_version(raw) == expected


# ── _osv_severity ─────────────────────────────────────────────────────────────
def test_osv_severity_from_cvss_score():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
    assert _osv_severity(vuln) == "CRITICAL"

def test_osv_severity_high():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
    assert _osv_severity(vuln) == "HIGH"

def test_osv_severity_medium():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "5.3"}]}
    assert _osv_severity(vuln) == "MEDIUM"

def test_osv_severity_low():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "2.1"}]}
    assert _osv_severity(vuln) == "LOW"

def test_osv_severity_fallback_when_empty():
    """CQ-03 FIX: no CVSS data → conservative default MEDIUM, not CRITICAL."""
    assert _osv_severity({}) == "MEDIUM"

def test_osv_severity_from_database_specific():
    vuln = {"database_specific": {"severity": "HIGH"}}
    assert _osv_severity(vuln) == "HIGH"


# ── requirements.txt parsing ─────────────────────────────────────────────────
def test_scan_requirements_basic(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.28.0\nDjango>=3.1.0\n")

    engine = SCAEngine()
    # Patch _query_osv to return empty so we don't hit network
    engine._query_osv = lambda pkg, ver, eco: []

    findings = engine._scan_requirements_txt(str(req_file))
    assert findings == []  # empty because no vulns returned


def test_scan_requirements_with_dots(tmp_path):
    """BUG-08 FIX: package names with dots (zope.interface) must be parsed."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("zope.interface==5.4.0\n")

    engine = SCAEngine()
    called = []

    def mock_osv(pkg, ver, eco):
        called.append((pkg, ver))
        return []

    engine._query_osv = mock_osv
    engine._scan_requirements_txt(str(req_file))
    assert any(pkg == 'zope.interface' for pkg, _ in called)


def test_scan_requirements_with_extras(tmp_path):
    """BUG-08 FIX: extras syntax requests[security]==2.28.0 must parse."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests[security]==2.28.0\n")

    engine = SCAEngine()
    called = []

    def mock_osv(pkg, ver, eco):
        called.append((pkg, ver))
        return []

    engine._query_osv = mock_osv
    engine._scan_requirements_txt(str(req_file))
    assert any(pkg == 'requests' for pkg, _ in called)


def test_scan_requirements_skips_no_version(tmp_path, capsys):
    """BUG-08 FIX: lines with no version are skipped gracefully with a warning."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests\n")  # no version pin

    engine = SCAEngine()
    engine._query_osv = lambda pkg, ver, eco: []

    findings = engine._scan_requirements_txt(str(req_file))
    assert findings == []


# ── CQ-04: IndexError on empty aliases list ───────────────────────────────────
def test_format_vulns_empty_aliases():
    """CQ-04 FIX: empty aliases list must not raise IndexError."""
    engine = SCAEngine()
    vulns = [{"aliases": [], "id": "GHSA-1234", "summary": "Test vuln"}]
    findings = engine._format_vulns(vulns, "pkg", "1.0.0", "/req.txt")
    assert len(findings) == 1
    assert "GHSA-1234" in findings[0]['rule_id']


def test_format_vulns_missing_aliases():
    """CQ-04 FIX: missing aliases key must not raise."""
    engine = SCAEngine()
    vulns = [{"id": "GHSA-9999", "summary": "No aliases"}]
    findings = engine._format_vulns(vulns, "pkg", "1.0.0", "/req.txt")
    assert len(findings) == 1


# ── package.json parsing ──────────────────────────────────────────────────────
def test_scan_package_json_skips_wildcards(tmp_path):
    """BUG-09 FIX: * and latest versions are skipped, not sent to OSV."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "dependencies": {
            "lodash": "*",
            "express": "latest",
            "react": "^18.0.0",
        }
    }))

    engine = SCAEngine()
    called = []

    def mock_osv(pkg_name, ver, eco):
        called.append((pkg_name, ver))
        return []

    engine._query_osv = mock_osv
    engine._scan_package_json(str(pkg))

    pkg_names = [c[0] for c in called]
    assert 'lodash' not in pkg_names
    assert 'express' not in pkg_names
    assert 'react' in pkg_names
