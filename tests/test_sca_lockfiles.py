"""
Tests for SCA lockfile parsers (T2-1).
"""
from __future__ import annotations

import json
import os
import pytest
from auditlens.sca_engine import SCAEngine


def _engine():
    e = SCAEngine()
    e._query_osv = lambda pkg, ver, eco: []  # no network
    return e


# ── Pipfile.lock ──────────────────────────────────────────────────────────────

def test_pipfile_lock_basic(tmp_path):
    data = {
        "default": {
            "requests": {"version": "==2.28.0"},
            "django": {"version": "==3.2.0"},
        },
        "develop": {}
    }
    lock = tmp_path / "Pipfile.lock"
    lock.write_text(json.dumps(data))

    called = []
    e = _engine()
    e._query_osv = lambda pkg, ver, eco: (called.append((pkg, ver, eco)) or [])
    e._scan_pipfile_lock(str(lock))

    pkg_names = [c[0] for c in called]
    assert 'requests' in pkg_names
    assert 'django' in pkg_names


def test_pipfile_lock_extracts_clean_version(tmp_path):
    data = {"default": {"flask": {"version": "==2.3.0"}}, "develop": {}}
    lock = tmp_path / "Pipfile.lock"
    lock.write_text(json.dumps(data))

    called = []
    e = _engine()
    e._query_osv = lambda pkg, ver, eco: (called.append((pkg, ver)) or [])
    e._scan_pipfile_lock(str(lock))

    assert ('flask', '2.3.0') in called


# ── poetry.lock ───────────────────────────────────────────────────────────────

def test_poetry_lock_manual_parser(tmp_path):
    content = """
[[package]]
name = "requests"
version = "2.28.0"
description = "Python HTTP for Humans."

[[package]]
name = "flask"
version = "2.3.0"
description = "A simple framework."
"""
    lock = tmp_path / "poetry.lock"
    lock.write_text(content)

    from auditlens.sca_engine import _parse_poetry_lock_manual
    result = _parse_poetry_lock_manual(str(lock))
    names = [p['name'] for p in result['package']]
    assert 'requests' in names
    assert 'flask' in names


# ── package-lock.json v2 ──────────────────────────────────────────────────────

def test_package_lock_v2(tmp_path):
    data = {
        "lockfileVersion": 2,
        "packages": {
            "": {"name": "my-app", "version": "1.0.0"},
            "node_modules/express": {"version": "4.18.0"},
            "node_modules/lodash": {"version": "4.17.21"},
        }
    }
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps(data))

    called = []
    e = _engine()
    e._query_osv = lambda pkg, ver, eco: (called.append((pkg, ver)) or [])
    e._scan_package_lock_json(str(lock))

    pkg_names = [c[0] for c in called]
    assert 'express' in pkg_names
    assert 'lodash' in pkg_names


def test_package_lock_v1(tmp_path):
    data = {
        "lockfileVersion": 1,
        "dependencies": {
            "express": {"version": "4.18.0"},
            "react": {"version": "18.2.0"}
        }
    }
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps(data))

    called = []
    e = _engine()
    e._query_osv = lambda pkg, ver, eco: (called.append((pkg, ver)) or [])
    e._scan_package_lock_json(str(lock))

    pkg_names = [c[0] for c in called]
    assert 'express' in pkg_names


# ── yarn.lock ─────────────────────────────────────────────────────────────────

def test_yarn_lock_basic(tmp_path):
    content = '''
"express@^4.18.0":
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"

"lodash@^4.17.0":
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
'''
    lock = tmp_path / "yarn.lock"
    lock.write_text(content)

    called = []
    e = _engine()
    e._query_osv = lambda pkg, ver, eco: (called.append((pkg, ver)) or [])
    e._scan_yarn_lock(str(lock))

    pkg_names = [c[0] for c in called]
    assert 'express' in pkg_names
    assert 'lodash' in pkg_names


# ── Progress indicator (T2-5) — just ensure no crash ─────────────────────────

def test_progress_indicator_non_tty(tmp_path, capsys):
    """Progress indicator should not crash in non-TTY environments."""
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\n")

    e = SCAEngine()
    e._query_osv = lambda pkg, ver, eco: []
    e._scan_requirements_txt(str(req))  # should not raise
