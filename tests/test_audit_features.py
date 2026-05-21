"""
Tests for ISO mapper, audit planner, and test coverage analyzer.
"""
from __future__ import annotations
import os
import pytest
from auditlens.iso_mapper import (
    get_iso_mapping,
    get_remediation,
    enrich_finding_with_iso,
    compute_iso_gap_analysis,
    RULE_ISO_MAP,
)
from auditlens.test_analyzer import analyze_test_coverage, _extract_module_name
from auditlens.audit_planner import (
    scan_project_structure,
    generate_smart_objectives,
    generate_audit_criteria,
    generate_roles,
    generate_kpis,
)


def _finding(rule_id='SEC-01', severity='HIGH', file='app.py', line=10):
    return {
        'rule_id': rule_id, 'name': 'Test Finding',
        'description': 'Test description',
        'file': file, 'line': line,
        'severity': severity, 'compliance': ['OWASP-A7:2021'],
    }


# ── ISO Mapper ────────────────────────────────────────────────────────────────

def test_get_iso_mapping_known_rule():
    mapping = get_iso_mapping('SEC-01-HARDCODED-SECRET')
    assert 'iso25040' in mapping
    assert 'iso12207' in mapping
    assert 'iso14764' in mapping
    assert 'criterion' in mapping
    assert len(mapping['criterion']) > 10


def test_get_iso_mapping_unknown_rule():
    mapping = get_iso_mapping('UNKNOWN-99')
    assert 'iso25040' in mapping
    assert 'ISO 25040' in mapping['iso25040']


def test_get_iso_mapping_all_prefixes():
    """All defined prefixes should return valid mappings."""
    for prefix in RULE_ISO_MAP:
        mapping = get_iso_mapping(prefix + 'TEST')
        assert mapping.get('iso25040')
        assert mapping.get('criterion')


def test_get_remediation_known_rule():
    rem = get_remediation('SEC-01')
    assert rem['titulo']
    assert len(rem['pasos']) >= 3
    assert rem['esfuerzo']
    assert rem['plazo']
    assert rem['prioridad']


def test_get_remediation_unknown_falls_back():
    rem = get_remediation('UNKNOWN-99')
    assert rem == get_remediation('DEFAULT')


def test_enrich_finding_with_iso():
    f = _finding('INJ-01', 'CRITICAL')
    enriched = enrich_finding_with_iso(f)
    assert 'condicion' in enriched
    assert 'criterio' in enriched
    assert 'causa' in enriched
    assert 'efecto' in enriched
    assert 'norma_iso25040' in enriched
    assert 'norma_iso12207' in enriched
    assert 'norma_iso14764' in enriched
    assert 'remediacion' in enriched
    assert enriched['condicion']
    assert 'CRÍTICO' in enriched['efecto'] or 'crítico' in enriched['efecto'].lower()


def test_compute_iso_gap_analysis_empty():
    result = compute_iso_gap_analysis([])
    assert 'iso25040' in result
    assert 'iso12207' in result
    assert 'iso14764' in result
    assert result['iso25040']['puntuacion_general'] == 100


def test_compute_iso_gap_analysis_with_findings():
    findings = [
        _finding('SEC-01', 'HIGH'),
        _finding('INJ-01', 'CRITICAL'),
        _finding('DESER-01', 'CRITICAL'),
    ]
    result = compute_iso_gap_analysis(findings)
    # Should have lower score than 100 due to violations
    assert result['iso25040']['puntuacion_general'] < 100
    assert result['iso25040']['puntuacion_general'] >= 0


def test_iso_gap_scores_between_0_and_100():
    findings = [_finding('SEC-01')] * 10
    result = compute_iso_gap_analysis(findings)
    for standard in ('iso25040', 'iso12207', 'iso14764'):
        score = result[standard]['puntuacion_general']
        assert 0 <= score <= 100, f"{standard} score out of range: {score}"


# ── Test Coverage Analyzer ────────────────────────────────────────────────────

def test_analyze_empty_directory(tmp_path):
    result = analyze_test_coverage(str(tmp_path))
    assert result['total_archivos_fuente'] == 0
    assert result['total_archivos_test'] == 0
    assert result['ratio_cobertura_estimado'] == 0.0


def test_analyze_detects_source_files(tmp_path):
    (tmp_path / 'app.py').write_text('x = 1\n')
    (tmp_path / 'models.py').write_text('class User: pass\n')
    result = analyze_test_coverage(str(tmp_path))
    assert result['total_archivos_fuente'] == 2


def test_analyze_detects_test_files(tmp_path):
    (tmp_path / 'app.py').write_text('x = 1\n')
    (tmp_path / 'test_app.py').write_text('def test_x(): assert 1 == 1\n')
    result = analyze_test_coverage(str(tmp_path))
    assert result['total_archivos_test'] >= 1
    assert result['ratio_cobertura_estimado'] > 0


def test_analyze_detects_test_dir(tmp_path):
    tests = tmp_path / 'tests'
    tests.mkdir()
    (tmp_path / 'app.py').write_text('x = 1\n')
    (tests / 'test_app.py').write_text('def test_x(): pass\n')
    result = analyze_test_coverage(str(tmp_path))
    assert result['total_archivos_test'] >= 1


def test_analyze_identifies_gaps_no_tests(tmp_path):
    (tmp_path / 'app.py').write_text('x = 1\n')
    result = analyze_test_coverage(str(tmp_path))
    gaps = result['brechas_identificadas']
    # Should have at least one gap when there are no test files
    assert len(gaps) >= 1


def test_extract_module_name():
    assert _extract_module_name('user_service.py') == 'user'
    assert _extract_module_name('auth.py') == 'auth'
    assert _extract_module_name('app.js') == 'app'


# ── Audit Planner ─────────────────────────────────────────────────────────────

def test_scan_project_structure(tmp_path):
    (tmp_path / 'app.py').write_text('x = 1\n')
    (tmp_path / 'models.js').write_text('const x = 1;\n')
    result = scan_project_structure(str(tmp_path))
    assert 'Python' in result['lenguajes'] or 'JavaScript' in result['lenguajes']
    assert result['total_archivos'] >= 2


def test_scan_detects_special_files(tmp_path):
    (tmp_path / 'requirements.txt').write_text('requests==2.28\n')
    (tmp_path / 'package.json').write_text('{"name":"test"}\n')
    (tmp_path / 'Dockerfile').write_text('FROM python:3.11\n')
    result = scan_project_structure(str(tmp_path))
    assert result['tiene_requirements']
    assert result['tiene_package_json']
    assert result['tiene_dockerfile']


def test_generate_smart_objectives():
    project_info = {'lenguajes': {'Python': 5}, 'total_archivos': 10, 'modulos': ['api', 'models']}
    findings = [_finding('SEC-01', 'CRITICAL')] * 3
    objectives = generate_smart_objectives(project_info, findings, 'Empresa', 'Sistema v1', '2025 Q3')
    assert len(objectives) >= 1
    for obj in objectives:
        assert obj['especifico']
        assert obj['medible']
        assert obj['alcanzable']
        assert obj['relevante']
        assert obj['plazo']
        assert obj['iso']


def test_generate_audit_criteria():
    gap = compute_iso_gap_analysis([_finding()])
    criteria = generate_audit_criteria(gap)
    assert len(criteria) == 3
    assert any('25040' in c['norma'] for c in criteria)
    assert any('12207' in c['norma'] for c in criteria)
    assert any('14764' in c['norma'] for c in criteria)


def test_generate_roles():
    roles = generate_roles()
    assert len(roles) == 3
    role_names = [r['rol'] for r in roles]
    assert 'Auditor Líder' in role_names
    assert 'Auditor Técnico de Software' in role_names
    assert 'Auditor de Procesos' in role_names


def test_generate_kpis():
    findings = [_finding('SEC-01', 'CRITICAL')] * 2 + [_finding('INJ-01', 'HIGH')] * 3
    test_analysis = {'ratio_cobertura_estimado': 25.0}
    kpis = generate_kpis(findings, test_analysis)
    assert len(kpis) >= 3
    for kpi in kpis:
        assert kpi['kpi']
        assert kpi['descripcion']
        assert kpi['meta'] is not None
        assert kpi['frecuencia']
        assert kpi['iso']
