"""
AuditLens — Test Coverage Analyzer

Detects test files, estimates coverage ratio, identifies gaps per ISO 12207
(Verification and Validation process).
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Set, Tuple

_TEST_PATTERNS = [
    re.compile(r'test_.*\.py$', re.IGNORECASE),
    re.compile(r'.*_test\.py$', re.IGNORECASE),
    re.compile(r'.*\.test\.(ts|tsx|js|jsx)$', re.IGNORECASE),
    re.compile(r'.*\.spec\.(ts|tsx|js|jsx)$', re.IGNORECASE),
    re.compile(r'.*Test\.java$'),
    re.compile(r'.*_test\.go$'),
    re.compile(r'.*_spec\.rb$', re.IGNORECASE),
]

_TEST_DIRS = {'tests', 'test', '__tests__', 'spec', 'specs', '__spec__', 'e2e'}

_SOURCE_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rb', '.kt', '.swift'}

_EXCLUDE_DIRS = {
    'venv', '.venv', 'env', '.env', 'node_modules', '.git',
    '__pycache__', 'build', 'dist', '.tox', 'site-packages',
    'migrations', 'vendor',
}

_SECURITY_TEST_PATTERNS = [
    re.compile(r'(?i)(security|pentest|penetration|injection|xss|sql|csrf|auth)', ),
    re.compile(r'(?i)(test.*password|test.*token|test.*secret|test.*credential)'),
]

_INTEGRATION_TEST_PATTERNS = [
    re.compile(r'(?i)(integration|e2e|end.to.end|api.test|functional)'),
]


def analyze_test_coverage(root_path: str) -> Dict:
    """
    Scan a project directory and return test coverage analysis.
    Returns metrics aligned with ISO 12207 Verification and Validation process.
    """
    source_files: List[str] = []
    test_files: List[str] = []
    source_modules: Set[str] = set()
    tested_modules: Set[str] = set()
    security_tests: List[str] = []
    integration_tests: List[str] = []
    has_test_config = False

    # Common test config files
    test_config_names = {
        'pytest.ini', 'setup.cfg', 'pyproject.toml', 'jest.config.js',
        'jest.config.ts', 'vitest.config.ts', 'karma.conf.js',
        '.mocharc.js', '.mocharc.yml', 'jasmine.json',
    }

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDE_DIRS]

        # Check for test config
        for fname in filenames:
            if fname in test_config_names:
                has_test_config = True

        is_test_dir = os.path.basename(dirpath).lower() in _TEST_DIRS

        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            fpath = os.path.join(dirpath, fname)

            if ext not in _SOURCE_EXTENSIONS:
                continue

            is_test_file = is_test_dir or any(p.match(fname) for p in _TEST_PATTERNS)

            if is_test_file:
                test_files.append(fpath)
                # Extract which module this test covers
                module = _extract_tested_module(fname)
                if module:
                    tested_modules.add(module)

                # Check test types
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                        content = fh.read(4000)  # first 4KB is enough
                    if any(p.search(content) for p in _SECURITY_TEST_PATTERNS):
                        security_tests.append(fpath)
                    if any(p.search(content) for p in _INTEGRATION_TEST_PATTERNS):
                        integration_tests.append(fpath)
                except OSError:
                    pass
            else:
                source_files.append(fpath)
                module = _extract_module_name(fname)
                if module:
                    source_modules.add(module)

    # Calculate metrics
    total_source = len(source_files)
    total_tests = len(test_files)

    # Files without any corresponding test
    untested_modules = source_modules - tested_modules
    untested_files = [
        f for f in source_files
        if _extract_module_name(os.path.basename(f)) in untested_modules
    ][:20]  # limit to top 20

    # Estimated coverage ratio
    if total_source == 0:
        coverage_ratio = 0.0
    else:
        coverage_ratio = min(100.0, (total_tests / max(total_source, 1)) * 100)

    # Test type breakdown
    has_unit = total_tests > 0
    has_security = len(security_tests) > 0
    has_integration = len(integration_tests) > 0

    # ISO 12207 compliance indicators
    iso12207_score = _compute_iso12207_test_score(
        total_source, total_tests, has_security, has_integration, has_test_config
    )

    return {
        'total_archivos_fuente': total_source,
        'total_archivos_test': total_tests,
        'ratio_cobertura_estimado': round(coverage_ratio, 1),
        'archivos_sin_tests': untested_files,
        'total_sin_tests': len(untested_files),
        'tiene_config_tests': has_test_config,
        'tipos_pruebas': {
            'unitarias': has_unit,
            'seguridad': has_security,
            'integracion': has_integration,
        },
        'tests_seguridad': security_tests[:5],
        'tests_integracion': integration_tests[:5],
        'puntuacion_iso12207': iso12207_score,
        'brechas_identificadas': _identify_test_gaps(
            total_source, total_tests, has_security, has_integration, has_test_config
        ),
    }


def _extract_module_name(filename: str) -> str:
    """Extract base module name from filename for matching."""
    name = os.path.splitext(filename)[0].lower()
    # Remove common suffixes
    for suffix in ('_service', '_controller', '_model', '_view', '_handler',
                   '_router', '_utils', '_helpers', '_api'):
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    return name


def _extract_tested_module(test_filename: str) -> str:
    """Extract which module a test file likely covers."""
    name = os.path.splitext(test_filename)[0].lower()
    # Remove test prefixes/suffixes
    for prefix in ('test_', 'spec_'):
        if name.startswith(prefix):
            name = name[len(prefix):]
    for suffix in ('_test', '_spec', '.test', '.spec'):
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    return name


def _compute_iso12207_test_score(
    total_source: int,
    total_tests: int,
    has_security: bool,
    has_integration: bool,
    has_config: bool,
) -> int:
    """Compute ISO 12207 V&V process conformance score (0-100)."""
    score = 0

    # Has any tests (base requirement)
    if total_tests > 0:
        score += 30

    # Reasonable test ratio (at least 0.5 tests per source file)
    if total_source > 0:
        ratio = total_tests / total_source
        if ratio >= 1.0:
            score += 30
        elif ratio >= 0.5:
            score += 20
        elif ratio >= 0.2:
            score += 10

    # Security tests (ISO 12207 security verification)
    if has_security:
        score += 20

    # Integration tests
    if has_integration:
        score += 10

    # Test configuration (automated testing infrastructure)
    if has_config:
        score += 10

    return min(100, score)


def _identify_test_gaps(
    total_source: int,
    total_tests: int,
    has_security: bool,
    has_integration: bool,
    has_config: bool,
) -> List[Dict]:
    """Identify specific testing gaps with recommendations."""
    gaps = []

    if total_tests == 0:
        gaps.append({
            'brecha': 'No se detectaron archivos de prueba',
            'impacto': 'CRÍTICO',
            'recomendacion': 'Implementar una suite de pruebas unitarias básica',
            'iso': 'ISO 12207 — Verificación y Validación (Sección 6.4)',
            'plazo': '2 semanas',
        })
    elif total_source > 0 and (total_tests / total_source) < 0.3:
        gaps.append({
            'brecha': f'Cobertura de pruebas insuficiente ({total_tests} pruebas para {total_source} archivos fuente)',
            'impacto': 'ALTO',
            'recomendacion': f'Incrementar la cobertura de pruebas al menos al 30% — agregar {max(0, int(total_source * 0.3) - total_tests)} archivos de prueba',
            'iso': 'ISO 12207 — Proceso de Pruebas (Sección 6.4.2)',
            'plazo': '1 mes',
        })

    if not has_security:
        gaps.append({
            'brecha': 'No se detectaron pruebas de seguridad',
            'impacto': 'ALTO',
            'recomendacion': 'Implementar pruebas de seguridad (autenticación, autorización, inyección)',
            'iso': 'ISO 25040 — Seguridad Funcional, ISO 12207 — Verificación (Sección 6.4)',
            'plazo': '2 semanas',
        })

    if not has_integration:
        gaps.append({
            'brecha': 'No se detectaron pruebas de integración',
            'impacto': 'MEDIO',
            'recomendacion': 'Agregar pruebas de integración para los flujos críticos del sistema',
            'iso': 'ISO 12207 — Pruebas de Integración (Sección 7.1.5)',
            'plazo': '1 mes',
        })

    if not has_config:
        gaps.append({
            'brecha': 'No se detectó infraestructura de pruebas automatizadas',
            'impacto': 'MEDIO',
            'recomendacion': 'Configurar un framework de pruebas (pytest, Jest, JUnit) e integrarlo al CI/CD',
            'iso': 'ISO 12207 — Gestión de Calidad (Sección 6.3)',
            'plazo': '1 semana',
        })

    return gaps
