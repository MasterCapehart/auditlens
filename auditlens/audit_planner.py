"""
AuditLens — Audit Planning Engine

Generates a complete audit planning document from project analysis.
Covers rubric sections 1.1, 1.2, 1.3, 1.4 automatically.

Usage:
    auditlens plan ./proyecto --empresa "MiEmpresa" --sistema "SistemaX v1.0"
    auditlens plan ./proyecto --output plan_auditoria.docx
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from .iso_mapper import (
    ISO_25040_CHARACTERISTICS,
    ISO_12207_PROCESSES,
    ISO_14764_ACTIVITIES,
    compute_iso_gap_analysis,
)
from .test_analyzer import analyze_test_coverage


# ── Project scanner ───────────────────────────────────────────────────────────

def scan_project_structure(root_path: str) -> Dict:
    """Analyze project structure to auto-generate planning context."""
    languages: Dict[str, int] = {}
    modules: List[str] = []
    has_requirements = False
    has_package_json = False
    has_dockerfile = False
    has_ci = False
    has_readme = False
    has_gitignore = False
    total_files = 0
    total_lines = 0

    ext_to_lang = {
        '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript',
        '.tsx': 'TypeScript/React', '.jsx': 'JavaScript/React',
        '.java': 'Java', '.kt': 'Kotlin', '.go': 'Go',
        '.rb': 'Ruby', '.swift': 'Swift', '.cs': 'C#',
        '.php': 'PHP', '.rs': 'Rust', '.cpp': 'C++', '.c': 'C',
    }

    exclude_dirs = {
        'venv', '.venv', 'env', '.env', 'node_modules', '.git',
        '__pycache__', 'build', 'dist', '.tox', 'site-packages',
    }

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        rel = os.path.relpath(dirpath, root_path)

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            ext = os.path.splitext(fname)[1].lower()
            fname_lower = fname.lower()

            # Detect special files
            if fname_lower in ('requirements.txt', 'pipfile', 'pyproject.toml', 'setup.py'):
                has_requirements = True
            if fname_lower == 'package.json':
                has_package_json = True
            if fname_lower in ('dockerfile', 'docker-compose.yml', 'docker-compose.yaml'):
                has_dockerfile = True
            if fname_lower in ('.gitignore', '.gitattributes'):
                has_gitignore = True
            if fname_lower in ('readme.md', 'readme.txt', 'readme.rst'):
                has_readme = True
            if '.github' in fpath or fname_lower in ('ci.yml', 'ci.yaml', '.travis.yml', 'jenkins.yml'):
                has_ci = True

            # Count languages
            if ext in ext_to_lang:
                lang = ext_to_lang[ext]
                languages[lang] = languages.get(lang, 0) + 1
                total_files += 1
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                        total_lines += sum(1 for _ in fh)
                except OSError:
                    pass

        # Detect top-level modules/components
        if rel == '.' or rel.count(os.sep) == 0:
            for d in dirnames:
                if not d.startswith('.') and d not in exclude_dirs:
                    modules.append(d)

    return {
        'lenguajes': languages,
        'modulos': modules[:15],  # top 15 modules
        'total_archivos': total_files,
        'total_lineas': total_lines,
        'tiene_requirements': has_requirements,
        'tiene_package_json': has_package_json,
        'tiene_dockerfile': has_dockerfile,
        'tiene_ci': has_ci,
        'tiene_readme': has_readme,
        'tiene_gitignore': has_gitignore,
    }


def generate_smart_objectives(
    project_info: Dict,
    findings_preview: List[dict],
    empresa: str,
    sistema: str,
    trimestre: str,
    fecha_entrega: str = '08/06/2026',
) -> List[Dict]:
    """Generate SMART objectives based on project analysis."""
    objectives = []

    # Use delivery date as deadline — NOT 12 weeks from now
    fecha_fin = fecha_entrega

    critical_count = sum(1 for f in findings_preview if f.get('severity') == 'CRITICAL')
    high_count = sum(1 for f in findings_preview if f.get('severity') == 'HIGH')
    total_files = project_info.get('total_archivos', 0)
    modules = project_info.get('modulos', [])
    top_modules = ', '.join(modules[:3]) if modules else 'módulos principales'

    objectives.append({
        'numero': 1,
        'titulo': 'Evaluación de Seguridad del Código',
        'descripcion': (
            f"Auditar el sistema {sistema} de la empresa {empresa} durante el {trimestre}, "
            f"evaluando la conformidad con los requisitos de seguridad de ISO 25040, "
            f"con foco en los módulos {top_modules}, para identificar y documentar "
            f"todas las vulnerabilidades críticas y de alta severidad."
        ),
        'especifico': (
            f"Analizar el 100% del código fuente de {sistema} ({total_files} archivos), "
            f"con énfasis en los módulos {top_modules} que concentran mayor riesgo"
        ),
        'medible': (
            f"Documentar los {critical_count} hallazgos CRÍTICOS y {high_count} ALTOS detectados; "
            f"proponer remediación para el 100% de los hallazgos CRÍTICOS"
        ),
        'alcanzable': (
            "Mediante análisis estático automatizado con AuditLens y SonarQube, "
            "revisión manual de código y entrevistas estructuradas al equipo de desarrollo"
        ),
        'relevante': (
            "La seguridad del sistema impacta directamente en la confidencialidad de los datos "
            "de usuarios y en el cumplimiento de ISO 25040 Seguridad Funcional"
        ),
        'plazo': f"Completar el análisis y entregar el informe antes del {fecha_fin}",
        'iso': ['ISO 25040 — Seguridad Funcional (Sección 4.2.5)', 'ISO 12207 — Verificación y Validación'],
    })

    if total_files > 5:
        test_coverage = project_info.get('ratio_cobertura', 0)
        objectives.append({
            'numero': 2,
            'titulo': 'Evaluación de Cobertura de Pruebas y Verificación',
            'descripcion': (
                f"Evaluar la cobertura de pruebas del software {sistema} y verificar "
                f"la conformidad con el proceso de Verificación y Validación de ISO 12207, "
                f"identificando los módulos sin cobertura de pruebas."
            ),
            'especifico': (
                f"Auditar los {total_files} archivos fuente del sistema {sistema} "
                f"en busca de archivos sin pruebas asociadas y brechas en la estrategia de testing"
            ),
            'medible': (
                "Documentar el ratio de cobertura actual y proponer un plan para "
                "alcanzar al menos el 70% de cobertura de pruebas en los módulos críticos"
            ),
            'alcanzable': (
                "Mediante análisis automático de la estructura del repositorio "
                "y verificación de la existencia de suites de prueba por módulo"
            ),
            'relevante': (
                "La falta de pruebas es la causa raíz de muchos defectos en producción "
                "y es requerida explícitamente por ISO 12207 en su proceso de V&V"
            ),
            'plazo': f"Completar antes del {fecha_fin}",
            'iso': ['ISO 12207 — Verificación y Validación (Sección 6.4)', 'ISO 25040 — Fiabilidad'],
        })

    objectives.append({
        'numero': 3,
        'titulo': 'Evaluación de Mantenibilidad y Procesos de Mantenimiento',
        'descripcion': (
            f"Evaluar las prácticas de mantenimiento del software {sistema} conforme a "
            f"ISO 14764, identificando brechas en los procesos de mantenimiento correctivo, "
            f"adaptativo y preventivo, con foco en la gestión de dependencias vulnerables."
        ),
        'especifico': (
            f"Auditar los procesos de mantenimiento, gestión de cambios y dependencias de "
            f"terceros del sistema {sistema}"
        ),
        'medible': (
            "Clasificar el 100% de los hallazgos según tipo de mantenimiento ISO 14764 "
            "(correctivo/adaptativo/preventivo/perfectivo) y calcular puntuación de conformidad"
        ),
        'alcanzable': (
            "Mediante análisis automatizado de dependencias con SCA y "
            "revisión documental del historial de cambios del repositorio"
        ),
        'relevante': (
            "Garantiza la sostenibilidad del sistema a largo plazo y "
            "el cumplimiento de ISO 14764 en los procesos de mantenimiento"
        ),
        'plazo': f"Completar antes del {fecha_fin}",
        'iso': ['ISO 14764 — Mantenimiento del Software', 'ISO 12207 — Gestión de Configuración'],
    })

    return objectives


def generate_audit_criteria(gap_analysis: Dict) -> List[Dict]:
    """Generate audit criteria based on ISO standards and gap analysis."""
    criteria = []

    # ISO 25040 criteria
    criteria.append({
        'numero': 1,
        'norma': 'ISO/IEC 25040 — Calidad del Producto Software',
        'caracteristicas': [
            'Seguridad Funcional: Confidencialidad, Integridad, No Repudio, Autenticidad',
            'Fiabilidad: Madurez, Disponibilidad, Tolerancia a fallos',
            'Mantenibilidad: Modularidad, Analizabilidad, Modificabilidad',
        ],
        'justificacion': (
            'ISO 25040 proporciona el marco de referencia para evaluar la calidad del producto '
            'software. Su aplicación permite identificar desviaciones en características críticas '
            'como la seguridad y la fiabilidad, que impactan directamente en la confiabilidad del sistema.'
        ),
        'metricas': [
            'Número de vulnerabilidades por característica de calidad',
            'Puntuación de conformidad por característica (0-100)',
            'Porcentaje de código con deuda técnica de seguridad',
        ],
    })

    # ISO 12207 criteria
    criteria.append({
        'numero': 2,
        'norma': 'ISO/IEC 12207 — Procesos del Ciclo de Vida del Software',
        'caracteristicas': [
            'Proceso de Desarrollo: Codificación segura y pruebas',
            'Verificación y Validación: Cobertura de pruebas unitarias e integración',
            'Gestión de la Configuración: Control de versiones y secretos',
            'Aseguramiento de la Calidad: Revisión de código y estándares',
        ],
        'justificacion': (
            'ISO 12207 define los procesos del ciclo de vida del software. Su aplicación '
            'permite verificar que el proceso de desarrollo incluye las actividades de '
            'seguridad necesarias en cada fase, desde el diseño hasta el despliegue.'
        ),
        'metricas': [
            'Ratio de archivos fuente con cobertura de pruebas',
            'Número de procesos del ciclo de vida implementados',
            'Puntuación de conformidad por proceso (0-100)',
        ],
    })

    # ISO 14764 criteria
    criteria.append({
        'numero': 3,
        'norma': 'ISO/IEC 14764 — Mantenimiento del Software',
        'caracteristicas': [
            'Mantenimiento Correctivo: Corrección de vulnerabilidades detectadas',
            'Mantenimiento Adaptativo: Actualización de algoritmos obsoletos',
            'Mantenimiento Preventivo: Actualización de dependencias vulnerables',
            'Mantenimiento Perfectivo: Mejora de prácticas de configuración',
        ],
        'justificacion': (
            'ISO 14764 establece los procesos de mantenimiento del software. Su aplicación '
            'permite clasificar y priorizar las acciones correctivas identificadas en la '
            'auditoría, asegurando una gestión estructurada de las vulnerabilidades.'
        ),
        'metricas': [
            'Número de hallazgos por tipo de mantenimiento requerido',
            'Puntuación de conformidad por actividad de mantenimiento (0-100)',
            'Tiempo estimado de remediación por categoría',
        ],
    })

    return criteria


def generate_methodology() -> Dict:
    """Generate audit methodology section with industry-standard tools."""
    return {
        'enfoque': 'Metodología Híbrida de Auditoría de Software',
        'descripcion': (
            'Se empleará una metodología híbrida que combina análisis estático automatizado, '
            'revisión documental y entrevistas estructuradas con el equipo de desarrollo, '
            'permitiendo una evaluación integral del software desde perspectivas técnicas y de proceso.'
        ),
        'tecnicas': [
            {
                'nombre': 'Análisis Estático de Código (SAST)',
                'herramienta': 'AuditLens v0.6.0 + SonarQube Community + Bandit (Python)',
                'descripcion': (
                    'Análisis automatizado del código fuente para detectar vulnerabilidades de seguridad, '
                    'patrones inseguros y deuda técnica. AuditLens proporciona análisis de taint y reglas '
                    'personalizadas; SonarQube evalúa calidad general del código; Bandit detecta '
                    'vulnerabilidades específicas de Python.'
                ),
                'cobertura': 'Código fuente Python (backend Django), JavaScript/JSX/TypeScript (frontend React)',
                'iso': 'ISO 12207 — Verificación Estática; ISO 25040 — Seguridad Funcional',
            },
            {
                'nombre': 'Análisis de Composición de Software (SCA)',
                'herramienta': 'AuditLens SCA Engine + OSV API + pip-audit + npm audit',
                'descripcion': (
                    'Verificación de dependencias de terceros contra bases de datos de vulnerabilidades '
                    'conocidas (CVE/OSV/NVD). pip-audit para dependencias Python; npm audit para '
                    'dependencias JavaScript.'
                ),
                'cobertura': 'requirements.txt, package.json, poetry.lock, Pipfile.lock',
                'iso': 'ISO 14764 — Mantenimiento Preventivo; ISO 25040 — Fiabilidad',
            },
            {
                'nombre': 'Pruebas de Seguridad Dinámicas (DAST)',
                'herramienta': 'OWASP ZAP (Zed Attack Proxy)',
                'descripcion': (
                    'Pruebas de penetración automatizadas sobre la aplicación en ejecución para detectar '
                    'vulnerabilidades en tiempo de ejecución: XSS, CSRF, inyección SQL, autenticación débil. '
                    'Se ejecuta en el ambiente de desarrollo/staging del sistema EcoAlerta.'
                ),
                'cobertura': 'API REST del backend Django, endpoints de autenticación, formularios del frontend',
                'iso': 'ISO 25040 — Seguridad Funcional; ISO 12207 — Pruebas de Sistema',
            },
            {
                'nombre': 'Análisis de Flujo de Datos (Taint Analysis)',
                'herramienta': 'AuditLens — Motor de Taint Inter-Procedural',
                'descripcion': (
                    'Rastreo de datos sensibles desde fuentes (request.args, request.form, input()) '
                    'hasta sumideros peligrosos (db.execute, os.system, subprocess). '
                    'Detecta flujos de datos peligrosos que pueden derivar en inyección SQL o command injection.'
                ),
                'cobertura': 'Análisis intra e inter-procedural en Python (backend Django)',
                'iso': 'ISO 25040 — Seguridad/Integridad; ISO 12207 — Codificación',
            },
            {
                'nombre': 'Análisis de Cobertura de Pruebas',
                'herramienta': 'AuditLens Test Coverage Analyzer + pytest-cov',
                'descripcion': (
                    'Detección automática de archivos de prueba y estimación del ratio de cobertura. '
                    'pytest-cov mide la cobertura real de líneas ejecutadas durante las pruebas.'
                ),
                'cobertura': 'Todos los módulos Python y JavaScript del proyecto',
                'iso': 'ISO 12207 — Verificación y Validación; ISO 25040 — Fiabilidad',
            },
            {
                'nombre': 'Entrevistas Estructuradas al Equipo de Desarrollo',
                'herramienta': 'Manual — Auditor de Procesos',
                'descripcion': (
                    'Entrevistas con el equipo que desarrolló EcoAlerta para obtener información '
                    'sobre el proceso de desarrollo, prácticas de seguridad, gestión de cambios '
                    'y conocimiento de las vulnerabilidades identificadas.'
                ),
                'cobertura': 'Proceso de desarrollo, gestión de cambios, prácticas de seguridad',
                'iso': 'ISO 12207 — Aseguramiento de la Calidad; ISO 14764 — Mantenimiento',
            },
            {
                'nombre': 'Revisión Documental',
                'herramienta': 'Manual — Auditor de Procesos',
                'descripcion': (
                    'Revisión de la documentación disponible del proyecto: README, comentarios de código, '
                    'configuraciones de entorno, archivos de prueba, historial de commits.'
                ),
                'cobertura': 'Documentación del repositorio EcoAlerta',
                'iso': 'ISO 12207 — Documentación; ISO 14764 — Registros de mantenimiento',
            },
        ],
        'herramientas': [
            {'nombre': 'AuditLens v0.6.0', 'tipo': 'SAST/SCA/Taint/ISO Gap Analysis', 'licencia': 'MIT Open Source'},
            {'nombre': 'SonarQube Community Edition', 'tipo': 'Análisis estático de calidad de código', 'licencia': 'LGPL v3 (gratuita)'},
            {'nombre': 'Bandit', 'tipo': 'SAST especializado en Python', 'licencia': 'Apache 2.0 (gratuita)'},
            {'nombre': 'OWASP ZAP', 'tipo': 'DAST / Pruebas de penetración web', 'licencia': 'Apache 2.0 (gratuita)'},
            {'nombre': 'pip-audit', 'tipo': 'SCA para dependencias Python', 'licencia': 'Apache 2.0 (gratuita)'},
            {'nombre': 'npm audit', 'tipo': 'SCA para dependencias JavaScript', 'licencia': 'Incluida en Node.js'},
            {'nombre': 'OSV API (Google)', 'tipo': 'Base de datos de vulnerabilidades CVE', 'licencia': 'Pública'},
            {'nombre': 'Jira Software', 'tipo': 'Gestión de hallazgos y seguimiento de acciones correctivas', 'licencia': 'Comercial (plan gratuito disponible)'},
        ],
        'guion_entrevista': [
            {'numero': 1, 'pregunta': '¿Existe un proceso formal de revisión de código (code review) antes de hacer merge al repositorio principal?', 'objetivo': 'Evaluar conformidad con ISO 12207 — Verificación'},
            {'numero': 2, 'pregunta': '¿Cómo se gestionan los secretos y credenciales (API keys, contraseñas) en el proyecto?', 'objetivo': 'Detectar riesgo de exposición de secretos (SEC-01)'},
            {'numero': 3, 'pregunta': '¿Se realizan pruebas de seguridad antes de desplegar una nueva versión? ¿Con qué herramientas?', 'objetivo': 'Evaluar madurez del proceso de V&V — ISO 12207'},
            {'numero': 4, 'pregunta': '¿Existe documentación actualizada de la arquitectura y los módulos del sistema?', 'objetivo': 'Evaluar conformidad con ISO 12207 — Documentación'},
            {'numero': 5, 'pregunta': '¿Cómo se gestionan las actualizaciones de dependencias de terceros? ¿Con qué frecuencia?', 'objetivo': 'Evaluar conformidad con ISO 14764 — Mantenimiento Preventivo'},
            {'numero': 6, 'pregunta': '¿Se han reportado incidentes de seguridad o errores críticos en producción? ¿Cómo se documentaron?', 'objetivo': 'Evaluar proceso de mantenimiento correctivo — ISO 14764'},
            {'numero': 7, 'pregunta': '¿Existe un pipeline de CI/CD? ¿Incluye análisis automático de seguridad?', 'objetivo': 'Evaluar madurez del proceso de integración — ISO 12207'},
            {'numero': 8, 'pregunta': '¿Los desarrolladores han recibido capacitación en seguridad de aplicaciones web (OWASP Top 10)?', 'objetivo': 'Identificar causa raíz de vulnerabilidades detectadas'},
        ],
        'fases': [
            {'fase': 1, 'nombre': 'Planificación', 'duracion': '3 días', 'actividades': ['Definición de alcance', 'Configuración de AuditLens y SonarQube', 'Reunión de inicio con el equipo auditado']},
            {'fase': 2, 'nombre': 'Ejecución', 'duracion': '5 días', 'actividades': ['Análisis estático con AuditLens + Bandit', 'SCA con pip-audit + npm audit', 'Pruebas DAST con OWASP ZAP', 'Entrevistas estructuradas', 'Revisión documental']},
            {'fase': 3, 'nombre': 'Análisis', 'duracion': '3 días', 'actividades': ['Análisis de brechas ISO', 'Análisis de causa raíz (5 Porqués)', 'Tablas de correlación', 'Formulación de hallazgos']},
            {'fase': 4, 'nombre': 'Informe', 'duracion': '3 días', 'actividades': ['Redacción del informe con AuditLens plan', 'Revisión y aprobación del equipo auditor', 'Entrega al cliente']},
            {'fase': 5, 'nombre': 'Seguimiento', 'duracion': 'Mensual', 'actividades': ['Revisión de KPIs en Jira', 'Re-scan con AuditLens --diff-baseline', 'Actualización del baseline']},
        ],
    }


def generate_roles(
    auditor_lider: str = 'Daniel Flores',
    auditor_tecnico: str = 'Marcelo Acevedo',
    auditor_procesos: str = 'Claudia Infante',
) -> List[Dict]:
    """Generate audit team roles with real names."""
    return [
        {
            'rol': 'Auditor Líder',
            'nombre': auditor_lider,
            'responsabilidades': [
                'Planificación general y coordinación de la auditoría',
                'Supervisión del equipo auditor y asignación de tareas',
                'Redacción y revisión del informe final de auditoría',
                'Presentación de resultados al equipo de EcoAlerta',
                'Gestión del plan de seguimiento en Jira',
            ],
            'fase': 'Todas las fases',
        },
        {
            'rol': 'Auditor Técnico de Software',
            'nombre': auditor_tecnico,
            'responsabilidades': [
                'Ejecución del análisis estático con AuditLens, SonarQube y Bandit',
                'Ejecución de pruebas de seguridad dinámicas con OWASP ZAP',
                'Interpretación y clasificación de hallazgos técnicos',
                'Validación de falsos positivos en los resultados del análisis',
                'Documentación de evidencia técnica con hash SHA-256',
            ],
            'fase': 'Ejecución y Análisis',
        },
        {
            'rol': 'Auditor de Procesos',
            'nombre': auditor_procesos,
            'responsabilidades': [
                'Conducción de entrevistas estructuradas al equipo de EcoAlerta',
                'Revisión documental (README, historial de commits, configuraciones)',
                'Evaluación de conformidad con ISO 12207 e ISO 14764',
                'Documentación de hallazgos de proceso y gestión de evidencia',
                'Registro y custodia de la cadena de evidencia',
            ],
            'fase': 'Ejecución y Análisis',
        },
    ]


def generate_kpis(findings: List[dict], test_analysis: Dict) -> List[Dict]:
    """Generate KPIs for the follow-up plan."""
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    total = len(findings)
    coverage = test_analysis.get('ratio_cobertura_estimado', 0)

    return [
        {
            'kpi': 'Reducción de Hallazgos Críticos',
            'descripcion': f"Reducir los {critical} hallazgos CRÍTICOS detectados",
            'valor_actual': critical,
            'meta': 0,
            'unidad': 'hallazgos',
            'frecuencia': 'Mensual',
            'iso': 'ISO 25040 — Seguridad, ISO 14764 — Correctivo',
            'plazo': '1 mes',
        },
        {
            'kpi': 'Reducción de Hallazgos de Alta Severidad',
            'descripcion': f"Reducir los hallazgos HIGH en un 80%",
            'valor_actual': high,
            'meta': max(0, int(high * 0.2)),
            'unidad': 'hallazgos',
            'frecuencia': 'Mensual',
            'iso': 'ISO 25040 — Seguridad, ISO 14764 — Correctivo',
            'plazo': '2 meses',
        },
        {
            'kpi': 'Cobertura de Pruebas',
            'descripcion': 'Incrementar el ratio de cobertura de pruebas',
            'valor_actual': f"{coverage}%",
            'meta': '70%',
            'unidad': 'porcentaje',
            'frecuencia': 'Mensual',
            'iso': 'ISO 12207 — Verificación y Validación',
            'plazo': '2 meses',
        },
        {
            'kpi': 'Conformidad ISO 25040',
            'descripcion': 'Puntuación general de conformidad con ISO 25040',
            'valor_actual': 'Pendiente de calcular',
            'meta': '80/100',
            'unidad': 'puntos',
            'frecuencia': 'Trimestral',
            'iso': 'ISO 25040',
            'plazo': '3 meses',
        },
        {
            'kpi': 'Dependencias Vulnerables',
            'descripcion': 'Número de dependencias con vulnerabilidades conocidas',
            'valor_actual': sum(1 for f in findings if f.get('rule_id', '').startswith('SCA-')),
            'meta': 0,
            'unidad': 'dependencias',
            'frecuencia': 'Mensual',
            'iso': 'ISO 14764 — Mantenimiento Preventivo',
            'plazo': '1 mes',
        },
    ]


def generate_audit_plan(
    root_path: str,
    findings: List[dict],
    empresa: str = 'Empresa',
    sistema: str = 'Sistema de Software',
    trimestre: str = 'tercer trimestre de 2025',
    auditor: str = '[Auditor por asignar]',
) -> Dict:
    """
    Generate a complete audit planning document.
    Returns a structured dict ready for Word/PDF export.
    """
    print('\033[94m[AuditLens Plan]\033[0m Analizando estructura del proyecto...')
    project_info = scan_project_structure(root_path)

    print('\033[94m[AuditLens Plan]\033[0m Analizando cobertura de pruebas...')
    test_analysis = analyze_test_coverage(root_path)

    print('\033[94m[AuditLens Plan]\033[0m Calculando análisis de brechas ISO...')
    gap_analysis = compute_iso_gap_analysis(findings)

    print('\033[94m[AuditLens Plan]\033[0m Generando documento de planificación...')

    objectives = generate_smart_objectives(
        project_info, findings, empresa, sistema, trimestre,
        fecha_entrega='08/06/2026',
    )
    criteria = generate_audit_criteria(gap_analysis)
    methodology = generate_methodology()
    # Extract names from auditor string if multiple names provided
    names = [n.strip() for n in auditor.replace(' y ', ',').replace(' Y ', ',').split(',')]
    roles = generate_roles(
        auditor_lider=names[0] if len(names) > 0 else auditor,
        auditor_tecnico=names[1] if len(names) > 1 else '[Por asignar]',
        auditor_procesos=names[2] if len(names) > 2 else '[Por asignar]',
    )
    kpis = generate_kpis(findings, test_analysis)

    now = datetime.now()

    return {
        'metadata': {
            'titulo': f'Plan de Auditoría de Software — {sistema}',
            'empresa': empresa,
            'sistema': sistema,
            'trimestre': trimestre,
            'fecha_generacion': now.strftime('%d/%m/%Y %H:%M'),
            'auditor_lider': auditor,
            'version': '1.0',
            'herramienta': 'AuditLens v0.3.0',
        },
        'resumen_proyecto': project_info,
        'cobertura_tests': test_analysis,
        'analisis_brechas_iso': gap_analysis,
        'seccion_1_1_alcance_objetivos': {
            'alcance': {
                'descripcion': (
                    f"La presente auditoría cubre el análisis de seguridad, calidad y "
                    f"mantenibilidad del sistema {sistema} de la empresa {empresa}, "
                    f"incluyendo el código fuente en {', '.join(list(project_info['lenguajes'].keys())[:3])}, "
                    f"las dependencias de terceros y los procesos de desarrollo y pruebas."
                ),
                'incluye': [
                    f"Código fuente: {project_info['total_archivos']} archivos ({project_info['total_lineas']:,} líneas)",
                    f"Módulos detectados: {', '.join(project_info['modulos'][:8]) or 'No identificados'}",
                    f"Lenguajes: {', '.join(f'{lang} ({count} archivos)' for lang, count in list(project_info['lenguajes'].items())[:5])}",
                    f"Dependencias de terceros: {'Sí' if project_info['tiene_requirements'] or project_info['tiene_package_json'] else 'No detectadas'}",
                    'Estándares aplicables: ISO 25040, ISO 12207, ISO 14764',
                ],
                'excluye': [
                    'Infraestructura de servidores y redes',
                    'Procesos de negocio no relacionados con el software',
                    'Datos de producción de usuarios',
                ],
            },
            'objetivos_smart': objectives,
        },
        'seccion_1_2_criterios': criteria,
        'seccion_1_3_metodologia': methodology,
        'seccion_1_4_roles': roles,
        'seccion_5_kpis': kpis,
    }
