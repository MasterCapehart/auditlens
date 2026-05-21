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
) -> List[Dict]:
    """Generate SMART objectives based on project analysis."""
    objectives = []
    now = datetime.now()
    fecha_fin = (now + timedelta(weeks=12)).strftime('%d/%m/%Y')

    # Always include security objective
    critical_count = sum(1 for f in findings_preview if f.get('severity') == 'CRITICAL')
    high_count = sum(1 for f in findings_preview if f.get('severity') == 'HIGH')

    objectives.append({
        'numero': 1,
        'titulo': 'Evaluación de Seguridad del Código',
        'descripcion': (
            f"Evaluar la conformidad del sistema {sistema} de la empresa {empresa} "
            f"con los requisitos de seguridad definidos en ISO 25040, identificando y "
            f"documentando todas las vulnerabilidades críticas y de alta severidad "
            f"durante el {trimestre}."
        ),
        'especifico': f"Analizar el 100% del código fuente del sistema {sistema}",
        'medible': f"Reducir en un 80% los {critical_count + high_count} hallazgos CRÍTICOS/ALTOS identificados",
        'alcanzable': "Mediante análisis estático automatizado y revisión manual de código",
        'relevante': "Cumplimiento de ISO 25040 Seguridad Funcional y normativas aplicables",
        'plazo': f"Completar antes del {fecha_fin}",
        'iso': ['ISO 25040 — Seguridad Funcional', 'ISO 12207 — Verificación y Validación'],
    })

    # Test coverage objective
    if project_info.get('total_archivos', 0) > 5:
        objectives.append({
            'numero': 2,
            'titulo': 'Mejora de Cobertura de Pruebas',
            'descripcion': (
                f"Evaluar y mejorar la cobertura de pruebas del software {sistema}, "
                f"verificando la conformidad con el proceso de Verificación y Validación "
                f"de ISO 12207."
            ),
            'especifico': f"Auditar los {project_info['total_archivos']} archivos fuente del sistema",
            'medible': "Alcanzar al menos 70% de ratio de cobertura de pruebas",
            'alcanzable': "Implementando pruebas unitarias para los módulos críticos identificados",
            'relevante': "Reducción de defectos en producción y cumplimiento de ISO 12207",
            'plazo': f"Completar antes del {fecha_fin}",
            'iso': ['ISO 12207 — Verificación y Validación (Sección 6.4)', 'ISO 25040 — Fiabilidad'],
        })

    # Maintenance objective
    objectives.append({
        'numero': 3,
        'titulo': 'Evaluación de Mantenibilidad',
        'descripcion': (
            f"Evaluar las prácticas de mantenimiento del software {sistema} conforme a "
            f"ISO 14764, identificando brechas en los procesos de mantenimiento correctivo, "
            f"adaptativo y preventivo."
        ),
        'especifico': f"Auditar los procesos de mantenimiento y gestión de cambios del sistema",
        'medible': "Documentar el 100% de los hallazgos de mantenimiento por categoría ISO 14764",
        'alcanzable': "Mediante análisis automatizado y revisión de historial de cambios",
        'relevante': "Garantizar la sostenibilidad y mantenibilidad a largo plazo del sistema",
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
    """Generate audit methodology section."""
    return {
        'enfoque': 'Metodología Híbrida de Auditoría de Software',
        'descripcion': (
            'Se empleará una metodología híbrida que combina análisis estático automatizado '
            'con AuditLens, revisión documental y entrevistas estructuradas, permitiendo '
            'una evaluación integral del software desde perspectivas técnicas y de proceso.'
        ),
        'tecnicas': [
            {
                'nombre': 'Análisis Estático de Código (SAST)',
                'herramienta': 'AuditLens v0.3.0',
                'descripcion': 'Análisis automatizado del código fuente para detectar vulnerabilidades de seguridad, patrones inseguros y deuda técnica.',
                'cobertura': 'Código fuente Python, JavaScript, TypeScript, Swift, Go, Java, Kotlin, Ruby',
                'iso': 'ISO 12207 — Verificación Estática, ISO 25040 — Seguridad',
            },
            {
                'nombre': 'Análisis de Composición de Software (SCA)',
                'herramienta': 'AuditLens + OSV API',
                'descripcion': 'Verificación de dependencias de terceros contra la base de datos de vulnerabilidades conocidas (CVE/OSV).',
                'cobertura': 'requirements.txt, package.json, poetry.lock, Pipfile.lock, yarn.lock',
                'iso': 'ISO 14764 — Mantenimiento Preventivo, ISO 25040 — Fiabilidad',
            },
            {
                'nombre': 'Análisis de Flujo de Datos (Taint Analysis)',
                'herramienta': 'AuditLens — Motor de Taint',
                'descripcion': 'Rastreo de datos sensibles desde fuentes (entrada de usuario) hasta sumideros peligrosos (base de datos, comandos shell).',
                'cobertura': 'Análisis intra e inter-procedural en Python',
                'iso': 'ISO 25040 — Seguridad/Integridad, ISO 12207 — Codificación',
            },
            {
                'nombre': 'Análisis de Cobertura de Pruebas',
                'herramienta': 'AuditLens — Test Coverage Analyzer',
                'descripcion': 'Detección automática de archivos de prueba y estimación del ratio de cobertura.',
                'cobertura': 'Todos los lenguajes soportados',
                'iso': 'ISO 12207 — Verificación y Validación, ISO 25040 — Fiabilidad',
            },
            {
                'nombre': 'Análisis de Brechas ISO',
                'herramienta': 'AuditLens — ISO Gap Analyzer',
                'descripcion': 'Evaluación automatizada del nivel de conformidad del software con ISO 25040, ISO 12207 e ISO 14764.',
                'cobertura': 'Todo el proyecto',
                'iso': 'ISO 25040, ISO 12207, ISO 14764',
            },
            {
                'nombre': 'Revisión Documental',
                'herramienta': 'Manual (auditor)',
                'descripcion': 'Revisión de documentación del proyecto: README, changelog, comentarios de código, configuraciones.',
                'cobertura': 'Documentación disponible en el repositorio',
                'iso': 'ISO 12207 — Documentación, ISO 14764 — Registros de mantenimiento',
            },
        ],
        'herramientas': [
            {'nombre': 'AuditLens v0.3.0', 'tipo': 'SAST/SCA/Taint', 'licencia': 'MIT'},
            {'nombre': 'OSV API (Google)', 'tipo': 'Base de datos de vulnerabilidades', 'licencia': 'Pública'},
        ],
        'fases': [
            {'fase': 1, 'nombre': 'Planificación', 'duracion': '1 semana', 'actividades': ['Definición de alcance', 'Preparación de herramientas', 'Reunión de inicio']},
            {'fase': 2, 'nombre': 'Ejecución', 'duracion': '2 semanas', 'actividades': ['Análisis estático', 'SCA', 'Taint analysis', 'Análisis de cobertura']},
            {'fase': 3, 'nombre': 'Análisis', 'duracion': '1 semana', 'actividades': ['Análisis de brechas ISO', 'Formulación de hallazgos', 'Análisis de causa raíz']},
            {'fase': 4, 'nombre': 'Reporte', 'duracion': '1 semana', 'actividades': ['Redacción del informe', 'Recomendaciones', 'Plan de seguimiento']},
            {'fase': 5, 'nombre': 'Seguimiento', 'duracion': 'Trimestral', 'actividades': ['Revisión de KPIs', 'Verificación de correcciones', 'Actualización de baseline']},
        ],
    }


def generate_roles() -> List[Dict]:
    """Generate audit team roles template."""
    return [
        {
            'rol': 'Auditor Líder',
            'nombre': '[Por asignar]',
            'responsabilidades': [
                'Planificación general de la auditoría',
                'Supervisión del equipo auditor',
                'Redacción del informe final',
                'Presentación de resultados al cliente',
                'Gestión del plan de seguimiento',
            ],
            'fase': 'Todas las fases',
        },
        {
            'rol': 'Auditor Técnico de Software',
            'nombre': '[Por asignar]',
            'responsabilidades': [
                'Ejecución del análisis estático con AuditLens',
                'Interpretación de hallazgos técnicos',
                'Validación de falsos positivos',
                'Propuesta de recomendaciones técnicas',
                'Documentación de evidencia técnica',
            ],
            'fase': 'Ejecución y Análisis',
        },
        {
            'rol': 'Auditor de Procesos',
            'nombre': '[Por asignar]',
            'responsabilidades': [
                'Entrevistas al equipo de desarrollo',
                'Revisión documental (README, changelog, políticas)',
                'Evaluación de conformidad con ISO 12207 e ISO 14764',
                'Documentación de hallazgos de proceso',
                'Registro y custodia de evidencia documental',
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

    objectives = generate_smart_objectives(project_info, findings, empresa, sistema, trimestre)
    criteria = generate_audit_criteria(gap_analysis)
    methodology = generate_methodology()
    roles = generate_roles()
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
