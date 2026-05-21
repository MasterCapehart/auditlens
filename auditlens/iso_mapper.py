"""
AuditLens — ISO Standards Mapper

Maps findings and rules to ISO 25040, ISO 12207, and ISO 14764 standards.
Provides gap analysis and conformance scoring per standard.

ISO 25040: Software product quality evaluation (SQuaRE)
  - Characteristics: Functional Suitability, Reliability, Security,
    Maintainability, Performance, Compatibility, Usability, Portability

ISO 12207: Software lifecycle processes
  - Key processes: Development, Testing, Configuration Management,
    Quality Assurance, Requirements, Design, Implementation

ISO 14764: Software maintenance
  - Maintenance types: Corrective, Adaptive, Perfective, Preventive
  - Key activities: Problem identification, Analysis, Design, Implementation,
    System test, Acceptance test, Delivery
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple


# ── ISO 25040 — Product Quality Characteristics ───────────────────────────────

ISO_25040_CHARACTERISTICS = {
    'security': {
        'name': 'Seguridad Funcional',
        'description': 'Capacidad del software para proteger información y datos.',
        'sub': ['Confidencialidad', 'Integridad', 'No Repudio', 'Autenticidad', 'Responsabilidad'],
        'rules': [
            'SEC-01', 'SEC-02', 'SEC-03', 'SEC-04', 'SEC-05', 'SEC-06', 'SEC-07',
            'SEC-08', 'SEC-09', 'SEC-10', 'SEC-11',
            'INJ-01', 'INJ-02', 'INJ-03', 'INJ-04', 'INJ-05', 'INJ-06', 'INJ-07',
            'INJ-08', 'INJ-09',
            'AUTH-01', 'AUTH-02', 'AUTH-03', 'AUTH-04',
            'DESER-01', 'DESER-02', 'DESER-03',
            'CRYPTO-01', 'CRYPTO-02', 'CRYPTO-03',
            'TAINT-01', 'TAINT-02', 'AST-01',
        ],
    },
    'reliability': {
        'name': 'Fiabilidad',
        'description': 'Capacidad del software de mantener su nivel de rendimiento bajo condiciones definidas.',
        'sub': ['Madurez', 'Disponibilidad', 'Tolerancia a fallos', 'Recuperabilidad'],
        'rules': ['CONF-07', 'PY-REQUESTS-NO-TIMEOUT', 'GO-10'],
    },
    'maintainability': {
        'name': 'Mantenibilidad',
        'description': 'Facilidad con la que el software puede ser modificado.',
        'sub': ['Modularidad', 'Reutilización', 'Analizabilidad', 'Modificabilidad', 'Capacidad de prueba'],
        'rules': ['CONF-01', 'CONF-02', 'CONF-03', 'CONF-04', 'CONF-05', 'CONF-06'],
    },
    'compatibility': {
        'name': 'Compatibilidad',
        'description': 'Capacidad del software de intercambiar información con otros sistemas.',
        'sub': ['Coexistencia', 'Interoperabilidad'],
        'rules': ['DATA-02'],
    },
    'functional_suitability': {
        'name': 'Adecuación Funcional',
        'description': 'Capacidad del software de satisfacer necesidades bajo condiciones especificadas.',
        'sub': ['Completitud funcional', 'Corrección funcional', 'Pertinencia funcional'],
        'rules': [],
    },
}

# ── ISO 12207 — Software Lifecycle Processes ──────────────────────────────────

ISO_12207_PROCESSES = {
    'development': {
        'name': 'Proceso de Desarrollo',
        'description': 'Actividades para especificar, diseñar, codificar, integrar y probar el software.',
        'sub': ['Análisis de requisitos', 'Diseño arquitectónico', 'Diseño detallado',
                'Codificación', 'Pruebas de unidad', 'Pruebas de integración'],
        'rules': ['INJ-01', 'INJ-02', 'SEC-01', 'TAINT-01', 'TAINT-02'],
        'indicators': ['cobertura_tests', 'hallazgos_criticos', 'deuda_tecnica'],
    },
    'testing': {
        'name': 'Proceso de Verificación y Validación',
        'description': 'Determinación de que el software cumple los requisitos especificados.',
        'sub': ['Revisión técnica', 'Pruebas de sistema', 'Pruebas de aceptación'],
        'rules': ['SEC-02', 'SEC-03', 'DESER-01', 'DESER-02'],
        'indicators': ['archivos_sin_tests', 'ratio_cobertura'],
    },
    'configuration_management': {
        'name': 'Gestión de la Configuración',
        'description': 'Control de los elementos de configuración del software.',
        'sub': ['Identificación', 'Control de cambios', 'Auditoría de configuración'],
        'rules': ['SEC-08', 'SEC-09', 'CONF-03'],
        'indicators': ['secrets_detectados', 'credenciales_expuestas'],
    },
    'quality_assurance': {
        'name': 'Aseguramiento de la Calidad',
        'description': 'Garantía de que los procesos y productos cumplen los planes establecidos.',
        'sub': ['Evaluación del producto', 'Evaluación del proceso', 'Gestión de no conformidades'],
        'rules': ['AUTH-01', 'AUTH-02', 'CONF-04', 'CONF-05', 'CONF-06'],
        'indicators': ['conformidad_general', 'hallazgos_por_severidad'],
    },
}

# ── ISO 14764 — Software Maintenance ─────────────────────────────────────────

ISO_14764_ACTIVITIES = {
    'corrective': {
        'name': 'Mantenimiento Correctivo',
        'description': 'Modificaciones para corregir fallos descubiertos en el software.',
        'sub': ['Análisis del problema', 'Análisis del impacto', 'Implementación'],
        'rules': ['SEC-01', 'SEC-05', 'INJ-01', 'INJ-02', 'DESER-01', 'DESER-03'],
        'priority': 'Alta',
    },
    'adaptive': {
        'name': 'Mantenimiento Adaptativo',
        'description': 'Modificaciones para mantener el software usable en entornos cambiantes.',
        'sub': ['Análisis del entorno', 'Planificación', 'Implementación', 'Pruebas'],
        'rules': ['CRYPTO-01', 'CRYPTO-02', 'CRYPTO-03', 'SEC-02', 'SEC-03'],
        'priority': 'Media',
    },
    'perfective': {
        'name': 'Mantenimiento Perfectivo',
        'description': 'Modificaciones para mejorar el rendimiento o mantenibilidad.',
        'sub': ['Identificación de mejoras', 'Análisis costo-beneficio', 'Implementación'],
        'rules': ['CONF-01', 'CONF-02', 'DATA-02', 'PY-REQUESTS-NO-TIMEOUT'],
        'priority': 'Baja',
    },
    'preventive': {
        'name': 'Mantenimiento Preventivo',
        'description': 'Modificaciones para detectar y corregir fallos latentes antes de que ocurran.',
        'sub': ['Revisión del código', 'Análisis de riesgos', 'Actualización de dependencias'],
        'rules': ['SEC-08', 'SEC-09', 'SEC-10', 'AUTH-04', 'CONF-07'],
        'priority': 'Media-Alta',
    },
}

# ── Rule → ISO mapping ────────────────────────────────────────────────────────

# Maps each rule_id prefix to its primary ISO standard and article
RULE_ISO_MAP: Dict[str, Dict] = {
    # Security rules → ISO 25040 Security + ISO 12207 Quality Assurance
    'SEC-': {
        'iso25040': 'ISO 25040 — Seguridad Funcional (Sección 4.2.5)',
        'iso12207': 'ISO 12207 — Aseguramiento de la Calidad del Software (Sección 6.3)',
        'iso14764': 'ISO 14764 — Mantenimiento Correctivo (Sección 5.3)',
        'criterion': 'El software debe proteger información y datos contra acceso no autorizado',
    },
    'INJ-': {
        'iso25040': 'ISO 25040 — Seguridad Funcional: Integridad (Sección 4.2.5.2)',
        'iso12207': 'ISO 12207 — Proceso de Desarrollo: Codificación (Sección 7.1.3)',
        'iso14764': 'ISO 14764 — Mantenimiento Correctivo (Sección 5.3)',
        'criterion': 'Toda entrada de usuario debe ser validada antes de procesarse',
    },
    'AUTH-': {
        'iso25040': 'ISO 25040 — Seguridad Funcional: Autenticidad (Sección 4.2.5.4)',
        'iso12207': 'ISO 12207 — Proceso de Verificación y Validación (Sección 6.4)',
        'iso14764': 'ISO 14764 — Mantenimiento Correctivo y Preventivo (Sección 5.3-5.6)',
        'criterion': 'Los controles de acceso deben implementarse correctamente',
    },
    'CRYPTO-': {
        'iso25040': 'ISO 25040 — Seguridad Funcional: Confidencialidad (Sección 4.2.5.1)',
        'iso12207': 'ISO 12207 — Aseguramiento de la Calidad (Sección 6.3)',
        'iso14764': 'ISO 14764 — Mantenimiento Adaptativo (Sección 5.4)',
        'criterion': 'Los algoritmos criptográficos utilizados deben ser seguros y vigentes',
    },
    'DESER-': {
        'iso25040': 'ISO 25040 — Seguridad Funcional: Integridad (Sección 4.2.5.2)',
        'iso12207': 'ISO 12207 — Proceso de Desarrollo: Pruebas de Integración (Sección 7.1.5)',
        'iso14764': 'ISO 14764 — Mantenimiento Correctivo (Sección 5.3)',
        'criterion': 'Los datos deserializados deben validarse y provenir de fuentes confiables',
    },
    'CONF-': {
        'iso25040': 'ISO 25040 — Mantenibilidad: Modificabilidad (Sección 4.2.6.4)',
        'iso12207': 'ISO 12207 — Gestión de la Configuración (Sección 6.2)',
        'iso14764': 'ISO 14764 — Mantenimiento Perfectivo (Sección 5.5)',
        'criterion': 'La configuración de seguridad debe seguir el principio de mínimo privilegio',
    },
    'TAINT-': {
        'iso25040': 'ISO 25040 — Seguridad Funcional: No Repudio (Sección 4.2.5.3)',
        'iso12207': 'ISO 12207 — Proceso de Desarrollo: Análisis de Requisitos (Sección 7.1.1)',
        'iso14764': 'ISO 14764 — Mantenimiento Correctivo (Sección 5.3)',
        'criterion': 'Los flujos de datos sensibles deben controlarse y sanitizarse',
    },
    'SCA-': {
        'iso25040': 'ISO 25040 — Fiabilidad: Madurez (Sección 4.2.2.1)',
        'iso12207': 'ISO 12207 — Gestión de Configuración: Control de cambios (Sección 6.2.3)',
        'iso14764': 'ISO 14764 — Mantenimiento Preventivo (Sección 5.6)',
        'criterion': 'Las dependencias de terceros deben mantenerse actualizadas y sin vulnerabilidades conocidas',
    },
    'DATA-': {
        'iso25040': 'ISO 25040 — Seguridad: Confidencialidad (Sección 4.2.5.1)',
        'iso12207': 'ISO 12207 — Proceso de Verificación (Sección 6.4)',
        'iso14764': 'ISO 14764 — Mantenimiento Perfectivo (Sección 5.5)',
        'criterion': 'Los datos sensibles no deben exponerse en logs ni en el código fuente',
    },
    'SSRF-': {
        'iso25040': 'ISO 25040 — Seguridad: Integridad (Sección 4.2.5.2)',
        'iso12207': 'ISO 12207 — Proceso de Desarrollo: Diseño (Sección 7.1.2)',
        'iso14764': 'ISO 14764 — Mantenimiento Correctivo (Sección 5.3)',
        'criterion': 'Las peticiones HTTP salientes deben validar y restringir los destinos permitidos',
    },
    'PT-': {
        'iso25040': 'ISO 25040 — Seguridad: Integridad (Sección 4.2.5.2)',
        'iso12207': 'ISO 12207 — Proceso de Desarrollo: Codificación (Sección 7.1.3)',
        'iso14764': 'ISO 14764 — Mantenimiento Correctivo (Sección 5.3)',
        'criterion': 'Las rutas de archivos deben validarse y restringirse al directorio permitido',
    },
    'AST-': {
        'iso25040': 'ISO 25040 — Seguridad: Confidencialidad (Sección 4.2.5.1)',
        'iso12207': 'ISO 12207 — Aseguramiento de la Calidad (Sección 6.3)',
        'iso14764': 'ISO 14764 — Mantenimiento Correctivo (Sección 5.3)',
        'criterion': 'Los valores sensibles no deben estar codificados directamente en el código fuente',
    },
}

# ── Recommendations database ──────────────────────────────────────────────────

REMEDIATION_DB: Dict[str, Dict] = {
    'SEC-01': {
        'titulo': 'Eliminar secretos del código fuente',
        'pasos': [
            'Revocar inmediatamente las credenciales expuestas',
            'Mover el valor a una variable de entorno o gestor de secretos (AWS Secrets Manager, HashiCorp Vault)',
            'Actualizar el código para leer de os.environ.get() o equivalente',
            'Agregar el archivo de configuración al .gitignore',
        ],
        'esfuerzo': 'Bajo (2-4 horas)',
        'plazo': '48 horas',
        'prioridad': 'CRÍTICA',
        'iso': 'ISO 25040 Seguridad, ISO 14764 Correctivo',
    },
    'SEC-02': {
        'titulo': 'Reemplazar MD5 por algoritmo seguro',
        'pasos': [
            'Identificar todos los usos de MD5 en el código',
            'Para hashing de contraseñas: migrar a bcrypt o argon2',
            'Para integridad de datos: migrar a SHA-256 o SHA-3',
            'Ejecutar pruebas de regresión tras el cambio',
        ],
        'esfuerzo': 'Medio (1-2 días)',
        'plazo': '1 semana',
        'prioridad': 'ALTA',
        'iso': 'ISO 25040 Seguridad, ISO 14764 Adaptativo',
    },
    'INJ-01': {
        'titulo': 'Implementar consultas parametrizadas',
        'pasos': [
            'Identificar todas las consultas SQL construidas con concatenación',
            'Reemplazar por consultas parametrizadas (prepared statements)',
            'Usar ORM cuando sea posible (SQLAlchemy, Hibernate)',
            'Implementar validación de entrada en todas las rutas de datos',
            'Ejecutar pruebas de inyección SQL con herramienta automatizada',
        ],
        'esfuerzo': 'Medio (2-3 días)',
        'plazo': '1 semana',
        'prioridad': 'CRÍTICA',
        'iso': 'ISO 25040 Seguridad/Integridad, ISO 12207 Codificación, ISO 14764 Correctivo',
    },
    'INJ-02': {
        'titulo': 'Eliminar construcción dinámica de comandos shell',
        'pasos': [
            'Reemplazar os.system() por subprocess.run() con lista de argumentos',
            'Nunca pasar input del usuario directamente a comandos shell',
            'Usar shell=False en todas las llamadas a subprocess',
            'Validar y sanitizar cualquier argumento antes de pasarlo',
        ],
        'esfuerzo': 'Bajo (1 día)',
        'plazo': '48 horas',
        'prioridad': 'CRÍTICA',
        'iso': 'ISO 25040 Seguridad, ISO 12207 Codificación, ISO 14764 Correctivo',
    },
    'DESER-01': {
        'titulo': 'Reemplazar pickle por formato seguro',
        'pasos': [
            'Reemplazar pickle por JSON o MessagePack para datos no confiables',
            'Si pickle es necesario, usar HMACed pickle con firma verificada',
            'Nunca deserializar datos de fuentes externas con pickle',
            'Documentar explícitamente qué datos se serializan y desde dónde',
        ],
        'esfuerzo': 'Medio (1-2 días)',
        'plazo': '1 semana',
        'prioridad': 'CRÍTICA',
        'iso': 'ISO 25040 Seguridad/Integridad, ISO 12207 Integración, ISO 14764 Correctivo',
    },
    'CRYPTO-01': {
        'titulo': 'Migrar a algoritmos criptográficos modernos',
        'pasos': [
            'Identificar todos los usos de DES/3DES en el código',
            'Migrar a AES-256-GCM para cifrado simétrico',
            'Actualizar protocolos de comunicación a TLS 1.3',
            'Revisar y actualizar configuraciones de cifrado en producción',
        ],
        'esfuerzo': 'Alto (3-5 días)',
        'plazo': '2 semanas',
        'prioridad': 'ALTA',
        'iso': 'ISO 25040 Seguridad, ISO 14764 Adaptativo',
    },
    'CONF-04': {
        'titulo': 'Deshabilitar modo debug en producción',
        'pasos': [
            'Establecer DEBUG=False mediante variable de entorno',
            'Configurar manejo de errores personalizado para producción',
            'Implementar logging estructurado sin exponer stack traces',
            'Revisar todas las configuraciones de entorno',
        ],
        'esfuerzo': 'Bajo (2 horas)',
        'plazo': '24 horas',
        'prioridad': 'CRÍTICA',
        'iso': 'ISO 25040 Seguridad/Mantenibilidad, ISO 12207 Gestión de Configuración',
    },
    'TAINT-01': {
        'titulo': 'Sanitizar flujos de datos sensibles',
        'pasos': [
            'Identificar todas las fuentes de entrada de usuario',
            'Implementar validación y sanitización en la capa de entrada',
            'Usar consultas parametrizadas para acceso a base de datos',
            'Implementar escape de salida apropiado según el contexto',
            'Agregar pruebas de penetración al pipeline de CI/CD',
        ],
        'esfuerzo': 'Alto (3-5 días)',
        'plazo': '2 semanas',
        'prioridad': 'ALTA',
        'iso': 'ISO 25040 Seguridad, ISO 12207 Análisis de Requisitos, ISO 14764 Correctivo',
    },
    'DEFAULT': {
        'titulo': 'Revisar y corregir el hallazgo identificado',
        'pasos': [
            'Analizar el contexto del hallazgo en el código fuente',
            'Consultar la documentación de la regla aplicada',
            'Implementar la corrección siguiendo las mejores prácticas',
            'Agregar una prueba unitaria que verifique la corrección',
            'Documentar el cambio en el registro de modificaciones',
        ],
        'esfuerzo': 'Variable',
        'plazo': '1-2 semanas',
        'prioridad': 'Según severidad',
        'iso': 'ISO 14764 — Mantenimiento Correctivo (Sección 5.3)',
    },
}


def get_iso_mapping(rule_id: str) -> Dict:
    """Return ISO mapping for a given rule_id."""
    for prefix, mapping in RULE_ISO_MAP.items():
        if rule_id.startswith(prefix):
            return mapping
    return {
        'iso25040': 'ISO 25040 — Calidad del Producto Software',
        'iso12207': 'ISO 12207 — Ciclo de Vida del Software',
        'iso14764': 'ISO 14764 — Mantenimiento del Software',
        'criterion': 'El software debe cumplir los requisitos de calidad y seguridad establecidos',
    }


def get_remediation(rule_id: str) -> Dict:
    """Return remediation guidance for a given rule_id."""
    return REMEDIATION_DB.get(rule_id, REMEDIATION_DB['DEFAULT'])


def enrich_finding_with_iso(finding: dict) -> dict:
    """Add Condicion/Criterio/Causa/Efecto and ISO mapping to a finding."""
    import os as _os
    rule_id = finding.get('rule_id', '')
    iso = get_iso_mapping(rule_id)
    rem = get_remediation(rule_id)
    severity = finding.get('severity', 'MEDIUM')
    file_path = finding.get('file', '')
    line = finding.get('line', 0)

    # Map severity to impact description
    efecto_map = {
        'CRITICAL': 'Riesgo crítico de seguridad con potencial de explotación inmediata y pérdida de datos',
        'HIGH': 'Vulnerabilidad de alta severidad que puede comprometer la seguridad del sistema',
        'MEDIUM': 'Riesgo moderado que puede ser explotado bajo condiciones específicas',
        'LOW': 'Riesgo menor que representa deuda técnica o incumplimiento de mejores prácticas',
    }

    causa_map = {
        'SEC-01': 'Ausencia de un proceso formal de gestión de secretos y variables de entorno',
        'SEC-02': 'Uso de biblioteca criptográfica deprecada sin proceso de actualización tecnológica',
        'INJ-01': 'Construcción dinámica de consultas sin validación ni parametrización de entrada',
        'INJ-02': 'Ejecución de comandos shell con concatenación directa de datos del usuario',
        'DESER-01': 'Uso de mecanismo de serialización inseguro para datos no confiables',
        'CRYPTO-01': 'Uso de algoritmo criptográfico obsoleto no compatible con estándares actuales',
        'TAINT-01': 'Ausencia de validación y sanitización en el flujo de datos desde la entrada hasta el sink',
        'CONF-04': 'Configuración de entorno de desarrollo utilizada en entorno de producción',
    }

    finding_enriched = {
        **finding,
        'condicion': (
            f"Se detectó {finding.get('name', 'hallazgo de seguridad')} en "
            f"{_os.path.basename(file_path)} línea {line}."
        ),
        'criterio': iso.get('criterion', ''),
        'norma_iso25040': iso.get('iso25040', ''),
        'norma_iso12207': iso.get('iso12207', ''),
        'norma_iso14764': iso.get('iso14764', ''),
        'causa': causa_map.get(
            rule_id,
            f"Incumplimiento de las directrices de desarrollo seguro para {rule_id}"
        ),
        'efecto': efecto_map.get(severity.upper(), efecto_map['MEDIUM']),
        'remediacion': rem,
    }
    return finding_enriched


def compute_iso_gap_analysis(findings: List[dict]) -> Dict:
    """
    Compute ISO gap analysis from findings list.
    Returns conformance scores per standard and characteristic.
    """
    import os

    # Count findings by rule prefix
    rule_counts: Dict[str, int] = {}
    for f in findings:
        rid = f.get('rule_id', '')
        for prefix in RULE_ISO_MAP:
            if rid.startswith(prefix):
                rule_counts[prefix] = rule_counts.get(prefix, 0) + 1
                break

    # ── ISO 25040 gap analysis ────────────────────────────────────────────────
    iso25040_results = {}
    for char_key, char_data in ISO_25040_CHARACTERISTICS.items():
        violations = sum(
            1 for f in findings
            if any(f.get('rule_id', '').startswith(r[:4]) for r in char_data['rules'])
        )
        # Score: 100 = no violations, decreases with each violation
        score = max(0, 100 - (violations * 15))
        status = 'CONFORME' if score >= 80 else ('PARCIALMENTE CONFORME' if score >= 50 else 'NO CONFORME')
        iso25040_results[char_key] = {
            'nombre': char_data['name'],
            'descripcion': char_data['description'],
            'violaciones': violations,
            'puntuacion': score,
            'estado': status,
        }

    # ── ISO 12207 gap analysis ────────────────────────────────────────────────
    iso12207_results = {}
    for proc_key, proc_data in ISO_12207_PROCESSES.items():
        violations = sum(
            1 for f in findings
            if any(f.get('rule_id', '').startswith(r[:4]) for r in proc_data['rules'])
        )
        score = max(0, 100 - (violations * 20))
        status = 'CONFORME' if score >= 80 else ('PARCIALMENTE CONFORME' if score >= 50 else 'NO CONFORME')
        iso12207_results[proc_key] = {
            'nombre': proc_data['name'],
            'descripcion': proc_data['description'],
            'violaciones': violations,
            'puntuacion': score,
            'estado': status,
        }

    # ── ISO 14764 gap analysis ────────────────────────────────────────────────
    iso14764_results = {}
    for act_key, act_data in ISO_14764_ACTIVITIES.items():
        violations = sum(
            1 for f in findings
            if any(f.get('rule_id', '').startswith(r[:4]) for r in act_data['rules'])
        )
        score = max(0, 100 - (violations * 18))
        status = 'CONFORME' if score >= 80 else ('PARCIALMENTE CONFORME' if score >= 50 else 'NO CONFORME')
        iso14764_results[act_key] = {
            'nombre': act_data['name'],
            'descripcion': act_data['description'],
            'prioridad': act_data['priority'],
            'violaciones': violations,
            'puntuacion': score,
            'estado': status,
        }

    # Overall scores
    def avg_score(results):
        if not results:
            return 100
        return round(sum(v['puntuacion'] for v in results.values()) / len(results))

    return {
        'iso25040': {
            'nombre': 'ISO/IEC 25040 — Calidad del Producto Software',
            'puntuacion_general': avg_score(iso25040_results),
            'caracteristicas': iso25040_results,
        },
        'iso12207': {
            'nombre': 'ISO/IEC 12207 — Ciclo de Vida del Software',
            'puntuacion_general': avg_score(iso12207_results),
            'procesos': iso12207_results,
        },
        'iso14764': {
            'nombre': 'ISO/IEC 14764 — Mantenimiento del Software',
            'puntuacion_general': avg_score(iso14764_results),
            'actividades': iso14764_results,
        },
    }
