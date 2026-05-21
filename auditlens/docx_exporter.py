"""
AuditLens — Word/DOCX Report Exporter

Generates a professional audit report in Word format with complete structure:
- Resumen Ejecutivo
- Introducción (alcance, objetivos SMART)
- Metodología (criterios, herramientas, ISO)
- Hallazgos (Condición/Criterio/Causa/Efecto)
- Análisis de Brechas ISO 25040/12207/14764
- Cobertura de Pruebas
- Conclusiones
- Recomendaciones priorizadas
- Plan de Seguimiento con KPIs
- Anexos

Requires: pip install python-docx
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Dict, List, Optional

from .iso_mapper import enrich_finding_with_iso, compute_iso_gap_analysis, get_remediation
from .test_analyzer import analyze_test_coverage


def _try_import_docx():
    try:
        from docx import Document
        from docx.shared import Inches, Pt, RGBColor, Cm
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.enum.table import WD_TABLE_ALIGNMENT
        from docx.oxml.ns import qn
        from docx.oxml import OxmlElement
        return True
    except ImportError:
        return False


_SEV_COLORS = {
    'CRITICAL': (220, 0, 0),
    'HIGH': (255, 102, 0),
    'MEDIUM': (204, 153, 0),
    'LOW': (0, 102, 204),
}

_STATUS_COLORS = {
    'CONFORME': (0, 153, 0),
    'PARCIALMENTE CONFORME': (204, 153, 0),
    'NO CONFORME': (220, 0, 0),
}


class DocxReportExporter:
    """Generates a full audit report as a Word .docx file."""

    def __init__(self):
        if not _try_import_docx():
            raise ImportError(
                "python-docx es requerido para exportar a Word. "
                "Instala con: pip install python-docx"
            )
        from docx import Document
        from docx.shared import Inches, Pt, RGBColor, Cm
        from docx.enum.text import WD_ALIGN_PARAGRAPH

        self.doc = Document()
        self._setup_styles()

    def _setup_styles(self):
        """Configure default document styles."""
        from docx.shared import Pt, RGBColor
        style = self.doc.styles['Normal']
        style.font.name = 'Calibri'
        style.font.size = Pt(11)

        # Margins
        section = self.doc.sections[0]
        from docx.shared import Cm
        section.top_margin = Cm(2.5)
        section.bottom_margin = Cm(2.5)
        section.left_margin = Cm(3)
        section.right_margin = Cm(2.5)

    def add_table_of_contents(self):
        """
        Insert an automatic Table of Contents (Tabla de Contenidos).
        Word generates the page numbers when the user opens and updates the TOC
        (right-click → Update Field, or Ctrl+A then F9).
        """
        from docx.oxml.ns import qn
        from docx.oxml import OxmlElement
        from docx.shared import Pt
        from docx.enum.text import WD_ALIGN_PARAGRAPH

        self._add_heading('Tabla de Contenidos', level=1)

        # Word TOC field instruction
        paragraph = self.doc.add_paragraph()
        paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT
        run = paragraph.add_run()
        fldChar_begin = OxmlElement('w:fldChar')
        fldChar_begin.set(qn('w:fldCharType'), 'begin')
        run._r.append(fldChar_begin)

        instrText = OxmlElement('w:instrText')
        instrText.set(qn('xml:space'), 'preserve')
        instrText.text = (
            'TOC \\o "1-3" \\h \\z \\u'
        )  # levels 1-3, hyperlinked, hide tab leader in web view, use applied styles
        run._r.append(instrText)

        fldChar_sep = OxmlElement('w:fldChar')
        fldChar_sep.set(qn('w:fldCharType'), 'separate')
        run._r.append(fldChar_sep)

        # Placeholder text shown before first update
        placeholder_para = self.doc.add_paragraph()
        placeholder_run = placeholder_para.add_run(
            'Haga clic derecho aquí → "Actualizar campo" para generar el índice con números de página.'
        )
        placeholder_run.font.size = Pt(10)
        placeholder_run.font.italic = True
        placeholder_run.font.color.rgb = __import__('docx').shared.RGBColor(128, 128, 128)

        fldChar_end = OxmlElement('w:fldChar')
        fldChar_end.set(qn('w:fldCharType'), 'end')
        run._r.append(fldChar_end)

        self.doc.add_page_break()

    def _add_heading(self, text: str, level: int = 1, color=None):
        from docx.shared import RGBColor, Pt
        p = self.doc.add_heading(text, level=level)
        if color:
            for run in p.runs:
                run.font.color.rgb = RGBColor(*color)
        return p

    def _add_paragraph(self, text: str, bold: bool = False, italic: bool = False,
                        color=None, size: int = 11):
        from docx.shared import RGBColor, Pt
        p = self.doc.add_paragraph()
        run = p.add_run(text)
        run.bold = bold
        run.italic = italic
        run.font.size = Pt(size)
        if color:
            run.font.color.rgb = RGBColor(*color)
        return p

    def _add_table(self, headers: List[str], rows: List[List[str]],
                   header_color=(68, 114, 196)):
        from docx.shared import RGBColor, Pt
        from docx.oxml.ns import qn
        from docx.oxml import OxmlElement

        table = self.doc.add_table(rows=1, cols=len(headers))
        table.style = 'Table Grid'

        # Header row
        hdr = table.rows[0].cells
        for i, h in enumerate(headers):
            hdr[i].text = h
            for para in hdr[i].paragraphs:
                for run in para.runs:
                    run.bold = True
                    run.font.color.rgb = RGBColor(255, 255, 255)
                    run.font.size = Pt(10)
            # Cell background color
            tc = hdr[i]._tc
            tcPr = tc.get_or_add_tcPr()
            shd = OxmlElement('w:shd')
            shd.set(qn('w:val'), 'clear')
            shd.set(qn('w:color'), 'auto')
            shd.set(qn('w:fill'), '%02X%02X%02X' % header_color)
            tcPr.append(shd)

        # Data rows
        for row_data in rows:
            row = table.add_row().cells
            for i, cell_text in enumerate(row_data):
                row[i].text = str(cell_text)
                for para in row[i].paragraphs:
                    for run in para.runs:
                        run.font.size = Pt(10)

        self.doc.add_paragraph()
        return table

    def _add_severity_badge(self, paragraph, severity: str):
        from docx.shared import RGBColor, Pt
        color = _SEV_COLORS.get(severity.upper(), (100, 100, 100))
        run = paragraph.add_run(f'[{severity.upper()}]')
        run.bold = True
        run.font.color.rgb = RGBColor(*color)
        run.font.size = Pt(11)

    # ── Sections ──────────────────────────────────────────────────────────────

    def add_cover_page(self, empresa: str, sistema: str, auditor: str,
                       fecha: str, trimestre: str):
        from docx.shared import Pt
        from docx.enum.text import WD_ALIGN_PARAGRAPH

        self.doc.add_paragraph()
        self.doc.add_paragraph()

        title = self.doc.add_paragraph()
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = title.add_run('INFORME DE AUDITORÍA DE SOFTWARE')
        run.bold = True
        run.font.size = Pt(20)

        subtitle = self.doc.add_paragraph()
        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run2 = subtitle.add_run(f'{sistema}')
        run2.bold = True
        run2.font.size = Pt(16)

        self.doc.add_paragraph()

        info_lines = [
            ('Empresa', empresa),
            ('Sistema', sistema),
            ('Período', trimestre),
            ('Fecha de Generación', fecha),
            ('Auditor Líder', auditor),
            ('Herramienta', 'AuditLens v0.3.0'),
            ('Estándares', 'ISO 25040 · ISO 12207 · ISO 14764'),
        ]

        table = self.doc.add_table(rows=len(info_lines), cols=2)
        table.style = 'Table Grid'
        for i, (label, value) in enumerate(info_lines):
            cells = table.rows[i].cells
            cells[0].text = label
            cells[1].text = value
            for run in cells[0].paragraphs[0].runs:
                run.bold = True

        self.doc.add_page_break()

    def add_executive_summary(self, findings: List[dict], gap_analysis: Dict,
                               test_analysis: Dict, empresa: str, sistema: str):
        self._add_heading('1. Resumen Ejecutivo', level=1)

        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            sev = f.get('severity', 'LOW').upper()
            if sev in counts:
                counts[sev] += 1

        iso_avg = round(
            (gap_analysis['iso25040']['puntuacion_general'] +
             gap_analysis['iso12207']['puntuacion_general'] +
             gap_analysis['iso14764']['puntuacion_general']) / 3
        )

        self._add_paragraph(
            f"La presente auditoría de software del sistema {sistema} de la empresa {empresa} "
            f"identificó un total de {len(findings)} hallazgos de seguridad y calidad, "
            f"distribuidos en {counts['CRITICAL']} críticos, {counts['HIGH']} altos, "
            f"{counts['MEDIUM']} medios y {counts['LOW']} bajos.",
        )

        self._add_paragraph(
            f"La puntuación general de conformidad con los estándares ISO evaluados es de "
            f"{iso_avg}/100, indicando oportunidades significativas de mejora en las áreas "
            f"de seguridad del código y cobertura de pruebas.",
        )

        # Summary table
        self._add_heading('Resumen de Hallazgos por Severidad', level=2)
        self._add_table(
            ['Severidad', 'Cantidad', 'Prioridad de Remediación'],
            [
                ['CRÍTICO', str(counts['CRITICAL']), 'Inmediata (< 48 horas)'],
                ['ALTO', str(counts['HIGH']), 'Urgente (< 1 semana)'],
                ['MEDIO', str(counts['MEDIUM']), 'Normal (< 1 mes)'],
                ['BAJO', str(counts['LOW']), 'Planificada (< 3 meses)'],
                ['TOTAL', str(len(findings)), '—'],
            ]
        )

        # ISO conformance summary
        self._add_heading('Conformidad con Estándares ISO', level=2)
        self._add_table(
            ['Estándar', 'Puntuación', 'Estado'],
            [
                ['ISO 25040 — Calidad del Producto',
                 f"{gap_analysis['iso25040']['puntuacion_general']}/100",
                 self._score_to_status(gap_analysis['iso25040']['puntuacion_general'])],
                ['ISO 12207 — Ciclo de Vida',
                 f"{gap_analysis['iso12207']['puntuacion_general']}/100",
                 self._score_to_status(gap_analysis['iso12207']['puntuacion_general'])],
                ['ISO 14764 — Mantenimiento',
                 f"{gap_analysis['iso14764']['puntuacion_general']}/100",
                 self._score_to_status(gap_analysis['iso14764']['puntuacion_general'])],
            ]
        )

    def _score_to_status(self, score: int) -> str:
        if score >= 80:
            return 'CONFORME'
        elif score >= 50:
            return 'PARCIALMENTE CONFORME'
        return 'NO CONFORME'

    def add_introduction(self, plan: Dict):
        self._add_heading('2. Introducción', level=1)

        meta = plan.get('metadata', {})
        sec = plan.get('seccion_1_1_alcance_objetivos', {})
        alcance = sec.get('alcance', {})

        self._add_heading('2.1 Propósito y Alcance', level=2)
        self._add_paragraph(alcance.get('descripcion', ''))

        self._add_heading('Incluye:', level=3)
        for item in alcance.get('incluye', []):
            p = self.doc.add_paragraph(style='List Bullet')
            p.add_run(item)

        self._add_heading('Excluye:', level=3)
        for item in alcance.get('excluye', []):
            p = self.doc.add_paragraph(style='List Bullet')
            p.add_run(item)

        self._add_heading('2.2 Objetivos SMART', level=2)
        for obj in sec.get('objetivos_smart', []):
            self._add_heading(f"Objetivo {obj['numero']}: {obj['titulo']}", level=3)
            self._add_paragraph(obj['descripcion'])
            rows = [
                ['Específico', obj['especifico']],
                ['Medible', obj['medible']],
                ['Alcanzable', obj['alcanzable']],
                ['Relevante', obj['relevante']],
                ['Con Plazo', obj['plazo']],
                ['Normas ISO', ', '.join(obj.get('iso', []))],
            ]
            self._add_table(['Criterio SMART', 'Detalle'], rows)

    def add_methodology(self, plan: Dict):
        self._add_heading('3. Metodología de Auditoría', level=1)
        met = plan.get('seccion_1_3_metodologia', {})

        self._add_paragraph(met.get('descripcion', ''))

        self._add_heading('3.1 Técnicas y Herramientas', level=2)
        for tec in met.get('tecnicas', []):
            self._add_heading(tec['nombre'], level=3)
            rows = [
                ['Herramienta', tec['herramienta']],
                ['Descripción', tec['descripcion']],
                ['Cobertura', tec['cobertura']],
                ['Norma ISO', tec['iso']],
            ]
            self._add_table(['Campo', 'Detalle'], rows)

        self._add_heading('3.2 Fases del Proceso de Auditoría', level=2)
        fase_rows = [
            [str(f['fase']), f['nombre'], f['duracion'], ', '.join(f['actividades'])]
            for f in met.get('fases', [])
        ]
        self._add_table(['Fase', 'Nombre', 'Duración', 'Actividades'], fase_rows)

        self._add_heading('3.3 Criterios de Auditoría', level=2)
        for crit in plan.get('seccion_1_2_criterios', []):
            self._add_heading(crit['norma'], level=3)
            self._add_paragraph(crit['justificacion'])
            for c in crit.get('caracteristicas', []):
                p = self.doc.add_paragraph(style='List Bullet')
                p.add_run(c)

        self._add_heading('3.4 Equipo Auditor', level=2)
        for rol in plan.get('seccion_1_4_roles', []):
            self._add_heading(rol['rol'], level=3)
            self._add_paragraph(f"Responsable: {rol['nombre']}", bold=True)
            for resp in rol['responsabilidades']:
                p = self.doc.add_paragraph(style='List Bullet')
                p.add_run(resp)

    def add_findings(self, findings: List[dict]):
        self._add_heading('4. Hallazgos de Auditoría', level=1)

        if not findings:
            self._add_paragraph(
                'No se identificaron hallazgos de seguridad en el código analizado.',
                italic=True
            )
            return

        self._add_paragraph(
            f"Se presentan a continuación los {len(findings)} hallazgos identificados, "
            f"ordenados por severidad. Cada hallazgo incluye el formato "
            f"Condición / Criterio / Causa / Efecto conforme a las mejores prácticas de auditoría.",
        )

        # Sort by severity
        sev_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(
            findings,
            key=lambda x: sev_rank.get(x.get('severity', 'LOW').upper(), 3)
        )

        for idx, finding in enumerate(sorted_findings, 1):
            enriched = enrich_finding_with_iso(finding)
            severity = finding.get('severity', 'LOW').upper()
            color = _SEV_COLORS.get(severity, (100, 100, 100))

            self._add_heading(
                f"Hallazgo #{idx} — {finding.get('name', finding.get('rule_id', ''))}",
                level=2,
                color=color,
            )

            file_short = '/'.join(finding.get('file', '').split('/')[-2:])
            rows = [
                ['Regla ID', finding.get('rule_id', '')],
                ['Severidad', severity],
                ['Archivo', f"{file_short} (línea {finding.get('line', '')})"],
                ['Condición', enriched.get('condicion', finding.get('description', ''))],
                ['Criterio', enriched.get('criterio', '')],
                ['Causa', enriched.get('causa', '')],
                ['Efecto', enriched.get('efecto', '')],
                ['ISO 25040', enriched.get('norma_iso25040', '')],
                ['ISO 12207', enriched.get('norma_iso12207', '')],
                ['ISO 14764', enriched.get('norma_iso14764', '')],
                ['Cumplimiento', ', '.join(finding.get('compliance', []))],
            ]
            self._add_table(['Campo', 'Descripción'], rows)

            # Remediation
            rem = enriched.get('remediacion', get_remediation(finding.get('rule_id', '')))
            self._add_heading('Recomendación de Remediación', level=3)
            rem_rows = [
                ['Título', rem.get('titulo', '')],
                ['Esfuerzo', rem.get('esfuerzo', '')],
                ['Plazo', rem.get('plazo', '')],
                ['Prioridad', rem.get('prioridad', '')],
                ['ISO Aplicable', rem.get('iso', '')],
            ]
            self._add_table(['Campo', 'Detalle'], rem_rows)
            self._add_heading('Pasos de corrección:', level=3)
            for step in rem.get('pasos', []):
                p = self.doc.add_paragraph(style='List Number')
                p.add_run(step)

    def add_iso_gap_analysis(self, gap_analysis: Dict):
        self._add_heading('5. Análisis de Brechas ISO', level=1)
        self._add_paragraph(
            'El siguiente análisis evalúa el nivel de conformidad del software con los '
            'tres estándares ISO aplicados en esta auditoría, identificando las brechas '
            'más significativas para priorizar las acciones de mejora.'
        )

        # ISO 25040
        self._add_heading('5.1 ISO/IEC 25040 — Calidad del Producto Software', level=2)
        iso25040 = gap_analysis.get('iso25040', {})
        self._add_paragraph(
            f"Puntuación General: {iso25040.get('puntuacion_general', 0)}/100 — "
            f"{self._score_to_status(iso25040.get('puntuacion_general', 0))}",
            bold=True
        )
        char_rows = []
        for key, char in iso25040.get('caracteristicas', {}).items():
            char_rows.append([
                char['nombre'],
                str(char['violaciones']),
                f"{char['puntuacion']}/100",
                char['estado'],
            ])
        self._add_table(
            ['Característica', 'Violaciones', 'Puntuación', 'Estado'],
            char_rows
        )

        # ISO 12207
        self._add_heading('5.2 ISO/IEC 12207 — Ciclo de Vida del Software', level=2)
        iso12207 = gap_analysis.get('iso12207', {})
        self._add_paragraph(
            f"Puntuación General: {iso12207.get('puntuacion_general', 0)}/100 — "
            f"{self._score_to_status(iso12207.get('puntuacion_general', 0))}",
            bold=True
        )
        proc_rows = []
        for key, proc in iso12207.get('procesos', {}).items():
            proc_rows.append([
                proc['nombre'],
                str(proc['violaciones']),
                f"{proc['puntuacion']}/100",
                proc['estado'],
            ])
        self._add_table(
            ['Proceso', 'Violaciones', 'Puntuación', 'Estado'],
            proc_rows
        )

        # ISO 14764
        self._add_heading('5.3 ISO/IEC 14764 — Mantenimiento del Software', level=2)
        iso14764 = gap_analysis.get('iso14764', {})
        self._add_paragraph(
            f"Puntuación General: {iso14764.get('puntuacion_general', 0)}/100 — "
            f"{self._score_to_status(iso14764.get('puntuacion_general', 0))}",
            bold=True
        )
        act_rows = []
        for key, act in iso14764.get('actividades', {}).items():
            act_rows.append([
                act['nombre'],
                act['prioridad'],
                str(act['violaciones']),
                f"{act['puntuacion']}/100",
                act['estado'],
            ])
        self._add_table(
            ['Actividad de Mantenimiento', 'Prioridad', 'Violaciones', 'Puntuación', 'Estado'],
            act_rows
        )

    def add_test_coverage(self, test_analysis: Dict):
        self._add_heading('6. Análisis de Cobertura de Pruebas', level=1)
        self._add_paragraph(
            'El análisis de cobertura de pruebas evalúa la conformidad con el proceso de '
            'Verificación y Validación de ISO 12207, identificando brechas en la estrategia '
            'de pruebas del proyecto.'
        )

        # Summary metrics
        self._add_table(
            ['Métrica', 'Valor'],
            [
                ['Archivos fuente totales', str(test_analysis.get('total_archivos_fuente', 0))],
                ['Archivos de prueba detectados', str(test_analysis.get('total_archivos_test', 0))],
                ['Ratio de cobertura estimado', f"{test_analysis.get('ratio_cobertura_estimado', 0)}%"],
                ['Pruebas unitarias', 'Sí' if test_analysis.get('tipos_pruebas', {}).get('unitarias') else 'No'],
                ['Pruebas de seguridad', 'Sí' if test_analysis.get('tipos_pruebas', {}).get('seguridad') else 'No'],
                ['Pruebas de integración', 'Sí' if test_analysis.get('tipos_pruebas', {}).get('integracion') else 'No'],
                ['Configuración de pruebas', 'Sí' if test_analysis.get('tiene_config_tests') else 'No'],
                ['Puntuación ISO 12207 V&V', f"{test_analysis.get('puntuacion_iso12207', 0)}/100"],
            ]
        )

        # Gaps
        gaps = test_analysis.get('brechas_identificadas', [])
        if gaps:
            self._add_heading('Brechas Identificadas en Pruebas', level=2)
            for gap in gaps:
                self._add_table(
                    ['Campo', 'Detalle'],
                    [
                        ['Brecha', gap['brecha']],
                        ['Impacto', gap['impacto']],
                        ['Recomendación', gap['recomendacion']],
                        ['Norma ISO', gap['iso']],
                        ['Plazo sugerido', gap['plazo']],
                    ]
                )

    def add_conclusions(self, findings: List[dict], gap_analysis: Dict,
                        sistema: str, empresa: str):
        self._add_heading('7. Conclusiones', level=1)

        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            sev = f.get('severity', 'LOW').upper()
            if sev in counts:
                counts[sev] += 1

        iso_avg = round(
            (gap_analysis['iso25040']['puntuacion_general'] +
             gap_analysis['iso12207']['puntuacion_general'] +
             gap_analysis['iso14764']['puntuacion_general']) / 3
        )

        conclusions = [
            (
                f"El sistema {sistema} presenta un nivel de conformidad general de {iso_avg}/100 "
                f"con los estándares ISO evaluados, con áreas críticas que requieren atención inmediata."
            ),
            (
                f"Se identificaron {counts['CRITICAL']} hallazgos de severidad CRÍTICA y "
                f"{counts['HIGH']} de severidad ALTA, que representan riesgos inmediatos para "
                f"la seguridad y confiabilidad del sistema."
            ),
            (
                f"La conformidad con ISO 25040 (Seguridad Funcional) es de "
                f"{gap_analysis['iso25040']['puntuacion_general']}/100, indicando la necesidad de "
                f"implementar controles de seguridad adicionales en el código fuente."
            ),
            (
                f"La conformidad con ISO 12207 (Ciclo de Vida) es de "
                f"{gap_analysis['iso12207']['puntuacion_general']}/100, reflejando oportunidades "
                f"de mejora en los procesos de desarrollo y verificación."
            ),
            (
                f"La conformidad con ISO 14764 (Mantenimiento) es de "
                f"{gap_analysis['iso14764']['puntuacion_general']}/100, con acciones de "
                f"mantenimiento correctivo requeridas de manera prioritaria."
            ),
        ]

        for i, conclusion in enumerate(conclusions, 1):
            p = self.doc.add_paragraph()
            p.add_run(f"{i}. ").bold = True
            p.add_run(conclusion)

    def add_recommendations(self, findings: List[dict]):
        self._add_heading('8. Recomendaciones', level=1)
        self._add_paragraph(
            'Las siguientes recomendaciones se presentan priorizadas por severidad e impacto, '
            'con plazos sugeridos de implementación y referencia a los estándares ISO aplicables.'
        )

        # Group by priority
        critical_findings = [f for f in findings if f.get('severity') == 'CRITICAL']
        high_findings = [f for f in findings if f.get('severity') == 'HIGH']
        med_findings = [f for f in findings if f.get('severity') == 'MEDIUM']

        for group_name, group_findings, plazo in [
            ('Acciones Inmediatas (CRÍTICO)', critical_findings, '< 48 horas'),
            ('Acciones Urgentes (ALTO)', high_findings, '< 1 semana'),
            ('Acciones Planificadas (MEDIO)', med_findings, '< 1 mes'),
        ]:
            if not group_findings:
                continue
            self._add_heading(group_name, level=2)
            for finding in group_findings[:5]:  # top 5 per group
                rem = get_remediation(finding.get('rule_id', ''))
                p = self.doc.add_paragraph(style='List Bullet')
                run = p.add_run(f"[{finding.get('rule_id', '')}] {rem.get('titulo', '')}")
                run.bold = True
                p2 = self.doc.add_paragraph(style='List Bullet 2')
                p2.add_run(f"Esfuerzo: {rem.get('esfuerzo', 'Variable')} | Plazo: {plazo} | {rem.get('iso', '')}")

    def add_followup_plan(self, kpis: List[Dict]):
        self._add_heading('9. Plan de Seguimiento', level=1)
        self._add_paragraph(
            'El plan de seguimiento establece los indicadores clave de rendimiento (KPIs) '
            'para medir la efectividad de las acciones correctivas implementadas, '
            'conforme a ISO 12207 e ISO 14764.'
        )

        kpi_rows = []
        for kpi in kpis:
            kpi_rows.append([
                kpi['kpi'],
                str(kpi['valor_actual']),
                str(kpi['meta']),
                kpi['unidad'],
                kpi['frecuencia'],
                kpi['plazo'],
                kpi['iso'],
            ])

        self._add_table(
            ['KPI', 'Valor Actual', 'Meta', 'Unidad', 'Frecuencia', 'Plazo', 'ISO'],
            kpi_rows
        )

        self._add_heading('Mecanismo de Seguimiento', level=2)
        steps = [
            'Revisión mensual del estado de hallazgos críticos y altos',
            'Ejecución periódica de AuditLens para medir progreso (auditlens scan --diff-baseline)',
            'Actualización del baseline tras cada sprint de remediación',
            'Revisión trimestral de KPIs con el equipo de desarrollo',
            'Informe de cierre cuando todos los hallazgos críticos estén resueltos',
        ]
        for step in steps:
            p = self.doc.add_paragraph(style='List Number')
            p.add_run(step)

    def add_annexes(self, project_info: Dict, test_analysis: Dict):
        self._add_heading('10. Anexos', level=1)

        self._add_heading('Anexo A — Estructura del Proyecto', level=2)
        proj_rows = [
            ['Total archivos fuente', str(project_info.get('total_archivos', 0))],
            ['Total líneas de código', f"{project_info.get('total_lineas', 0):,}"],
            ['Lenguajes detectados', ', '.join(project_info.get('lenguajes', {}).keys())],
            ['Módulos principales', ', '.join(project_info.get('modulos', [])[:8])],
            ['Archivo requirements.txt', 'Sí' if project_info.get('tiene_requirements') else 'No'],
            ['Archivo package.json', 'Sí' if project_info.get('tiene_package_json') else 'No'],
            ['CI/CD configurado', 'Sí' if project_info.get('tiene_ci') else 'No'],
            ['Dockerfile', 'Sí' if project_info.get('tiene_dockerfile') else 'No'],
            ['README', 'Sí' if project_info.get('tiene_readme') else 'No'],
        ]
        self._add_table(['Característica', 'Valor'], proj_rows)

        self._add_heading('Anexo B — Archivos sin Cobertura de Pruebas', level=2)
        untested = test_analysis.get('archivos_sin_tests', [])
        if untested:
            self._add_paragraph(
                f"Los siguientes {len(untested)} archivos no tienen pruebas asociadas detectadas:"
            )
            for fpath in untested[:15]:
                p = self.doc.add_paragraph(style='List Bullet')
                p.add_run('/'.join(fpath.split('/')[-3:]))
        else:
            self._add_paragraph('No se detectaron archivos sin cobertura de pruebas.', italic=True)

        self._add_heading('Anexo C — Herramienta Utilizada', level=2)
        tool_rows = [
            ['Nombre', 'AuditLens'],
            ['Versión', '0.3.0'],
            ['Tipo', 'SAST / SCA / Taint Analysis'],
            ['Licencia', 'MIT Open Source'],
            ['Repositorio', 'https://github.com/MasterCapehart/auditlens'],
            ['Reglas de detección', '88 reglas activas'],
            ['Lenguajes soportados', 'Python, JavaScript, TypeScript, Swift, Go, Java, Kotlin, Ruby'],
        ]
        self._add_table(['Campo', 'Valor'], tool_rows)

    def save(self, output_path: str):
        self.doc.save(output_path)
        print(
            f'\n\033[92m[AuditLens]\033[0m Informe Word guardado: '
            f'\033[1m{os.path.abspath(output_path)}\033[0m'
        )


def generate_docx_report(
    findings: List[dict],
    scan_path: str,
    output_path: str = 'informe_auditoria.docx',
    empresa: str = 'Empresa',
    sistema: str = 'Sistema de Software',
    auditor: str = '[Auditor por asignar]',
    trimestre: str = 'tercer trimestre de 2025',
    plan: Optional[Dict] = None,
) -> str:
    """
    Generate the complete unified audit document (plan + scan results).

    Structure:
      Portada
      Tabla de Contenidos  ← NEW: auto-generated TOC
      1. Resumen Ejecutivo
      2. Introducción (alcance, objetivos SMART)  ← from plan
      3. Metodología (técnicas, fases, criterios, roles)  ← from plan
      4. Hallazgos (Condición/Criterio/Causa/Efecto)  ← from scan
      5. Análisis de Brechas ISO 25040/12207/14764
      6. Análisis de Cobertura de Pruebas
      7. Conclusiones
      8. Recomendaciones priorizadas
      9. Plan de Seguimiento con KPIs
      10. Anexos

    Returns the path to the generated file.
    """
    from .iso_mapper import compute_iso_gap_analysis, enrich_finding_with_iso
    from .test_analyzer import analyze_test_coverage
    from .audit_planner import generate_audit_plan, generate_kpis

    print('\033[94m[AuditLens]\033[0m Preparando informe Word unificado...')

    # Enrich findings with ISO Condición/Criterio/Causa/Efecto
    enriched_findings = [enrich_finding_with_iso(f) for f in findings]

    # Compute ISO gap analysis and test coverage
    gap_analysis = compute_iso_gap_analysis(findings)
    test_analysis = analyze_test_coverage(scan_path)

    # Generate full audit plan (includes project structure, SMART objectives, etc.)
    if plan is None:
        plan = generate_audit_plan(
            scan_path, findings, empresa, sistema, trimestre, auditor
        )

    kpis = generate_kpis(findings, test_analysis)
    project_info = plan.get('resumen_proyecto', {})
    fecha = datetime.now().strftime('%d/%m/%Y')

    exporter = DocxReportExporter()

    # ── 1. Portada ────────────────────────────────────────────────────────────
    exporter.add_cover_page(empresa, sistema, auditor, fecha, trimestre)

    # ── 2. Tabla de Contenidos ────────────────────────────────────────────────
    exporter.add_table_of_contents()

    # ── 3. Resumen Ejecutivo ──────────────────────────────────────────────────
    exporter.add_executive_summary(findings, gap_analysis, test_analysis, empresa, sistema)

    # ── 4. Introducción (alcance + objetivos SMART) ───────────────────────────
    exporter.add_introduction(plan)

    # ── 5. Metodología ────────────────────────────────────────────────────────
    exporter.add_methodology(plan)

    # ── 6. Hallazgos ─────────────────────────────────────────────────────────
    exporter.add_findings(enriched_findings)

    # ── 7. Análisis de Brechas ISO ────────────────────────────────────────────
    exporter.add_iso_gap_analysis(gap_analysis)

    # ── 8. Análisis de Cobertura de Pruebas ──────────────────────────────────
    exporter.add_test_coverage(test_analysis)

    # ── 9. Conclusiones ───────────────────────────────────────────────────────
    exporter.add_conclusions(findings, gap_analysis, sistema, empresa)

    # ── 10. Recomendaciones ───────────────────────────────────────────────────
    exporter.add_recommendations(findings)

    # ── 11. Plan de Seguimiento ───────────────────────────────────────────────
    exporter.add_followup_plan(kpis)

    # ── 12. Anexos ────────────────────────────────────────────────────────────
    exporter.add_annexes(project_info, test_analysis)

    exporter.save(output_path)
    return output_path
