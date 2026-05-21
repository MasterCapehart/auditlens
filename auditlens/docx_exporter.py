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
        self._bm_counter = 0  # bookmark ID counter

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

    # ── Bookmark / hyperlink helpers ──────────────────────────────────────────

    def _add_bookmark(self, paragraph, bookmark_id: int, bookmark_name: str):
        """
        Insert a Word bookmark at the start of a paragraph.
        This is the anchor that TOC hyperlinks point to.
        """
        from docx.oxml.ns import qn
        from docx.oxml import OxmlElement

        tag = paragraph._p
        # bookmarkStart
        bm_start = OxmlElement('w:bookmarkStart')
        bm_start.set(qn('w:id'), str(bookmark_id))
        bm_start.set(qn('w:name'), bookmark_name)
        tag.insert(0, bm_start)
        # bookmarkEnd
        bm_end = OxmlElement('w:bookmarkEnd')
        bm_end.set(qn('w:id'), str(bookmark_id))
        tag.append(bm_end)

    def _add_hyperlink_to_bookmark(self, paragraph, bookmark_name: str,
                                    display_text: str, bold: bool = False,
                                    color=None, size: int = 11):
        """
        Add a run inside a paragraph that is a clickable internal hyperlink
        pointing to bookmark_name.
        """
        from docx.oxml.ns import qn
        from docx.oxml import OxmlElement
        from docx.shared import RGBColor, Pt

        # <w:hyperlink w:anchor="bookmark_name" ...>
        hyperlink = OxmlElement('w:hyperlink')
        hyperlink.set(qn('w:anchor'), bookmark_name)
        hyperlink.set(qn('r:id'), '')  # internal anchor, no rId needed

        # Run inside hyperlink
        run = OxmlElement('w:r')

        # Run properties
        rPr = OxmlElement('w:rPr')
        # Underline
        u = OxmlElement('w:u')
        u.set(qn('w:val'), 'single')
        rPr.append(u)
        # Color — blue link or custom
        c = OxmlElement('w:color')
        if color:
            c.set(qn('w:val'), '%02X%02X%02X' % color)
        else:
            c.set(qn('w:val'), '1155CC')  # standard hyperlink blue
        rPr.append(c)
        # Font size
        sz = OxmlElement('w:sz')
        sz.set(qn('w:val'), str(size * 2))
        rPr.append(sz)
        # Bold
        if bold:
            b = OxmlElement('w:b')
            rPr.append(b)
        run.append(rPr)

        # Text
        t = OxmlElement('w:t')
        t.set(qn('xml:space'), 'preserve')
        t.text = display_text
        run.append(t)

        hyperlink.append(run)
        paragraph._p.append(hyperlink)

    def add_table_of_contents(self, findings_count: int = 0):
        """
        Insert a clickable Table of Contents.
        Each entry is a Word internal hyperlink pointing to a bookmark
        placed on the corresponding heading — so clicking navigates directly.
        """
        from docx.shared import Pt, RGBColor, Cm

        # Page heading (no bookmark needed — TOC itself has no link)
        self.doc.add_heading('Tabla de Contenidos', level=1)
        self.doc.add_paragraph()

        # (level, number_label, display_title, bookmark_name)
        entries = [
            (0, '1.',   'Resumen Ejecutivo',                          'sec_resumen'),
            (0, '2.',   'Introducción',                               'sec_intro'),
            (1, '2.1',  'Propósito y Alcance',                        'sec_alcance'),
            (1, '2.2',  'Objetivos SMART',                            'sec_smart'),
            (0, '3.',   'Metodología de Auditoría',                   'sec_metodologia'),
            (1, '3.1',  'Técnicas y Herramientas',                    'sec_tecnicas'),
            (1, '3.2',  'Fases del Proceso',                          'sec_fases'),
            (1, '3.3',  'Criterios ISO 25040 / 12207 / 14764',        'sec_criterios'),
            (1, '3.4',  'Equipo Auditor',                             'sec_roles'),
            (0, '4.',   'Ejecución y Recolección de Evidencia',       'sec_ejecucion'),
            (1, '4.1',  'Procedimientos de Recolección de Evidencia', 'sec_recoleccion'),
            (1, '4.2',  'Estrategias de Pruebas de Software',         'sec_pruebas'),
            (1, '4.3',  'Validez y Confiabilidad de la Evidencia',    'sec_validez'),
            (0, '5.',   f'Hallazgos ({findings_count} hallazgos)',    'sec_hallazgos'),
            (0, '6.',   'Análisis de Brechas ISO',                    'sec_brechas'),
            (1, '6.1',  'ISO 25040 — Calidad del Producto',           'sec_iso25040'),
            (1, '6.2',  'ISO 12207 — Ciclo de Vida',                  'sec_iso12207'),
            (1, '6.3',  'ISO 14764 — Mantenimiento',                  'sec_iso14764'),
            (0, '7.',   'Cobertura de Pruebas',                       'sec_tests'),
            (0, '8.',   'Conclusiones',                               'sec_conclusiones'),
            (0, '9.',   'Recomendaciones y Seguimiento',              'sec_recomendaciones'),
            (1, '9.1',  'Recomendaciones Priorizadas',                'sec_rec_critico'),
            (1, '9.2',  'Plan de Seguimiento con KPIs',               'sec_seguimiento'),
            (1, '9.3',  'Criterios de Cierre de la Auditoría',        'sec_cierre'),
            (1, '9.4',  'Lecciones Aprendidas',                       'sec_lecciones'),
            (0, '10.',  'Anexos',                                     'sec_anexos'),
            (1, 'A.',   'Estructura del Proyecto',                    'sec_anexo_a'),
            (1, 'B.',   'Archivos sin Cobertura de Pruebas',          'sec_anexo_b'),
            (1, 'C.',   'Herramienta Utilizada',                      'sec_anexo_c'),
        ]

        for level, num, title, bookmark in entries:
            para = self.doc.add_paragraph()
            para.paragraph_format.space_before = Pt(1)
            para.paragraph_format.space_after = Pt(1)
            if level == 1:
                para.paragraph_format.left_indent = Cm(1.2)

            # Build display text: "1.  Título ········"
            dots_count = max(4, 60 - len(num) - len(title) - level * 6)
            display = f'{num}  {title}  {"·" * dots_count}'

            is_main = (level == 0)
            link_color = (44, 90, 160) if is_main else (90, 110, 160)

            self._add_hyperlink_to_bookmark(
                para,
                bookmark_name=bookmark,
                display_text=display,
                bold=is_main,
                color=link_color,
                size=11 if is_main else 10,
            )

        self.doc.add_paragraph()
        self.doc.add_page_break()

        # Store bookmark counter for headings
        self._bm_counter = 0
        self._bm_map = {entry[3]: False for entry in entries}

    # Mapping from heading text fragments to bookmark names
    _HEADING_BOOKMARK_MAP = {
        'Resumen Ejecutivo':                    'sec_resumen',
        'Introducción':                         'sec_intro',
        'Propósito y Alcance':                  'sec_alcance',
        'Objetivos SMART':                      'sec_smart',
        'Metodología':                          'sec_metodologia',
        'Técnicas y Herramientas':              'sec_tecnicas',
        'Fases del Proceso':                    'sec_fases',
        'Criterios de Auditoría':               'sec_criterios',
        'Equipo Auditor':                       'sec_roles',
        'Ejecución y Recolección':              'sec_ejecucion',
        'Procedimientos de Recolección':        'sec_recoleccion',
        'Estrategias de Pruebas':               'sec_pruebas',
        'Validez y Confiabilidad':              'sec_validez',
        'Hallazgos de Auditoría':               'sec_hallazgos',
        'Análisis de Brechas ISO':              'sec_brechas',
        'ISO/IEC 25040':                        'sec_iso25040',
        'ISO/IEC 12207':                        'sec_iso12207',
        'ISO/IEC 14764':                        'sec_iso14764',
        'Cobertura de Pruebas':                 'sec_tests',
        'Conclusiones':                         'sec_conclusiones',
        'Recomendaciones y Seguimiento':        'sec_recomendaciones',
        'Recomendaciones Priorizadas':          'sec_rec_critico',
        'Acciones Inmediatas':                  'sec_rec_critico',
        'Plan de Seguimiento':                  'sec_seguimiento',
        'Criterios para el Cierre':             'sec_cierre',
        'Lecciones Aprendidas':                 'sec_lecciones',
        'Anexos':                               'sec_anexos',
        'Anexo A':                              'sec_anexo_a',
        'Estructura del Proyecto':              'sec_anexo_a',
        'Archivos sin Cobertura':               'sec_anexo_b',
        'Herramienta Utilizada':                'sec_anexo_c',
    }

    def _add_heading(self, text: str, level: int = 1, color=None):
        from docx.shared import RGBColor, Pt
        p = self.doc.add_heading(text, level=level)
        if color:
            for run in p.runs:
                run.font.color.rgb = RGBColor(*color)

        # Add bookmark if this heading matches a TOC entry
        bookmark_name = None
        for fragment, bm in self._HEADING_BOOKMARK_MAP.items():
            if fragment in text:
                bookmark_name = bm
                break

        if bookmark_name and hasattr(self, '_bm_counter'):
            self._add_bookmark(p, self._bm_counter, bookmark_name)
            self._bm_counter += 1

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

    def add_evidence_collection(self, findings: List[dict], project_info: Dict, sistema: str):
        """
        Sección 2.1 — Procedimientos de Recolección de Evidencia
        Incluye plantillas de recolección pre-llenadas con datos del proyecto.
        """
        self._add_heading('2.1 Procedimientos de Recolección de Evidencia', level=2)
        self._add_paragraph(
            'Los siguientes procedimientos especifican qué evidencia se recolecta, '
            'cómo se obtiene y qué artefactos se analizan conforme a ISO 25040, '
            'ISO 12207 e ISO 14764.'
        )

        # Procedimiento 1 — Análisis estático de código
        self._add_heading('Procedimiento 1: Análisis Estático del Código Fuente', level=3)
        self._add_table(
            ['Campo', 'Detalle'],
            [
                ['Objetivo', 'Identificar vulnerabilidades, deuda técnica y violaciones de estándares en el código fuente'],
                ['Norma ISO', 'ISO 25040 — Seguridad Funcional; ISO 12207 — Codificación y Verificación'],
                ['Qué se busca', 'Vulnerabilidades de seguridad, patrones inseguros, secrets expuestos, flujos de datos peligrosos'],
                ['Cómo se obtiene', f'Ejecución de AuditLens sobre {project_info.get("total_archivos", 0)} archivos fuente del sistema {sistema}'],
                ['Artefactos analizados', f'{", ".join(list(project_info.get("lenguajes", {}).keys())[:4])} — código fuente del repositorio'],
                ['Herramienta', 'AuditLens v0.3.0 (SAST + Taint Analysis + SCA)'],
                ['Resultado', 'Reporte de hallazgos con Condición/Criterio/Causa/Efecto y mapeo ISO'],
                ['Responsable', 'Auditor Técnico de Software'],
            ]
        )

        # Procedimiento 2 — Análisis de dependencias
        self._add_heading('Procedimiento 2: Análisis de Composición de Software (SCA)', level=3)
        self._add_table(
            ['Campo', 'Detalle'],
            [
                ['Objetivo', 'Detectar dependencias de terceros con vulnerabilidades conocidas (CVEs)'],
                ['Norma ISO', 'ISO 25040 — Fiabilidad; ISO 14764 — Mantenimiento Preventivo'],
                ['Qué se busca', 'Dependencias con CVEs publicados en la base de datos OSV/NVD'],
                ['Cómo se obtiene', 'Análisis de requirements.txt, package.json, poetry.lock, Pipfile.lock, yarn.lock'],
                ['Fuente de datos', 'Google OSV API (api.osv.dev) — base de datos pública de vulnerabilidades'],
                ['Herramienta', 'AuditLens SCA Engine + OSV API'],
                ['Resultado', 'Lista de dependencias vulnerables con CVE, severidad y recomendación de actualización'],
                ['Responsable', 'Auditor Técnico de Software'],
            ]
        )

        # Procedimiento 3 — Cobertura de pruebas
        self._add_heading('Procedimiento 3: Revisión de Cobertura de Pruebas', level=3)
        self._add_table(
            ['Campo', 'Detalle'],
            [
                ['Objetivo', 'Evaluar la existencia y calidad de las pruebas de software del sistema'],
                ['Norma ISO', 'ISO 12207 — Verificación y Validación; ISO 25040 — Fiabilidad'],
                ['Qué se busca', 'Archivos de prueba, tipos de pruebas (unitarias, integración, seguridad), ratio de cobertura'],
                ['Cómo se obtiene', 'Análisis automático del repositorio en busca de archivos test_*.py, *.test.ts, *.spec.js, etc.'],
                ['Herramienta', 'AuditLens Test Coverage Analyzer'],
                ['Resultado', 'Ratio de cobertura estimado, lista de archivos sin pruebas, brechas identificadas'],
                ['Responsable', 'Auditor Técnico de Software'],
            ]
        )

        # Plantilla de registro de evidencia
        self._add_heading('Plantilla de Registro de Evidencia', level=3)
        self._add_paragraph(
            'La siguiente plantilla debe utilizarse para registrar cada pieza de evidencia '
            'recolectada durante la auditoría, asegurando trazabilidad e integridad.'
        )

        n_findings = len(findings)
        criticos = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        altos = sum(1 for f in findings if f.get('severity') == 'HIGH')

        self._add_table(
            ['Campo', 'Descripción', 'Valor registrado'],
            [
                ['ID Evidencia', 'Identificador único de la evidencia', 'AUD-2025-001'],
                ['Fecha de recolección', 'Fecha y hora de obtención', datetime.now().strftime('%d/%m/%Y %H:%M')],
                ['Tipo de evidencia', 'Código fuente / Dependencias / Pruebas / Documentación', 'Código fuente + Dependencias'],
                ['Sistema auditado', 'Nombre y versión del sistema', sistema],
                ['Módulo afectado', 'Módulo o componente específico', 'Todo el repositorio'],
                ['Total hallazgos', 'Número de hallazgos detectados', str(n_findings)],
                ['Hallazgos críticos', 'Hallazgos de severidad CRÍTICA', str(criticos)],
                ['Hallazgos altos', 'Hallazgos de severidad ALTA', str(altos)],
                ['Herramienta', 'Herramienta utilizada para recolección', 'AuditLens v0.3.0'],
                ['Auditor responsable', 'Nombre del auditor que recolectó la evidencia', '[Completar]'],
                ['Cadena de custodia', 'Ubicación de almacenamiento seguro', '[Completar ruta/repositorio]'],
                ['Integridad verificada', 'Hash SHA-256 del archivo de evidencia', '[Completar]'],
            ]
        )

    def add_test_strategies(self, findings: List[dict], test_analysis: Dict, sistema: str):
        """
        Sección 2.2 — Estrategias de Pruebas de Software
        Genera casos de prueba automáticos basados en los hallazgos encontrados.
        """
        self._add_heading('2.2 Diseño de Estrategias de Pruebas de Software', level=2)
        self._add_paragraph(
            'Se proponen los siguientes tipos de pruebas y casos de prueba representativos, '
            'diseñados a partir de los hallazgos identificados y alineados con los '
            'criterios de auditoría y los estándares ISO aplicables.'
        )

        # Tipos de pruebas propuestas
        self._add_heading('Tipos de Pruebas Propuestas', level=3)
        self._add_table(
            ['Tipo de Prueba', 'Descripción', 'Norma ISO', 'Prioridad'],
            [
                ['Pruebas de Seguridad (SAST)', 'Análisis estático automatizado del código fuente para detectar vulnerabilidades', 'ISO 25040 — Seguridad Funcional', 'ALTA'],
                ['Pruebas de Composición (SCA)', 'Verificación de dependencias contra base de datos de CVEs conocidos', 'ISO 14764 — Mantenimiento Preventivo', 'ALTA'],
                ['Pruebas de Flujo de Datos', 'Rastreo de datos de usuario desde entrada hasta sinks peligrosos', 'ISO 25040 — Integridad', 'ALTA'],
                ['Pruebas de Cobertura', 'Verificación de que el código cuenta con pruebas unitarias e integración', 'ISO 12207 — V&V', 'MEDIA'],
                ['Pruebas de Regresión', 'Verificación de que correcciones no introducen nuevas vulnerabilidades', 'ISO 12207 — Pruebas de sistema', 'MEDIA'],
                ['Pruebas de Configuración', 'Validación de variables de entorno, secretos y configuraciones seguras', 'ISO 25040 — Seguridad', 'ALTA'],
            ]
        )

        # Generar casos de prueba desde hallazgos reales
        self._add_heading('Casos de Prueba Derivados de Hallazgos', level=3)
        self._add_paragraph(
            f'Los siguientes casos de prueba fueron generados automáticamente a partir de '
            f'los {len(findings)} hallazgos detectados en el sistema {sistema}.'
        )

        # Map rule_id to test case template
        test_case_templates = {
            'SEC-01': {
                'caso': 'Verificar ausencia de secretos hardcodeados',
                'descripcion': 'Escanear todo el repositorio en busca de contraseñas, tokens y API keys en texto plano',
                'precondicion': 'Acceso de lectura al repositorio de código fuente',
                'pasos': 'Ejecutar: auditlens scan . --severity HIGH --no-sca',
                'resultado_esperado': 'Cero hallazgos SEC-01 en el código fuente',
                'resultado_obtenido': '[Completar tras ejecución]',
                'iso': 'ISO 25040 — Confidencialidad',
            },
            'INJ-01': {
                'caso': 'Verificar ausencia de inyección SQL',
                'descripcion': 'Detectar construcción dinámica de queries SQL con datos de usuario sin parametrizar',
                'precondicion': 'Acceso al código fuente del módulo de base de datos',
                'pasos': 'Revisar todas las llamadas a execute(), query(), raw() con formato de string',
                'resultado_esperado': 'Todas las consultas SQL usan parámetros vinculados (prepared statements)',
                'resultado_obtenido': '[Completar tras revisión]',
                'iso': 'ISO 25040 — Integridad; ISO 12207 — Codificación',
            },
            'INJ-02': {
                'caso': 'Verificar ausencia de inyección de comandos',
                'descripcion': 'Detectar ejecución de comandos shell con datos de usuario sin sanitizar',
                'precondicion': 'Acceso al código que llama a subprocess, os.system o equivalentes',
                'pasos': 'Buscar os.system(), subprocess.run() con shell=True o concatenación de strings',
                'resultado_esperado': 'Ningún comando shell construido con datos de usuario',
                'resultado_obtenido': '[Completar tras revisión]',
                'iso': 'ISO 25040 — Seguridad; ISO 12207 — Codificación',
            },
            'TAINT-01': {
                'caso': 'Verificar sanitización de flujos de datos',
                'descripcion': 'Comprobar que datos de entrada de usuario son sanitizados antes de llegar a sinks peligrosos',
                'precondicion': 'Acceso al código de controladores/vistas que reciben input externo',
                'pasos': 'Ejecutar: auditlens scan . --interprocedural --no-sca',
                'resultado_esperado': 'Cero hallazgos TAINT-01/TAINT-02 en el análisis',
                'resultado_obtenido': '[Completar tras ejecución]',
                'iso': 'ISO 25040 — Integridad; CWE-89, CWE-79',
            },
            'DESER-01': {
                'caso': 'Verificar deserialización segura',
                'descripcion': 'Comprobar que no se usa pickle.loads() u otros mecanismos inseguros con datos externos',
                'precondicion': 'Acceso al código que maneja datos serializados',
                'pasos': 'Buscar uso de pickle, marshal, yaml.load() sin SafeLoader en rutas de datos de usuario',
                'resultado_esperado': 'Solo se usa JSON o SafeLoader para deserialización de datos externos',
                'resultado_obtenido': '[Completar tras revisión]',
                'iso': 'ISO 25040 — Seguridad; ISO 12207 — Integración',
            },
            'CONF-04': {
                'caso': 'Verificar configuración de producción segura',
                'descripcion': 'Comprobar que DEBUG=False y otras configuraciones de seguridad están correctas en producción',
                'precondicion': 'Acceso al archivo de configuración del entorno de producción',
                'pasos': 'Revisar variables de entorno y archivos de configuración del sistema desplegado',
                'resultado_esperado': 'DEBUG=False, SECRET_KEY desde variable de entorno, HTTPS habilitado',
                'resultado_obtenido': '[Completar tras revisión]',
                'iso': 'ISO 25040 — Seguridad; ISO 12207 — Gestión de Configuración',
            },
        }

        # Generate test cases for rules found in findings
        seen_rules = set()
        test_cases_generated = 0

        for finding in findings:
            rule_id = finding.get('rule_id', '')
            # Get base rule (strip version suffix)
            base_rule = '-'.join(rule_id.split('-')[:2]) if '-' in rule_id else rule_id

            if base_rule in seen_rules:
                continue
            seen_rules.add(base_rule)

            template = test_case_templates.get(base_rule) or test_case_templates.get(rule_id)
            if not template:
                continue

            test_cases_generated += 1
            file_short = '/'.join(finding.get('file', '').split('/')[-2:])

            self._add_heading(
                f'Caso de Prueba CP-{test_cases_generated:02d}: {template["caso"]}',
                level=3
            )
            self._add_table(
                ['Campo', 'Detalle'],
                [
                    ['ID Caso', f'CP-{test_cases_generated:02d}'],
                    ['Tipo', 'Prueba de Seguridad Automatizada'],
                    ['Regla relacionada', rule_id],
                    ['Hallazgo de referencia', f'{file_short} línea {finding.get("line", "")}'],
                    ['Descripción', template['descripcion']],
                    ['Pre-condición', template['precondicion']],
                    ['Pasos de ejecución', template['pasos']],
                    ['Resultado esperado', template['resultado_esperado']],
                    ['Resultado obtenido', template['resultado_obtenido']],
                    ['Estado', '[ ] Pasado  [ ] Fallido  [ ] No ejecutado'],
                    ['Norma ISO', template['iso']],
                    ['Responsable', 'Auditor Técnico de Software'],
                    ['Fecha ejecución', '[Completar]'],
                ]
            )

        # Always add a coverage test case
        test_cases_generated += 1
        coverage = test_analysis.get('ratio_cobertura_estimado', 0)
        self._add_heading(
            f'Caso de Prueba CP-{test_cases_generated:02d}: Verificar Cobertura de Pruebas',
            level=3
        )
        self._add_table(
            ['Campo', 'Detalle'],
            [
                ['ID Caso', f'CP-{test_cases_generated:02d}'],
                ['Tipo', 'Prueba de Proceso (ISO 12207 V&V)'],
                ['Descripción', 'Verificar que el sistema cuenta con cobertura de pruebas suficiente'],
                ['Pre-condición', 'Acceso al repositorio de código fuente'],
                ['Pasos de ejecución', 'Ejecutar: auditlens plan . y revisar sección de Cobertura de Pruebas'],
                ['Resultado esperado', 'Ratio de cobertura ≥ 70% con pruebas unitarias, de seguridad e integración'],
                ['Resultado obtenido', f'Cobertura actual estimada: {coverage}%'],
                ['Estado', '[ ] Pasado  [ ] Fallido  [ ] No ejecutado'],
                ['Norma ISO', 'ISO 12207 — Verificación y Validación; ISO 25040 — Fiabilidad'],
                ['Responsable', 'Auditor Técnico de Software'],
                ['Fecha ejecución', '[Completar]'],
            ]
        )

    def add_evidence_validity(self, empresa: str, sistema: str, fecha: str):
        """
        Sección 2.3 — Criterios para la Validez y Confiabilidad de la Evidencia
        """
        self._add_heading('2.3 Criterios para la Validez y Confiabilidad de la Evidencia', level=2)
        self._add_paragraph(
            'Los siguientes criterios garantizan que la evidencia recolectada sea suficiente, '
            'competente y relevante para soportar los hallazgos de la auditoría, '
            'asegurando su integridad y trazabilidad.'
        )

        self._add_heading('Criterios de Validez', level=3)
        self._add_table(
            ['Criterio', 'Descripción', 'Verificación'],
            [
                ['Suficiencia', 'La evidencia es suficiente en cantidad para soportar los hallazgos', 'Mínimo 1 evidencia por hallazgo crítico/alto'],
                ['Competencia', 'La evidencia proviene de fuentes confiables y fue obtenida con herramientas validadas', 'AuditLens genera evidencia reproducible y verificable'],
                ['Relevancia', 'La evidencia está directamente relacionada con los criterios de auditoría evaluados', 'Cada hallazgo referencia la norma ISO aplicable'],
                ['Oportunidad', 'La evidencia fue recolectada en el momento adecuado y refleja el estado actual del sistema', f'Fecha de recolección: {fecha}'],
                ['Objetividad', 'La evidencia es objetiva y no está influenciada por sesgos del auditor', 'Análisis automatizado con AuditLens elimina sesgos subjetivos'],
            ]
        )

        self._add_heading('Cadena de Custodia', level=3)
        self._add_paragraph(
            'Para garantizar la integridad de la evidencia digital recolectada, '
            'se deben seguir los siguientes procedimientos:'
        )
        steps = [
            f'Todos los reportes generados por AuditLens deben almacenarse con fecha y hora del sistema ({fecha})',
            'Los archivos SARIF, JSON y DOCX deben firmarse digitalmente o calcular su hash SHA-256',
            'El acceso a la evidencia debe restringirse al equipo auditor autorizado',
            'Cualquier modificación a la evidencia debe quedar registrada con fecha, responsable y motivo',
            'La evidencia de primera mano (resultados directos de AuditLens) tiene prioridad sobre evidencia de segunda mano',
            'Las capturas de pantalla del dashboard deben incluir fecha, hora y URL visible',
        ]
        for step in steps:
            p = self.doc.add_paragraph(style='List Bullet')
            p.add_run(step)

        self._add_heading('Registro de Integridad de Evidencia', level=3)
        self._add_table(
            ['Archivo de Evidencia', 'Tipo', 'Fecha', 'Hash SHA-256', 'Responsable'],
            [
                [f'informe_auditoria.docx', 'Informe Word completo', fecha, '[Calcular con: shasum -a 256]', '[Auditor]'],
                [f'audit_results.sarif', 'Reporte SARIF', fecha, '[Calcular con: shasum -a 256]', '[Auditor]'],
                [f'audit_results.json', 'Reporte JSON', fecha, '[Calcular con: shasum -a 256]', '[Auditor]'],
                [f'plan_auditoria.docx', 'Plan de auditoría', fecha, '[Calcular con: shasum -a 256]', '[Auditor]'],
            ]
        )

    def add_audit_closure(self, findings: List[dict], sistema: str, empresa: str):
        """
        Sección 5.2 — Criterios para el Cierre de la Auditoría + Lecciones Aprendidas
        """
        self._add_heading('9.2 Criterios para el Cierre de la Auditoría', level=2)

        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            sev = f.get('severity', 'LOW').upper()
            if sev in counts:
                counts[sev] += 1

        self._add_paragraph(
            f'La auditoría del sistema {sistema} de la empresa {empresa} se considerará '
            f'oficialmente cerrada cuando se cumplan los siguientes criterios:'
        )

        self._add_heading('Condiciones de Cierre', level=3)
        self._add_table(
            ['#', 'Condición de Cierre', 'Estado actual', 'Responsable'],
            [
                ['1', f'Todos los {counts["CRITICAL"]} hallazgos CRÍTICOS han sido corregidos y verificados',
                 f'Pendiente ({counts["CRITICAL"]} hallazgos)', 'Auditor Líder'],
                ['2', f'Al menos el 80% de los {counts["HIGH"]} hallazgos ALTOS han sido resueltos',
                 f'Pendiente ({counts["HIGH"]} hallazgos)', 'Auditor Técnico'],
                ['3', 'Se ha ejecutado un re-escaneo con AuditLens y el baseline actualizado muestra cero hallazgos nuevos',
                 'Pendiente', 'Auditor Técnico'],
                ['4', 'El equipo de desarrollo ha aceptado formalmente el plan de acción para hallazgos pendientes',
                 'Pendiente', 'Auditor Líder'],
                ['5', 'Todos los KPIs del plan de seguimiento han sido definidos y asignados a responsables',
                 'Completado (ver sección 9)', 'Auditor Líder'],
                ['6', 'El informe final de auditoría ha sido revisado y aprobado por el cliente',
                 'Pendiente', 'Auditor Líder'],
            ]
        )

        self._add_heading('Proceso de Cierre Formal', level=3)
        steps = [
            'El Auditor Líder convoca reunión de cierre con el equipo de desarrollo y stakeholders',
            'Se revisan todos los hallazgos críticos y altos con las correcciones implementadas',
            'Se ejecuta un re-escaneo final: auditlens scan . --diff-baseline .auditlens-baseline.json',
            'Si hay hallazgos pendientes, se firma un plan de acción con plazos comprometidos',
            'Se entrega el informe final firmado a la empresa auditada',
            'Se programa la primera revisión de seguimiento (30 días después del cierre)',
        ]
        for i, step in enumerate(steps, 1):
            p = self.doc.add_paragraph(style='List Number')
            p.add_run(step)

        # Lecciones aprendidas
        self._add_heading('Lecciones Aprendidas', level=2)
        self._add_paragraph(
            'El siguiente registro documenta los aprendizajes del proceso de auditoría '
            'para mejorar futuras evaluaciones, conforme a la mejora continua de ISO 12207.'
        )

        self._add_table(
            ['Categoría', 'Observación', 'Acción para futuras auditorías'],
            [
                ['Herramientas', 'AuditLens automatizó el 100% del análisis estático, reduciendo tiempo de ejecución',
                 'Mantener AuditLens actualizado e incorporar nuevas reglas según el contexto del proyecto'],
                ['Cobertura de pruebas', 'La falta de pruebas automatizadas dificultó la validación de correcciones',
                 'Exigir cobertura mínima de 70% como criterio de aceptación en futuras auditorías'],
                ['Comunicación', 'La clasificación Condición/Criterio/Causa/Efecto facilitó la comprensión de hallazgos',
                 'Mantener este formato en todos los informes de auditoría'],
                ['ISO Standards', 'El mapeo a ISO 25040/12207/14764 proporcionó contexto normativo claro',
                 'Ampliar el mapeo a ISO 27001 e ISO 29119 en futuras auditorías'],
                ['Alcance', 'El análisis automatizado cubrió todo el código fuente sin exclusiones manuales',
                 'Ajustar exclude_paths en .auditlens.yaml para proyectos con código legado extenso'],
                ['Seguimiento', 'El uso de baseline permite comparar hallazgos entre versiones del sistema',
                 'Establecer baseline al inicio de cada sprint y ejecutar scan al finalizar'],
            ]
        )

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
    exporter.add_table_of_contents(findings_count=len(findings))

    # ── 3. Resumen Ejecutivo ──────────────────────────────────────────────────
    exporter.add_executive_summary(findings, gap_analysis, test_analysis, empresa, sistema)

    # ── 4. Introducción (alcance + objetivos SMART) ───────────────────────────
    exporter.add_introduction(plan)

    # ── 5. Metodología ────────────────────────────────────────────────────────
    exporter.add_methodology(plan)

    # ── 6. Ejecución y Recolección de Evidencia (secciones 2.x del rubric) ───
    exporter._add_heading('4. Ejecución y Recolección de Evidencia', level=1)
    exporter._add_paragraph(
        'Esta sección documenta los procedimientos de recolección de evidencia, '
        'las estrategias de pruebas diseñadas y los criterios de validez aplicados '
        'durante la ejecución de la auditoría, conforme a ISO 25040, ISO 12207 e ISO 14764.'
    )
    exporter.add_evidence_collection(findings, project_info, sistema)
    exporter.add_test_strategies(findings, test_analysis, sistema)
    exporter.add_evidence_validity(empresa, sistema, fecha)

    # ── 7. Hallazgos ─────────────────────────────────────────────────────────
    exporter.add_findings(enriched_findings)

    # ── 8. Análisis de Brechas ISO ────────────────────────────────────────────
    exporter.add_iso_gap_analysis(gap_analysis)

    # ── 9. Análisis de Cobertura de Pruebas ──────────────────────────────────
    exporter.add_test_coverage(test_analysis)

    # ── 10. Conclusiones ──────────────────────────────────────────────────────
    exporter.add_conclusions(findings, gap_analysis, sistema, empresa)

    # ── 11. Recomendaciones + Seguimiento + Cierre ────────────────────────────
    exporter._add_heading('9. Recomendaciones y Seguimiento', level=1)
    exporter.add_recommendations(findings)
    exporter.add_followup_plan(kpis)
    exporter.add_audit_closure(findings, sistema, empresa)

    # ── 12. Anexos ────────────────────────────────────────────────────────────
    exporter.add_annexes(project_info, test_analysis)

    exporter.save(output_path)
    return output_path
