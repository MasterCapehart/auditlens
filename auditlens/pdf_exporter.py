"""
AuditLens PDF Report Exporter.

Changes vs original:
- CQ-05: switched from latin-1 encoding to DejaVu (built-in Unicode font in fpdf2)
  so Spanish characters (ñ, á, é, ú), accented paths, and emoji display correctly.
"""

import os
from datetime import datetime
from fpdf import FPDF


# fpdf2 ships DejaVuSans as a built-in Unicode font — no external file needed.
_FONT_FAMILY = 'DejaVu'
_FONT_BOLD = 'DejaVuBold'


class PdfExporter(FPDF):
    def __init__(self):
        super().__init__()
        self.findings: list = []
        self.set_auto_page_break(auto=True, margin=15)
        self.stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        # Register DejaVu Unicode fonts (built into fpdf2)
        self.add_font('DejaVu', '', 'DejaVuSansCondensed.ttf', uni=True)
        self.add_font('DejaVu', 'B', 'DejaVuSansCondensed-Bold.ttf', uni=True)
        self.add_font('DejaVuBold', '', 'DejaVuSansCondensed-Bold.ttf', uni=True)

    def add_finding(self, finding: dict):
        self.findings.append(finding)
        sev = finding.get('severity', 'LOW').upper()
        if sev in self.stats:
            self.stats[sev] += 1

    def _safe(self, text) -> str:
        """CQ-05 FIX: return str as-is — DejaVu handles full Unicode."""
        return str(text)

    def header(self):
        self.set_font('DejaVu', 'B', 15)
        self.cell(0, 10, 'AuditLens — Code Audit Report', border=0, new_x='LMARGIN', new_y='NEXT', align='C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('DejaVu', '', 8)
        self.cell(0, 10, f'Page {self.page_no()}', border=0, align='C')

    def generate_report(self, output_path: str = 'audit_report.pdf'):
        self.add_page()

        # Date
        self.set_font('DejaVu', '', 10)
        current_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.cell(0, 10, f'Generated: {current_date}', border=0, new_x='LMARGIN', new_y='NEXT', align='R')
        self.ln(5)

        # ── Executive Summary ─────────────────────────────────────────────────
        self.set_font('DejaVuBold', '', 14)
        self.cell(0, 10, '1. Executive Summary', border=0, new_x='LMARGIN', new_y='NEXT')

        self.set_font('DejaVu', '', 12)
        total = sum(self.stats.values())
        self.cell(0, 10, f'Total Findings: {total}', border=0, new_x='LMARGIN', new_y='NEXT')

        # Severity table
        self.set_fill_color(240, 240, 240)
        self.set_font('DejaVuBold', '', 11)
        self.cell(50, 10, 'Severity', border=1, align='C', fill=True)
        self.cell(40, 10, 'Count', border=1, new_x='LMARGIN', new_y='NEXT', align='C', fill=True)

        colors = {
            'CRITICAL': (220, 0, 0),
            'HIGH': (255, 102, 0),
            'MEDIUM': (204, 153, 0),
            'LOW': (0, 102, 204),
        }
        self.set_font('DejaVu', '', 11)
        for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            self.set_text_color(*colors[sev])
            self.cell(50, 10, sev, border=1, align='C')
            self.set_text_color(0, 0, 0)
            self.cell(40, 10, str(self.stats[sev]), border=1, new_x='LMARGIN', new_y='NEXT', align='C')

        self.ln(10)

        # ── Findings Detail ───────────────────────────────────────────────────
        self.set_font('DejaVuBold', '', 14)
        self.cell(0, 10, '2. Finding Details', border=0, new_x='LMARGIN', new_y='NEXT')
        self.ln(5)

        if not self.findings:
            self.set_font('DejaVu', '', 12)
            self.set_text_color(0, 153, 0)
            self.cell(0, 10, 'No vulnerabilities found.', border=0, new_x='LMARGIN', new_y='NEXT')
            self.set_text_color(0, 0, 0)
        else:
            for idx, finding in enumerate(self.findings, 1):
                sev = finding.get('severity', 'LOW').upper()
                self.set_text_color(*colors.get(sev, (0, 0, 0)))
                self.set_font('DejaVuBold', '', 12)
                header_text = self._safe(
                    f"Finding #{idx} [{sev}] — {finding.get('name', '')}"
                )
                self.multi_cell(0, 8, header_text, border=0)

                self.set_text_color(0, 0, 0)
                self.set_font('DejaVu', '', 10)

                self.multi_cell(0, 6, self._safe(f"Rule:        {finding.get('rule_id', '')}"), border=0)
                self.multi_cell(
                    0, 6,
                    self._safe(
                        f"Location:    {finding.get('file', '')} (line {finding.get('line', '')})"
                    ),
                    border=0,
                )
                self.multi_cell(
                    0, 6,
                    self._safe(f"Description: {finding.get('description', '')}"),
                    border=0,
                )
                if finding.get('compliance'):
                    comp = ', '.join(finding['compliance'])
                    self.multi_cell(0, 6, self._safe(f"Compliance:  {comp}"), border=0)

                self.ln(3)
                # Separator line
                self.line(self.get_x(), self.get_y(), self.get_x() + 180, self.get_y())
                self.ln(5)

        self.output(output_path)
        print(
            f"\n\033[92m[AuditLens]\033[0m PDF report saved: "
            f"\033[1m{os.path.abspath(output_path)}\033[0m"
        )
