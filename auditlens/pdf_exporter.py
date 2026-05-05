import os
from datetime import datetime
from fpdf import FPDF

class PdfExporter(FPDF):
    def __init__(self):
        super().__init__()
        self.findings = []
        self.set_auto_page_break(auto=True, margin=15)
        self.stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def add_finding(self, finding):
        self.findings.append(finding)
        severity = finding.get('severity', 'LOW').upper()
        if severity in self.stats:
            self.stats[severity] += 1

    def header(self):
        # Arial bold 15
        self.set_font('Helvetica', 'B', 15)
        # Título
        self.cell(0, 10, 'AuditLens Enterprise - Reporte de Auditoria de Codigo', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Pagina {self.page_no()}', 0, 0, 'C')

    def generate_report(self, output_path="audit_report.pdf"):
        self.add_page()
        
        # Fecha del escaneo
        self.set_font('Helvetica', 'I', 10)
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cell(0, 10, f'Fecha de generacion: {current_date}', 0, 1, 'R')
        self.ln(5)

        # Resumen Estadístico
        self.set_font('Helvetica', 'B', 14)
        self.cell(0, 10, '1. Resumen Ejecutivo', 0, 1)
        
        self.set_font('Helvetica', '', 12)
        total = sum(self.stats.values())
        self.cell(0, 10, f'Total de Vulnerabilidades Encontradas: {total}', 0, 1)
        
        # Tabla de severidades
        self.set_fill_color(240, 240, 240)
        self.cell(40, 10, 'Severidad', 1, 0, 'C', fill=True)
        self.cell(40, 10, 'Cantidad', 1, 1, 'C', fill=True)
        
        colors = {
            "CRITICAL": (255, 0, 0),    # Red
            "HIGH": (255, 102, 0),      # Orange
            "MEDIUM": (255, 204, 0),    # Yellow
            "LOW": (0, 102, 204)        # Blue
        }

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            self.set_text_color(*colors[sev])
            self.cell(40, 10, sev, 1, 0, 'C')
            self.set_text_color(0, 0, 0)
            self.cell(40, 10, str(self.stats[sev]), 1, 1, 'C')

        self.ln(10)

        # Detalle de Hallazgos
        self.set_font('Helvetica', 'B', 14)
        self.cell(0, 10, '2. Detalle de Hallazgos', 0, 1)
        self.ln(5)

        if not self.findings:
            self.set_font('Helvetica', 'I', 12)
            self.cell(0, 10, 'No se encontraron vulnerabilidades en el codigo escaneado.', 0, 1)
        else:
            for idx, f in enumerate(self.findings, 1):
                sev = f.get('severity', 'LOW').upper()
                self.set_text_color(*colors.get(sev, (0,0,0)))
                self.set_font('Helvetica', 'B', 12)
                self.cell(0, 10, f"Hallazgo #{idx} [{sev}] - {f.get('name', '')}", 0, 1)
                
                self.set_text_color(0, 0, 0)
                self.set_font('Helvetica', '', 10)
                
                # Regla y Archivo
                self.write(6, f"Regla: {f.get('rule_id', '')}\n")
                self.write(6, f"Archivo: {f.get('file', '')} (Linea: {f.get('line', '')})\n")
                
                # Descripción
                self.write(6, f"Descripcion: {f.get('description', '')}\n")
                
                # Cumplimiento
                if f.get('compliance'):
                    comp_text = ", ".join(f['compliance'])
                    self.write(6, f"Matriz de Cumplimiento: {comp_text}\n")
                
                self.ln(5)
                # Línea separadora
                self.line(self.get_x(), self.get_y(), self.get_x() + 180, self.get_y())
                self.ln(5)

        self.output(output_path)
        print(f"\n\033[92m[DevSecOps]\033[0m Reporte PDF exportado con éxito a: \033[1m{os.path.abspath(output_path)}\033[0m")
