import os
import argparse
from tree_sitter import Language, Parser
from .rules_engine import RulesEngine
from .taint_analyzer import TaintAnalyzer
from .sca_engine import SCAEngine

def load_parser(ext):
    try:
        if ext == '.py':
            import tree_sitter_python as ts
            lang = Language(ts.language())
        elif ext == '.js' or ext == '.jsx':
            import tree_sitter_javascript as ts
            lang = Language(ts.language())
        elif ext == '.swift':
            import tree_sitter_swift as ts
            lang = Language(ts.language())
        else:
            return None
            
        parser = Parser(lang)
        return parser
    except ImportError:
        return None

def analyze_file(file_path, rules_engine, taint_analyzer, sarif_exporter=None, pdf_exporter=None):
    ext = os.path.splitext(file_path)[1].lower()
    
    # 1. Obtener reglas aplicables para este lenguaje
    rules = rules_engine.get_rules_for_language(ext)
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code_lines = f.readlines()
            code_text = "".join(code_lines)
    except Exception:
        return
        
    findings = []
    
    # 2. Análisis basado en Regex / AST desde el YAML
    # Para el MVP híbrido, las reglas YAML se aplican sobre las líneas,
    # pero usamos Tree-sitter para validar que sea código real (opcionalmente)
    for rule in rules:
        for i, line in enumerate(code_lines):
            if rule.match_text(line):
                finding = {
                    "rule_id": rule.id,
                    "name": rule.name,
                    "description": rule.description,
                    "file": file_path,
                    "line": i + 1,
                    "severity": rule.severity,
                    "compliance": rule.compliance
                }
                findings.append(finding)

    # 3. Taint Analysis (Flujo de datos) - MVP Python y JS/Swift básico
    taint_findings = taint_analyzer.analyze(file_path, code_lines)
    findings.extend(taint_findings)

    # 4. Parsing Estructural con Tree-sitter (Opcional, para análisis más profundos)
    parser = load_parser(ext)
    if parser:
        tree = parser.parse(code_text.encode('utf-8'))
        # Aquí se podrían recorrer los nodos del AST generado por Tree-sitter
        # (root_node = tree.root_node) para auditorías de estructura de datos avanzadas.

    # Imprimir o exportar hallazgos
    for finding in findings:
        color = "\033[91m" if finding['severity'] == "CRITICAL" or finding['severity'] == "HIGH" else "\033[93m"
        print(f"{color}[{finding['rule_id']}] {finding['file']}:{finding['line']} - {finding['name']}\033[0m")
        if finding.get('compliance'):
            print(f"   \033[90mCumplimiento: {', '.join(finding['compliance'])}\033[0m")
            
        if sarif_exporter:
            sarif_exporter.add_finding(finding)
        if pdf_exporter:
            pdf_exporter.add_finding(finding)

def run_static_analysis(path, export_sarif=False, export_pdf=False):
    print(f"\033[94m[AuditLens Enterprise]\033[0m Iniciando escaneo en: {path}...\n")
    
    rules_engine = RulesEngine()
    taint_analyzer = TaintAnalyzer()
    sca_engine = SCAEngine()
    
    sarif_exporter = None
    if export_sarif:
        from .sarif_exporter import SarifExporter
        sarif_exporter = SarifExporter()
        
    pdf_exporter = None
    if export_pdf:
        from .pdf_exporter import PdfExporter
        pdf_exporter = PdfExporter()

    print("\033[94m[AuditLens Enterprise]\033[0m Ejecutando Analisis de Composicion de Software (SCA)...")
    sca_findings = sca_engine.analyze_directory(path)
    for finding in sca_findings:
        color = "\033[91m"
        print(f"{color}[{finding['rule_id']}] {finding['file']}:{finding['line']} - {finding['name']}\033[0m")
        if finding.get('compliance'):
            print(f"   \033[90mCumplimiento: {', '.join(finding['compliance'])}\033[0m")
        if sarif_exporter:
            sarif_exporter.add_finding(finding)
        if pdf_exporter:
            pdf_exporter.add_finding(finding)

    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        if ext in ['.py', '.js', '.jsx', '.swift']:
            analyze_file(path, rules_engine, taint_analyzer, sarif_exporter, pdf_exporter)
    elif os.path.isdir(path):
        exclude_dirs = {'venv', 'env', '.env', '.git', '__pycache__', 'node_modules', 'build'}
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in ['.py', '.js', '.jsx', '.swift']:
                    analyze_file(os.path.join(root, file), rules_engine, taint_analyzer, sarif_exporter, pdf_exporter)
    else:
        print("\033[91m[ERROR]\033[0m La ruta especificada no existe.")
        
    print(f"\n\033[92m[AuditLens Enterprise]\033[0m Escaneo finalizado.")
    
    if sarif_exporter:
        sarif_exporter.export()
        
    if pdf_exporter:
        pdf_exporter.generate_report()
