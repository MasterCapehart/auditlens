# Taint Analysis MVP para AuditLens
# Rastrea asignaciones de variables y su uso posterior en "sinks" peligrosos.

class TaintAnalyzer:
    def __init__(self):
        # source_patterns define qué variables se consideran "contaminadas" desde su nacimiento
        self.source_patterns = ['rut', 'password', 'token', 'secret']
        
        # sink_patterns define funciones críticas donde un dato contaminado no debería entrar en texto plano
        self.sink_patterns = ['print', 'db.execute', 'cursor.execute', 'fetch', 'requests.post', 'requests.get']
        
    def analyze(self, file_path, code_lines):
        """
        MVP: Análisis de Flujo de Datos Intra-procedural simple.
        Rastrea si una variable sensible se define y luego se usa en un sink en el mismo archivo.
        """
        findings = []
        tainted_vars = {} # var_name -> line_number_where_tainted
        
        for line_idx, line in enumerate(code_lines):
            line_num = line_idx + 1
            text = line.strip()
            
            # 1. Detectar Sources (Declaración de variables contaminadas)
            # Ej: rut = "1234" o const password = req.body
            for src in self.source_patterns:
                # Regla súper simplificada: Si la variable aparece antes de un '=' 
                if f"{src} =" in text or f"{src}=" in text or f"let {src} =" in text or f"const {src} =" in text:
                    tainted_vars[src] = line_num
            
            # 2. Detectar Sinks (Uso de variables en funciones peligrosas)
            for var_name, source_line in tainted_vars.items():
                # Si la línea actual contiene la variable PERO no es la línea de su propia declaración
                if var_name in text and line_num != source_line:
                    # ¿Está dentro de un Sink?
                    for sink in self.sink_patterns:
                        if f"{sink}(" in text or f"{sink} " in text:
                            finding = {
                                "rule_id": "TAINT-01",
                                "name": "Vulnerabilidad de Flujo de Datos (Taint)",
                                "description": f"La variable sensible '{var_name}' (declarada en línea {source_line}) fue enviada al sumidero inseguro '{sink}()' sin ofuscación.",
                                "file": file_path,
                                "line": line_num,
                                "severity": "CRITICAL",
                                "compliance": ["CWE-79", "CWE-89"]
                            }
                            findings.append(finding)
                            # Remove from tainted to avoid spamming the same variable
                            del tainted_vars[var_name]
                            break
                            
        return findings
