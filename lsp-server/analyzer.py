import ast
from lsprotocol.types import Diagnostic, Range, Position, DiagnosticSeverity

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.diagnostics = []

    def visit_Assign(self, node):
        # Regla 1: Detección de Hardcoded Secrets
        # Si asignamos a una variable que se llame 'password', 'secret', 'token', etc.
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(x in var_name for x in ['password', 'secret', 'token', 'api_key']):
                    # Revisar si el valor asignado es un string plano (hardcoded)
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.diagnostics.append(
                            Diagnostic(
                                range=Range(
                                    start=Position(line=node.lineno - 1, character=node.col_offset),
                                    end=Position(line=node.end_lineno - 1, character=node.end_col_offset)
                                ),
                                message=f"[AuditLens: SAST] Se detectó un posible secreto hardcodeado en la variable '{target.id}'.",
                                source="AuditLens SAST",
                                severity=DiagnosticSeverity.Warning
                            )
                        )
        self.generic_visit(node)

class ComplianceVisitor(ast.NodeVisitor):
    def __init__(self):
        self.diagnostics = []

    def visit_Assign(self, node):
        # Regla 2: Compliance Ley 19.628 (Manejo de RUT)
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if 'rut' in var_name:
                    # En la vida real, aquí revisaríamos si esta variable está siendo pasada por una función de hash.
                    # Para el MVP, advertimos sobre el almacenamiento de este dato sensible.
                    self.diagnostics.append(
                        Diagnostic(
                            range=Range(
                                start=Position(line=node.lineno - 1, character=node.col_offset),
                                end=Position(line=node.end_lineno - 1, character=node.end_col_offset)
                            ),
                            message=f"[AuditLens: Compliance] Manejo de dato sensible (RUT) detectado (Ley N° 19.628). Asegúrate de ofuscar o encriptar este valor si lo guardas en base de datos.",
                            source="AuditLens Compliance",
                            severity=DiagnosticSeverity.Information
                        )
                    )
        self.generic_visit(node)

def analyze_code_with_ast(code: str):
    diagnostics = []
    try:
        tree = ast.parse(code)
        
        # Ejecutar análisis de Seguridad
        sec_visitor = SecurityVisitor()
        sec_visitor.visit(tree)
        diagnostics.extend(sec_visitor.diagnostics)

        # Ejecutar análisis de Compliance
        comp_visitor = ComplianceVisitor()
        comp_visitor.visit(tree)
        diagnostics.extend(comp_visitor.diagnostics)
        
    except SyntaxError:
        # Si el código tiene un error de sintaxis, no podemos parsear el AST, ignoramos por ahora
        # ya que el propio linter nativo de Python se lo dirá al usuario.
        pass

    return diagnostics
