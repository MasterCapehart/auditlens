import ast
import os

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, filepath):
        self.diagnostics = []
        self.filepath = filepath

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(x in var_name for x in ['password', 'secret', 'token', 'api_key']):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.diagnostics.append(
                            f"\033[91m[SAST WARNING]\033[0m {self.filepath}:{node.lineno} - Se detectó un posible secreto hardcodeado en la variable '{target.id}'."
                        )
        self.generic_visit(node)

class ComplianceVisitor(ast.NodeVisitor):
    def __init__(self, filepath):
        self.diagnostics = []
        self.filepath = filepath

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if 'rut' in var_name:
                    self.diagnostics.append(
                        f"\033[93m[COMPLIANCE INFO]\033[0m {self.filepath}:{node.lineno} - Manejo de dato sensible (RUT) detectado (Ley N° 19.628). Asegúrate de ofuscar/encriptar este valor."
                    )
        self.generic_visit(node)

def analyze_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
        
        tree = ast.parse(code)
        
        sec_visitor = SecurityVisitor(filepath)
        sec_visitor.visit(tree)
        for diag in sec_visitor.diagnostics:
            print(diag)

        comp_visitor = ComplianceVisitor(filepath)
        comp_visitor.visit(tree)
        for diag in comp_visitor.diagnostics:
            print(diag)
            
    except SyntaxError:
        print(f"\033[91m[ERROR]\033[0m Error de sintaxis en {filepath}. No se pudo analizar.")
    except Exception as e:
        pass # Ignorar archivos binarios u otros errores de lectura

def run_static_analysis(path):
    print(f"\033[94m[AuditLens]\033[0m Iniciando escaneo estático en: {path}...\n")
    if os.path.isfile(path):
        if path.endswith('.py'):
            analyze_file(path)
    elif os.path.isdir(path):
        exclude_dirs = {'venv', 'env', '.env', '.git', '__pycache__', 'node_modules'}
        for root, dirs, files in os.walk(path):
            # Ignorar carpetas excluidas modificando la lista dirs in-place
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if file.endswith('.py'):
                    analyze_file(os.path.join(root, file))
    else:
        print("La ruta especificada no existe.")
    
    print("\n\033[92m[AuditLens]\033[0m Escaneo finalizado.")
