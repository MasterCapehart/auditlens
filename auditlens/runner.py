import sys
import traceback

def auditlens_excepthook(exc_type, exc_value, exc_traceback):
    """
    Inyector Post-Mortem para CLI.
    """
    tb_list = traceback.extract_tb(exc_traceback)
    last_frame = tb_list[-1]

    print("\n" + "=" * 80)
    print("\033[91m💥 [AuditLens] ¡CRASH DETECTADO! Diagnóstico Post-Mortem 💥\033[0m")
    print("=" * 80)
    
    print(f"\n\033[1m📍 Ubicación del fallo:\033[0m")
    print(f"   Archivo:  \033[93m{last_frame.filename}\033[0m")
    print(f"   Línea:    \033[93m{last_frame.lineno}\033[0m")
    print(f"   Función:  \033[93m{last_frame.name}\033[0m")
    
    print(f"\n\033[1m❌ Error Original:\033[0m")
    print(f"   \033[91m{exc_type.__name__}: {exc_value}\033[0m")
    
    print(f"\n\033[1m💻 Contexto del Código:\033[0m")
    print(f"   > \033[96m{last_frame.line}\033[0m")
    
    print("\n" + "=" * 80 + "\n")

    # Opcional: imprimir el traceback completo para el desarrollador
    # traceback.print_exception(exc_type, exc_value, exc_traceback)

def run_script_with_hook(script_path, extra_args):
    print(f"\033[94m[AuditLens]\033[0m Ejecutando {script_path} en modo inyección...\n")
    
    # Inyectamos nuestro hook
    sys.excepthook = auditlens_excepthook
    
    # Preparamos los argumentos como si se hubiera llamado directamente a python
    sys.argv = [script_path] + extra_args
    
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            code = compile(f.read(), script_path, 'exec')
            # Ejecutamos el código. Si falla, sys.excepthook lo atrapará.
            exec(code, {"__name__": "__main__"})
    except FileNotFoundError:
        print(f"\033[91m[ERROR]\033[0m No se encontró el script: {script_path}")
