import time
import re
import os
import subprocess
import threading

# Regex para detectar errores típicos de Swift/Xcode
# Ej: "Fatal error: Index out of range: file /path/to/File.swift, line 42"
SWIFT_ERROR_REGEX = re.compile(r'(?:Fatal error|Exception|Error):.*?(?:file\s+)?([/\w\.-]+?\.(?:swift|py))(?:,|\s+line)?\s+(\d+)', re.IGNORECASE)

def _find_file_in_project(filename, search_path="."):
    """Busca el archivo en el proyecto local si solo tenemos el nombre."""
    if os.path.isabs(filename) and os.path.exists(filename):
        return filename
        
    base_name = os.path.basename(filename)
    for root, _, files in os.walk(search_path):
        if base_name in files:
            return os.path.join(root, base_name)
    return None

def _print_forensic_report(log_line, filepath, line_num):
    """Imprime el análisis post-mortem sacado del log."""
    print("\n" + "=" * 80)
    print("\033[91m💥 [AuditLens] ¡ERROR EN TIEMPO DE EJECUCIÓN DETECTADO EN LOGS! 💥\033[0m")
    print("=" * 80)
    
    print(f"\n\033[1m📜 Mensaje del Log:\033[0m")
    print(f"   \033[93m{log_line.strip()}\033[0m")
    
    print(f"\n\033[1m📍 Ubicación Identificada:\033[0m")
    print(f"   Archivo:  \033[96m{filepath}\033[0m")
    print(f"   Línea:    \033[96m{line_num}\033[0m")
    
    # Intentar leer el código fuente
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # line_num es 1-indexed
            idx = int(line_num) - 1
            if 0 <= idx < len(lines):
                print(f"\n\033[1m💻 Contexto del Código:\033[0m")
                # Mostrar contexto (-1 y +1 línea)
                if idx > 0: print(f"   {idx}: {lines[idx-1].rstrip()}")
                print(f"   \033[91m> {idx+1}: {lines[idx].rstrip()}\033[0m")
                if idx < len(lines) - 1: print(f"   {idx+2}: {lines[idx+1].rstrip()}")
    except Exception as e:
        print(f"\n   \033[90m(No se pudo leer el código fuente: {e})\033[0m")
        
    print("\n" + "=" * 80 + "\n")

def _process_log_line(line):
    """Busca firmas de error en la línea y correlaciona con el código."""
    match = SWIFT_ERROR_REGEX.search(line)
    if match:
        filename = match.group(1)
        line_num = match.group(2)
        
        # Correlacionar
        actual_path = _find_file_in_project(filename)
        if actual_path:
            _print_forensic_report(line, actual_path, line_num)
        else:
            print(f"\033[93m[AuditLens Watcher]\033[0m Error detectado, pero no se encontró el archivo '{filename}' localmente.")

def watch_log_file(filepath):
    """Hace un 'tail -f' de un archivo de texto en Python."""
    if not os.path.exists(filepath):
        print(f"\033[91m[ERROR]\033[0m El archivo log '{filepath}' no existe.")
        return

    print(f"\033[94m[AuditLens Watcher]\033[0m Escuchando eventos en {filepath}...\n")
    with open(filepath, 'r') as f:
        # Ir al final del archivo
        f.seek(0, 2)
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                _process_log_line(line)
        except KeyboardInterrupt:
            print("\n\033[92m[AuditLens Watcher]\033[0m Escucha finalizada.")

def watch_xcode_simulator():
    """Se conecta al log stream del emulador activo de iOS usando xcrun."""
    print(f"\033[94m[AuditLens Xcode Watcher]\033[0m Conectando a los logs del Simulador de iOS...")
    print("Abre tu app EcoAlerta en el emulador. Detectaremos errores nativos en tiempo real.\n")
    
    # Comando nativo de mac: xcrun simctl spawn booted log stream
    cmd = ["xcrun", "simctl", "spawn", "booted", "log", "stream", "--level", "error"]
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in iter(process.stdout.readline, ''):
            _process_log_line(line)
    except FileNotFoundError:
        print("\033[91m[ERROR]\033[0m No se encontraron las herramientas de Xcode (xcrun). ¿Estás en un Mac con Xcode instalado?")
    except KeyboardInterrupt:
        if process:
            process.terminate()
        print("\n\033[92m[AuditLens Xcode Watcher]\033[0m Escucha finalizada.")
