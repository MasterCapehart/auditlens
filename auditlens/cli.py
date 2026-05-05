import argparse
import sys
from .analyzer import run_static_analysis
from .runner import run_script_with_hook

def main():
    parser = argparse.ArgumentParser(description="AuditLens CLI: Análisis Estático y Dinámico.")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # Comando Scan (SAST)
    scan_parser = subparsers.add_parser("scan", help="Ejecutar análisis estático (SAST) en un directorio o archivo.")
    scan_parser.add_argument("path", type=str, help="Ruta del directorio o archivo a analizar.")

    # Comando Run (Post-Mortem)
    run_parser = subparsers.add_parser("run", help="Ejecutar un script de Python con inyección Post-Mortem.")
    run_parser.add_argument("script", type=str, help="Ruta del script de Python a ejecutar.")
    run_parser.add_argument("args", nargs=argparse.REMAINDER, help="Argumentos adicionales para tu script.")

    args = parser.parse_args()

    if args.command == "scan":
        run_static_analysis(args.path)
    elif args.command == "run":
        run_script_with_hook(args.script, args.args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
