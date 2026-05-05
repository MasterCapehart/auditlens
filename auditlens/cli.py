import argparse
import sys
from .analyzer import run_static_analysis
from .runner import run_script_with_hook
from .log_watcher import watch_log_file, watch_xcode_simulator

def main():
    parser = argparse.ArgumentParser(description="AuditLens CLI: Análisis Estático y Dinámico.")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # Comando Scan (SAST)
    scan_parser = subparsers.add_parser("scan", help="Ejecutar análisis estático (SAST) en un directorio o archivo.")
    scan_parser.add_argument("path", type=str, help="Ruta del directorio o archivo a analizar.")
    scan_parser.add_argument("--format", type=str, choices=["text", "sarif", "pdf"], default="text", help="Formato de salida del reporte (default: text).")

    # Comando Run (Post-Mortem)
    run_parser = subparsers.add_parser("run", help="Ejecutar un script de Python con inyección Post-Mortem.")
    run_parser.add_argument("script", type=str, help="Ruta del script de Python a ejecutar.")
    run_parser.add_argument("args", nargs=argparse.REMAINDER, help="Argumentos adicionales para tu script.")

    # Comando Watch (Log genérico)
    watch_parser = subparsers.add_parser("watch", help="Monitorear un archivo de log en tiempo real.")
    watch_parser.add_argument("logfile", type=str, help="Ruta del archivo .log a escuchar.")

    # Comando Watch Xcode (Específico iOS)
    xcode_parser = subparsers.add_parser("watch-xcode", help="Monitorear los logs del simulador de iOS activo.")

    args = parser.parse_args()

    if args.command == "scan":
        export_sarif = (args.format == "sarif")
        export_pdf = (args.format == "pdf")
        run_static_analysis(args.path, export_sarif, export_pdf)
    elif args.command == "run":
        run_script_with_hook(args.script, args.args)
    elif args.command == "watch":
        watch_log_file(args.logfile)
    elif args.command == "watch-xcode":
        watch_xcode_simulator()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
