"""
AuditLens — Malware / Backdoor Detector

Detecta patrones de malware, webshells, backdoors, y código ofuscado
en código fuente sin depender de la librería yara-python (usa regex).

Incluye reglas equivalentes para:
- PHP webshells (eval+base64, system(), shell_exec)
- Python backdoors (reverse shells, bind shells)
- Crypto miners (monero, xmrig, stratum+tcp)
- Ofuscación extrema (base64 chains, rot13, hex escape)
- Supply chain injection patterns
- Suspicious scheduled tasks / cron injections
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

# (pattern, rule_id, name, severity, description)
_RULES: List[Tuple[re.Pattern, str, str, str, str]] = [

    # PHP Webshells
    (re.compile(r'(?i)eval\s*\(\s*base64_decode\s*\('),
     'MAL-PHP-WEBSHELL-EVAL', 'PHP Webshell: eval(base64_decode(...))',
     'CRITICAL',
     'Patrón clásico de PHP webshell. eval(base64_decode()) ejecuta código arbitrario ofuscado en base64.'),

    (re.compile(r'(?i)(?:system|exec|shell_exec|passthru)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'),
     'MAL-PHP-CMD-WEBSHELL', 'PHP Webshell: ejecución de comandos desde input HTTP',
     'CRITICAL',
     'Webshell PHP que ejecuta comandos del sistema operativo pasados via GET/POST/COOKIE.'),

    (re.compile(r'(?i)assert\s*\(\s*\$_(?:GET|POST|REQUEST)'),
     'MAL-PHP-ASSERT-WEBSHELL', 'PHP Webshell: assert() con input del usuario',
     'CRITICAL',
     'PHP assert() con input del usuario equivale a eval(). Permite ejecución remota de código.'),

    # Python Backdoors / Reverse Shells
    (re.compile(
        r'(?i)socket\.connect\s*\(\s*\(["\'][\d.]+["\'],\s*\d{4,5}\)\s*\)'
        r'|subprocess\.[^\n]*shell=True[^\n]*socket'
    ),
     'MAL-PY-REVERSE-SHELL', 'Python: posible reverse shell',
     'CRITICAL',
     'Patrón de reverse shell en Python: socket.connect() con subprocess. '
     'Revisar contexto — puede ser código legítimo de networking.'),

    (re.compile(r'(?i)__import__\s*\(\s*["\']os["\']\s*\)\s*\.system\s*\('),
     'MAL-PY-OBFUSCATED-EXEC', 'Python: ejecución de OS con __import__ ofuscado',
     'HIGH',
     '__import__("os").system() es una técnica de ofuscación para ocultar imports maliciosos.'),

    # Crypto miners
    (re.compile(r'(?i)(?:stratum\+tcp|xmrig|monero|cryptonight|minergate)'),
     'MAL-CRYPTOMINER', 'Referencia a crypto miner detectada',
     'CRITICAL',
     'Se detectaron referencias a pools de minería de criptomonedas (stratum+tcp, xmrig, monero). '
     'Posible inyección de crypto miner.'),

    # Ofuscación extrema
    (re.compile(r'(?i)(?:base64_decode|b64decode)\s*\(["\'][A-Za-z0-9+/]{100,}={0,2}["\']'),
     'MAL-OBFUSCATION-BASE64', 'String base64 muy largo embebido en código',
     'HIGH',
     'String base64 de más de 100 chars hardcodeado. Posible payload ofuscado. Decodificar y revisar.'),

    (re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){19,}'),
     'MAL-OBFUSCATION-HEX', 'Secuencia hexadecimal larga (posible shellcode/payload)',
     'HIGH',
     'Secuencia de 20+ bytes hexadecimales consecutivos. Posible shellcode embebido.'),

    # Supply chain / typosquatting indicators
    (re.compile(r'(?i)(?:setup\.py|pyproject\.toml)[^\n]*(?:install_requires|dependencies).*'
                r'(?:requests|urllib|httplib)[_\-]?(?:2|3|pro|sec|new|fork)'),
     'MAL-SUPPLY-CHAIN-TYPO', 'Posible dependencia typosquatting',
     'HIGH',
     'Nombre de dependencia similar a librería conocida con sufijo sospechoso. '
     'Posible ataque de dependency confusion o typosquatting.'),

    # Cron/task injection
    (re.compile(r'(?i)(?:crontab|at\s+-f|schtasks)[^\n]*(?:curl|wget|bash|python)[^\n]*(?:http|ftp)'),
     'MAL-CRON-INJECTION', 'Posible inyección en cron/tarea programada',
     'HIGH',
     'Cron o tarea programada que descarga y ejecuta código de internet. '
     'Vector común de persistencia de malware.'),

    # Encoded PowerShell (Windows backdoors)
    (re.compile(r'(?i)powershell[^\n]*-enc(?:odedcommand)?\s+[A-Za-z0-9+/]{50,}'),
     'MAL-PS-ENCODED', 'PowerShell encoded command',
     'CRITICAL',
     'PowerShell con comando encodeado en base64. Técnica común de evasión de AV y backdoors.'),
]

_SUPPORTED = {
    '.py', '.php', '.js', '.ts', '.rb', '.sh', '.bash',
    '.ps1', '.html', '.htm', '.asp', '.aspx', '.jsp',
    '.go', '.java', '.c', '.cpp', '.pl',
}

_SKIP_DIRS = {'venv', '.venv', 'node_modules', '.git', '__pycache__', 'build', 'dist'}


def scan_file_for_malware(file_path: str) -> List[dict]:
    path = Path(file_path)
    if path.suffix.lower() not in _SUPPORTED:
        return []
    try:
        with open(file_path, encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
    except OSError:
        return []

    findings = []
    seen: set = set()

    for lineno, line in enumerate(lines, 1):
        for pattern, rule_id, name, severity, desc in _RULES:
            if pattern.search(line):
                key = f'{rule_id}:{file_path}:{lineno}'
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    'rule_id': rule_id,
                    'name': name,
                    'description': desc,
                    'severity': severity,
                    'file': file_path,
                    'line': lineno,
                    'snippet': line.rstrip()[:120],
                    'compliance': ['CWE-506', 'OWASP-A08:2021'],
                    'source': 'YARA-SCANNER',
                })
    return findings


def scan_directory_for_malware(project_path: str, max_files: int = 1000) -> List[dict]:
    root  = Path(project_path).resolve()
    found = []
    count = 0
    for fpath in sorted(root.rglob('*')):
        if count >= max_files:
            break
        if not fpath.is_file():
            continue
        if set(fpath.relative_to(root).parts) & _SKIP_DIRS:
            continue
        found.extend(scan_file_for_malware(str(fpath)))
        count += 1
    if found:
        print(f'\033[91m[AuditLens YARA]\033[0m ⚠️  {len(found)} posibles indicadores de malware/backdoor')
    else:
        print(f'\033[92m[AuditLens YARA]\033[0m No se detectaron indicadores de malware')
    return found
