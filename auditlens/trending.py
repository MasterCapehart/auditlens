"""
AuditLens Trending Dashboard — visualiza tendencias de hallazgos
desde la base de datos SQLite del historial.

Usage:
    auditlens trending
    auditlens trending --days 30 --format html --output trends.html
"""

from __future__ import annotations

import os
import sqlite3
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


_DB_PATH = os.path.expanduser('~/.auditlens/history.db')

_COLORS = {
    'CRITICAL': '\033[91m',
    'HIGH':     '\033[93m',
    'MEDIUM':   '\033[94m',
    'LOW':      '\033[92m',
    'RESET':    '\033[0m',
    'BOLD':     '\033[1m',
}


def _get_db(db_path: str) -> Optional[sqlite3.Connection]:
    if not os.path.isfile(db_path):
        return None
    try:
        return sqlite3.connect(db_path)
    except sqlite3.Error:
        return None


def _load_history(db_path: str, days: int = 90) -> List[Dict]:
    conn = _get_db(db_path)
    if not conn:
        return []

    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT scan_date, scan_path, severity, COUNT(*) as count
            FROM findings
            WHERE scan_date >= date('now', ?)
            GROUP BY scan_date, scan_path, severity
            ORDER BY scan_date ASC
            """,
            (f'-{days} days',),
        )
        rows = cur.fetchall()
        return [
            {'date': r[0], 'path': r[1], 'severity': r[2], 'count': r[3]}
            for r in rows
        ]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def _aggregate_by_date(history: List[Dict]) -> Dict[str, Dict[str, int]]:
    """Returns {date: {severity: count}}."""
    by_date: Dict[str, Dict[str, int]] = defaultdict(lambda: {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})
    for row in history:
        date = row['date'][:10]
        sev = row.get('severity', 'LOW')
        if sev in by_date[date]:
            by_date[date][sev] += row['count']
    return dict(sorted(by_date.items()))


def _aggregate_by_path(history: List[Dict]) -> Dict[str, int]:
    """Returns {project_path: total_findings}."""
    by_path: Dict[str, int] = defaultdict(int)
    for row in history:
        by_path[row['path']] += row['count']
    return dict(sorted(by_path.items(), key=lambda x: x[1], reverse=True))


def print_trending_dashboard(db_path: str = _DB_PATH, days: int = 30) -> None:
    """Print trends to terminal."""
    history = _load_history(db_path, days=days)
    if not history:
        print(f'\033[93m[AuditLens Trending]\033[0m No hay historial en {db_path}')
        print('Ejecuta un escaneo con "auditlens scan" para comenzar a acumular historial.')
        return

    by_date = _aggregate_by_date(history)
    by_path = _aggregate_by_path(history)
    C = _COLORS

    print(f'\n{C["BOLD"]}=== TENDENCIAS DE SEGURIDAD (últimos {days} días) ==={C["RESET"]}')

    print(f'\n{C["BOLD"]}Hallazgos por fecha:{C["RESET"]}')
    for date, counts in by_date.items():
        total = sum(counts.values())
        bar = '█' * min(total, 40)
        crit = f'{C["CRITICAL"]}{counts["CRITICAL"]}C{C["RESET"]}' if counts['CRITICAL'] else ''
        high = f'{C["HIGH"]}{counts["HIGH"]}H{C["RESET"]}' if counts['HIGH'] else ''
        med = f'{C["MEDIUM"]}{counts["MEDIUM"]}M{C["RESET"]}' if counts['MEDIUM'] else ''
        low = f'{counts["LOW"]}L' if counts['LOW'] else ''
        parts = ' '.join(p for p in [crit, high, med, low] if p)
        print(f'  {date}  {bar:<40} {total:>4} total ({parts})')

    print(f'\n{C["BOLD"]}Top proyectos por número de hallazgos:{C["RESET"]}')
    for path, total in list(by_path.items())[:10]:
        bar = '█' * min(total // 2, 30)
        print(f'  {path[-50:]:<50} {bar:<30} {total}')


def generate_trending_html(db_path: str = _DB_PATH, days: int = 30, output_path: str = 'trending.html') -> str:
    """Generate an HTML trending dashboard with Chart.js charts."""
    history = _load_history(db_path, days=days)
    by_date = _aggregate_by_date(history)
    by_path = _aggregate_by_path(history)

    dates = list(by_date.keys())
    criticals = [by_date[d]['CRITICAL'] for d in dates]
    highs = [by_date[d]['HIGH'] for d in dates]
    mediums = [by_date[d]['MEDIUM'] for d in dates]
    lows = [by_date[d]['LOW'] for d in dates]

    top_paths = list(by_path.items())[:10]
    path_labels = [p[0][-40:] for p in top_paths]
    path_counts = [p[1] for p in top_paths]

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>AuditLens — Trending Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 20px; }}
  h1 {{ color: #58a6ff; margin-bottom: 5px; }}
  .subtitle {{ color: #8b949e; margin-bottom: 30px; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; max-width: 1200px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }}
  .card h2 {{ color: #58a6ff; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; margin-top: 0; }}
  canvas {{ max-height: 300px; }}
</style>
</head>
<body>
<h1>AuditLens — Tendencias de Seguridad</h1>
<p class="subtitle">Últimos {days} días | {len(history)} entradas en historial</p>
<div class="grid">
  <div class="card">
    <h2>Hallazgos por Fecha</h2>
    <canvas id="timelineChart"></canvas>
  </div>
  <div class="card">
    <h2>Top Proyectos</h2>
    <canvas id="projectsChart"></canvas>
  </div>
</div>
<script>
const dates = {dates};
new Chart(document.getElementById('timelineChart'), {{
  type: 'line',
  data: {{
    labels: dates,
    datasets: [
      {{ label: 'CRITICAL', data: {criticals}, borderColor: '#da3633', backgroundColor: '#da363322', tension: 0.3 }},
      {{ label: 'HIGH', data: {highs}, borderColor: '#e3b341', backgroundColor: '#e3b34122', tension: 0.3 }},
      {{ label: 'MEDIUM', data: {mediums}, borderColor: '#388bfd', backgroundColor: '#388bfd22', tension: 0.3 }},
      {{ label: 'LOW', data: {lows}, borderColor: '#3fb950', backgroundColor: '#3fb95022', tension: 0.3 }},
    ]
  }},
  options: {{ responsive: true, plugins: {{ legend: {{ labels: {{ color: '#e6edf3' }} }} }}, scales: {{ x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }}, y: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }} }} }}
}});
new Chart(document.getElementById('projectsChart'), {{
  type: 'bar',
  data: {{
    labels: {path_labels},
    datasets: [{{ label: 'Total', data: {path_counts}, backgroundColor: '#388bfd88', borderColor: '#388bfd', borderWidth: 1 }}]
  }},
  options: {{ indexAxis: 'y', responsive: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }}, y: {{ ticks: {{ color: '#8b949e' }} }} }} }}
}});
</script>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html)

    print(f'\033[92m[AuditLens Trending]\033[0m Dashboard HTML generado: {output_path}')
    return output_path
