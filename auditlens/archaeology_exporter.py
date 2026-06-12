"""
AuditLens Temporal Archaeology — HTML report exporter with Chart.js timeline.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict


_SEV_COLOR = {
    'CRITICAL': '#da3633',
    'HIGH':     '#e3b341',
    'MEDIUM':   '#388bfd',
    'LOW':      '#3fb950',
}

_DAYS_ES = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo']


def generate_archaeology_html(result: Dict[str, Any], output_path: str) -> str:
    """Generate a standalone HTML report for the archaeology results."""

    stats      = result.get('stats', {})
    lifecycles = result.get('lifecycles', [])
    profiles   = result.get('developer_profiles', [])
    predictions = result.get('predictions', [])
    timeline   = result.get('risk_timeline', [])

    # Timeline chart data
    tl_dates  = json.dumps([t['date'] for t in timeline])
    tl_scores = json.dumps([t['risk_score'] for t in timeline])

    # Open vs fixed donut
    open_count  = stats.get('open_vulnerabilities', 0)
    fixed_count = stats.get('fixed_vulnerabilities', 0)

    # Severity breakdown
    sev_counts = stats.get('severity_counts', {})
    sev_labels = json.dumps(list(sev_counts.keys()))
    sev_data   = json.dumps(list(sev_counts.values()))
    sev_colors = json.dumps([_SEV_COLOR.get(k, '#8b949e') for k in sev_counts.keys()])

    # Lifecycle table rows
    lc_rows = ''
    for lc in sorted(lifecycles, key=lambda x: (
        {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x.get('severity', 'LOW'), 4),
        x.get('status', '') == 'fixed',
    ))[:50]:
        sev   = lc.get('severity', 'LOW')
        color = _SEV_COLOR.get(sev, '#8b949e')
        status = lc.get('status', 'open')
        status_badge = (
            '<span style="color:#da3633">● open</span>' if status == 'open'
            else '<span style="color:#3fb950">✓ fixed</span>'
        )
        lt = lc.get('lifetime_days')
        lt_str = f'{int(lt)}d' if lt is not None else '—'
        intro = lc.get('introduced', {})
        snippet = (intro.get('snippet', '') or '')[:60].replace('<', '&lt;').replace('>', '&gt;')
        lc_rows += f"""
        <tr>
          <td><span class="sev-dot" style="background:{color}"></span>{sev}</td>
          <td>{lc.get('rule_name','')[:35]}</td>
          <td class="mono">{lc.get('file_path','').split('/')[-1]}</td>
          <td>{intro.get('author','')}</td>
          <td>{intro.get('date','')}</td>
          <td>{lt_str}</td>
          <td>{status_badge}</td>
          <td class="mono code-cell">{snippet}</td>
        </tr>"""

    # Developer profile cards
    dev_cards = ''
    for p in sorted(profiles, key=lambda x: x.get('risk_score', 0), reverse=True)[:8]:
        if p.get('vuln_introductions', 0) == 0:
            continue
        rs = p.get('risk_score', 0)
        rs_color = '#da3633' if rs >= 50 else '#e3b341' if rs >= 25 else '#3fb950'
        sev_bd = p.get('severity_breakdown', {})
        sev_html = ' '.join(
            f'<span class="sev-pill" style="background:{_SEV_COLOR.get(s,"#8b949e")}22;'
            f'border:1px solid {_SEV_COLOR.get(s,"#8b949e")};color:{_SEV_COLOR.get(s,"#8b949e")}">'
            f'{s[0]}: {n}</span>'
            for s, n in sev_bd.items() if n
        )
        dev_cards += f"""
        <div class="dev-card">
          <div class="dev-header">
            <span class="dev-name">{p.get('name','')}</span>
            <span class="risk-badge" style="background:{rs_color}22;border:1px solid {rs_color};color:{rs_color}">
              Risk {rs:.0f}
            </span>
          </div>
          <div class="dev-stats">
            <span>{p.get('total_commits',0)} commits</span>
            <span style="color:#da3633">{p.get('vuln_introductions',0)} vulns introducidas</span>
            <span style="color:#3fb950">{p.get('vuln_fixes',0)} vulns fijadas</span>
          </div>
          <div class="dev-pattern">
            Patrón: {p.get('top_risky_day') or 'N/A'} a las
            {f"{p.get('top_risky_hour'):02d}:00" if p.get('top_risky_hour') is not None else 'N/A'}
            · Vida prom: {p.get('avg_lifetime_days',0):.0f}d
          </div>
          <div style="margin-top:6px">{sev_html}</div>
        </div>"""

    # Predictions table
    pred_rows = ''
    for pred in predictions[:10]:
        prob  = pred.get('risk_probability', 0)
        pct   = int(prob * 100)
        color = '#da3633' if prob > 0.7 else '#e3b341' if prob > 0.4 else '#388bfd'
        bar   = f'<div class="prob-bar"><div class="prob-fill" style="width:{pct}%;background:{color}"></div></div>'
        factors = '<br>'.join(f'• {f}' for f in pred.get('contributing_factors', [])[:2])
        pred_rows += f"""
        <tr>
          <td class="mono">{pred.get('file_path','').split('/')[-1]}</td>
          <td>{bar} {pct}%</td>
          <td>{pred.get('last_touched_by','')}</td>
          <td>{pred.get('historical_vuln_count',0)}</td>
          <td style="font-size:11px;color:#8b949e">{factors}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>AuditLens — Temporal Vulnerability Archaeology</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; padding: 24px; }}
h1 {{ color: #58a6ff; font-size: 22px; margin-bottom: 4px; }}
.subtitle {{ color: #8b949e; font-size: 13px; margin-bottom: 24px; }}
h2 {{ color: #58a6ff; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; margin: 0; }}

.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 24px; }}
.stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }}
.stat-value {{ font-size: 28px; font-weight: 700; color: #58a6ff; }}
.stat-label {{ font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}

.section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
.section-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }}

.charts-grid {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 20px; }}
.chart-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }}
.chart-card h2 {{ margin-bottom: 12px; }}
canvas {{ max-height: 220px; }}

table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
th {{ text-align: left; padding: 8px; color: #8b949e; border-bottom: 1px solid #30363d; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
td {{ padding: 7px 8px; border-bottom: 1px solid #21262d; vertical-align: top; }}
tr:last-child td {{ border-bottom: none; }}
.mono {{ font-family: 'SF Mono', Consolas, monospace; font-size: 11px; }}
.code-cell {{ color: #79c0ff; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

.sev-dot {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px; }}

.dev-cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }}
.dev-card {{ background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 14px; }}
.dev-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
.dev-name {{ font-weight: 600; font-size: 14px; }}
.risk-badge {{ padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
.dev-stats {{ display: flex; gap: 12px; font-size: 12px; color: #8b949e; margin-bottom: 6px; }}
.dev-pattern {{ font-size: 11px; color: #6e7681; }}
.sev-pill {{ padding: 2px 6px; border-radius: 10px; font-size: 11px; }}

.prob-bar {{ height: 6px; background: #21262d; border-radius: 3px; margin-bottom: 4px; }}
.prob-fill {{ height: 100%; border-radius: 3px; }}
</style>
</head>
<body>
<h1>⏳ Temporal Vulnerability Archaeology</h1>
<p class="subtitle">Análisis histórico completo del ciclo de vida de vulnerabilidades · {stats.get('total_commits_analyzed', 0)} commits minados</p>

<div class="stats-grid">
  <div class="stat-card">
    <div class="stat-value" style="color:#da3633">{open_count}</div>
    <div class="stat-label">Vulnerabilidades abiertas</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:#3fb950">{fixed_count}</div>
    <div class="stat-label">Vulnerabilidades corregidas</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:#e3b341">{stats.get('avg_lifetime_days', 0):.0f}d</div>
    <div class="stat-label">Vida promedio en producción</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{stats.get('unique_files_affected', 0)}</div>
    <div class="stat-label">Archivos afectados</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:#f78166">{stats.get('high_risk_developers', 0)}</div>
    <div class="stat-label">Devs de alto riesgo</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{stats.get('unique_developers', 0)}</div>
    <div class="stat-label">Desarrolladores analizados</div>
  </div>
</div>

<div class="charts-grid">
  <div class="chart-card" style="grid-column: span 2">
    <h2>Serie de Tiempo — Risk Score Histórico</h2>
    <canvas id="timelineChart"></canvas>
  </div>
  <div class="chart-card">
    <h2>Por Severidad</h2>
    <canvas id="sevChart"></canvas>
  </div>
</div>

<div class="section">
  <div class="section-header">
    <h2>Ciclos de Vida de Vulnerabilidades</h2>
    <span style="color:#8b949e;font-size:12px">mostrando top {min(len(lifecycles),50)} de {len(lifecycles)}</span>
  </div>
  <table>
    <thead><tr>
      <th>Severidad</th><th>Vulnerabilidad</th><th>Archivo</th>
      <th>Introducida por</th><th>Fecha intro</th><th>Vida</th>
      <th>Estado</th><th>Código</th>
    </tr></thead>
    <tbody>{lc_rows}</tbody>
  </table>
</div>

<div class="section">
  <div class="section-header"><h2>Perfiles de Desarrolladores</h2></div>
  <div class="dev-cards">{dev_cards if dev_cards else '<p style="color:#6e7681">No se encontraron vulnerabilidades asociadas a desarrolladores.</p>'}</div>
</div>

<div class="section">
  <div class="section-header">
    <h2>Predicción — Archivos en Riesgo</h2>
    <span style="color:#8b949e;font-size:12px">probabilidad de vulnerabilidad futura basada en patrones históricos</span>
  </div>
  <table>
    <thead><tr>
      <th>Archivo</th><th>Probabilidad</th><th>Último editor</th>
      <th>Vulns históricas</th><th>Factores</th>
    </tr></thead>
    <tbody>{pred_rows if pred_rows else '<tr><td colspan="5" style="color:#6e7681;text-align:center;padding:20px">Datos insuficientes para predicción.</td></tr>'}</tbody>
  </table>
</div>

<script>
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#21262d';

new Chart(document.getElementById('timelineChart'), {{
  type: 'line',
  data: {{
    labels: {tl_dates},
    datasets: [{{
      label: 'Risk Score',
      data: {tl_scores},
      borderColor: '#da3633',
      backgroundColor: '#da363318',
      fill: true,
      tension: 0.3,
      pointRadius: 0,
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ maxTicksLimit: 8, color: '#6e7681' }}, grid: {{ color: '#21262d' }} }},
      y: {{ ticks: {{ color: '#6e7681' }}, grid: {{ color: '#21262d' }}, beginAtZero: true }}
    }}
  }}
}});

new Chart(document.getElementById('sevChart'), {{
  type: 'doughnut',
  data: {{
    labels: {sev_labels},
    datasets: [{{ data: {sev_data}, backgroundColor: {sev_colors}, borderWidth: 0 }}]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ position: 'bottom', labels: {{ padding: 12, font: {{ size: 11 }} }} }}
    }}
  }}
}});
</script>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html)

    print(f'\033[92m[AuditLens Archaeology]\033[0m Reporte HTML generado: {output_path}')
    return output_path
