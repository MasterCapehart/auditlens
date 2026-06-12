"""
AuditLens HTML Exporter — self-contained static report with charts and findings table.

Usage:
    auditlens scan ./project --format html -o report.html
"""

from __future__ import annotations

import html
import json
import os
from datetime import datetime
from typing import List

_SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
_SEVERITY_COLOR = {
    'CRITICAL': '#ef4444',
    'HIGH': '#f97316',
    'MEDIUM': '#eab308',
    'LOW': '#3b82f6',
}


def _esc(s: object) -> str:
    return html.escape(str(s))


def generate_html_report(
    findings: List[dict],
    scan_path: str,
    output_path: str = 'audit_report.html',
) -> None:
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.get('severity', 'LOW').upper()
        if sev in counts:
            counts[sev] += 1

    # Per-file risk score
    file_risk: dict = {}
    for f in findings:
        fp = f.get('file', 'unknown')
        rank = 4 - _SEVERITY_ORDER.get(f.get('severity', 'LOW').upper(), 3)
        file_risk[fp] = file_risk.get(fp, 0) + rank
    top_files = sorted(file_risk.items(), key=lambda x: -x[1])[:10]

    # Compliance coverage
    compliance_counts: dict = {}
    for f in findings:
        for c in f.get('compliance', []):
            compliance_counts[c] = compliance_counts.get(c, 0) + 1
    top_compliance = sorted(compliance_counts.items(), key=lambda x: -x[1])[:10]

    rows_html = ''
    for f in sorted(findings, key=lambda x: _SEVERITY_ORDER.get(x.get('severity', 'LOW').upper(), 3)):
        sev = f.get('severity', 'LOW').upper()
        color = _SEVERITY_COLOR.get(sev, '#64748b')
        file_short = '/'.join(f.get('file', '').split('/')[-2:])
        compliance = ', '.join(f.get('compliance', []))
        rows_html += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{_esc(sev)}</span></td>
          <td><code>{_esc(f.get('rule_id',''))}</code></td>
          <td>{_esc(f.get('name',''))}</td>
          <td><code>{_esc(file_short)}:{_esc(f.get('line',''))}</code></td>
          <td class="small">{_esc(compliance)}</td>
        </tr>"""

    chart_data = json.dumps({
        'labels': list(counts.keys()),
        'values': list(counts.values()),
        'colors': [_SEVERITY_COLOR[k] for k in counts],
    })

    file_chart_data = json.dumps({
        'labels': [os.path.basename(fp) for fp, _ in top_files],
        'values': [score for _, score in top_files],
    })

    compliance_chart_data = json.dumps({
        'labels': [c for c, _ in top_compliance],
        'values': [n for _, n in top_compliance],
    })

    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    total = len(findings)

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>AuditLens Report — {_esc(os.path.basename(scan_path))}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}}
    .header{{background:linear-gradient(135deg,#1e3a5f,#0f172a);padding:2rem 3rem;border-bottom:1px solid #1e293b}}
    .header h1{{font-size:1.8rem;font-weight:700;color:#60a5fa}}
    .header p{{color:#94a3b8;margin-top:.4rem;font-size:.95rem}}
    .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;padding:2rem 3rem 0}}
    .card{{background:#1e293b;border-radius:12px;padding:1.2rem;text-align:center;border:1px solid #334155}}
    .card .num{{font-size:2.5rem;font-weight:800;line-height:1}}
    .card .lbl{{font-size:.75rem;color:#94a3b8;margin-top:.4rem;text-transform:uppercase;letter-spacing:.05em}}
    .charts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1.5rem;padding:2rem 3rem}}
    .chart-box{{background:#1e293b;border-radius:12px;padding:1.5rem;border:1px solid #334155}}
    .chart-box h3{{font-size:.85rem;color:#94a3b8;margin-bottom:1rem;text-transform:uppercase;letter-spacing:.05em}}
    .table-wrap{{padding:0 3rem 3rem;overflow-x:auto}}
    table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:12px;overflow:hidden;font-size:.85rem}}
    th{{background:#0f172a;color:#94a3b8;padding:.75rem 1rem;text-align:left;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}}
    td{{padding:.7rem 1rem;border-top:1px solid #334155;vertical-align:top}}
    tr:hover td{{background:#263248}}
    .badge{{display:inline-block;padding:.2rem .5rem;border-radius:6px;font-size:.7rem;font-weight:700;color:#fff}}
    code{{font-family:'SF Mono','Fira Code',monospace;font-size:.8rem;color:#7dd3fc;background:#0f172a;padding:.1rem .3rem;border-radius:4px}}
    .small{{font-size:.75rem;color:#64748b}}
    h2{{padding:2rem 3rem .5rem;font-size:1.1rem;color:#cbd5e1}}
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ AuditLens Security Report</h1>
    <p>Scan path: <code style="color:#7dd3fc">{_esc(scan_path)}</code> &nbsp;·&nbsp; Generated: {now}</p>
  </div>

  <div class="cards">
    <div class="card"><div class="num" style="color:#94a3b8">{total}</div><div class="lbl">Total Findings</div></div>
    <div class="card"><div class="num" style="color:#ef4444">{counts['CRITICAL']}</div><div class="lbl">Critical</div></div>
    <div class="card"><div class="num" style="color:#f97316">{counts['HIGH']}</div><div class="lbl">High</div></div>
    <div class="card"><div class="num" style="color:#eab308">{counts['MEDIUM']}</div><div class="lbl">Medium</div></div>
    <div class="card"><div class="num" style="color:#3b82f6">{counts['LOW']}</div><div class="lbl">Low</div></div>
  </div>

  <div class="charts">
    <div class="chart-box">
      <h3>Severity Distribution</h3>
      <canvas id="sevChart" height="200"></canvas>
    </div>
    <div class="chart-box">
      <h3>Top Risky Files</h3>
      <canvas id="fileChart" height="200"></canvas>
    </div>
    <div class="chart-box">
      <h3>Top Compliance Violations</h3>
      <canvas id="compChart" height="200"></canvas>
    </div>
  </div>

  <h2>All Findings ({total})</h2>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Severity</th><th>Rule</th><th>Name</th><th>Location</th><th>Compliance</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>

  <script>
  const sevData = {chart_data};
  const fileData = {file_chart_data};
  const compData = {compliance_chart_data};

  new Chart(document.getElementById('sevChart'), {{
    type: 'doughnut',
    data: {{ labels: sevData.labels, datasets: [{{ data: sevData.values, backgroundColor: sevData.colors, borderWidth: 0 }}] }},
    options: {{ plugins: {{ legend: {{ labels: {{ color: '#94a3b8' }} }} }}, cutout: '60%' }}
  }});

  new Chart(document.getElementById('fileChart'), {{
    type: 'bar',
    data: {{ labels: fileData.labels, datasets: [{{ data: fileData.values, backgroundColor: '#3b82f6', borderRadius: 4 }}] }},
    options: {{ indexAxis: 'y', plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ ticks: {{ color: '#94a3b8' }} }}, y: {{ ticks: {{ color: '#94a3b8', font: {{ size: 11 }} }} }} }} }}
  }});

  new Chart(document.getElementById('compChart'), {{
    type: 'bar',
    data: {{ labels: compData.labels, datasets: [{{ data: compData.values, backgroundColor: '#8b5cf6', borderRadius: 4 }}] }},
    options: {{ indexAxis: 'y', plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ ticks: {{ color: '#94a3b8' }} }}, y: {{ ticks: {{ color: '#94a3b8', font: {{ size: 11 }} }} }} }} }}
  }});
  </script>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html_content)

    abs_path = os.path.abspath(output_path)
    print(f'\033[92m[AuditLens]\033[0m Reporte HTML guardado: \033[1m{abs_path}\033[0m')
