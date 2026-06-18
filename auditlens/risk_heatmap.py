"""
AuditLens — Risk Heatmap + Compliance Radar Chart

Genera visualizaciones interactivas:
1. Risk Heatmap — mapa de calor por archivo/módulo (hallazgos × severidad)
2. Compliance Radar Chart — spider chart de cobertura por framework
3. Remediation Gantt — timeline de correcciones priorizadas
"""
from __future__ import annotations

import os
from collections import defaultdict
from typing import Any, Dict, List


def generate_risk_heatmap_html(findings: List[dict], output_path: str) -> str:
    # Group by file
    file_scores: Dict[str, Dict] = defaultdict(lambda: {
        'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'score': 0
    })
    sev_w = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}

    for f in findings:
        fp  = f.get('file', 'unknown')
        rel = os.path.basename(fp) if fp else 'unknown'
        sev = f.get('severity', 'LOW')
        file_scores[rel][sev] += 1
        file_scores[rel]['score'] += sev_w.get(sev, 1)

    # Sort by score desc
    sorted_files = sorted(file_scores.items(), key=lambda x: -x[1]['score'])[:40]

    rows = ''
    for fname, counts in sorted_files:
        score   = counts['score']
        bar_w   = min(score * 3, 300)
        color   = '#da3633' if score >= 20 else '#e3b341' if score >= 8 else '#388bfd'
        rows += f'''<tr>
          <td class="mono" title="{fname}">{fname[:45]}</td>
          <td style="color:#da3633">{counts["CRITICAL"]}</td>
          <td style="color:#e3b341">{counts["HIGH"]}</td>
          <td style="color:#388bfd">{counts["MEDIUM"]}</td>
          <td style="color:#8b949e">{counts["LOW"]}</td>
          <td><div style="background:{color};width:{bar_w}px;height:10px;border-radius:2px"></div></td>
          <td style="color:{color};font-weight:bold">{score}</td>
        </tr>'''

    html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<title>AuditLens — Risk Heatmap</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;padding:24px}}
h1{{color:#58a6ff;font-size:20px;margin-bottom:4px}}
.sub{{color:#8b949e;font-size:12px;margin-bottom:20px}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px;margin-bottom:16px}}
h2{{color:#58a6ff;font-size:12px;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{text-align:left;padding:8px;color:#8b949e;border-bottom:1px solid #30363d;font-size:11px;text-transform:uppercase}}
td{{padding:6px 8px;border-bottom:1px solid #21262d}}
.mono{{font-family:monospace;font-size:11px}}
</style></head><body>
<h1>🔥 Risk Heatmap</h1>
<p class="sub">Top archivos por score de riesgo (CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1)</p>
<div class="section">
<h2>Archivos con mayor riesgo ({len(sorted_files)} mostrados)</h2>
<table>
<thead><tr><th>Archivo</th><th>CRIT</th><th>HIGH</th><th>MED</th><th>LOW</th><th>Riesgo</th><th>Score</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
</body></html>"""

    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html)
    print(f'\033[92m[AuditLens]\033[0m Risk heatmap: {output_path}')
    return output_path


def generate_compliance_radar_html(
    findings: List[dict],
    output_path: str,
    frameworks: List[str] = None,
) -> str:
    """Generate radar chart showing compliance coverage per framework."""
    if frameworks is None:
        frameworks = ['OWASP', 'ISO27001', 'CMF', 'GDPR', 'HIPAA', 'NIST', 'LEY21719', 'PCI']

    # Count findings per framework tag prefix
    fw_counts: Dict[str, int] = {fw: 0 for fw in frameworks}
    for f in findings:
        for tag in f.get('compliance', []):
            for fw in frameworks:
                if tag.upper().startswith(fw.replace('LEY21719', 'LEY21719').upper()):
                    fw_counts[fw] += 1

    # Score = 100 - min(findings*3, 100)
    fw_scores = {fw: max(0, 100 - min(fw_counts[fw] * 4, 100)) for fw in frameworks}

    # Chart.js radar
    labels  = str([fw for fw in frameworks])
    data    = str([fw_scores[fw] for fw in frameworks])
    max_val = 100

    html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<title>AuditLens — Compliance Radar</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;padding:24px;text-align:center}}
h1{{color:#58a6ff;font-size:20px;margin-bottom:16px}}
canvas{{max-width:600px;margin:0 auto;display:block}}
.legend{{display:flex;justify-content:center;gap:16px;flex-wrap:wrap;margin-top:16px;font-size:12px}}
.leg-item{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:6px 12px}}
</style></head><body>
<h1>📡 Compliance Coverage Radar</h1>
<canvas id="radar"></canvas>
<div class="legend">
{chr(10).join(f'<div class="leg-item"><strong>{fw}</strong>: {fw_scores[fw]}/100</div>' for fw in frameworks)}
</div>
<script>
new Chart(document.getElementById('radar'), {{
  type: 'radar',
  data: {{
    labels: {labels},
    datasets: [{{
      label: 'Score de cumplimiento',
      data: {data},
      backgroundColor: 'rgba(88,166,255,0.15)',
      borderColor: '#58a6ff',
      pointBackgroundColor: '#58a6ff',
      pointRadius: 4,
    }}]
  }},
  options: {{
    scales: {{
      r: {{
        min: 0, max: {max_val},
        ticks: {{ color: '#8b949e', stepSize: 20 }},
        grid: {{ color: '#30363d' }},
        pointLabels: {{ color: '#e6edf3', font: {{ size: 12 }} }},
        angleLines: {{ color: '#30363d' }},
      }}
    }},
    plugins: {{
      legend: {{ labels: {{ color: '#e6edf3' }} }}
    }}
  }}
}});
</script>
</body></html>"""

    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html)
    print(f'\033[92m[AuditLens]\033[0m Compliance radar: {output_path}')
    return output_path
