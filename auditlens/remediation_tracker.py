"""
AuditLens — Remediation Tracker

Compara dos archivos JSON de hallazgos (baseline vs current) y genera un
reporte de progreso: hallazgos resueltos, nuevos, persistentes y regresiones.

Uso:
    auditlens track baseline.json current.json
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple


def _finding_key(f: dict) -> str:
    """Canonical dedup key for a finding."""
    return f'{f.get("rule_id","")}::{f.get("file","")}::{f.get("line","")}'


def compare_findings(
    baseline: List[dict],
    current: List[dict],
) -> Dict[str, Any]:
    """
    Compare two findings lists.

    Returns:
        resolved   — in baseline, not in current (fixed!)
        new        — in current, not in baseline (regression or new code)
        persistent — in both (not fixed)
        improved   — severity went down
        worsened   — severity went up
    """
    sev_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}

    base_map  = {_finding_key(f): f for f in baseline}
    curr_map  = {_finding_key(f): f for f in current}

    base_keys = set(base_map)
    curr_keys = set(curr_map)

    resolved   = [base_map[k] for k in (base_keys - curr_keys)]
    new_f      = [curr_map[k] for k in (curr_keys - base_keys)]
    persistent = []
    improved   = []
    worsened   = []

    for k in base_keys & curr_keys:
        bf = base_map[k]
        cf = curr_map[k]
        br = sev_rank.get(bf.get('severity', 'LOW'), 1)
        cr = sev_rank.get(cf.get('severity', 'LOW'), 1)
        if cr < br:
            improved.append({'before': bf, 'after': cf})
        elif cr > br:
            worsened.append({'before': bf, 'after': cf})
        else:
            persistent.append(cf)

    total_base = len(baseline)
    total_curr = len(current)
    resolution_rate = round(len(resolved) / total_base * 100) if total_base else 0

    # Score delta
    def _score(findings):
        if not findings:
            return 100
        weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}
        total_w = sum(weights.get(f.get('severity', 'LOW'), 1) for f in findings)
        return max(0, 100 - min(total_w, 100))

    score_before = _score(baseline)
    score_after  = _score(current)

    return {
        'resolved':         resolved,
        'new':              new_f,
        'persistent':       persistent,
        'improved':         improved,
        'worsened':         worsened,
        'stats': {
            'total_before':    total_base,
            'total_after':     total_curr,
            'resolved_count':  len(resolved),
            'new_count':       len(new_f),
            'persistent_count':len(persistent),
            'resolution_rate': resolution_rate,
            'score_before':    score_before,
            'score_after':     score_after,
            'score_delta':     score_after - score_before,
        },
    }


def print_remediation_summary(result: Dict[str, Any]) -> None:
    C = {'RED': '\033[91m', 'YEL': '\033[93m', 'GRN': '\033[92m',
         'CYN': '\033[94m', 'BLD': '\033[1m', 'GRY': '\033[90m', 'RST': '\033[0m'}
    s = result['stats']
    delta_color = C['GRN'] if s['score_delta'] >= 0 else C['RED']
    delta_sign  = '+' if s['score_delta'] >= 0 else ''

    print(f'\n{C["BLD"]}{"=" * 58}')
    print(' REMEDIATION TRACKER — PROGRESO ENTRE AUDITORÍAS')
    print(f'{"=" * 58}{C["RST"]}')

    print(f'\n  Hallazgos anteriores:  {s["total_before"]}')
    print(f'  Hallazgos actuales:    {s["total_after"]}')
    print(f'\n  {C["GRN"]}✓ Resueltos:{C["RST"]}   {C["GRN"]}{C["BLD"]}{s["resolved_count"]}{C["RST"]}')
    print(f'  {C["RED"]}✗ Nuevos:{C["RST"]}      {C["RED"]}{C["BLD"]}{s["new_count"]}{C["RST"]}')
    print(f'  {C["YEL"]}◌ Persistentes:{C["RST"]} {s["persistent_count"]}')
    print(f'\n  Tasa de resolución:  {C["BLD"]}{s["resolution_rate"]}%{C["RST"]}')
    print(f'  Score anterior:      {s["score_before"]}/100')
    print(f'  Score actual:        {s["score_after"]}/100  '
          f'({delta_color}{delta_sign}{s["score_delta"]} pts{C["RST"]})')

    if result['new']:
        print(f'\n{C["BLD"]}  Hallazgos nuevos (requieren atención):{C["RST"]}')
        for f in sorted(result['new'],
                        key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x.get('severity','LOW'),4))[:10]:
            sev = f.get('severity', 'LOW')
            col = C['RED'] if sev in ('CRITICAL','HIGH') else C['YEL']
            print(f'  {col}• [{sev}]{C["RST"]} {f.get("rule_id","")} — '
                  f'{f.get("file","").split("/")[-1]}:{f.get("line","")}')

    if result['resolved']:
        print(f'\n{C["BLD"]}  Resueltos en esta iteración:{C["RST"]}')
        for f in result['resolved'][:8]:
            print(f'  {C["GRN"]}✓{C["RST"]} {f.get("rule_id","")} — '
                  f'{f.get("file","").split("/")[-1]}:{f.get("line","")}')


def generate_tracker_html(result: Dict[str, Any], output_path: str) -> str:
    s = result['stats']
    delta_color = '#3fb950' if s['score_delta'] >= 0 else '#da3633'
    delta_sign  = '+' if s['score_delta'] >= 0 else ''

    def _finding_rows(findings, color):
        rows = ''
        for f in sorted(findings,
                        key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x.get('severity','LOW'),4))[:20]:
            sev = f.get('severity','LOW')
            sc  = {'CRITICAL':'#da3633','HIGH':'#e3b341','MEDIUM':'#388bfd','LOW':'#3fb950'}.get(sev,'#8b949e')
            rows += (f'<tr><td><span style="color:{sc}">{sev}</span></td>'
                     f'<td style="font-family:monospace">{f.get("rule_id","")}</td>'
                     f'<td>{f.get("name","")[:50]}</td>'
                     f'<td style="font-family:monospace;font-size:11px">'
                     f'{f.get("file","").split("/")[-1]}:{f.get("line","")}</td></tr>')
        return rows or f'<tr><td colspan="4" style="color:#6e7681;text-align:center">—</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<title>AuditLens — Remediation Tracker</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;padding:28px;max-width:1000px;margin:0 auto}}
h1{{color:#58a6ff;font-size:20px;margin-bottom:4px}}
.sub{{color:#8b949e;font-size:12px;margin-bottom:20px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}}
.val{{font-size:28px;font-weight:700}}
.lbl{{font-size:11px;color:#8b949e;text-transform:uppercase;margin-top:4px}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px;margin-bottom:14px}}
h2{{color:#58a6ff;font-size:12px;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{text-align:left;padding:7px;color:#8b949e;border-bottom:1px solid #30363d;font-size:11px;text-transform:uppercase}}
td{{padding:6px 7px;border-bottom:1px solid #21262d}}
</style></head><body>
<h1>📊 Remediation Tracker</h1>
<p class="sub">Progreso entre auditorías</p>
<div class="stats">
  <div class="card"><div class="val" style="color:#3fb950">{s["resolved_count"]}</div><div class="lbl">Resueltos</div></div>
  <div class="card"><div class="val" style="color:#da3633">{s["new_count"]}</div><div class="lbl">Nuevos</div></div>
  <div class="card"><div class="val" style="color:#e3b341">{s["persistent_count"]}</div><div class="lbl">Persistentes</div></div>
  <div class="card"><div class="val" style="color:{delta_color}">{delta_sign}{s["score_delta"]}</div><div class="lbl">Score delta</div></div>
</div>
<div class="section"><h2>Score</h2>
  <p>Antes: <strong>{s["score_before"]}/100</strong> → Después: <strong>{s["score_after"]}/100</strong>
  &nbsp; Tasa de resolución: <strong>{s["resolution_rate"]}%</strong></p>
</div>
<div class="section"><h2>Hallazgos nuevos ({s["new_count"]})</h2>
<table><thead><tr><th>Sev</th><th>Regla</th><th>Descripción</th><th>Archivo</th></tr></thead>
<tbody>{_finding_rows(result["new"], "#da3633")}</tbody></table></div>
<div class="section"><h2>Resueltos ({s["resolved_count"]})</h2>
<table><thead><tr><th>Sev</th><th>Regla</th><th>Descripción</th><th>Archivo</th></tr></thead>
<tbody>{_finding_rows(result["resolved"], "#3fb950")}</tbody></table></div>
</body></html>"""

    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html)
    print(f'\033[92m[AuditLens]\033[0m Remediation report: {output_path}')
    return output_path
