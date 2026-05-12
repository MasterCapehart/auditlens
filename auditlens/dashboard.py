"""
AuditLens Web Dashboard — local browser UI for scan history and findings.

Usage:
    auditlens serve ./my_project
    auditlens serve ./my_project --port 8080
    auditlens serve ./my_project --scan-first   # run a fresh scan then open dashboard

Opens http://localhost:8080 with:
  - Severity trend chart (Chart.js)
  - Filterable findings table
  - File heatmap (most vulnerable files)
  - Compliance coverage breakdown
  - Scan comparison
"""

from __future__ import annotations

import json
import os
import threading
import webbrowser
from datetime import datetime
from typing import Dict, List, Optional

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AuditLens Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0f1117; --card: #1a1d27; --border: #2a2d3e;
    --text: #e2e8f0; --muted: #64748b;
    --critical: #ef4444; --high: #f97316;
    --medium: #eab308; --low: #3b82f6;
    --green: #22c55e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
  header { background: var(--card); border-bottom: 1px solid var(--border); padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 20px; font-weight: 700; }
  header .badge { background: var(--critical); color: #fff; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }
  .stat-card { text-align: center; }
  .stat-num { font-size: 40px; font-weight: 800; line-height: 1; }
  .stat-label { color: var(--muted); font-size: 12px; margin-top: 6px; text-transform: uppercase; letter-spacing: .05em; }
  .critical-num { color: var(--critical); }
  .high-num { color: var(--high); }
  .medium-num { color: var(--medium); }
  .low-num { color: var(--low); }
  .card h2 { font-size: 15px; font-weight: 600; margin-bottom: 16px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
  .chart-wrap { position: relative; height: 220px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 8px 12px; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid var(--border); }
  td { padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 13px; }
  tr:hover td { background: rgba(255,255,255,.03); }
  .sev { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
  .sev-CRITICAL { background: rgba(239,68,68,.2); color: var(--critical); }
  .sev-HIGH     { background: rgba(249,115,22,.2); color: var(--high); }
  .sev-MEDIUM   { background: rgba(234,179,8,.2);  color: var(--medium); }
  .sev-LOW      { background: rgba(59,130,246,.2); color: var(--low); }
  .filter-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  input[type=text], select {
    background: var(--bg); border: 1px solid var(--border); color: var(--text);
    padding: 8px 12px; border-radius: 6px; font-size: 13px;
  }
  input[type=text] { flex: 1; min-width: 200px; }
  .path { color: var(--muted); font-family: monospace; font-size: 12px; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-wrap { display: flex; align-items: center; gap: 8px; }
  .bar { height: 8px; border-radius: 4px; min-width: 2px; }
  .heatmap-row td:first-child { font-family: monospace; font-size: 12px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); }
  .empty { color: var(--muted); text-align: center; padding: 40px; font-size: 13px; }
  .tag { display: inline-block; background: rgba(255,255,255,.07); padding: 1px 6px; border-radius: 3px; font-size: 10px; margin: 1px; color: var(--muted); }
  #scan-btn { background: var(--critical); color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; }
  #scan-btn:hover { opacity: .85; }
  .spinner { display: none; width: 16px; height: 16px; border: 2px solid rgba(255,255,255,.3); border-top-color: #fff; border-radius: 50%; animation: spin .6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .scan-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 24px; background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 20px; }
  .scan-path { color: var(--muted); font-family: monospace; font-size: 12px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .last-scan { color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
<header>
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
  <h1>AuditLens</h1>
  <span class="badge" id="header-badge">Cargando...</span>
</header>
<div class="container">
  <div class="scan-bar">
    <span class="scan-path" id="scan-path-label"></span>
    <span class="last-scan" id="last-scan-label"></span>
    <button id="scan-btn" onclick="triggerScan()">&#9654; Escanear Ahora</button>
    <div class="spinner" id="spinner"></div>
  </div>

  <!-- Estadísticas -->
  <div class="grid-4">
    <div class="card stat-card"><div class="stat-num critical-num" id="cnt-critical">0</div><div class="stat-label">Crítico</div></div>
    <div class="card stat-card"><div class="stat-num high-num"     id="cnt-high">0</div><div class="stat-label">Alto</div></div>
    <div class="card stat-card"><div class="stat-num medium-num"   id="cnt-medium">0</div><div class="stat-label">Medio</div></div>
    <div class="card stat-card"><div class="stat-num low-num"      id="cnt-low">0</div><div class="stat-label">Bajo</div></div>
  </div>

  <div class="grid-2">
    <!-- Gráfico de tendencia -->
    <div class="card">
      <h2>Tendencia de Severidad</h2>
      <div class="chart-wrap"><canvas id="trendChart"></canvas></div>
    </div>
    <!-- Mapa de calor de archivos -->
    <div class="card">
      <h2>Archivos más Vulnerables</h2>
      <table id="heatmap-table">
        <thead><tr><th>Archivo</th><th>Hallazgos</th><th>Peor</th></tr></thead>
        <tbody id="heatmap-body"><tr><td colspan="3" class="empty">Sin datos</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="grid-2">
    <!-- Cobertura de cumplimiento -->
    <div class="card">
      <h2>Cobertura de Cumplimiento</h2>
      <div class="chart-wrap"><canvas id="complianceChart"></canvas></div>
    </div>
    <!-- Reglas más activadas -->
    <div class="card">
      <h2>Reglas más Activadas</h2>
      <table>
        <thead><tr><th>Regla</th><th>Cantidad</th><th>Severidad</th></tr></thead>
        <tbody id="rules-body"><tr><td colspan="3" class="empty">Sin datos</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- Tabla de hallazgos -->
  <div class="card">
    <h2>Todos los Hallazgos</h2>
    <div class="filter-bar">
      <input type="text" id="search" placeholder="Buscar regla, archivo, descripción..." oninput="filterTable()">
      <select id="sev-filter" onchange="filterTable()">
        <option value="">Todas las severidades</option>
        <option value="CRITICAL">Crítico</option>
        <option value="HIGH">Alto</option>
        <option value="MEDIUM">Medio</option>
        <option value="LOW">Bajo</option>
      </select>
    </div>
    <table>
      <thead><tr><th>Severidad</th><th>Regla</th><th>Archivo : Línea</th><th>Descripción</th><th>Cumplimiento</th></tr></thead>
      <tbody id="findings-body"><tr><td colspan="5" class="empty">Sin hallazgos</td></tr></tbody>
    </table>
  </div>
</div>

<script>
let allFindings = [];
let trendChart = null;
let compChart = null;

async function load() {
  const [dataResp, histResp] = await Promise.all([
    fetch('/api/findings'),
    fetch('/api/history'),
  ]);
  const data    = await dataResp.json();
  const history = await histResp.json();

  allFindings = data.findings || [];
  document.getElementById('scan-path-label').textContent = data.scan_path || '';
  document.getElementById('last-scan-label').textContent = data.last_scan
    ? 'Último escaneo: ' + data.last_scan : '';
  document.getElementById('header-badge').textContent =
    allFindings.length + ' hallazgo' + (allFindings.length !== 1 ? 's' : '');

  updateStats(allFindings);
  renderHeatmap(allFindings);
  renderRules(allFindings);
  renderFindings(allFindings);
  renderTrend(history);
  renderCompliance(allFindings);
}

function updateStats(findings) {
  const counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
  findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  document.getElementById('cnt-critical').textContent = counts.CRITICAL;
  document.getElementById('cnt-high').textContent     = counts.HIGH;
  document.getElementById('cnt-medium').textContent   = counts.MEDIUM;
  document.getElementById('cnt-low').textContent      = counts.LOW;
}

function renderHeatmap(findings) {
  const fileMap = {};
  findings.forEach(f => {
    const key = f.file.split('/').slice(-2).join('/');
    if (!fileMap[key]) fileMap[key] = {count:0, worst:'LOW', full: f.file};
    fileMap[key].count++;
    const rank = {LOW:0,MEDIUM:1,HIGH:2,CRITICAL:3};
    if ((rank[f.severity]||0) > (rank[fileMap[key].worst]||0)) fileMap[key].worst = f.severity;
  });
  const sorted = Object.entries(fileMap).sort((a,b) => b[1].count - a[1].count).slice(0,8);
  const max = sorted[0]?.[1].count || 1;
  const tbody = document.getElementById('heatmap-body');
  if (!sorted.length) { tbody.innerHTML = '<tr><td colspan="3" class="empty">Sin datos</td></tr>'; return; }
  tbody.innerHTML = sorted.map(([file, info]) => `
    <tr class="heatmap-row">
      <td title="${info.full}">${file}</td>
      <td><div class="bar-wrap">
        <div class="bar" style="width:${Math.max(4, info.count/max*120)}px; background:var(--${info.worst.toLowerCase()})"></div>
        <span>${info.count}</span>
      </div></td>
      <td><span class="sev sev-${info.worst}">${info.worst}</span></td>
    </tr>`).join('');
}

function renderRules(findings) {
  const ruleMap = {};
  findings.forEach(f => {
    if (!ruleMap[f.rule_id]) ruleMap[f.rule_id] = {count:0, severity: f.severity};
    ruleMap[f.rule_id].count++;
  });
  const sorted = Object.entries(ruleMap).sort((a,b) => b[1].count - a[1].count).slice(0,8);
  const tbody = document.getElementById('rules-body');
  if (!sorted.length) { tbody.innerHTML = '<tr><td colspan="3" class="empty">Sin datos</td></tr>'; return; }
  tbody.innerHTML = sorted.map(([rule, info]) => `
    <tr>
      <td><code style="font-size:12px">${rule}</code></td>
      <td>${info.count}</td>
      <td><span class="sev sev-${info.severity}">${info.severity}</span></td>
    </tr>`).join('');
}

function renderFindings(findings) {
  const tbody = document.getElementById('findings-body');
  if (!findings.length) { tbody.innerHTML = '<tr><td colspan="5" class="empty">Sin hallazgos</td></tr>'; return; }
  tbody.innerHTML = findings.map(f => {
    const file = f.file.split('/').slice(-2).join('/');
    const comp = (f.compliance||[]).map(c => `<span class="tag">${c}</span>`).join('');
    const desc = (f.description||'').substring(0,100) + ((f.description||'').length > 100 ? '...' : '');
    return `<tr>
      <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
      <td><code style="font-size:11px">${f.rule_id}</code></td>
      <td class="path" title="${f.file}:${f.line}">${file}:${f.line}</td>
      <td style="max-width:300px;color:#94a3b8;font-size:12px">${desc}</td>
      <td>${comp}</td>
    </tr>`;
  }).join('');
}

function filterTable() {
  const search = document.getElementById('search').value.toLowerCase();
  const sev    = document.getElementById('sev-filter').value;
  const filtered = allFindings.filter(f =>
    (!sev || f.severity === sev) &&
    (!search || [f.rule_id,f.file,f.description,f.name].join(' ').toLowerCase().includes(search))
  );
  renderFindings(filtered);
  updateStats(filtered);
}

function renderTrend(history) {
  const labels = history.map(r => r.scanned_at.substring(0,10)).reverse();
  const crit   = history.map(r => r.critical).reverse();
  const high   = history.map(r => r.high).reverse();
  const med    = history.map(r => r.medium).reverse();
  const low    = history.map(r => r.low).reverse();
  if (trendChart) trendChart.destroy();
  trendChart = new Chart(document.getElementById('trendChart'), {
    type: 'line',
    data: { labels, datasets: [
      {label:'Crítico', data:crit, borderColor:'#ef4444', backgroundColor:'rgba(239,68,68,.1)', tension:.3, fill:true},
      {label:'Alto',    data:high, borderColor:'#f97316', backgroundColor:'rgba(249,115,22,.1)', tension:.3, fill:true},
      {label:'Medio',   data:med,  borderColor:'#eab308', backgroundColor:'rgba(234,179,8,.1)',  tension:.3, fill:true},
      {label:'Bajo',    data:low,  borderColor:'#3b82f6', backgroundColor:'rgba(59,130,246,.1)', tension:.3, fill:true},
    ]},
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins: {legend:{labels:{color:'#94a3b8',font:{size:11}}}},
      scales: {
        x:{ticks:{color:'#64748b',font:{size:10}}, grid:{color:'#1e2130'}},
        y:{ticks:{color:'#64748b',font:{size:10}}, grid:{color:'#1e2130'}, beginAtZero:true},
      }
    }
  });
}

function renderCompliance(findings) {
  const counts = {};
  findings.forEach(f => (f.compliance||[]).forEach(c => { counts[c] = (counts[c]||0)+1; }));
  const sorted = Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,8);
  if (compChart) compChart.destroy();
  compChart = new Chart(document.getElementById('complianceChart'), {
    type: 'bar',
    data: {
      labels: sorted.map(([k])=>k),
      datasets:[{
        label:'Findings',
        data: sorted.map(([,v])=>v),
        backgroundColor: ['#ef4444','#f97316','#eab308','#3b82f6','#8b5cf6','#22c55e','#06b6d4','#ec4899'],
        borderRadius: 4,
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        x:{ticks:{color:'#64748b',font:{size:10}}, grid:{color:'#1e2130'}},
        y:{ticks:{color:'#64748b',font:{size:10}}, grid:{color:'#1e2130'}, beginAtZero:true},
      }
    }
  });
}

async function triggerScan() {
  document.getElementById('scan-btn').disabled = true;
  document.getElementById('spinner').style.display = 'block';
  document.getElementById('scan-btn').textContent = 'Escaneando...';
  try {
    await fetch('/api/scan', {method:'POST'});
    await load();
  } finally {
    document.getElementById('scan-btn').disabled = false;
    document.getElementById('spinner').style.display = 'none';
    document.getElementById('scan-btn').textContent = '▶ Escanear Ahora';
  }
}

load();
setInterval(load, 30000); // actualizar cada 30 segundos
</script>
</body>
</html>
"""


def _build_app(scan_path: str, db_path: Optional[str] = None):
    """Build and return a Flask WSGI app for the dashboard."""
    try:
        from flask import Flask, jsonify, request as flask_request
    except ImportError:
        raise ImportError(
            "Flask is required for the dashboard. Install with: pip install flask"
        )

    from .history import get_history, record_scan, _db_path
    from .analyzer import run_static_analysis

    app = Flask(__name__, static_folder=None)
    app.config['scan_path'] = os.path.abspath(scan_path)

    # In-memory cache of latest findings
    _state: Dict = {'findings': [], 'last_scan': None}

    def _refresh_from_history():
        rows = get_history(app.config['scan_path'], limit=1, db_path=db_path)
        if rows:
            import sqlite3
            conn = __import__('sqlite3').connect(db_path or _db_path())
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                'SELECT findings_json FROM scans WHERE id=?', (rows[0]['id'],)
            ).fetchone()
            conn.close()
            if row:
                _state['findings'] = json.loads(row['findings_json'])
                _state['last_scan'] = rows[0]['scanned_at'][:19]

    _refresh_from_history()

    @app.route('/')
    def index():
        return _DASHBOARD_HTML, 200, {'Content-Type': 'text/html; charset=utf-8'}

    @app.route('/api/findings')
    def api_findings():
        return jsonify({
            'findings': _state['findings'],
            'scan_path': app.config['scan_path'],
            'last_scan': _state['last_scan'],
            'total': len(_state['findings']),
        })

    @app.route('/api/history')
    def api_history():
        return jsonify(get_history(app.config['scan_path'], limit=20, db_path=db_path))

    @app.route('/api/scan', methods=['POST'])
    def api_scan():
        """Trigger a fresh scan in a background thread."""
        def _do_scan():
            run_static_analysis(
                app.config['scan_path'],
                run_sca=False,
                record_history=True,
            )
            _refresh_from_history()

        t = threading.Thread(target=_do_scan, daemon=True)
        t.start()
        t.join(timeout=120)
        _refresh_from_history()
        return jsonify({'status': 'ok', 'total': len(_state['findings'])})

    return app


def serve_dashboard(
    scan_path: str,
    port: int = 8080,
    host: str = '127.0.0.1',
    open_browser: bool = True,
    scan_first: bool = False,
    db_path: Optional[str] = None,
):
    """Start the AuditLens web dashboard."""
    abs_path = os.path.abspath(scan_path)
    if not os.path.exists(abs_path):
        print(f'\033[91m[ERROR]\033[0m Path does not exist: {abs_path}')
        return

    if scan_first:
        print('\033[94m[AuditLens Dashboard]\033[0m Running initial scan...')
        from .analyzer import run_static_analysis
        run_static_analysis(abs_path, run_sca=False, record_history=True)

    print(f'\033[94m[AuditLens Dashboard]\033[0m Starting at http://{host}:{port}')
    print(f'\033[94m[AuditLens Dashboard]\033[0m Scanning: \033[1m{abs_path}\033[0m')
    print('\033[90mPress Ctrl+C to stop.\033[0m\n')

    if open_browser:
        threading.Timer(1.2, lambda: webbrowser.open(f'http://{host}:{port}')).start()

    app = _build_app(abs_path, db_path)
    # Use werkzeug directly to avoid Flask CLI overhead
    from werkzeug.serving import run_simple
    run_simple(host, port, app, use_reloader=False, use_debugger=False)
