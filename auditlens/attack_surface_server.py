"""
AuditLens Attack Surface Graph — Flask server + D3.js visualizer.

Serves an interactive force-directed graph of the project's attack surface.
Nodes are colored by type and severity. Click any node for details.

Usage:
    auditlens graph ./project --serve
    # Opens http://127.0.0.1:7777 in the browser
"""

from __future__ import annotations

import json
import os
import threading
import webbrowser
from typing import Optional

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>AuditLens — Attack Surface Graph</title>
<script src="https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js"></script>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', system-ui, sans-serif;
  background: #0d1117;
  color: #e6edf3;
  overflow: hidden;
  height: 100vh;
}

/* ── Toolbar ── */
#toolbar {
  position: absolute; top: 0; left: 0; right: 0; z-index: 10;
  display: flex; align-items: center; gap: 12px;
  padding: 10px 16px;
  background: #161b22;
  border-bottom: 1px solid #30363d;
}
#toolbar h1 { font-size: 14px; color: #58a6ff; white-space: nowrap; }
.stat-chip {
  display: inline-flex; align-items: center; gap: 5px;
  background: #21262d; border: 1px solid #30363d;
  border-radius: 20px; padding: 3px 10px; font-size: 12px;
}
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.dot-critical { background: #da3633; }
.dot-high     { background: #e3b341; }
.dot-medium   { background: #388bfd; }
.dot-entry    { background: #3fb950; }
.dot-sink     { background: #f78166; }
.dot-func     { background: #8b949e; }

#search {
  margin-left: auto;
  background: #21262d; border: 1px solid #30363d;
  color: #e6edf3; border-radius: 6px;
  padding: 4px 10px; font-size: 13px; width: 200px;
}
#search::placeholder { color: #6e7681; }

#filter-group { display: flex; gap: 6px; }
.filter-btn {
  background: #21262d; border: 1px solid #30363d;
  color: #8b949e; border-radius: 6px;
  padding: 3px 10px; font-size: 12px; cursor: pointer;
  transition: all 0.15s;
}
.filter-btn:hover, .filter-btn.active {
  border-color: #58a6ff; color: #58a6ff;
}

/* ── Legend ── */
#legend {
  position: absolute; bottom: 16px; left: 16px; z-index: 10;
  background: #161b22; border: 1px solid #30363d;
  border-radius: 8px; padding: 12px 16px; font-size: 12px;
}
#legend h3 { color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
.legend-item { display: flex; align-items: center; gap: 8px; margin: 4px 0; }
.legend-dot { width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }

/* ── Detail Panel ── */
#detail {
  position: absolute; top: 52px; right: 0; bottom: 0; z-index: 10;
  width: 300px;
  background: #161b22; border-left: 1px solid #30363d;
  padding: 16px; overflow-y: auto;
  transform: translateX(100%); transition: transform 0.2s ease;
}
#detail.open { transform: translateX(0); }
#detail h2 { font-size: 14px; color: #58a6ff; margin-bottom: 12px; word-break: break-all; }
.detail-row { margin: 8px 0; }
.detail-label { font-size: 11px; color: #6e7681; text-transform: uppercase; letter-spacing: 1px; }
.detail-value { font-size: 13px; color: #e6edf3; margin-top: 2px; word-break: break-all; }
.sev-badge {
  display: inline-block; padding: 2px 8px; border-radius: 12px;
  font-size: 12px; font-weight: 600;
}
.sev-CRITICAL { background: #3d1a1a; color: #f85149; border: 1px solid #da3633; }
.sev-HIGH     { background: #3d2e00; color: #d29922; border: 1px solid #9e6a03; }
.sev-MEDIUM   { background: #0d2044; color: #79c0ff; border: 1px solid #388bfd; }
.sev-LOW      { background: #0d2b17; color: #56d364; border: 1px solid #2ea043; }
.sev-INFO     { background: #21262d; color: #8b949e; border: 1px solid #30363d; }

#close-detail {
  float: right; cursor: pointer; color: #6e7681; font-size: 16px;
}
#close-detail:hover { color: #e6edf3; }

/* ── SVG ── */
#graph-container { width: 100%; height: calc(100vh - 48px); margin-top: 48px; }
svg { width: 100%; height: 100%; }

.link { stroke: #30363d; stroke-width: 1.5; }
.link-calls_sink { stroke: #da363380; stroke-width: 2; }
.link-tainted { stroke: #e3b34180; stroke-width: 2; }

.node circle {
  stroke-width: 1.5;
  cursor: pointer;
  transition: r 0.15s;
}
.node circle:hover { stroke-width: 3; }
.node.highlighted circle { stroke-width: 3; }

.node text {
  font-size: 11px; fill: #8b949e;
  pointer-events: none;
  text-anchor: middle;
}
.node.highlighted text { fill: #e6edf3; font-weight: 600; }

/* Tooltip */
#tooltip {
  position: absolute; display: none;
  background: #161b22; border: 1px solid #30363d;
  border-radius: 6px; padding: 8px 12px;
  font-size: 12px; color: #e6edf3;
  pointer-events: none; max-width: 240px; z-index: 20;
}
</style>
</head>
<body>

<div id="toolbar">
  <h1>⚡ AuditLens — Attack Surface Graph</h1>
  <span class="stat-chip"><span class="dot dot-entry"></span><span id="cnt-entry">0</span> Entry Points</span>
  <span class="stat-chip"><span class="dot dot-sink"></span><span id="cnt-sink">0</span> Sinks</span>
  <span class="stat-chip"><span class="dot dot-critical"></span><span id="cnt-critical">0</span> Critical</span>
  <span class="stat-chip"><span class="dot dot-high"></span><span id="cnt-high">0</span> High</span>
  <div id="filter-group">
    <button class="filter-btn active" data-filter="all">All</button>
    <button class="filter-btn" data-filter="entry">Entries</button>
    <button class="filter-btn" data-filter="sink">Sinks</button>
    <button class="filter-btn" data-filter="tainted">Tainted</button>
  </div>
  <input id="search" type="text" placeholder="Search nodes..." />
</div>

<div id="legend">
  <h3>Legend</h3>
  <div class="legend-item"><div class="legend-dot" style="background:#3fb950"></div>Entry Point</div>
  <div class="legend-item"><div class="legend-dot" style="background:#f78166"></div>Dangerous Sink</div>
  <div class="legend-item"><div class="legend-dot" style="background:#79c0ff"></div>Function</div>
  <div class="legend-item"><div class="legend-dot" style="background:#ffa657"></div>Data Store</div>
  <div class="legend-item"><div class="legend-dot" style="background:#d2a8ff"></div>External Call</div>
  <hr style="border-color:#30363d;margin:8px 0">
  <div class="legend-item"><div class="legend-dot" style="background:#da3633;opacity:0.8"></div>CRITICAL severity</div>
  <div class="legend-item"><div class="legend-dot" style="background:#e3b341;opacity:0.8"></div>HIGH severity</div>
  <div class="legend-item" style="font-size:11px;color:#6e7681;margin-top:6px">Scroll to zoom · Drag to pan<br>Click node for details</div>
</div>

<div id="detail">
  <span id="close-detail">✕</span>
  <h2 id="detail-title">Node</h2>
  <div id="detail-content"></div>
</div>

<div id="graph-container"><svg id="graph"></svg></div>
<div id="tooltip"></div>

<script>
const GRAPH_DATA = __GRAPH_DATA__;

const NODE_COLORS = {
  entry:     '#3fb950',
  sink:      '#f78166',
  function:  '#79c0ff',
  datastore: '#ffa657',
  external:  '#d2a8ff',
};
const SEV_STROKE = {
  CRITICAL: '#da3633',
  HIGH:     '#e3b341',
  MEDIUM:   '#388bfd',
  LOW:      '#3fb950',
  INFO:     '#30363d',
};
const NODE_RADIUS = {
  entry: 14, sink: 14, function: 9, datastore: 12, external: 10,
};

// Update stats
const s = GRAPH_DATA.stats;
document.getElementById('cnt-entry').textContent    = s.type_counts.entry || 0;
document.getElementById('cnt-sink').textContent     = s.type_counts.sink || 0;
document.getElementById('cnt-critical').textContent = s.severity_counts.CRITICAL || 0;
document.getElementById('cnt-high').textContent     = s.severity_counts.HIGH || 0;

// D3 setup
const svg = d3.select('#graph');
const container = document.getElementById('graph-container');
const W = () => container.clientWidth;
const H = () => container.clientHeight;

const g = svg.append('g');

svg.call(d3.zoom().scaleExtent([0.1, 6]).on('zoom', (e) => {
  g.attr('transform', e.transform);
}));

// Arrow markers
svg.append('defs').selectAll('marker')
  .data(['default', 'tainted', 'sink'])
  .join('marker')
  .attr('id', d => `arrow-${d}`)
  .attr('viewBox', '0 -5 10 10')
  .attr('refX', 20).attr('refY', 0)
  .attr('markerWidth', 6).attr('markerHeight', 6)
  .attr('orient', 'auto')
  .append('path')
  .attr('d', 'M0,-5L10,0L0,5')
  .attr('fill', d => d === 'tainted' ? '#e3b341' : d === 'sink' ? '#da3633' : '#30363d');

let nodes = [...GRAPH_DATA.nodes];
let links = [...GRAPH_DATA.links];

function buildGraph(filteredNodes, filteredLinks) {
  g.selectAll('*').remove();

  const nodeIds = new Set(filteredNodes.map(n => n.id));
  const visLinks = filteredLinks.filter(l => nodeIds.has(l.source) && nodeIds.has(l.target));

  // Simulation
  const sim = d3.forceSimulation(filteredNodes)
    .force('link', d3.forceLink(visLinks).id(d => d.id).distance(d =>
      d.type === 'calls_sink' ? 80 : 60
    ).strength(0.8))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(W() / 2, H() / 2))
    .force('collision', d3.forceCollide(d => (NODE_RADIUS[d.type] || 10) + 5))
    .force('x', d3.forceX(W() / 2).strength(0.03))
    .force('y', d3.forceY(H() / 2).strength(0.03));

  // Links
  const link = g.append('g').attr('class', 'links')
    .selectAll('line')
    .data(visLinks)
    .join('line')
    .attr('class', d => `link link-${d.type}${d.tainted ? ' link-tainted' : ''}`)
    .attr('marker-end', d =>
      d.type === 'calls_sink' ? 'url(#arrow-sink)' :
      d.tainted ? 'url(#arrow-tainted)' : 'url(#arrow-default)'
    );

  // Nodes
  const node = g.append('g').attr('class', 'nodes')
    .selectAll('g')
    .data(filteredNodes)
    .join('g')
    .attr('class', 'node')
    .call(d3.drag()
      .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
      .on('end',   (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
    );

  node.append('circle')
    .attr('r', d => NODE_RADIUS[d.type] || 9)
    .attr('fill', d => NODE_COLORS[d.type] || '#79c0ff')
    .attr('fill-opacity', d => d.tainted ? 1 : 0.7)
    .attr('stroke', d => SEV_STROKE[d.severity] || '#30363d')
    .on('mouseover', (e, d) => {
      const tip = document.getElementById('tooltip');
      tip.style.display = 'block';
      tip.style.left = (e.pageX + 14) + 'px';
      tip.style.top  = (e.pageY - 8) + 'px';
      tip.innerHTML = `<strong>${d.label}</strong><br>${d.file}:${d.line}<br><em>${d.type} · ${d.severity}</em>`;
    })
    .on('mousemove', (e) => {
      const tip = document.getElementById('tooltip');
      tip.style.left = (e.pageX + 14) + 'px';
      tip.style.top  = (e.pageY - 8) + 'px';
    })
    .on('mouseout', () => {
      document.getElementById('tooltip').style.display = 'none';
    })
    .on('click', (e, d) => {
      e.stopPropagation();
      showDetail(d);
      d3.selectAll('.node').classed('highlighted', false);
      d3.select(e.currentTarget.parentNode).classed('highlighted', true);
    });

  node.append('text')
    .attr('dy', d => (NODE_RADIUS[d.type] || 9) + 12)
    .text(d => d.label.length > 20 ? d.label.slice(0, 18) + '…' : d.label);

  // Pulse animation on CRITICAL sinks
  node.filter(d => d.severity === 'CRITICAL' || (d.type === 'sink' && d.severity === 'HIGH'))
    .select('circle')
    .style('animation', 'pulse 2s infinite');

  sim.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);
    node.attr('transform', d => `translate(${d.x},${d.y})`);
  });
}

function showDetail(d) {
  const panel = document.getElementById('detail');
  panel.classList.add('open');
  document.getElementById('detail-title').textContent = d.label;
  const sev = d.severity || 'INFO';
  document.getElementById('detail-content').innerHTML = `
    <div class="detail-row">
      <div class="detail-label">Severity</div>
      <div class="detail-value"><span class="sev-badge sev-${sev}">${sev}</span></div>
    </div>
    <div class="detail-row">
      <div class="detail-label">Type</div>
      <div class="detail-value">${d.type}</div>
    </div>
    <div class="detail-row">
      <div class="detail-label">File</div>
      <div class="detail-value">${d.file}</div>
    </div>
    <div class="detail-row">
      <div class="detail-label">Line</div>
      <div class="detail-value">${d.line}</div>
    </div>
    ${d.description ? `<div class="detail-row">
      <div class="detail-label">Description</div>
      <div class="detail-value">${d.description}</div>
    </div>` : ''}
    <div class="detail-row">
      <div class="detail-label">Tainted path</div>
      <div class="detail-value">${d.tainted ? '⚠️ Yes — reachable from entry point' : '✓ No'}</div>
    </div>
  `;
}

document.getElementById('close-detail').addEventListener('click', () => {
  document.getElementById('detail').classList.remove('open');
  d3.selectAll('.node').classed('highlighted', false);
});

// Filters
let currentFilter = 'all';
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter;
    applyFilter();
  });
});

function applyFilter() {
  const q = document.getElementById('search').value.toLowerCase();
  let fn = nodes, fl = links;

  if (currentFilter === 'entry')   fn = nodes.filter(n => n.type === 'entry');
  if (currentFilter === 'sink')    fn = nodes.filter(n => n.type === 'sink');
  if (currentFilter === 'tainted') fn = nodes.filter(n => n.tainted);

  if (q) fn = fn.filter(n =>
    n.label.toLowerCase().includes(q) ||
    n.file.toLowerCase().includes(q) ||
    (n.description || '').toLowerCase().includes(q)
  );

  buildGraph(fn, fl);
}

document.getElementById('search').addEventListener('input', applyFilter);
svg.on('click', () => {
  document.getElementById('detail').classList.remove('open');
  d3.selectAll('.node').classed('highlighted', false);
});

// Initial render
buildGraph(nodes, links);

// Pulse keyframe
const style = document.createElement('style');
style.textContent = '@keyframes pulse { 0%,100%{r:14} 50%{r:17} }';
document.head.appendChild(style);
</script>
</body>
</html>
"""


def _build_html(graph_data: dict) -> str:
    return _HTML_TEMPLATE.replace(
        '__GRAPH_DATA__',
        json.dumps(graph_data, ensure_ascii=False, separators=(',', ':')),
    )


def serve_attack_surface_graph(
    graph_data: dict,
    port: int = 7777,
    host: str = '127.0.0.1',
    open_browser: bool = True,
) -> None:
    """Serve the attack surface graph as an interactive HTML page."""
    try:
        from flask import Flask, Response
    except ImportError:
        _save_and_open(graph_data, open_browser)
        return

    html = _build_html(graph_data)
    app = Flask(__name__)

    @app.route('/')
    def index():
        return Response(html, content_type='text/html; charset=utf-8')

    @app.route('/api/graph')
    def api_graph():
        return Response(
            json.dumps(graph_data, ensure_ascii=False),
            content_type='application/json',
        )

    url = f'http://{host}:{port}'
    print(f'\033[92m[AuditLens ASG]\033[0m Servidor iniciado: {url}')
    print('\033[90m  Ctrl+C para detener\033[0m')

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    app.run(host=host, port=port, debug=False, use_reloader=False)


def _save_and_open(graph_data: dict, open_browser: bool = True) -> str:
    """Fallback: save to HTML file and open in browser."""
    import tempfile
    html = _build_html(graph_data)
    fd, path = tempfile.mkstemp(suffix='.html', prefix='auditlens_asg_')
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        fh.write(html)
    print(f'\033[92m[AuditLens ASG]\033[0m Grafo guardado: {path}')
    if open_browser:
        webbrowser.open(f'file://{path}')
    return path


def export_graph_html(graph_data: dict, output_path: str) -> str:
    """Export graph to a standalone HTML file."""
    html = _build_html(graph_data)
    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html)
    print(f'\033[92m[AuditLens ASG]\033[0m HTML exportado: {output_path}')
    return output_path
