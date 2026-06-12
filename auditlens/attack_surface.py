"""
AuditLens Attack Surface Graph Analyzer

Walks AST of Python and JavaScript source files to extract:
  - Entry points: HTTP handlers (Flask/Django/FastAPI/Express), CLI arg parsers,
                  env var reads, file reads, stdin
  - Functions / methods: call graph edges
  - Dangerous sinks: SQL execution, subprocess, eval, file write, HTTP requests
  - Taint paths: entry point → sink with intermediate nodes highlighted

The output is a graph dict ready for D3.js force-directed visualization:
  {
    "nodes": [{"id": str, "type": str, "severity": str, "file": str, "line": int, ...}],
    "links": [{"source": str, "target": str, "type": str}],
    "stats": {...}
  }

Usage:
    from auditlens.attack_surface import build_attack_surface_graph
    graph = build_attack_surface_graph('./my_project')
"""

from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ── Node types ────────────────────────────────────────────────────────────────
NT_ENTRY       = 'entry'       # external input (HTTP route, CLI, env)
NT_FUNCTION    = 'function'    # internal function/method
NT_SINK        = 'sink'        # dangerous sink (SQL, subprocess, eval...)
NT_DATA_STORE  = 'datastore'   # DB/file/cache
NT_EXTERNAL    = 'external'    # outbound HTTP call, external service

# Severity for sinks
_SINK_SEVERITY = {
    'eval':                   'CRITICAL',
    'exec':                   'CRITICAL',
    'subprocess':             'CRITICAL',
    'os.system':              'CRITICAL',
    'os.popen':               'CRITICAL',
    'pickle.loads':           'CRITICAL',
    'marshal.loads':          'HIGH',
    'yaml.load':              'HIGH',
    'sql':                    'HIGH',
    'cursor.execute':         'HIGH',
    'raw_input':              'MEDIUM',
    'open':                   'MEDIUM',
    'requests.get':           'MEDIUM',
    'requests.post':          'MEDIUM',
    'urllib':                 'MEDIUM',
    'http.client':            'MEDIUM',
    'smtplib':                'MEDIUM',
    'shutil.rmtree':          'HIGH',
    'os.remove':              'MEDIUM',
    'os.unlink':              'MEDIUM',
    'hashlib.md5':            'MEDIUM',
    'hashlib.sha1':           'MEDIUM',
    'random.random':          'LOW',
    'json.loads':             'LOW',
}

# Flask/FastAPI/Django route decorator patterns
_PY_ROUTE_DECORATORS = {
    'route', 'get', 'post', 'put', 'patch', 'delete',
    'api_view', 'action', 'path', 'url', 'router',
}

# Entry point function name patterns
_PY_ENTRY_PATTERNS = re.compile(
    r'^(main|handle|handler|view|endpoint|callback|hook|'
    r'on_event|process_request|dispatch|resolve|execute)$',
    re.IGNORECASE,
)

# Sink call patterns (dotted or bare)
_SINK_PATTERNS = re.compile(
    r'(eval|exec|subprocess|os\.system|os\.popen|os\.exec|'
    r'pickle\.loads|marshal\.loads|yaml\.load|'
    r'cursor\.execute|\.execute|\.executemany|\.raw|\.query|'
    r'requests\.(get|post|put|delete|patch)|urllib|http\.client|'
    r'open\(|shutil\.rmtree|os\.remove|os\.unlink|'
    r'smtplib|hashlib\.md5|hashlib\.sha1|random\.random)',
    re.IGNORECASE,
)

# JS patterns
_JS_ROUTE_RE = re.compile(
    r'(app|router)\.(get|post|put|patch|delete|use)\s*\(\s*["\'/]',
    re.IGNORECASE,
)
_JS_SINK_RE = re.compile(
    r'(eval\s*\(|exec\s*\(|child_process|execSync|spawnSync|'
    r'\.query\s*\(|\.execute\s*\(|db\.run|db\.exec|'
    r'fs\.writeFile|fs\.unlink|fs\.rmdir|'
    r'require\s*\(\s*[\'"]child_process|'
    r'innerHTML\s*=|outerHTML\s*=|document\.write)',
    re.IGNORECASE,
)
_JS_ENTRY_RE = re.compile(
    r'(exports\.|module\.exports\s*=|router\.|app\.)',
    re.IGNORECASE,
)

# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    id: str
    label: str
    type: str
    severity: str = 'INFO'
    file: str = ''
    line: int = 0
    description: str = ''
    group: int = 0
    calls: List[str] = field(default_factory=list)

@dataclass
class GraphLink:
    source: str
    target: str
    type: str = 'call'
    tainted: bool = False


class AttackSurfaceGraph:
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.links: List[GraphLink] = []
        self._call_map: Dict[str, Set[str]] = {}
        self._func_file: Dict[str, Tuple[str, int]] = {}

    def add_node(self, node: GraphNode) -> None:
        existing = self.nodes.get(node.id)
        if existing:
            # Upgrade severity if higher
            _rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
            if _rank.get(node.severity, 0) > _rank.get(existing.severity, 0):
                existing.severity = node.severity
        else:
            self.nodes[node.id] = node

    def add_link(self, link: GraphLink) -> None:
        key = f'{link.source}→{link.target}'
        if not any(f'{l.source}→{l.target}' == key for l in self.links):
            self.links.append(link)

    def to_dict(self) -> dict:
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        type_counts: Dict[str, int] = {}
        for n in self.nodes.values():
            counts[n.severity] = counts.get(n.severity, 0) + 1
            type_counts[n.type] = type_counts.get(n.type, 0) + 1

        tainted_paths = self._find_tainted_paths()

        return {
            'nodes': [
                {
                    'id': n.id,
                    'label': n.label,
                    'type': n.type,
                    'severity': n.severity,
                    'file': n.file,
                    'line': n.line,
                    'description': n.description,
                    'group': n.group,
                    'tainted': n.id in tainted_paths,
                }
                for n in self.nodes.values()
            ],
            'links': [
                {
                    'source': l.source,
                    'target': l.target,
                    'type': l.type,
                    'tainted': l.tainted,
                }
                for l in self.links
            ],
            'stats': {
                'total_nodes': len(self.nodes),
                'total_links': len(self.links),
                'severity_counts': counts,
                'type_counts': type_counts,
                'tainted_nodes': len(tainted_paths),
            },
        }

    def _find_tainted_paths(self) -> Set[str]:
        """BFS from entry points to sinks to mark tainted nodes."""
        entry_ids = {n.id for n in self.nodes.values() if n.type == NT_ENTRY}
        sink_ids = {n.id for n in self.nodes.values() if n.type == NT_SINK}

        adj: Dict[str, Set[str]] = {}
        for link in self.links:
            adj.setdefault(link.source, set()).add(link.target)

        tainted: Set[str] = set()
        visited: Set[str] = set()
        queue = list(entry_ids)

        while queue:
            node_id = queue.pop(0)
            if node_id in visited:
                continue
            visited.add(node_id)
            tainted.add(node_id)
            if node_id in sink_ids:
                continue
            for neighbor in adj.get(node_id, set()):
                if neighbor not in visited:
                    queue.append(neighbor)

        return tainted & (entry_ids | {
            n.id for n in self.nodes.values()
            if n.type in (NT_FUNCTION, NT_SINK) and n.id in tainted
        })


# ── Python AST analyzer ───────────────────────────────────────────────────────

class _PyVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str, graph: AttackSurfaceGraph):
        self.filepath = filepath
        self.rel_path = filepath
        self.graph = graph
        self._current_func: Optional[str] = None
        self._func_stack: List[str] = []

    def _node_id(self, name: str) -> str:
        return f'{self.rel_path}::{name}'

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def _visit_func(self, node) -> None:
        fname = node.name
        fid = self._node_id(fname)

        # Detect entry points via decorators
        is_entry = False
        entry_desc = ''
        for deco in node.decorator_list:
            deco_name = ''
            if isinstance(deco, ast.Attribute):
                deco_name = deco.attr.lower()
            elif isinstance(deco, ast.Name):
                deco_name = deco.id.lower()
            elif isinstance(deco, ast.Call):
                if isinstance(deco.func, ast.Attribute):
                    deco_name = deco.func.attr.lower()
                elif isinstance(deco.func, ast.Name):
                    deco_name = deco.func.id.lower()

            if deco_name in _PY_ROUTE_DECORATORS:
                is_entry = True
                entry_desc = f'HTTP route handler (decorator: @{deco_name})'
                break

        if is_entry:
            self.graph.add_node(GraphNode(
                id=fid,
                label=fname,
                type=NT_ENTRY,
                severity='INFO',
                file=self.rel_path,
                line=node.lineno,
                description=entry_desc,
                group=1,
            ))
        elif _PY_ENTRY_PATTERNS.match(fname):
            self.graph.add_node(GraphNode(
                id=fid,
                label=fname,
                type=NT_ENTRY,
                severity='INFO',
                file=self.rel_path,
                line=node.lineno,
                description=f'Likely entry point by name convention: {fname}',
                group=1,
            ))
        else:
            self.graph.add_node(GraphNode(
                id=fid,
                label=fname,
                type=NT_FUNCTION,
                severity='INFO',
                file=self.rel_path,
                line=node.lineno,
                group=3,
            ))

        prev = self._current_func
        self._current_func = fid
        self.generic_visit(node)
        self._current_func = prev

    def visit_Call(self, node: ast.Call) -> None:
        callee_name = ''
        if isinstance(node.func, ast.Name):
            callee_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            n = node.func
            while isinstance(n, ast.Attribute):
                parts.append(n.attr)
                n = n.value
            if isinstance(n, ast.Name):
                parts.append(n.id)
            callee_name = '.'.join(reversed(parts))

        if not callee_name:
            self.generic_visit(node)
            return

        callee_id = self._node_id(callee_name)

        # Sink detection
        for sink_key, sev in _SINK_SEVERITY.items():
            if sink_key in callee_name.lower():
                sink_id = f'sink::{self.rel_path}:{node.lineno}::{callee_name}'
                self.graph.add_node(GraphNode(
                    id=sink_id,
                    label=callee_name,
                    type=NT_SINK,
                    severity=sev,
                    file=self.rel_path,
                    line=node.lineno,
                    description=f'Dangerous sink: {callee_name}',
                    group=5,
                ))
                if self._current_func:
                    self.graph.add_link(GraphLink(
                        source=self._current_func,
                        target=sink_id,
                        type='calls_sink',
                    ))
                break
        else:
            # Regular call — only add edge if caller is known
            if self._current_func:
                self.graph.add_link(GraphLink(
                    source=self._current_func,
                    target=callee_id,
                    type='calls',
                ))

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect env var reads and other entry-point patterns."""
        if isinstance(node.value, ast.Call):
            func = node.value.func
            fname = ''
            if isinstance(func, ast.Attribute):
                fname = f'{getattr(func.value, "id", "")}.{func.attr}'
            elif isinstance(func, ast.Name):
                fname = func.id

            if fname in ('os.getenv', 'os.environ.get', 'getenv'):
                target = ''
                if node.targets and isinstance(node.targets[0], ast.Name):
                    target = node.targets[0].id
                nid = f'entry::env::{self.rel_path}:{node.lineno}'
                self.graph.add_node(GraphNode(
                    id=nid,
                    label=f'ENV:{target}',
                    type=NT_ENTRY,
                    severity='LOW',
                    file=self.rel_path,
                    line=node.lineno,
                    description=f'Environment variable read: {target}',
                    group=1,
                ))
                if self._current_func:
                    self.graph.add_link(GraphLink(
                        source=nid,
                        target=self._current_func,
                        type='env_input',
                    ))

        self.generic_visit(node)


def _analyze_python_file(filepath: str, graph: AttackSurfaceGraph) -> None:
    try:
        with open(filepath, encoding='utf-8', errors='replace') as fh:
            source = fh.read()
        tree = ast.parse(source, filename=filepath)
        visitor = _PyVisitor(filepath, graph)
        visitor.visit(tree)
    except SyntaxError:
        pass
    except Exception:
        pass


# ── JavaScript analyzer (regex-based) ────────────────────────────────────────

def _analyze_js_file(filepath: str, graph: AttackSurfaceGraph) -> None:
    try:
        with open(filepath, encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
    except OSError:
        return

    current_func: Optional[str] = None
    func_re = re.compile(
        r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))',
        re.IGNORECASE,
    )

    for lineno, line in enumerate(lines, 1):
        # Route entry points
        m = _JS_ROUTE_RE.search(line)
        if m:
            method = m.group(2).upper()
            path_m = re.search(r'["\']([^"\']+)["\']', line)
            path_str = path_m.group(1) if path_m else '/'
            nid = f'entry::route::{filepath}:{lineno}'
            graph.add_node(GraphNode(
                id=nid,
                label=f'{method} {path_str}',
                type=NT_ENTRY,
                severity='INFO',
                file=filepath,
                line=lineno,
                description=f'Express/Node HTTP {method} route: {path_str}',
                group=1,
            ))

        # Function definitions
        fm = func_re.search(line)
        if fm:
            fname = fm.group(1) or fm.group(2) or f'fn_{lineno}'
            fid = f'{filepath}::{fname}'
            graph.add_node(GraphNode(
                id=fid,
                label=fname,
                type=NT_FUNCTION,
                severity='INFO',
                file=filepath,
                line=lineno,
                group=3,
            ))
            current_func = fid

        # Sinks
        sm = _JS_SINK_RE.search(line)
        if sm:
            sink_name = sm.group(0).split('(')[0].strip()
            # Determine severity
            sev = 'MEDIUM'
            for k, s in _SINK_SEVERITY.items():
                if k in sink_name.lower():
                    sev = s
                    break
            sink_id = f'sink::{filepath}:{lineno}::{sink_name}'
            graph.add_node(GraphNode(
                id=sink_id,
                label=sink_name,
                type=NT_SINK,
                severity=sev,
                file=filepath,
                line=lineno,
                description=f'Dangerous sink: {sink_name}',
                group=5,
            ))
            if current_func:
                graph.add_link(GraphLink(
                    source=current_func,
                    target=sink_id,
                    type='calls_sink',
                ))


# ── Main builder ──────────────────────────────────────────────────────────────

_EXCLUDED_DIRS = {
    'venv', '.venv', 'env', '.env', 'node_modules', '.git',
    '__pycache__', 'build', 'dist', 'site-packages', '.tox', 'coverage',
    'migrations', '.mypy_cache', '.pytest_cache',
}

_SUPPORTED_EXTS = {'.py', '.js', '.ts', '.mjs', '.cjs'}


def build_attack_surface_graph(
    project_path: str,
    max_files: int = 200,
) -> dict:
    """
    Walk a project directory and build the attack surface graph.
    Returns a dict ready for JSON serialization and D3.js rendering.
    """
    graph = AttackSurfaceGraph()
    root = Path(project_path).resolve()
    files_processed = 0

    print(f'\033[94m[AuditLens ASG]\033[0m Analizando superficie de ataque: {project_path}')

    for fpath in sorted(root.rglob('*')):
        if files_processed >= max_files:
            break
        if not fpath.is_file():
            continue
        # Skip excluded dirs
        parts = set(fpath.relative_to(root).parts)
        if parts & _EXCLUDED_DIRS:
            continue
        ext = fpath.suffix.lower()
        if ext not in _SUPPORTED_EXTS:
            continue

        rel = str(fpath.relative_to(root))

        if ext == '.py':
            _analyze_python_file(str(fpath), graph)
        elif ext in ('.js', '.ts', '.mjs', '.cjs'):
            _analyze_js_file(str(fpath), graph)

        files_processed += 1

    # Post-process: remove orphan function nodes with no links
    linked_ids = set()
    for link in graph.links:
        linked_ids.add(link.source)
        linked_ids.add(link.target)

    # Keep all entry/sink nodes even if isolated, remove isolated generic functions
    to_remove = [
        nid for nid, n in graph.nodes.items()
        if n.type == NT_FUNCTION and nid not in linked_ids
    ]
    for nid in to_remove:
        del graph.nodes[nid]

    result = graph.to_dict()

    stats = result['stats']
    print(
        f'\033[92m[AuditLens ASG]\033[0m Grafo construido: '
        f'{stats["total_nodes"]} nodos, {stats["total_links"]} enlaces | '
        f'Entry points: {stats["type_counts"].get("entry", 0)} | '
        f'Sinks: {stats["type_counts"].get("sink", 0)} | '
        f'CRITICAL: {stats["severity_counts"]["CRITICAL"]} '
        f'HIGH: {stats["severity_counts"]["HIGH"]}'
    )
    return result
