"""
AuditLens Inter-Procedural Taint Analyzer.

Builds a cross-file call graph by resolving Python imports and tracking
taint flow across function boundaries.

Algorithm:
  1. Parse each .py file with ast, extract:
     - FunctionDef nodes → function signatures
     - Import/ImportFrom nodes → module aliases
     - Call nodes → which functions are called with which args
  2. Build a call graph: {(module, func) -> [(callee_module, callee_func, arg_positions)]}
  3. For each user-input source (request.args, input(), etc.), propagate taint
     through the call graph to find sinks in downstream functions.

This catches the classic pattern:
    # views.py
    user_id = request.args['id']
    result = build_query(user_id)    # taint flows here
    db.execute(result)               # sink

    # utils.py
    def build_query(uid):
        return f"SELECT * WHERE id={uid}"  # taint reaches here
"""

from __future__ import annotations

import ast
import os
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple


# ── Data structures ───────────────────────────────────────────────────────────

class FunctionNode:
    """Represents a function definition in a file."""
    __slots__ = ('module', 'name', 'params', 'lineno', 'source_lines')

    def __init__(self, module: str, name: str, params: List[str],
                 lineno: int, source_lines: List[str]):
        self.module = module
        self.name = name
        self.params = params
        self.lineno = lineno
        self.source_lines = source_lines


class CallEdge:
    """Represents a function call at a specific line."""
    __slots__ = ('caller_func', 'callee_module', 'callee_name', 'arg_names', 'lineno')

    def __init__(self, caller_func: str, callee_module: str, callee_name: str,
                 arg_names: List[str], lineno: int):
        self.caller_func = caller_func
        self.callee_module = callee_module
        self.callee_name = callee_name
        self.arg_names = arg_names
        self.lineno = lineno


# ── AST visitors ─────────────────────────────────────────────────────────────

class _ImportCollector(ast.NodeVisitor):
    """Collect all import aliases in a module."""

    def __init__(self):
        # alias → absolute module path (best effort)
        self.imports: Dict[str, str] = {}

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ''
        for alias in node.names:
            name = alias.asname or alias.name
            if name == '*':
                continue
            self.imports[name] = f'{module}.{alias.name}' if module else alias.name
        self.generic_visit(node)


class _FunctionCollector(ast.NodeVisitor):
    """Collect function defs and call sites."""

    def __init__(self, module_name: str, source_lines: List[str],
                 imports: Dict[str, str]):
        self.module_name = module_name
        self.source_lines = source_lines
        self.imports = imports
        self.functions: List[FunctionNode] = []
        self.call_edges: List[CallEdge] = []
        self._current_func: Optional[str] = None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        params = [arg.arg for arg in node.args.args]
        fn = FunctionNode(
            module=self.module_name,
            name=node.name,
            params=params,
            lineno=node.lineno,
            source_lines=self.source_lines,
        )
        self.functions.append(fn)
        old = self._current_func
        self._current_func = node.name
        self.generic_visit(node)
        self._current_func = old

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call):
        if self._current_func is None:
            self.generic_visit(node)
            return

        callee_module, callee_name = self._resolve_call(node.func)
        if callee_name:
            # Collect argument names (identifiers passed positionally)
            arg_names = []
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    arg_names.append(arg.id)
                elif isinstance(arg, ast.Constant):
                    arg_names.append(f'__const_{arg.value!r}')
                else:
                    arg_names.append('__expr')
            for kw in node.keywords:
                if isinstance(kw.value, ast.Name):
                    arg_names.append(kw.value.id)

            self.call_edges.append(CallEdge(
                caller_func=self._current_func,
                callee_module=callee_module or self.module_name,
                callee_name=callee_name,
                arg_names=arg_names,
                lineno=node.lineno,
            ))
        self.generic_visit(node)

    def _resolve_call(self, func_node) -> Tuple[str, str]:
        """Return (module, function_name) from a Call's func attribute."""
        if isinstance(func_node, ast.Name):
            name = func_node.id
            resolved = self.imports.get(name, '')
            parts = resolved.rsplit('.', 1)
            if len(parts) == 2:
                return parts[0], parts[1]
            return '', name

        if isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                obj = func_node.value.id
                method = func_node.attr
                resolved_mod = self.imports.get(obj, obj)
                return resolved_mod, method
        return '', ''


# ── Inter-procedural engine ───────────────────────────────────────────────────

_USER_INPUT_SOURCES = {
    'request.args', 'request.form', 'request.json', 'request.data',
    'request.values', 'request.cookies', 'request.get_json',
    'input', 'sys.argv', 'os.environ', 'os.getenv',
    'req.body', 'req.params', 'req.query',
}

_DANGEROUS_SINKS = {
    'execute', 'raw', 'rawQuery', 'query',
    'system', 'popen', 'run', 'call', 'Popen',
    'render_template_string', 'eval', 'exec',
    'send_file', 'send_from_directory',
    'redirect', 'make_response',
}


class InterProceduralTaintAnalyzer:
    """
    Cross-file taint analysis using a simplified call graph.
    Works on a collection of Python source files.
    """

    def __init__(self):
        # module_name -> list of FunctionNodes
        self._functions: Dict[str, List[FunctionNode]] = defaultdict(list)
        # module_name -> list of CallEdges
        self._calls: Dict[str, List[CallEdge]] = defaultdict(list)
        # (module, func_name) -> FunctionNode
        self._func_index: Dict[Tuple[str, str], FunctionNode] = {}
        # file_path -> module_name
        self._file_to_module: Dict[str, str] = {}

    def load_file(self, file_path: str) -> bool:
        """Parse a Python file and add it to the call graph. Returns False on parse error."""
        if not file_path.endswith('.py'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
                source = fh.read()
                source_lines = source.splitlines()
            tree = ast.parse(source, filename=file_path)
        except (SyntaxError, OSError):
            return False

        module_name = _path_to_module(file_path)
        self._file_to_module[file_path] = module_name

        ic = _ImportCollector()
        ic.visit(tree)

        fc = _FunctionCollector(module_name, source_lines, ic.imports)
        fc.visit(tree)

        for fn in fc.functions:
            self._functions[module_name].append(fn)
            self._func_index[(module_name, fn.name)] = fn

        for edge in fc.call_edges:
            self._calls[module_name].append(edge)

        return True

    def load_directory(self, root_path: str, exclude_dirs: Optional[Set[str]] = None):
        """Load all .py files from a directory tree."""
        exclude = exclude_dirs or {
            'venv', 'env', '.env', '.git', '__pycache__',
            'node_modules', 'build', 'dist', '.tox',
        }
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if d not in exclude]
            for fname in filenames:
                if fname.endswith('.py'):
                    self.load_file(os.path.join(dirpath, fname))

    def analyze(self) -> List[dict]:
        """
        Run inter-procedural taint analysis on the loaded call graph.
        Returns a list of finding dicts.
        """
        findings: List[dict] = []
        visited: Set[Tuple[str, str, str]] = set()  # (module, func, tainted_param)

        # Seed: find all functions that receive tainted data from user-input sources
        tainted_funcs = self._find_tainted_entry_points()

        # BFS/DFS through the call graph
        queue: List[Tuple[str, str, str, int, str]] = []  # (module, func, param, src_line, src_file)
        for mod, func, param, src_line, src_file in tainted_funcs:
            key = (mod, func, param)
            if key not in visited:
                visited.add(key)
                queue.append((mod, func, param, src_line, src_file))

        while queue:
            mod, func_name, tainted_param, src_line, src_file = queue.pop()
            fn_node = self._func_index.get((mod, func_name))
            if fn_node is None:
                continue

            # Check if this function passes tainted param to a dangerous sink
            sink_findings = self._check_sinks_in_function(fn_node, tainted_param, src_file, src_line)
            findings.extend(sink_findings)

            # Propagate taint through outgoing calls from this function
            for edge in self._calls.get(mod, []):
                if edge.caller_func != func_name:
                    continue
                if tainted_param not in edge.arg_names:
                    continue

                # Find which parameter position receives the tainted arg
                tainted_idx = edge.arg_names.index(tainted_param)
                callee_key = (edge.callee_module, edge.callee_name)
                callee_fn = self._func_index.get(callee_key)
                if callee_fn is None:
                    # Unknown function — check if it's a known sink
                    if edge.callee_name in _DANGEROUS_SINKS:
                        findings.append({
                            'rule_id': 'TAINT-02',
                            'name': 'Inter-Procedural Taint Flow to Sink',
                            'description': (
                                f"Tainted value '{tainted_param}' from "
                                f"'{mod}.{func_name}' flows into dangerous "
                                f"function '{edge.callee_name}()' at line {edge.lineno}."
                            ),
                            'file': src_file,
                            'line': edge.lineno,
                            'severity': 'HIGH',
                            'compliance': ['CWE-89', 'CWE-78', 'OWASP-A3:2021'],
                        })
                    continue

                # Propagate to callee
                if tainted_idx < len(callee_fn.params):
                    callee_param = callee_fn.params[tainted_idx]
                    key = (edge.callee_module, edge.callee_name, callee_param)
                    if key not in visited:
                        visited.add(key)
                        # Find the actual file path for the callee
                        callee_file = self._module_to_file(edge.callee_module) or src_file
                        queue.append((
                            edge.callee_module, edge.callee_name,
                            callee_param, edge.lineno, callee_file,
                        ))

        return findings

    def _find_tainted_entry_points(self) -> List[Tuple[str, str, str, int, str]]:
        """
        Find all call sites where a function is called with a user-input source
        as an argument. These are the seeds of taint propagation.
        Returns list of (module, func_name, param_name, line, file_path).
        """
        results = []
        for mod, edges in self._calls.items():
            file_path = self._module_to_file(mod) or mod
            for edge in edges:
                for i, arg in enumerate(edge.arg_names):
                    # Check if arg looks like a user-input source call
                    if any(src in arg for src in ('request', 'input', 'argv', 'environ', 'req')):
                        callee_fn = self._func_index.get((edge.callee_module, edge.callee_name))
                        if callee_fn and i < len(callee_fn.params):
                            param = callee_fn.params[i]
                            results.append((
                                edge.callee_module, edge.callee_name,
                                param, edge.lineno, file_path,
                            ))
        return results

    def _check_sinks_in_function(
        self, fn: FunctionNode, tainted_param: str,
        source_file: str, source_line: int,
    ) -> List[dict]:
        """Scan a function's source lines for dangerous sinks using tainted_param."""
        findings: List[dict] = []
        import re
        sink_re = re.compile(
            r'(?<!\w)(?:' + '|'.join(re.escape(s) for s in _DANGEROUS_SINKS) + r')\s*\(',
            re.IGNORECASE,
        )
        for i, line in enumerate(fn.source_lines[fn.lineno - 1:], start=fn.lineno):
            if tainted_param in line and sink_re.search(line):
                file_path = self._module_to_file(fn.module) or source_file
                findings.append({
                    'rule_id': 'TAINT-02',
                    'name': 'Inter-Procedural Taint Flow to Sink',
                    'description': (
                        f"Parameter '{tainted_param}' in '{fn.module}.{fn.name}()' "
                        f"(tainted from caller at line {source_line}) reaches a "
                        f"dangerous sink. Validate/sanitize before use."
                    ),
                    'file': file_path,
                    'line': i,
                    'severity': 'HIGH',
                    'compliance': ['CWE-89', 'CWE-78', 'CWE-79', 'OWASP-A3:2021'],
                })
                break  # one finding per function per param
        return findings

    def _module_to_file(self, module_name: str) -> Optional[str]:
        """Reverse lookup: module name → file path."""
        for fpath, mod in self._file_to_module.items():
            if mod == module_name:
                return fpath
        return None


def _path_to_module(file_path: str) -> str:
    """Convert a file path to a dotted module name (best effort)."""
    path = os.path.abspath(file_path)
    # Strip .py extension
    if path.endswith('.py'):
        path = path[:-3]
    # Replace path separators with dots
    parts = []
    while True:
        head, tail = os.path.split(path)
        if not tail:
            break
        parts.append(tail)
        path = head
        # Stop at common project root markers
        if tail in ('src', 'app', 'lib') or not head:
            break
    return '.'.join(reversed(parts))
