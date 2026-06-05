"""
synapse/parser.py — Codebase parser using tree-sitter

Scans a repo's Python and JS/TS files and extracts:
  - Every function/method defined
  - Every import statement
  - Which functions call which other functions

Builds a NetworkX directed graph from this data.

Supported languages:
  - Python  (.py)         via tree-sitter-python
  - JavaScript (.js, .jsx) via tree-sitter-javascript
  - TypeScript (.ts, .tsx) via tree-sitter-typescript

Teaching note — why tree-sitter:
    tree-sitter works across languages with a uniform API.
    Each language has its own grammar package (tree-sitter-python, etc.)
    but the Parser, Node, and traversal API are identical.
    Adding a new language = install grammar + map its AST node type names.

Teaching note — what an AST is:
    AST = Abstract Syntax Tree.
    When a language parser reads code, it builds a tree.

    Python:                          JavaScript:
      def login(user):                 function login(user) {
          requests.get(url)              axios.get(url);
                                       }

    Both produce similar tree shapes — function node with a call inside.
    The node TYPE NAMES differ per language (function_definition vs
    function_declaration), which is why we have language-specific extractors.
"""

import re
from pathlib import Path
from typing import Optional
import networkx as nx
from sage.utils.colors import cprint

# ── tree-sitter availability flags ───────────────────────────────────────────

try:
    from tree_sitter import Language, Parser
    _TS_CORE = True
except ImportError:
    _TS_CORE = False

try:
    import tree_sitter_python as _tspython
    _TS_PYTHON = True
except ImportError:
    _TS_PYTHON = False

try:
    import tree_sitter_javascript as _tsjs
    _TS_JS = True
except ImportError:
    _TS_JS = False

try:
    import tree_sitter_typescript as _tsts
    _TS_TS = True
except ImportError:
    _TS_TS = False

TREE_SITTER_AVAILABLE = _TS_CORE and _TS_PYTHON

# Dirs to always skip when walking a repo
_SKIP_DIRS = {"__pycache__", ".venv", "venv", "env", "node_modules", ".git",
              "dist", "build", ".next", "out", "coverage", ".cache"}


# ── Public entry point ────────────────────────────────────────────────────────

def parse_repo(repo_path: str) -> nx.DiGraph:
    """
    Parse an entire repo and return a NetworkX directed graph.

    Detects Python, JavaScript, and TypeScript files automatically.
    The graph schema is language-agnostic:

      Nodes:
        type=file     — source file
        type=function — function, method, or arrow function
        type=library  — imported package

      Edges:
        CONTAINS — file → function
        IMPORTS  — file → library
        USES     — function → library (call site)

    Args:
        repo_path: Path to the repo root

    Returns:
        nx.DiGraph — the full code knowledge graph
    """
    if not TREE_SITTER_AVAILABLE:
        cprint("[synapse] tree-sitter or tree-sitter-python not installed.")
        cprint("[synapse] Run: pip install tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-typescript")
        cprint("[synapse] Falling back to basic import scanning...")
        return _parse_repo_basic(repo_path)

    G = nx.DiGraph()
    path = Path(repo_path)

    # Build parsers for available languages
    parsers = {}
    py_lang = Language(_tspython.language())
    parsers["python"] = Parser(py_lang)

    if _TS_JS and _TS_CORE:
        js_lang = Language(_tsjs.language())
        parsers["javascript"] = Parser(js_lang)

    if _TS_TS and _TS_CORE:
        ts_lang = Language(_tsts.language_typescript())
        tsx_lang = Language(_tsts.language_tsx())
        parsers["typescript"] = Parser(ts_lang)
        parsers["tsx"] = Parser(tsx_lang)

    # Collect files by language
    ext_to_lang = {
        ".py":  "python",
        ".js":  "javascript",
        ".jsx": "javascript",
        ".ts":  "typescript",
        ".tsx": "tsx",
    }

    files_by_lang: dict[str, list[Path]] = {}
    for ext, lang in ext_to_lang.items():
        if lang not in parsers:
            continue
        found = [
            f for f in path.rglob(f"*{ext}")
            if not any(part in _SKIP_DIRS for part in f.parts)
        ]
        files_by_lang.setdefault(lang, []).extend(found)

    # Report what was found
    total = sum(len(v) for v in files_by_lang.values())
    for lang, files in sorted(files_by_lang.items()):
        if files:
            cprint(f"[synapse] Found {len(files)} {lang} files to parse")
    if not total:
        cprint("[synapse] No source files found.")

    # Parse each file
    for lang, files in files_by_lang.items():
        parser = parsers[lang]
        for f in files:
            if lang == "python":
                _parse_python_file(G, f, path, parser)
            else:
                _parse_js_file(G, f, path, parser, lang)

    cprint(f"[synapse] Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


# ── Python parser ─────────────────────────────────────────────────────────────

def _parse_python_file(G: nx.DiGraph, file_path: Path, repo_root: Path, parser):
    """Parse a single Python file and add nodes/edges to the graph."""
    rel_path = str(file_path.relative_to(repo_root))
    file_id  = f"file:{rel_path}"
    G.add_node(file_id, id=file_id, label=rel_path, type="file",
               path=str(file_path), lang="python")

    try:
        source = file_path.read_bytes()
    except Exception as e:
        cprint(f"[synapse] Could not read {rel_path}: {e}")
        return

    tree = parser.parse(source)
    root = tree.root_node
    import_aliases = _py_extract_imports(G, root, source, file_id)
    _py_extract_functions(G, root, source, file_id, rel_path, import_aliases)


def _py_extract_imports(G: nx.DiGraph, root, source: bytes, file_id: str) -> dict:
    """
    Find all Python import statements → library nodes + IMPORTS edges.

    Handles:
      import aiohttp
      import aiohttp as ah
      from aiohttp import ClientSession
      from aiohttp.client import ClientSession

    Returns import_aliases: {imported_symbol → lib_id}
    Used by _py_extract_calls to resolve `from X import Y; Y()` patterns.
    """
    import_aliases = {}

    def walk(node):
        if node.type in ("import_statement", "import_from_statement"):
            module_name = _py_get_import_module(node, source)
            if module_name and not module_name.startswith("."):
                lib_id = f"lib:{module_name}"
                if not G.has_node(lib_id):
                    G.add_node(lib_id, id=lib_id, label=module_name, type="library")
                if not G.has_edge(file_id, lib_id):
                    G.add_edge(file_id, lib_id, label="IMPORTS")

                text = source[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
                if text.startswith("from ") and " import " in text:
                    imports_part = text.split(" import ", 1)[1].strip().strip("()\\ \n")
                    for item in imports_part.split(","):
                        item = item.strip().split("#")[0].strip()
                        if " as " in item:
                            _, alias = item.split(" as ", 1)
                            import_aliases[alias.strip()] = lib_id
                        elif item:
                            import_aliases[item.strip()] = lib_id

        for child in node.children:
            walk(child)

    walk(root)
    return import_aliases


def _py_extract_functions(G: nx.DiGraph, root, source: bytes,
                           file_id: str, rel_path: str, import_aliases: dict):
    """Find Python function/method definitions and add to graph."""

    def walk(node):
        if node.type in ("function_definition", "decorated_definition"):
            func_node = node
            if node.type == "decorated_definition":
                for child in node.children:
                    if child.type == "function_definition":
                        func_node = child
                        break

            func_name = _get_field_text(func_node, source, "name")
            if func_name:
                func_id = f"func:{rel_path}:{func_name}"
                G.add_node(func_id, id=func_id, label=f"{func_name}()",
                           type="function", file=rel_path, name=func_name,
                           line=func_node.start_point[0] + 1, lang="python")
                G.add_edge(file_id, func_id, label="CONTAINS")
                _py_extract_calls(G, func_node, source, func_id, import_aliases)

                for child in func_node.children:
                    walk(child)
            return

        for child in node.children:
            walk(child)

    walk(root)


def _py_extract_calls(G: nx.DiGraph, func_node, source: bytes,
                       func_id: str, import_aliases: dict):
    """Find library call sites inside a Python function body."""

    def walk(node):
        if node.type == "call":
            func_part = node.child_by_field_name("function")
            if func_part:
                if func_part.type == "attribute":
                    obj = func_part.child_by_field_name("object")
                    if obj:
                        obj_name = source[obj.start_byte:obj.end_byte].decode("utf-8", errors="ignore")
                        if obj_name not in ("self", "cls", "super") and "." not in obj_name:
                            lib_id = f"lib:{obj_name}"
                            if G.has_node(lib_id) and not G.has_edge(func_id, lib_id):
                                G.add_edge(func_id, lib_id, label="USES")

                elif func_part.type == "identifier":
                    name = source[func_part.start_byte:func_part.end_byte].decode("utf-8", errors="ignore")
                    if name in import_aliases:
                        lib_id = import_aliases[name]
                        if G.has_node(lib_id) and not G.has_edge(func_id, lib_id):
                            G.add_edge(func_id, lib_id, label="USES")

        for child in node.children:
            walk(child)

    walk(func_node)


def _py_get_import_module(node, source: bytes) -> Optional[str]:
    """Extract top-level module name from a Python import node."""
    try:
        text = source[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
        if text.startswith("from "):
            module = text.split("from ")[1].split(" import")[0].strip()
        elif text.startswith("import "):
            module = text.split("import ")[1].split(" as ")[0].strip()
            module = module.split(",")[0].strip()
        else:
            return None
        return module.split(".")[0]
    except Exception:
        return None


# ── JS / TS parser ────────────────────────────────────────────────────────────

def _parse_js_file(G: nx.DiGraph, file_path: Path, repo_root: Path,
                   parser, lang: str):
    """
    Parse a single JS/TS/JSX/TSX file and add nodes/edges to the graph.

    JS/TS AST node types we handle:

    Imports:
      import_statement          — ES module: import X from 'y'
      lexical_declaration       — CommonJS: const x = require('y')

    Functions:
      function_declaration      — function foo() {}
      export_statement wrapping function_declaration
      arrow_function            — const foo = () => {}  (via variable_declarator)
      method_definition         — class methods
    """
    rel_path = str(file_path.relative_to(repo_root))
    file_id  = f"file:{rel_path}"
    G.add_node(file_id, id=file_id, label=rel_path, type="file",
               path=str(file_path), lang=lang)

    try:
        source = file_path.read_bytes()
    except Exception as e:
        cprint(f"[synapse] Could not read {rel_path}: {e}")
        return

    tree = parser.parse(source)
    root = tree.root_node
    import_aliases = _js_extract_imports(G, root, source, file_id)
    _js_extract_functions(G, root, source, file_id, rel_path, import_aliases)


def _js_extract_imports(G: nx.DiGraph, root, source: bytes, file_id: str) -> dict:
    """
    Find JS/TS imports and add library nodes + IMPORTS edges.

    Handles three forms:

    1. ES module default:
         import React from 'react'
         import_clause → identifier → 'React'

    2. ES module named:
         import { useState, useEffect } from 'react'
         import_clause → named_imports → import_specifier(s)

    3. CommonJS require:
         const axios = require('axios')
         lexical_declaration → variable_declarator → call_expression(require)

    Returns import_aliases: {symbol → lib_id}
    """
    import_aliases = {}

    def walk(node):
        # ── ES module import ──────────────────────────────────────────────
        if node.type == "import_statement":
            module_name = _js_get_import_module(node, source)
            if module_name:
                lib_id = _register_lib(G, file_id, module_name)

                # Default import: import React from 'react' → alias React→lib:react
                clause = node.child_by_field_name("import")  # import_clause node
                if clause:
                    for child in clause.children:
                        if child.type == "identifier":
                            name = source[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
                            import_aliases[name] = lib_id

                        elif child.type == "named_imports":
                            # { useState, useEffect as ue }
                            for spec in child.children:
                                if spec.type == "import_specifier":
                                    # alias is the local name (after 'as' if present)
                                    alias_node = spec.child_by_field_name("alias")
                                    name_node  = spec.child_by_field_name("name")
                                    local = alias_node or name_node
                                    if local:
                                        sym = source[local.start_byte:local.end_byte].decode("utf-8", errors="ignore")
                                        import_aliases[sym] = lib_id

        # ── CommonJS require ──────────────────────────────────────────────
        elif node.type in ("lexical_declaration", "variable_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    _js_handle_require(G, child, source, file_id, import_aliases)

        for child in node.children:
            walk(child)

    walk(root)
    return import_aliases


def _js_handle_require(G: nx.DiGraph, declarator, source: bytes,
                        file_id: str, import_aliases: dict):
    """
    Detect `const x = require('module')` and register the library.
    Also handles destructured: const { readFile } = require('fs')
    """
    value = declarator.child_by_field_name("value")
    if not value:
        return

    # Direct: const axios = require('axios')
    if value.type == "call_expression":
        fn = value.child_by_field_name("function")
        args = value.child_by_field_name("arguments")
        if fn and source[fn.start_byte:fn.end_byte].decode("utf-8", errors="ignore") == "require":
            module_name = _js_string_from_args(args, source)
            if module_name:
                lib_id = _register_lib(G, file_id, module_name)
                # Bind the variable name
                name_node = declarator.child_by_field_name("name")
                if name_node:
                    if name_node.type == "identifier":
                        sym = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="ignore")
                        import_aliases[sym] = lib_id
                    elif name_node.type == "object_pattern":
                        # const { readFile, writeFile } = require('fs')
                        for child in name_node.children:
                            if child.type in ("shorthand_property_identifier_pattern",
                                              "identifier"):
                                sym = source[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
                                import_aliases[sym] = lib_id


def _js_extract_functions(G: nx.DiGraph, root, source: bytes,
                           file_id: str, rel_path: str, import_aliases: dict):
    """
    Find JS/TS function definitions and add to graph.

    Handles:
      function_declaration       — function foo() {}
      export_statement           — export function foo() {} / export default function
      arrow_function             — const foo = () => {}  (via variable_declarator)
      method_definition          — class methods
    """

    def walk(node):
        # ── Named function declaration ─────────────────────────────────────
        if node.type == "function_declaration":
            _js_register_func(G, node, source, file_id, rel_path, import_aliases,
                              name_field="name")
            return  # don't recurse into body — nested funcs handled by recursion

        # ── export function foo() / export default function ────────────────
        if node.type == "export_statement":
            for child in node.children:
                if child.type == "function_declaration":
                    _js_register_func(G, child, source, file_id, rel_path,
                                      import_aliases, name_field="name")
                    return

        # ── Arrow / anonymous: const foo = () => {} ───────────────────────
        if node.type in ("lexical_declaration", "variable_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    val = child.child_by_field_name("value")
                    if val and val.type in ("arrow_function", "function"):
                        name_node = child.child_by_field_name("name")
                        if name_node and name_node.type == "identifier":
                            func_name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="ignore")
                            _js_register_named_func(G, val, source, file_id, rel_path,
                                                    import_aliases, func_name)

        # ── Class method ───────────────────────────────────────────────────
        if node.type == "method_definition":
            key = node.child_by_field_name("name")
            if key:
                func_name = source[key.start_byte:key.end_byte].decode("utf-8", errors="ignore")
                _js_register_named_func(G, node, source, file_id, rel_path,
                                        import_aliases, func_name)
            return

        for child in node.children:
            walk(child)

    walk(root)


def _js_register_func(G: nx.DiGraph, node, source: bytes, file_id: str,
                       rel_path: str, import_aliases: dict, name_field: str):
    """Register a JS function node from a declaration with a named field."""
    name_node = node.child_by_field_name(name_field)
    if not name_node:
        return
    func_name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="ignore")
    _js_register_named_func(G, node, source, file_id, rel_path, import_aliases, func_name)


def _js_register_named_func(G: nx.DiGraph, node, source: bytes, file_id: str,
                              rel_path: str, import_aliases: dict, func_name: str):
    """Add a function node and scan its body for library calls."""
    func_id = f"func:{rel_path}:{func_name}"
    if not G.has_node(func_id):
        G.add_node(func_id, id=func_id, label=f"{func_name}()", type="function",
                   file=rel_path, name=func_name,
                   line=node.start_point[0] + 1, lang="js")
        G.add_edge(file_id, func_id, label="CONTAINS")
    _js_extract_calls(G, node, source, func_id, import_aliases)


def _js_extract_calls(G: nx.DiGraph, func_node, source: bytes,
                       func_id: str, import_aliases: dict):
    """
    Find library call sites inside a JS/TS function body.

    Patterns:
      axios.get(url)       — member_expression call → object name matches lib
      useState(...)        — direct call → identifier in import_aliases
      require('x')         — already handled in import phase, skip
    """

    def walk(node):
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn:
                if fn.type == "member_expression":
                    # axios.get() — check if 'axios' is a known lib
                    obj = fn.child_by_field_name("object")
                    if obj and obj.type == "identifier":
                        obj_name = source[obj.start_byte:obj.end_byte].decode("utf-8", errors="ignore")
                        lib_id = f"lib:{obj_name}"
                        if G.has_node(lib_id) and not G.has_edge(func_id, lib_id):
                            G.add_edge(func_id, lib_id, label="USES")
                        # Also check import_aliases
                        if obj_name in import_aliases:
                            lib_id = import_aliases[obj_name]
                            if G.has_node(lib_id) and not G.has_edge(func_id, lib_id):
                                G.add_edge(func_id, lib_id, label="USES")

                elif fn.type == "identifier":
                    name = source[fn.start_byte:fn.end_byte].decode("utf-8", errors="ignore")
                    if name != "require" and name in import_aliases:
                        lib_id = import_aliases[name]
                        if G.has_node(lib_id) and not G.has_edge(func_id, lib_id):
                            G.add_edge(func_id, lib_id, label="USES")

        for child in node.children:
            walk(child)

    walk(func_node)


def _js_get_import_module(node, source: bytes) -> Optional[str]:
    """
    Extract package name from an ES import_statement node.
    'import X from "react"' → 'react'
    '@scope/pkg' → '@scope/pkg' (keep scoped names intact)
    """
    try:
        # The string source is the last child (the from-clause string)
        for child in reversed(node.children):
            if child.type == "string":
                raw = source[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
                # Strip quotes
                module = raw.strip("'\"` ")
                # Return top-level package (handle @scope/pkg → @scope/pkg, pkg/sub → pkg)
                if module.startswith("@"):
                    return "/".join(module.split("/")[:2])  # @scope/pkg
                return module.split("/")[0]
    except Exception:
        pass
    return None


def _js_string_from_args(args_node, source: bytes) -> Optional[str]:
    """Extract the string value from a call's argument list — for require('x')."""
    if not args_node:
        return None
    for child in args_node.children:
        if child.type == "string":
            raw = source[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
            module = raw.strip("'\"` ")
            if module.startswith("@"):
                return "/".join(module.split("/")[:2])
            return module.split("/")[0]
    return None


def _register_lib(G: nx.DiGraph, file_id: str, module_name: str) -> str:
    """Add a library node and IMPORTS edge if not already present. Returns lib_id."""
    # Skip relative imports (./foo, ../bar)
    if module_name.startswith("."):
        return f"lib:{module_name}"
    # Skip Node built-ins that aren't useful as CVE targets
    _NODE_BUILTINS = {"fs", "path", "os", "http", "https", "crypto", "util",
                      "events", "stream", "buffer", "child_process", "cluster",
                      "net", "dns", "url", "querystring", "readline", "zlib"}
    lib_id = f"lib:{module_name}"
    if not G.has_node(lib_id):
        G.add_node(lib_id, id=lib_id, label=module_name, type="library",
                   builtin=(module_name in _NODE_BUILTINS))
    if not G.has_edge(file_id, lib_id):
        G.add_edge(file_id, lib_id, label="IMPORTS")
    return lib_id


# ── Shared helpers ────────────────────────────────────────────────────────────

def _get_field_text(node, source: bytes, field: str) -> Optional[str]:
    """Get the text of a named field from a tree-sitter node."""
    child = node.child_by_field_name(field)
    if child:
        return source[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
    return None


# ── Fallback (no tree-sitter) ─────────────────────────────────────────────────

def _parse_repo_basic(repo_path: str) -> nx.DiGraph:
    """
    Fallback parser — regex-based import scanning when tree-sitter isn't installed.
    Covers Python and JS/TS. Less accurate but works with zero extra deps.
    """
    G = nx.DiGraph()
    path = Path(repo_path)

    py_re = re.compile(
        r"^(?:from\s+([\w.]+)\s+import|import\s+([\w.,\s]+))", re.MULTILINE
    )
    js_re = re.compile(
        r"""(?:import\s+.*?\s+from\s+['"](@?[\w./\-@]+)['"]|require\s*\(\s*['"](@?[\w./\-@]+)['"]\s*\))""",
        re.MULTILINE,
    )

    exts = {".py": py_re, ".js": js_re, ".jsx": js_re, ".ts": js_re, ".tsx": js_re}

    total = 0
    for ext, pattern in exts.items():
        files = [
            f for f in path.rglob(f"*{ext}")
            if not any(p in _SKIP_DIRS for p in f.parts)
        ]
        for src_file in files:
            rel_path = str(src_file.relative_to(path))
            file_id  = f"file:{rel_path}"
            G.add_node(file_id, id=file_id, label=rel_path, type="file")
            try:
                text = src_file.read_text(errors="ignore")
            except Exception:
                continue
            for match in pattern.finditer(text):
                module = next((g for g in match.groups() if g), "").split(".")[0].strip()
                if module and not module.startswith("."):
                    lib_id = f"lib:{module}"
                    if not G.has_node(lib_id):
                        G.add_node(lib_id, id=lib_id, label=module, type="library")
                    G.add_edge(file_id, lib_id, label="IMPORTS")
            total += 1

    cprint(f"[synapse] Basic mode: {total} files scanned, "
           f"{G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G
