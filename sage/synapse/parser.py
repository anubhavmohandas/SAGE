"""
synapse/parser.py — Codebase parser using tree-sitter

Scans a real repo's Python files and extracts:
  - Every function/method defined
  - Every import statement
  - Which functions call which other functions

Builds a NetworkX directed graph from this data.

Teaching note — why tree-sitter:
    We could use Python's built-in `ast` module for Python files.
    But tree-sitter works across languages — Python, JS, Go, Rust.
    SAGE will eventually scan multi-language repos.
    Using tree-sitter now means we don't rewrite the parser later.

Teaching note — what an AST is:
    AST = Abstract Syntax Tree.
    When Python reads your code, it doesn't see text — it builds a tree.

    This code:
        def login(user):
            requests.get(url)

    Becomes a tree like:
        function_definition
          name: "login"
          parameters: ["user"]
          body:
            call
              function: attribute
                object: "requests"
                attr: "get"
              arguments: ["url"]

    Tree-sitter gives us this tree. We walk it to find
    functions, imports, and call relationships.
"""

import os
from pathlib import Path
from typing import Optional
import networkx as nx

# Try tree-sitter imports — explain clearly if missing
try:
    from tree_sitter import Language, Parser
    import tree_sitter_python as tspython
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


def parse_repo(repo_path: str) -> nx.DiGraph:
    """
    Parse an entire repo and return a NetworkX directed graph.

    The graph contains:
      - File nodes (type: file)
      - Function nodes (type: function)
      - Library nodes (type: library) — from imports
      - Edges: CONTAINS, CALLS, IMPORTS

    Args:
        repo_path: Path to the repo root

    Returns:
        nx.DiGraph — the full code knowledge graph

    Teaching note:
        We return a NetworkX DiGraph (Directed Graph).
        Directed means edges have direction: A → B ≠ B → A
        "login_user CALLS requests" is directional — not the reverse.
    """
    if not TREE_SITTER_AVAILABLE:
        print("[synapse] tree-sitter not installed. Run: pip3 install tree-sitter tree-sitter-python")
        print("[synapse] Falling back to basic import scanning...")
        return _parse_repo_basic(repo_path)

    G = nx.DiGraph()
    path = Path(repo_path)

    # Find all Python files
    py_files = list(path.rglob("*.py"))
    # Filter out common non-source dirs
    py_files = [
        f for f in py_files
        if not any(part in f.parts for part in
                   ["__pycache__", ".venv", "venv", "env", "node_modules", ".git"])
    ]

    print(f"[synapse] Found {len(py_files)} Python files to parse")

    # Set up tree-sitter Python parser
    PY_LANGUAGE = Language(tspython.language())
    parser = Parser(PY_LANGUAGE)

    for py_file in py_files:
        _parse_file(G, py_file, path, parser)

    print(f"[synapse] Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


def _parse_file(G: nx.DiGraph, file_path: Path, repo_root: Path, parser):
    """
    Parse a single Python file and add nodes/edges to the graph.

    Extracts:
      - File node
      - Import statements → library nodes + IMPORTS edges
      - Function definitions → function nodes + CONTAINS edges
      - Function calls → CALLS edges (best effort)
    """
    # Relative path for cleaner node IDs
    rel_path = str(file_path.relative_to(repo_root))
    file_id  = f"file:{rel_path}"

    # Add file node
    G.add_node(file_id, {
        "id":    file_id,
        "label": rel_path,
        "type":  "file",
        "path":  str(file_path),
    })

    # Read file content
    try:
        source = file_path.read_bytes()
    except Exception as e:
        print(f"[synapse] Could not read {rel_path}: {e}")
        return

    # Parse with tree-sitter
    tree = parser.parse(source)
    root = tree.root_node

    # Walk the AST
    _extract_imports(G, root, source, file_id)
    _extract_functions(G, root, source, file_id, rel_path)


def _extract_imports(G: nx.DiGraph, root, source: bytes, file_id: str):
    """
    Find all import statements and add library nodes + IMPORTS edges.

    Handles:
      import aiohttp
      import aiohttp as ah
      from aiohttp import ClientSession
      from aiohttp.client import ClientSession
    """
    def walk(node):
        if node.type in ("import_statement", "import_from_statement"):
            # Extract the top-level module name
            module_name = _get_import_module(node, source)
            if module_name and not module_name.startswith("."):
                lib_id = f"lib:{module_name}"
                if not G.has_node(lib_id):
                    G.add_node(lib_id, {
                        "id":    lib_id,
                        "label": module_name,
                        "type":  "library",
                    })
                if not G.has_edge(file_id, lib_id):
                    G.add_edge(file_id, lib_id, label="IMPORTS")

        for child in node.children:
            walk(child)

    walk(root)


def _extract_functions(G: nx.DiGraph, root, source: bytes,
                        file_id: str, rel_path: str):
    """
    Find all function/method definitions and add function nodes.
    Also detects library calls inside function bodies.
    """
    def walk(node, parent_func=None):
        if node.type in ("function_definition", "decorated_definition"):
            # Get the actual function_definition if decorated
            func_node = node
            if node.type == "decorated_definition":
                for child in node.children:
                    if child.type == "function_definition":
                        func_node = child
                        break

            func_name = _get_node_text(func_node, source, "name")
            if func_name:
                func_id = f"func:{rel_path}:{func_name}"
                G.add_node(func_id, {
                    "id":       func_id,
                    "label":    f"{func_name}()",
                    "type":     "function",
                    "file":     rel_path,
                    "name":     func_name,
                    "line":     func_node.start_point[0] + 1,
                })
                # File CONTAINS function
                G.add_edge(file_id, func_id, label="CONTAINS")

                # Detect library calls inside this function
                _extract_calls(G, func_node, source, func_id)

                # Recurse into function body (nested functions)
                for child in func_node.children:
                    walk(child, func_id)
            return

        for child in node.children:
            walk(child, parent_func)

    walk(root)


def _extract_calls(G: nx.DiGraph, func_node, source: bytes, func_id: str):
    """
    Find library calls inside a function body.
    Looks for patterns like: aiohttp.ClientSession(), requests.get()

    Teaching note:
        This is "best effort" — statically knowing EXACTLY what
        a function calls is hard (dynamic dispatch, aliases, etc).
        We catch the obvious cases: module.something() calls.
    """
    def walk(node):
        if node.type == "call":
            # Look for attribute access: module.method()
            func_part = node.child_by_field_name("function")
            if func_part and func_part.type == "attribute":
                obj = func_part.child_by_field_name("object")
                if obj:
                    obj_name = source[obj.start_byte:obj.end_byte].decode("utf-8", errors="ignore")
                    # If this looks like a library name (not 'self', 'cls', etc)
                    if obj_name not in ("self", "cls", "super") and "." not in obj_name:
                        lib_id = f"lib:{obj_name}"
                        if G.has_node(lib_id):
                            if not G.has_edge(func_id, lib_id):
                                G.add_edge(func_id, lib_id, label="USES")

        for child in node.children:
            walk(child)

    walk(func_node)


def _get_import_module(node, source: bytes) -> Optional[str]:
    """Extract the top-level module name from an import node."""
    try:
        text = source[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
        # "import aiohttp" → "aiohttp"
        # "from aiohttp import X" → "aiohttp"
        # "from aiohttp.client import X" → "aiohttp"
        if text.startswith("from "):
            module = text.split("from ")[1].split(" import")[0].strip()
        elif text.startswith("import "):
            module = text.split("import ")[1].split(" as ")[0].strip()
            module = module.split(",")[0].strip()
        else:
            return None
        # Return only top-level package name
        return module.split(".")[0]
    except Exception:
        return None


def _get_node_text(node, source: bytes, field: str) -> Optional[str]:
    """Get the text of a named field from a tree-sitter node."""
    child = node.child_by_field_name(field)
    if child:
        return source[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
    return None


def _parse_repo_basic(repo_path: str) -> nx.DiGraph:
    """
    Fallback parser — no tree-sitter, just scans imports with regex.
    Less accurate but works without any extra deps.

    Teaching note:
        This is why we have fallbacks — if a dependency isn't installed,
        SAGE degrades gracefully instead of crashing.
        "Degrade gracefully" is a real engineering principle.
    """
    import re
    G = nx.DiGraph()
    path = Path(repo_path)

    py_files = [
        f for f in path.rglob("*.py")
        if not any(p in f.parts for p in ["__pycache__", "venv", ".venv"])
    ]

    print(f"[synapse] Basic mode: scanning {len(py_files)} Python files for imports")

    import_re = re.compile(
        r"^(?:from\s+([\w.]+)\s+import|import\s+([\w.,\s]+))", re.MULTILINE
    )

    for py_file in py_files:
        rel_path = str(py_file.relative_to(path))
        file_id  = f"file:{rel_path}"
        G.add_node(file_id, {"id": file_id, "label": rel_path, "type": "file"})

        try:
            text = py_file.read_text(errors="ignore")
        except Exception:
            continue

        for match in import_re.finditer(text):
            module = (match.group(1) or match.group(2) or "").split(".")[0].strip()
            if module:
                lib_id = f"lib:{module}"
                if not G.has_node(lib_id):
                    G.add_node(lib_id, {"id": lib_id, "label": module, "type": "library"})
                G.add_edge(file_id, lib_id, label="IMPORTS")

    print(f"[synapse] Basic graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G
