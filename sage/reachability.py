"""
sage/reachability.py — Reachability analysis engine

Answers: "Is this CVE actually reachable in my code?"

Algorithm:
  1. For each CVE node in the graph, find its library node.
  2. Walk the graph backwards from library → USES edges → functions.
  3. From each function, walk backwards up CALLS edges toward entry points.
  4. Entry points are: public functions (no leading _), HTTP handlers, CLI commands,
     __main__ blocks, pytest test functions.
  5. Output: list of call paths from entry_point → ... → vulnerable_library.

This transforms the question from:
  "Does my code import this library?" (blast radius)
to:
  "Can an attacker reach the vulnerable code path?" (reachability)

The result is fed to the analyzer as additional context, letting the LLM
confirm whether the path is actually exploitable — not just present.

Graph edge types used:
  CALLS     function_A → function_B  (A calls B)
  USES      function_A → library_B   (A uses library_B)
  CONTAINS  file_A → function_B      (file contains function)
  DEPENDS   library_A → cve_B        (library affected by CVE)

Walk direction (reversed):
  cve → library (via DEPENDS, reversed)
  library → function (via USES, reversed)
  function → function (via CALLS, reversed — find callers)
  function → entry (stop when entry point detected)
"""

from __future__ import annotations

import re
from typing import Optional
import networkx as nx


# Max depth for caller traversal — prevents infinite loops in recursive code
MAX_DEPTH = 8

# Entry point detection patterns
ENTRY_PATTERNS = [
    re.compile(r"^(main|run|start|serve|app|cli|handle|dispatch|execute)"),
    re.compile(r"^test_"),          # pytest
    re.compile(r"^on_"),            # event handlers
    re.compile(r"_(handler|view|route|endpoint|command)$"),
    re.compile(r"^__"),             # dunder methods (__init__, __call__)
]

HTTP_FRAMEWORKS = {"flask", "fastapi", "django", "starlette", "aiohttp", "tornado"}


# ─── Main entry ──────────────────────────────────────────────────────────────

def analyze_reachability(G: nx.DiGraph) -> list[dict]:
    """
    For every CVE node in G, compute reachability paths.

    Returns list of ReachabilityResult dicts:
    {
        "cve_id":      "CVE-2024-XXXX",
        "package":     "aiohttp",
        "severity":    "HIGH",
        "reachable":   True,
        "paths":       [
            {
                "entry":    "handle_request",
                "path":     ["handle_request", "fetch_url", "aiohttp"],
                "depth":    2,
                "entry_type": "http_handler",
            },
            ...
        ],
        "entry_count": 3,
        "max_depth":   2,
    }
    """
    results: list[dict] = []
    cve_nodes = [n for n in G.nodes() if n.startswith("cve:")]

    if not cve_nodes:
        return results

    # Build a reverse graph once — cheaper than reversing per-CVE
    G_rev = G.reverse(copy=False)

    for cve_node in cve_nodes:
        data    = G.nodes[cve_node]
        cve_id  = data.get("cve_id", cve_node.replace("cve:", ""))
        package = data.get("package", "")
        severity = data.get("severity", "UNKNOWN")

        paths = _find_paths_to_cve(G, G_rev, cve_node, package)

        results.append({
            "cve_id":      cve_id,
            "package":     package,
            "severity":    severity,
            "reachable":   len(paths) > 0,
            "paths":       paths,
            "entry_count": len(set(p["entry"] for p in paths)),
            "max_depth":   max((p["depth"] for p in paths), default=0),
        })

    return results


# ─── Path finding ─────────────────────────────────────────────────────────────

def _find_paths_to_cve(
    G: nx.DiGraph,
    G_rev: nx.DiGraph,
    cve_node: str,
    package: str,
) -> list[dict]:
    """
    Find all paths from entry points down to the CVE's library.
    """
    paths: list[dict] = []

    # Step 1 — Find the library node for this CVE
    lib_nodes = _get_library_nodes(G, cve_node, package)
    if not lib_nodes:
        return paths

    # Step 2 — Find functions that directly use any of these libraries
    direct_users: set[str] = set()
    for lib_node in lib_nodes:
        for fn_node in G_rev.predecessors(lib_node):
            if fn_node.startswith("fn:") or fn_node.startswith("function:"):
                direct_users.add(fn_node)

    if not direct_users:
        return paths

    # Step 3 — For each direct user, walk backwards up call chains to entry points
    for fn_node in direct_users:
        fn_paths = _trace_to_entries(G_rev, fn_node, sink_lib=lib_nodes, depth=0)
        paths.extend(fn_paths)

    # Deduplicate by path tuple
    seen: set[tuple] = set()
    unique: list[dict] = []
    for p in paths:
        key = tuple(p["path"])
        if key not in seen:
            seen.add(key)
            unique.append(p)

    # Sort: shorter paths first (lower depth = more direct)
    unique.sort(key=lambda x: x["depth"])
    return unique[:20]  # cap at 20 paths per CVE


def _get_library_nodes(G: nx.DiGraph, cve_node: str, package: str) -> list[str]:
    """Find library nodes connected to this CVE (via DEPENDS edges, reversed)."""
    lib_nodes: list[str] = []
    G_rev = G.reverse(copy=False)

    for pred in G_rev.predecessors(cve_node):
        if pred.startswith("lib:"):
            lib_nodes.append(pred)

    # Also check by package name match if no DEPENDS edges
    if not lib_nodes and package:
        for node in G.nodes():
            if node == f"lib:{package}" or node.startswith(f"lib:{package}"):
                lib_nodes.append(node)

    return lib_nodes


def _trace_to_entries(
    G_rev: nx.DiGraph,
    fn_node: str,
    sink_lib: list[str],
    depth: int,
    path: Optional[list[str]] = None,
    visited: Optional[set[str]] = None,
) -> list[dict]:
    """
    Recursively walk backwards from fn_node through CALLS edges.
    Returns list of path dicts when an entry point is found.
    """
    if path is None:
        path = []
    if visited is None:
        visited = set()

    if depth > MAX_DEPTH:
        return []
    if fn_node in visited:
        return []

    visited = visited | {fn_node}
    fn_name = _node_display(fn_node)
    current_path = path + [fn_name]

    # Is this node an entry point?
    entry_type = _classify_entry(fn_node, G_rev)
    if entry_type:
        # Build the full forward path (entry → ... → lib)
        full_path = list(reversed(current_path)) + [_node_display(sink_lib[0])]
        return [{
            "entry":      fn_name,
            "path":       full_path,
            "depth":      depth,
            "entry_type": entry_type,
        }]

    # Walk to callers
    results: list[dict] = []
    callers = [n for n in G_rev.predecessors(fn_node)
               if n.startswith("fn:") or n.startswith("function:")]

    if not callers:
        # No callers — this function is itself a root. Treat as potential entry.
        full_path = list(reversed(current_path)) + [_node_display(sink_lib[0])]
        return [{
            "entry":      fn_name,
            "path":       full_path,
            "depth":      depth,
            "entry_type": "root_function",
        }]

    for caller in callers:
        sub = _trace_to_entries(G_rev, caller, sink_lib, depth + 1, current_path, visited)
        results.extend(sub)

    return results


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _node_display(node: str) -> str:
    """Strip the node type prefix for readable path display."""
    for prefix in ("fn:", "function:", "lib:", "file:", "cve:", "repo:"):
        if node.startswith(prefix):
            return node[len(prefix):]
    return node


def _classify_entry(fn_node: str, G_rev: nx.DiGraph) -> Optional[str]:
    """
    Classify a function node as an entry point type, or None if not an entry.

    Entry types:
      "http_handler"   — Flask/FastAPI route, Django view
      "cli_command"    — click/argparse command, __main__
      "test_function"  — pytest test
      "public_api"     — public module-level function (no leading _)
      "event_handler"  — on_* / handle_* functions
    """
    name = _node_display(fn_node).lower()

    # HTTP handlers — common framework patterns
    if any(x in name for x in ("route", "view", "endpoint", "handler", "webhook")):
        return "http_handler"
    if name.startswith("on_"):
        return "http_handler"

    # CLI / main entry
    if name in ("main", "__main__", "run", "cli", "start"):
        return "cli_command"
    if name.startswith("cli_") or name.endswith("_command"):
        return "cli_command"

    # Tests
    if name.startswith("test_"):
        return "test_function"

    # Public API — no leading underscore, not a helper
    if not name.startswith("_") and not name.startswith("__"):
        # Only flag as entry if it has no callers within the graph
        callers = [n for n in G_rev.predecessors(fn_node)
                   if n.startswith("fn:") or n.startswith("function:")]
        if not callers:
            return "public_api"

    return None


# ─── Summary printer ─────────────────────────────────────────────────────────

def print_reachability_summary(results: list[dict]):
    """Print a concise reachability summary table."""
    reachable = [r for r in results if r["reachable"]]
    print(f"\n[reach] ── Reachability Analysis ──")
    print(f"  CVEs analyzed:   {len(results)}")
    print(f"  Reachable:       {len(reachable)}")

    if not reachable:
        print("  No reachable attack paths found.")
        return

    for r in reachable:
        sev = r.get("severity", "?")
        print(f"\n  {r['cve_id']}  [{sev}]  →  {r['package']}")
        print(f"    Entry points: {r['entry_count']}  |  Shortest path: {r['max_depth']} hop(s)")
        for p in r["paths"][:3]:
            arrow = " → ".join(p["path"])
            print(f"    [{p['entry_type']:14s}]  {arrow}")
        if len(r["paths"]) > 3:
            print(f"    ... and {len(r['paths']) - 3} more paths")


def save_reachability(results: list[dict], output_path: str = ""):
    """Save reachability results to JSON."""
    import json
    from pathlib import Path
    from sage.config import cfg
    p = Path(output_path) if output_path else cfg.data_dir() / "reachability.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[reach] Reachability saved → {p}")
