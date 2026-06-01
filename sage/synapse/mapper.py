"""
synapse/mapper.py — CVE node mapper

Takes the code graph from parser.py and attaches CVE nodes to it.

Before mapping:
    file:cybertrace/dns.py → lib:dnspython

After mapping:
    file:cybertrace/dns.py → lib:dnspython → cve:CVE-2025-13836

Teaching note — why this is the key step:
    This is what makes SAGE different from a simple CVE scanner.
    A scanner says: "dnspython has CVE-2025-13836"
    SAGE says: "dns.py imports dnspython, resolve_domain() calls it,
                and CVE-2025-13836 affects exactly the version you have"

    The graph makes the blast radius visible — not just which library
    is vulnerable, but which of YOUR functions are exposed.
"""

import json
from pathlib import Path
import networkx as nx

from sage.fetcher.store import get_new_cves


# CVE severity → color mapping for the visualization
SEVERITY_COLOR = {
    "CRITICAL": "#ff2020",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#ffb347",
    "LOW":      "#7fd4a0",
    "UNKNOWN":  "#aaaaaa",
}


def attach_cves(G: nx.DiGraph) -> nx.DiGraph:
    """
    Load CVEs from the database and attach them as nodes to the graph.

    For each CVE in the DB:
      1. Find the library node it affects (e.g. lib:aiohttp)
      2. Add a CVE node
      3. Add an AFFECTS edge: lib:aiohttp → cve:CVE-XXXX

    Returns the same graph with CVE nodes added.

    Teaching note:
        We modify the graph in place AND return it.
        This is a common Python pattern — makes it usable both ways:
            G = attach_cves(G)       ← reassignment style
            attach_cves(G)           ← mutation style
    """
    cves = get_new_cves()
    print(f"[mapper] Attaching {len(cves)} CVEs to the graph...")

    attached = 0
    for cve_row in cves:
        cve_id  = cve_row["cve_id"]
        package = cve_row["package"]  # e.g. "aiohttp"
        severity = cve_row["severity"]

        # Find the library node in the graph
        lib_id = f"lib:{package}"
        # Also try with hyphens (aiohttp vs aio-http)
        lib_id_hyphen = f"lib:{package.replace('_', '-')}"

        target_lib = None
        if G.has_node(lib_id):
            target_lib = lib_id
        elif G.has_node(lib_id_hyphen):
            target_lib = lib_id_hyphen
        else:
            # Try partial match — sometimes package names differ slightly
            for node in G.nodes():
                if node.startswith("lib:") and package in node:
                    target_lib = node
                    break

        if not target_lib:
            # Library not imported anywhere in the codebase — skip
            continue

        # Add CVE node
        cve_node_id = f"cve:{cve_id}"
        color = SEVERITY_COLOR.get(severity, SEVERITY_COLOR["UNKNOWN"])

        G.add_node(cve_node_id, {
            "id":       cve_node_id,
            "label":    cve_id,
            "type":     "cve",
            "color":    color,
            "severity": severity,
            "package":  package,
            "affected_range": cve_row.get("affected_range", ""),
            "info":     f"{severity} severity\nAffects: {package} {cve_row.get('affected_range', '')}",
            "children": [],
        })

        # Add AFFECTS edge: library → CVE
        G.add_edge(target_lib, cve_node_id, label="AFFECTS")
        attached += 1

    print(f"[mapper] Attached {attached}/{len(cves)} CVEs to library nodes")
    return G


def get_blast_radius(G: nx.DiGraph, cve_node_id: str) -> dict:
    """
    Given a CVE node, trace backwards to find all exposed functions.

    Returns a dict with:
      - affected_library: which library is vulnerable
      - exposed_files: which files import that library
      - exposed_functions: which functions use that library

    Teaching note:
        This is the transitive chain trace.
        CVE → library → (files that import it) → (functions in those files)
        We walk the graph BACKWARDS from the CVE node.
    """
    if not G.has_node(cve_node_id):
        return {}

    # Find the library this CVE affects (reverse edge: lib → cve)
    affected_libs = [
        n for n in G.predecessors(cve_node_id)
        if G.nodes[n].get("type") == "library"
    ]

    if not affected_libs:
        return {}

    lib_id = affected_libs[0]

    # Find files that import this library
    exposed_files = [
        n for n in G.predecessors(lib_id)
        if G.nodes[n].get("type") == "file"
    ]

    # Find functions that use this library
    exposed_functions = [
        n for n in G.predecessors(lib_id)
        if G.nodes[n].get("type") == "function"
    ]

    return {
        "cve_id":             cve_node_id.replace("cve:", ""),
        "affected_library":   lib_id.replace("lib:", ""),
        "exposed_files":      [f.replace("file:", "") for f in exposed_files],
        "exposed_functions":  [f.replace("func:", "") for f in exposed_functions],
        "total_exposure":     len(exposed_files) + len(exposed_functions),
    }
