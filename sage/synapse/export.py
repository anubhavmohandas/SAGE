"""
synapse/export.py — Export graph to synapse_graph.json

Converts the NetworkX graph into the format our
synapse.html visualization expects.

Output format (NetworkX node_link_data):
{
  "nodes": [
    {
      "id":       "lib:aiohttp",
      "label":    "aiohttp",
      "type":     "library",
      "color":    "#e8960a",
      "info":     "...",
      "children": ["cve:CVE-2025-69223", ...]
    },
    ...
  ],
  "links": [
    { "source": "lib:aiohttp", "target": "cve:CVE-2025-69223", "label": "AFFECTS" },
    ...
  ]
}

Teaching note:
    The viz was built to consume exactly this format.
    This is the UI-first payoff — we built the viz first,
    locked the format, now export produces exactly what it needs.
    No mismatch possible.
"""

import json
from pathlib import Path
from typing import Optional
import networkx as nx
from networkx.readwrite import json_graph


# Type → color mapping (matches synapse.html)
TYPE_COLORS = {
    "file":     "#5bc8ff",
    "function": "#4db87a",
    "library":  "#e8960a",
    "cve":      "#ff4444",
}

OUTPUT_PATH = Path("data/synapse_graph.json")


def export_graph(G: nx.DiGraph, output_path: Optional[str] = None) -> str:
    """
    Export the NetworkX graph to synapse_graph.json.

    Args:
        G:           The knowledge graph
        output_path: Where to write the file. Default: data/synapse_graph.json

    Returns:
        Path to the written file as string.

    Teaching note:
        We enrich each node with display properties before exporting.
        The raw graph has minimal data — we add colors, labels, children
        lists here so the viz doesn't need to compute them.
    """
    out = Path(output_path) if output_path else OUTPUT_PATH
    out.parent.mkdir(parents=True, exist_ok=True)

    # Remove stdlib/noise libraries — not security relevant
    G = _filter_graph(G)

    # Enrich nodes with display data
    _enrich_nodes(G)

    # Convert to node_link_data format
    data = json_graph.node_link_data(G, edges="links")

    nodes = []
    for node in data.get("nodes", []):
        node_id   = node.get("id", "")
        node_data = G.nodes[node_id] if G.has_node(node_id) else {}
        nodes.append({
            "id":       node_id,
            "label":    node_data.get("label", node_id),
            "type":     node_data.get("type", "unknown"),
            "color":    node_data.get("color", "#888888"),
            "info":     node_data.get("info", ""),
            "children": node_data.get("children", []),
            "severity": node_data.get("severity", ""),
            "package":  node_data.get("package", ""),
            "cwe":      node_data.get("cwe", ""),
            "file":     node_data.get("file", ""),
            "line":     node_data.get("line", 0),
            "stdlib":   node_data.get("stdlib", False),
        })

    links = []
    for link in data.get("links", []):
        source = link.get("source", "")
        target = link.get("target", "")
        label  = G.edges[source, target].get("label", "") if G.has_edge(source, target) else ""
        links.append({
            "source": source,
            "target": target,
            "label":  label,
        })

    output = {"nodes": nodes, "links": links}

    with open(out, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[export] synapse_graph.json written → {out}")
    print(f"[export] {len(nodes)} nodes, {len(links)} edges")
    _print_summary(G)

    return str(out)


# Python stdlib modules — not security relevant, clutter the graph
STDLIB = {
    're', 'os', 'sys', 'json', 'datetime', 'time', 'math', 'random',
    'typing', 'pathlib', 'logging', 'abc', 'enum', 'dataclasses',
    'collections', 'functools', 'itertools', 'hashlib', 'base64',
    'socket', 'urllib', 'http', 'ssl', 'threading', 'asyncio',
    'subprocess', 'io', 'tempfile', 'shutil', 'copy', 'string',
    'textwrap', 'contextlib', 'warnings', 'traceback', 'inspect',
    'importlib', 'unittest', 'argparse', 'struct', 'array', 'queue',
    'weakref', 'gc', 'platform', 'signal', 'errno', 'stat', 'glob',
    'fnmatch', 'fileinput', 'configparser', 'csv', 'html', 'xml',
    'email', 'mimetypes', 'uuid', 'hmac', 'secrets', 'decimal',
    'fractions', 'statistics', 'pprint', 'reprlib', 'operator',
    'builtins', '__future__', 'types', 'numbers', 'cmath',
}


def _filter_graph(G: nx.DiGraph) -> nx.DiGraph:
    """
    Remove stdlib library nodes and their edges.
    Also tag remaining library nodes as stdlib=True/False.
    Returns a cleaned copy of the graph.
    """
    import copy
    G2 = copy.deepcopy(G)

    # Remove stdlib lib nodes
    to_remove = [
        n for n in G2.nodes()
        if n.startswith("lib:") and n.replace("lib:", "") in STDLIB
    ]
    G2.remove_nodes_from(to_remove)

    # Remove test files from main view (tag them, don't delete)
    for n in G2.nodes():
        if n.startswith("file:") and ("test" in n.lower() or "__init__" in n):
            G2.nodes[n]["is_test"] = True

    print(f"[export] Filtered {len(to_remove)} stdlib libraries from graph")
    return G2


def _enrich_nodes(G: nx.DiGraph):
    """
    Add display properties to all nodes in the graph.
    Modifies nodes in place.
    """
    for node_id in G.nodes():
        data = G.nodes[node_id]
        node_type = data.get("type", "unknown")

        # Set color based on type
        if "color" not in data:
            data["color"] = TYPE_COLORS.get(node_type, "#888888")

        # Set info tooltip text if not already set
        if "info" not in data:
            if node_type == "file":
                data["info"] = f"File: {data.get('label', '')}"
            elif node_type == "function":
                data["info"] = f"Function in {data.get('file', '')}\nLine {data.get('line', '?')}"
            elif node_type == "library":
                data["info"] = f"Library: {data.get('label', '')}"

        # Build children list (outgoing neighbours)
        data["children"] = list(G.successors(node_id))


def _print_summary(G: nx.DiGraph):
    """Print a summary of the graph for the terminal."""
    type_counts = {}
    for node_id in G.nodes():
        t = G.nodes[node_id].get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    print("[export] Graph summary:")
    for t, count in sorted(type_counts.items()):
        print(f"         {t:12s} {count}")

    # Show CVE summary
    cve_nodes = [n for n in G.nodes() if n.startswith("cve:")]
    if cve_nodes:
        print(f"\n[export] CVEs in graph: {len(cve_nodes)}")
        by_severity = {}
        for cve_id in cve_nodes:
            sev = G.nodes[cve_id].get("severity", "UNKNOWN")
            by_severity[sev] = by_severity.get(sev, 0) + 1
        for sev, count in sorted(by_severity.items()):
            print(f"         {sev:10s} {count}")
