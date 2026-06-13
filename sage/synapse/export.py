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
from sage.utils.colors import cprint


# Type → color mapping (matches synapse.html)
TYPE_COLORS = {
    "file":     "#5bc8ff",
    "function": "#4db87a",
    "library":  "#e8960a",
    "cve":      "#ff4444",
}

def _output_path() -> Path:
    try:
        from sage.config import cfg
        return cfg.data_dir() / "synapse_graph.json"
    except Exception:
        return Path("data/synapse_graph.json")

_CURRENT_REPO_NAME = ""  # set by export_graph from repo_path


def export_graph(
    G: nx.DiGraph,
    output_path: Optional[str] = None,
    repo_path: Optional[str] = None,
    reach_results: Optional[list] = None,
) -> str:
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
    global _CURRENT_REPO_NAME
    out = Path(output_path) if output_path else _output_path()
    out.parent.mkdir(parents=True, exist_ok=True)
    if repo_path:
        _CURRENT_REPO_NAME = Path(repo_path).name

    # Remove stdlib/noise libraries — not security relevant
    G = _filter_graph(G)

    # Inject virtual repo root node — connects to all file nodes
    # This makes the opening view show the full codebase, not just vulnerable libs
    repo_label = _CURRENT_REPO_NAME or "repo"
    root_id    = "repo:root"
    file_nodes = [n for n in G.nodes() if n.startswith("file:")]
    cve_count  = sum(1 for n in G.nodes() if n.startswith("cve:"))
    G.add_node(root_id,
        id=root_id, label=repo_label, type="repo",
        color="#a78bfa",
        info=f"Repository: {repo_label}\n{len(file_nodes)} files · {cve_count} CVEs",
        children=file_nodes,
    )
    for fid in file_nodes:
        G.add_edge(root_id, fid, label="CONTAINS")

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

    # Embed attack paths from reachability analysis
    # Format: list of {cve_id, severity, reachable, paths: [{entry, path, depth, entry_type}]}
    attack_paths: list[dict] = []
    if reach_results:
        for r in reach_results:
            if r.get("reachable") and r.get("paths"):
                attack_paths.append({
                    "cve_id":   r["cve_id"],
                    "severity": r.get("severity", "UNKNOWN"),
                    "paths":    r["paths"][:5],  # top 5 paths per CVE
                })

    output = {"nodes": nodes, "links": links, "attack_paths": attack_paths}

    with open(out, "w") as f:
        json.dump(output, f, indent=2)

    cprint(f"[export] synapse_graph.json written → {out}")
    cprint(f"[export] {len(nodes)} nodes, {len(links)} edges")
    _print_summary(G)

    # Auto-generate index.html with fresh data embedded
    _generate_index_html(output, out.parent)

    return str(out)


def _generate_index_html(graph_data: dict, output_dir: Path):
    """
    Inject fresh graph data into synapse.html template and write index.html.
    This means you can just open index.html — no LOAD GRAPH click needed.
    """
    # Find synapse.html template (walk up from data/ to SAGE root)
    template = None
    for parent in output_dir.parents:
        candidate = parent / "synapse.html"
        if candidate.exists():
            template = candidate
            break

    if not template:
        cprint("[export] synapse.html template not found — skipping index.html generation")
        return

    html = template.read_text()

    # Inject graph data as JS variable right before </body>.
    # Escape </script> → <\/script> so a CVE description containing that string
    # cannot break out of the <script> block and inject arbitrary HTML.
    graph_json = json.dumps(graph_data, separators=(",", ":")).replace("</script>", r"<\/script>")
    inject = f"""
<script>
// Auto-injected by SAGE export — {len(graph_data['nodes'])} nodes, {len(graph_data['links'])} edges
(function() {{
  if (typeof loadGraphData === 'function') {{
    loadGraphData({graph_json});
  }}
}})();
</script>
"""
    html = html.replace("</body>", inject + "</body>")

    # Write to demos/<repo>_<date>/index.html — always at SAGE project root
    from datetime import datetime
    date_str  = datetime.now().strftime("%Y-%m-%d")
    repo_name = _CURRENT_REPO_NAME or "repo"
    # template is synapse.html at the SAGE root — use its parent as the demos anchor
    # This is stable regardless of where data/ is scoped to
    sage_root = template.parent
    demo_dir  = sage_root / "demos" / f"{repo_name}_{date_str}"
    demo_dir.mkdir(parents=True, exist_ok=True)

    index_path = demo_dir / "index.html"
    index_path.write_text(html)
    cprint(f"[export] index.html generated → {index_path}")
    cprint(f"[export] Open in browser: file://{index_path.resolve()}")


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
    'ast', 'dis', 'difflib', 'tokenize', 'token', 'keyword',
    'tomllib', 'sqlite3', 'pickle', 'shelve', 'zipfile', 'tarfile',
    'gzip', 'bz2', 'lzma', 'zlib', 'heapq', 'bisect', 'calendar',
    'locale', 'gettext', 'codecs', 'unicodedata', 'linecache',
}


def _filter_graph(G: nx.DiGraph) -> nx.DiGraph:
    """
    Remove stdlib library nodes and their edges.
    Also tag remaining library nodes as stdlib=True/False.
    Returns a cleaned copy of the graph.
    """
    import copy
    G2 = copy.deepcopy(G)

    # Detect local packages — any lib: node whose name is a directory in the repo root
    from pathlib import Path as _Path
    repo_root = _Path(".").resolve()
    local_pkgs = {d.name.lower() for d in repo_root.iterdir() if d.is_dir() and (d / "__init__.py").exists()}

    # Import aliases that map to known packages (dotenv → python-dotenv, etc)
    IMPORT_ALIASES = {'dotenv', 'tomli', 'google'}  # noisy low-signal libs

    repo_name = _CURRENT_REPO_NAME.lower() if _CURRENT_REPO_NAME else ""
    to_remove = [
        n for n in G2.nodes()
        if n.startswith("lib:") and (
            n.replace("lib:", "") in STDLIB
            or n.replace("lib:", "").lower() in local_pkgs
            or n.replace("lib:", "") in IMPORT_ALIASES
            or (repo_name and n.replace("lib:", "").lower().startswith(repo_name))
        )
    ]
    G2.remove_nodes_from(to_remove)

    # Remove test files from main view (tag them, don't delete)
    for n in G2.nodes():
        if n.startswith("file:") and ("test" in n.lower() or "__init__" in n):
            G2.nodes[n]["is_test"] = True

    cprint(f"[export] Filtered {len(to_remove)} stdlib libraries from graph")
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

    cprint("[export] Graph summary:")
    for t, count in sorted(type_counts.items()):
        cprint(f"         {t:12s} {count}")

    # Show CVE summary
    cve_nodes = [n for n in G.nodes() if n.startswith("cve:")]
    if cve_nodes:
        cprint(f"\n[export] CVEs in graph: {len(cve_nodes)}")
        by_severity = {}
        for cve_id in cve_nodes:
            sev = G.nodes[cve_id].get("severity", "UNKNOWN")
            by_severity[sev] = by_severity.get(sev, 0) + 1
        for sev, count in sorted(by_severity.items()):
            cprint(f"         {sev:10s} {count}")
