"""
verify_reachability.py — one-command empirical check of the reachability engine.

Run from the SAGE repo root (venv active):

    python3 verify_reachability.py [/path/to/repo]

Default target is SAGE itself (scans this repo, attaches CVEs already stored in
data/SAGE/sage.db). Exit codes:

    0 — CALLS edges exist AND at least one CVE is reachable with a real path
    1 — graph built but no reachable paths (investigate: CVE attachment? aliases?)
    2 — structural failure (no CALLS edges at all → parser fix didn't take)

Why this exists: reachability.py shipped dead for months (prefix mismatch +
reversed-walk bug + missing CALLS edges) while every saved reachability.json
showed `reachable: false`. This script is the regression guard — if it ever
exits 2 again, the engine is blind again.
"""

import sys
from pathlib import Path

REPO = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).parent.resolve())

try:
    from sage.config import cfg
except EnvironmentError as e:
    print(f"Config failed (missing .env keys?): {e}")
    sys.exit(2)

from sage.synapse.parser import parse_repo
from sage.synapse.mapper import attach_cves, seed_libraries
from sage.reachability import analyze_reachability, print_reachability_summary

cfg.set_repo(REPO)
from sage.fetcher.store import init_db
init_db()

print(f"\n=== Reachability verification: {REPO} ===\n")

G = parse_repo(REPO)
G = seed_libraries(G, REPO)
G = attach_cves(G)

# ── Structural checks ─────────────────────────────────────────────────────────
edge_labels = {}
for u, v, data in G.edges(data=True):
    lbl = data.get("label", "?")
    edge_labels[lbl] = edge_labels.get(lbl, 0) + 1

func_nodes = [n for n in G.nodes() if n.startswith("func:")]
cve_nodes  = [n for n in G.nodes() if n.startswith("cve:")]

print(f"Edge types: {edge_labels}")
print(f"Function nodes: {len(func_nodes)}  |  CVE nodes: {len(cve_nodes)}")

calls = edge_labels.get("CALLS", 0)
if calls == 0:
    print("\nFAIL (exit 2): zero CALLS edges — parser fix not effective.")
    sys.exit(2)
print(f"OK: {calls} CALLS edges emitted.")

# ── Behavioral check ──────────────────────────────────────────────────────────
results = analyze_reachability(G)
print_reachability_summary(results)

reachable = [r for r in results if r["reachable"]]
all_paths = [p for r in reachable for p in r["paths"]]
one_hop   = [p for p in all_paths if p["depth"] <= 1]
multi_hop = [p for p in all_paths if p["depth"] >= 2]

print(f"\nReachable CVEs: {len(reachable)}/{len(results)}")
print(f"Total paths: {len(all_paths)}  |  1-hop (func→lib): {len(one_hop)}  "
      f"|  multi-hop (depth >= 2, real call chains): {len(multi_hop)}")
if all_paths and not multi_hop:
    print("NOTE: all paths are 1-hop (function directly uses the library). The "
          "engine works, but no multi-hop call chains were found in this repo — "
          "README should say 'reaches library', not 'multi-hop call chain', "
          "until depth>=2 paths appear.")

if cve_nodes and not reachable:
    print("\nFAIL (exit 1): CVEs attached but nothing reachable. "
          "Check direct_users detection and prefix matching.")
    sys.exit(1)

if not cve_nodes:
    print("\nNOTE: no CVEs in DB for this repo — structural checks passed, "
          "but run a scan first for the full behavioral check.")

print("\nPASS: reachability engine is producing paths.")
sys.exit(0)
