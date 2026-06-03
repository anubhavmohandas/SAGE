"""
main.py — SAGE entry point

Usage:
    python main.py --repo /path/to/your/repo
    python main.py --repo /path/to/your/repo --days 7
    python main.py --cve CVE-2021-44228          (lookup single CVE)
    python main.py --status                       (show pipeline summary)

Teaching note:
    main.py is the only file you run directly.
    It wires all the modules together in the correct pipeline order.
    Each module is independent — main.py is the conductor.
"""

import argparse
import json
import sys

# Config loads first — fails fast if .env is missing keys
from sage.config import cfg
from sage.fetcher.nvd    import fetch_cves_since, fetch_cve_by_id
from sage.fetcher.filter import detect_stack, filter_relevant_cves
from sage.fetcher.store  import init_db, save_cves, get_new_cves, get_summary
from sage.synapse.parser import parse_repo
from sage.synapse.mapper import attach_cves, get_blast_radius
from sage.synapse.export import export_graph
from sage.scanner.semgrep import scan_blast_radius, save_findings, print_findings_summary
from sage.analyzer.llm import analyze_findings, save_confirmed, print_analysis_summary
from sage.patcher.llm  import run_patcher, print_patch_summary


def run_fetch(repo_path: str, days: int = 1):
    """
    Run the CVE fetch + filter pipeline for a given repo.

    Pipeline:
        1. Detect stack from repo
        2. Fetch today's CVEs from NVD
        3. Filter to only CVEs affecting this stack
        4. Save new ones to DB
        5. Report what was found
    """
    print(f"\n{'='*60}")
    print(f"  SAGE — Security Analysis & Graph Engine")
    print(f"  Repo: {repo_path}")
    print(f"  Days: last {days} day(s)")
    print(f"{'='*60}\n")

    # Step 1 — Detect repo stack
    print("[SAGE] Step 1/4 — Detecting repo stack...")
    stack = detect_stack(repo_path)

    if stack:
        print(f"\n[SAGE] Detected {len(stack)} packages:")
        for pkg, ver in sorted(stack.items()):
            print(f"         {pkg:30s} {ver}")
    else:
        print("[SAGE] No dependencies found. Nothing to scan.")
        print("[SAGE] Tip: SAGE works best on repos with requirements.txt or package.json")
        return

    # Step 2 — Fetch CVEs from NVD
    print(f"\n[SAGE] Step 2/4 — Fetching CVEs from NVD (last {days} day(s))...")
    raw_cves = fetch_cves_since(days=days)

    if not raw_cves:
        print("[SAGE] No CVEs fetched. Check your internet connection or NVD API key.")
        return

    # Step 3 — Filter to relevant CVEs
    print(f"\n[SAGE] Step 3/4 — Filtering {len(raw_cves)} CVEs against your stack...")
    relevant = filter_relevant_cves(raw_cves, stack)

    # Step 4 — Save to DB
    print(f"\n[SAGE] Step 4/4 — Saving to database...")
    save_cves(relevant)

    # Report
    print(f"\n{'='*60}")
    print(f"  SAGE Fetch Complete")
    print(f"{'='*60}")
    print(f"  CVEs fetched from NVD:     {len(raw_cves)}")
    print(f"  Relevant to your stack:    {len(relevant)}")
    print(f"  Saved to DB:               data/sage.db")

    if relevant:
        print(f"\n  Relevant CVEs found:")
        for entry in relevant:
            m = entry.get("sage_match", {})
            print(f"    [{m.get('severity', '?'):8s}] {m.get('cve_id', '?')} "
                  f"→ {m.get('package', '?')} {m.get('installed_version', '?')}")
        print(f"\n  Next step: building Synapse knowledge graph...")
        print(f"{'='*60}\n")

        # Step 5 — Build Synapse knowledge graph
        run_synapse(repo_path)
    else:
        print(f"\n  No relevant CVEs found. Your stack looks clean for this period.")
        print(f"{'='*60}\n")


def run_synapse(repo_path: str):
    """
    Build the Synapse knowledge graph for a repo.
    Parses code, attaches CVEs, exports synapse_graph.json.
    """
    print(f"{'='*60}")
    print(f"  SYNAPSE — Knowledge Graph Builder")
    print(f"{'='*60}\n")

    # Step 1 — Parse codebase
    print("[SAGE] Synapse Step 1/3 — Parsing codebase...")
    G = parse_repo(repo_path)

    # Step 2 — Attach CVEs from DB
    print("\n[SAGE] Synapse Step 2/3 — Attaching CVE nodes...")
    G = attach_cves(G)

    # Step 3 — Export to JSON for visualization
    print("\n[SAGE] Synapse Step 3/3 — Exporting graph...")
    out_path = export_graph(G)

    # Show blast radius for each CVE
    cve_nodes = [n for n in G.nodes() if n.startswith("cve:")]
    if cve_nodes:
        print(f"\n[SAGE] Blast radius analysis:")
        for cve_node in cve_nodes[:10]:  # Show first 10
            blast = get_blast_radius(G, cve_node)
            if blast:
                print(f"  {blast['cve_id']:20s} → "
                      f"{blast['affected_library']:15s} | "
                      f"{len(blast['exposed_files'])} files, "
                      f"{len(blast['exposed_functions'])} functions exposed")

    print(f"\n{'='*60}")
    print(f"  Graph ready → {out_path}")
    print(f"  Open synapse.html and load this file to visualize.")
    print(f"{'='*60}\n")

    # Step 4 — Run Semgrep on blast radius
    print(f"{'='*60}")
    print(f"  SCANNER — Semgrep Static Analysis")
    print(f"{'='*60}\n")
    print("[SAGE] Scanner Step 1/1 — Running Semgrep on exposed functions...")
    findings = scan_blast_radius(G, repo_path)
    save_findings(findings)
    print_findings_summary(findings)

    # Step 5 — LLM Analyzer
    print(f"\n{'='*60}")
    print(f"  ANALYZER — LLM Vulnerability Confirmation")
    print(f"{'='*60}\n")
    print("[SAGE] Analyzer Step 1/1 — Confirming with Claude...")
    confirmed = analyze_findings(findings, G, repo_path)
    save_confirmed(confirmed)
    print_analysis_summary(confirmed)

    # Step 6 — Patcher
    print(f"\n{'='*60}")
    print(f"  PATCHER — Automated Fix Generation")
    print(f"{'='*60}\n")
    print("[SAGE] Patcher Step 1/1 — Generating patches...")

    # Pass all CVE nodes from graph for dep bump (not just confirmed)
    all_cves = []
    for node, data in G.nodes(data=True):
        if node.startswith("cve:"):
            all_cves.append({
                "cve_id":         data.get("cve_id", node.replace("cve:", "")),
                "package":        data.get("package", ""),
                "affected_range": data.get("affected_range", ""),
            })

    patch_result = run_patcher(confirmed, repo_path, all_cves=all_cves)
    print_patch_summary(patch_result)


def run_single_cve(cve_id: str):
    """Look up and display a single CVE by ID."""
    print(f"\n[SAGE] Looking up {cve_id}...")
    entry = fetch_cve_by_id(cve_id)

    if not entry:
        print(f"[SAGE] CVE {cve_id} not found.")
        return

    cve = entry.get("cve", {})
    print(f"\n  ID:          {cve.get('id')}")
    print(f"  Published:   {cve.get('published', 'N/A')[:10]}")

    # Description
    descs = cve.get("descriptions", [])
    for d in descs:
        if d.get("lang") == "en":
            print(f"  Description: {d.get('value', '')[:200]}...")
            break

    print(f"\n  Full JSON saved to: cve_{cve_id}.json")
    with open(f"cve_{cve_id}.json", "w") as f:
        json.dump(entry, f, indent=2)


def run_status():
    """Show pipeline status summary."""
    summary = get_summary()
    print(f"\n{'='*60}")
    print(f"  SAGE — Pipeline Status")
    print(f"{'='*60}")
    if not summary:
        print("  No CVEs in database yet. Run: python main.py --repo <path>")
    else:
        for status, count in sorted(summary.items()):
            print(f"  {status:15s} {count}")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SAGE — Security Analysis & Graph Engine"
    )
    parser.add_argument("--repo",    type=str, help="Path to repo to scan")
    parser.add_argument("--days",    type=int, default=1, help="Days of CVEs to fetch (default: 1)")
    parser.add_argument("--cve",     type=str, help="Look up a specific CVE by ID")
    parser.add_argument("--status",  action="store_true", help="Show pipeline status")
    parser.add_argument("--synapse", type=str, help="Build Synapse graph for a repo (skip CVE fetch)")

    args = parser.parse_args()

    # Initialize DB on every run
    init_db()

    if args.status:
        run_status()
    elif args.cve:
        run_single_cve(args.cve)
    elif args.synapse:
        run_synapse(args.synapse)
    elif args.repo:
        run_fetch(args.repo, days=args.days)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
