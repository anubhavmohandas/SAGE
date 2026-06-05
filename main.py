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
from sage.utils.colors import console, print_banner, log, log_success, log_fail, log_warn, print_pipeline_result
from sage.fetcher.nvd    import fetch_cves_since, fetch_cve_by_id
from sage.fetcher.filter import detect_stack, filter_relevant_cves
from sage.fetcher.npm    import fetch_npm_advisories
from sage.fetcher.store  import init_db, save_cves, get_new_cves, get_summary
from sage.synapse.parser import parse_repo
from sage.synapse.mapper import attach_cves, seed_libraries, get_blast_radius
from sage.synapse.export import export_graph
from sage.scanner.semgrep import scan_blast_radius, save_findings, print_findings_summary
from sage.analyzer.llm import analyze_findings, save_confirmed, print_analysis_summary
from sage.patcher.llm  import run_patcher, print_patch_summary
from sage.tests.runner    import run_tests, print_test_summary, save_test_results
from sage.verifier.semgrep import run_verifier, print_verifier_summary, save_verifier_results
from sage.github.pr        import run_github_pr, print_pr_summary, save_pr_result
from sage.reachability     import analyze_reachability, print_reachability_summary, save_reachability


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

    # Set repo context — scopes all data/ paths to data/<repo_name>/
    cfg.set_repo(repo_path)
    init_db()  # must come after set_repo()

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

    # Detect if this is a Node.js/JS repo
    from pathlib import Path as _Path
    is_js_repo = (_Path(repo_path) / "package.json").exists()

    # Step 2 — Fetch CVEs (NVD for Python, GHSA/npm-audit for JS)
    if is_js_repo:
        print(f"\n[SAGE] Step 2/4 — Fetching npm advisories (last {days} day(s))...")
        # JS repos: use GHSA + npm audit (no NVD key needed for npm packages)
        js_stack = {k: v for k, v in stack.items()}
        relevant = fetch_npm_advisories(js_stack, days=days)
        raw_cves = relevant  # already filtered by ecosystem
        print(f"[SAGE] npm advisory fetch: {len(relevant)} advisories")
    else:
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
    source = "npm advisories" if is_js_repo else "NVD"
    print(f"  CVEs fetched from {source}:  {len(raw_cves)}")
    print(f"  Relevant to your stack:    {len(relevant)}")
    from sage.fetcher.store import _db_path
    print(f"  Saved to DB:               {_db_path()}")

    if relevant:
        print(f"\n  Relevant CVEs found:")
        for entry in relevant:
            m = entry.get("sage_match", {})
            print(f"    [{m.get('severity', '?'):8s}] {m.get('cve_id', '?')} "
                  f"→ {m.get('package', '?')} {m.get('installed_version', '?')}")
    else:
        print(f"\n  No relevant CVEs found. Stack looks clean for this period.")

    # Always build the graph — it's a live map of the codebase.
    # CVEs are overlaid on top if present; graph exists regardless.
    print(f"\n  Building Synapse knowledge graph...")
    print(f"{'='*60}\n")
    run_synapse(repo_path)


def run_synapse(repo_path: str):
    """
    Build the Synapse knowledge graph for a repo.
    Parses code, attaches CVEs, exports synapse_graph.json.
    """
    # Set repo context first — all data paths scope to data/<repo_name>/
    cfg.set_repo(repo_path)
    init_db()  # must come after set_repo() so DB lands in data/<repo_name>/
    print_banner("SYNAPSE — Knowledge Graph Builder")

    log("SAGE", "Synapse Step 1/4 — Parsing codebase...")
    G = parse_repo(repo_path)

    log("SAGE", "Synapse Step 2/4 — Seeding library nodes from requirements...")
    G = seed_libraries(G, repo_path)

    log("SAGE", "Synapse Step 3/4 — Attaching CVE nodes...")
    G = attach_cves(G)

    log("SAGE", "Synapse Step 3.5/4 — Analyzing attack reachability...")
    reach_results = analyze_reachability(G)
    save_reachability(reach_results)
    print_reachability_summary(reach_results)

    log("SAGE", "Synapse Step 4/4 — Exporting graph...")
    out_path = export_graph(G, repo_path=repo_path, reach_results=reach_results)

    # Blast radius table
    cve_nodes = [n for n in G.nodes() if n.startswith("cve:")]
    if cve_nodes:
        from sage.utils.colors import print_blast_table
        blasts = []
        for cve_node in cve_nodes[:10]:
            blast = get_blast_radius(G, cve_node)
            if blast:
                blasts.append(blast)
        if blasts:
            console.print("\n[header]Blast Radius[/header]")
            print_blast_table(blasts)

    log_success("SAGE", f"Graph ready → {out_path}  |  Open synapse.html to visualize")

    # Step 4 — Scanner
    print_banner("SCANNER — Semgrep Static Analysis")
    log("SAGE", "Scanner Step 1/1 — Running Semgrep on exposed functions...")
    findings = scan_blast_radius(G, repo_path)
    save_findings(findings)
    print_findings_summary(findings)

    # Step 5 — Analyzer
    print_banner("ANALYZER — LLM Vulnerability Confirmation")
    log("SAGE", "Analyzer Step 1/1 — Confirming exploitability...")
    confirmed = analyze_findings(findings, G, repo_path, reach_results=reach_results)
    save_confirmed(confirmed)
    print_analysis_summary(confirmed)

    # Step 6 — Patcher
    print_banner("PATCHER — Automated Fix Generation")
    log("SAGE", "Patcher Step 1/1 — Generating patches...")

    seen_cves = set()
    all_cves = []
    for node, data in G.nodes(data=True):
        if node.startswith("cve:"):
            cve_id = data.get("cve_id", node.replace("cve:", ""))
            if cve_id not in seen_cves:
                seen_cves.add(cve_id)
                all_cves.append({
                    "cve_id":         cve_id,
                    "package":        data.get("package", ""),
                    "affected_range": data.get("affected_range", ""),
                    "severity":       data.get("severity", "UNKNOWN"),
                })

    patch_result = run_patcher(confirmed, repo_path, all_cves=all_cves)
    print_patch_summary(patch_result)

    # Step 7 — Tests
    print_banner("TESTS — Existing + Security Test Runner")
    log("SAGE", "Tests Step 1/1 — Running tests...")
    test_results = run_tests(patch_result, confirmed, repo_path)
    save_test_results(test_results)
    print_test_summary(test_results)

    # Step 8 — Verifier
    print_banner("VERIFIER — Final Semgrep Check")
    log("SAGE", "Verifier Step 1/1 — Running final Semgrep pass...")
    verify_results = run_verifier(patch_result, confirmed, repo_path)
    save_verifier_results(verify_results)
    print_verifier_summary(verify_results)

    # Step 9 — GitHub PR
    print_banner("GITHUB — Pull Request")
    log("SAGE", "GitHub Step 1/1 — Creating PR...")
    pr_result = run_github_pr(
        patch_result=patch_result,
        confirmed=confirmed,
        all_cves=all_cves,
        test_results=test_results,
        verify_results=verify_results,
        repo_path=repo_path,
    )
    save_pr_result(pr_result)
    print_pr_summary(pr_result)


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
    parser.add_argument("--digest",  type=str, nargs="+", metavar="REPO",
                        help="Morning digest: run full pipeline non-interactively for one or more repos")

    args = parser.parse_args()

    # DB init happens inside run_synapse/run_fetch after set_repo() so it's repo-scoped.
    # Only init here for commands that don't have a repo path.
    if args.status or args.cve:
        init_db()

    if args.status:
        run_status()
    elif args.cve:
        run_single_cve(args.cve)
    elif args.synapse:
        run_synapse(args.synapse)
    elif args.digest:
        from sage.digest import run_digest
        sys.exit(run_digest(args.digest, days=args.days))
    elif args.repo:
        run_fetch(args.repo, days=args.days)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[SAGE] Interrupted — exiting cleanly.")
        sys.exit(0)
