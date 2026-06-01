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
        print(f"\n  Next step: run the analyzer to confirm and generate patches.")
    else:
        print(f"\n  No relevant CVEs found. Your stack looks clean for this period.")

    print(f"{'='*60}\n")


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
    parser.add_argument("--repo",   type=str, help="Path to repo to scan")
    parser.add_argument("--days",   type=int, default=1, help="Days of CVEs to fetch (default: 1)")
    parser.add_argument("--cve",    type=str, help="Look up a specific CVE by ID")
    parser.add_argument("--status", action="store_true", help="Show pipeline status")

    args = parser.parse_args()

    # Initialize DB on every run
    init_db()

    if args.status:
        run_status()
    elif args.cve:
        run_single_cve(args.cve)
    elif args.repo:
        run_fetch(args.repo, days=args.days)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
