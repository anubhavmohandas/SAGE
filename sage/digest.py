"""
sage/digest.py — Morning digest: scheduled daily scan with terminal summary

Designed to run non-interactively (cron, launchd, CI).
Runs the full pipeline for one or more repos, then prints a compact
color summary to stdout/stderr.

Usage (CLI):
    python main.py --digest /path/to/repo
    python main.py --digest /path/to/repo --days 1
    python main.py --digest /path/to/repo1 /path/to/repo2

Cron example (daily at 08:00):
    0 8 * * * cd /path/to/SAGE && source venv/bin/activate && python main.py --digest /path/to/repo >> logs/digest.log 2>&1

Output format:
    ╔══════════════════════════════════════════════════╗
    ║  SAGE Morning Digest — 2026-06-05                ║
    ╚══════════════════════════════════════════════════╝

    Repo: /path/to/repo  (MyProject)
    ──────────────────────────────
    CVEs found:      3
      CRITICAL  1   CVE-2026-XXXX  →  some-lib  (patched, PR #7)
      HIGH      2   CVE-2026-YYYY  →  other-lib  (dep bump only)

    No action needed: 0 CVEs

    ╔ DIGEST COMPLETE ✓  1 repo scanned, 3 CVEs, 1 PR raised ╗
"""

from __future__ import annotations

import os
import sys
import json
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

# Force API mode before any analyzer import — digest is always non-interactive
os.environ.setdefault("SAGE_API_MODE", "1")


# ─── ANSI helpers (no rich dep — digest output must survive plain log files) ─

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
DIM    = "\033[2m"
PURPLE = "\033[95m"


def _c(text: str, *codes: str) -> str:
    """Wrap text in ANSI codes (stripped when not a TTY)."""
    if not sys.stdout.isatty():
        return text
    return "".join(codes) + text + RESET


def _box(title: str, width: int = 56) -> str:
    pad = width - len(title) - 2
    left  = pad // 2
    right = pad - left
    line  = "═" * width
    return (
        f"╔{line}╗\n"
        f"║{' ' * left}{title}{' ' * right}║\n"
        f"╚{line}╝"
    )


SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     YELLOW,
    "MEDIUM":   CYAN,
    "LOW":      DIM,
    "UNKNOWN":  DIM,
}


# ─── Main entry ──────────────────────────────────────────────────────────────

def run_digest(repo_paths: list[str], days: int = 1) -> int:
    """
    Run the full SAGE pipeline for each repo_path, print digest summary.
    Returns exit code: 0 = clean, 1 = CVEs found / PRs raised, 2 = error.
    """
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    print(_c(_box(f"SAGE Morning Digest — {date_str}"), BOLD, PURPLE))
    print()

    total_cves   = 0
    total_prs    = 0
    total_errors = 0
    results: list[dict] = []

    for repo_path in repo_paths:
        result = _scan_repo(repo_path, days)
        results.append(result)
        total_cves   += result.get("cve_count", 0)
        total_prs    += (1 if result.get("pr_url") else 0)
        total_errors += (1 if result.get("error") else 0)

    # Per-repo summaries
    for r in results:
        _print_repo_summary(r)

    # Final line
    print()
    status_icon = "✓" if total_errors == 0 else "⚠"
    parts = [
        f"{len(repo_paths)} repo{'s' if len(repo_paths) != 1 else ''} scanned",
        f"{total_cves} CVE{'s' if total_cves != 1 else ''}",
        f"{total_prs} PR{'s' if total_prs != 1 else ''} raised",
    ]
    if total_errors:
        parts.append(f"{total_errors} error{'s' if total_errors != 1 else ''}")

    summary = f" DIGEST {status_icon}  {', '.join(parts)} "
    width   = max(56, len(summary) + 2)
    line    = "═" * width
    color   = GREEN if total_errors == 0 and total_cves == 0 else (RED if total_errors else YELLOW)
    print(_c(f"╔{line}╗", color))
    print(_c(f"║{summary.center(width)}║", color, BOLD))
    print(_c(f"╚{line}╝", color))
    print()

    return 0 if total_errors == 0 else 2


def _scan_repo(repo_path: str, days: int) -> dict:
    """Run full pipeline for one repo. Returns structured result dict."""
    repo_name = Path(repo_path).name
    result: dict = {"repo_path": repo_path, "repo_name": repo_name}

    try:
        # Import here so digest can be imported without triggering pipeline
        from sage.fetcher.nvd    import fetch_cves_since
        from sage.fetcher.filter import detect_stack, filter_relevant_cves
        from sage.fetcher.store  import init_db, save_cves
        from sage.synapse.parser import parse_repo
        from sage.synapse.mapper import attach_cves, seed_libraries
        from sage.synapse.export import export_graph
        from sage.scanner.semgrep import scan_blast_radius, save_findings
        from sage.analyzer.llm import analyze_findings, save_confirmed
        from sage.patcher.llm  import run_patcher
        from sage.tests.runner    import run_tests, save_test_results
        from sage.verifier.semgrep import run_verifier, save_verifier_results
        from sage.github.pr        import run_github_pr, save_pr_result

        init_db()

        # 1 — Stack detection
        stack = detect_stack(repo_path)
        if not stack:
            result["skipped"] = True
            result["skip_reason"] = "No dependency files found"
            return result

        result["stack_size"] = len(stack)

        # 2 — Fetch + filter CVEs
        raw_cves  = fetch_cves_since(days=days)
        relevant  = filter_relevant_cves(raw_cves, stack)
        save_cves(relevant)
        result["raw_cve_count"] = len(raw_cves)

        # 3 — Synapse graph
        G = parse_repo(repo_path)
        G = seed_libraries(G, repo_path)
        G = attach_cves(G)
        export_graph(G, repo_path=repo_path)

        # Collect all CVE nodes
        seen_cves: set[str] = set()
        all_cves: list[dict] = []
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

        result["cve_count"] = len(all_cves)
        result["cves"]      = all_cves

        # 4 — Scanner
        findings = scan_blast_radius(G, repo_path)
        save_findings(findings)

        # 5 — Analyzer (always API in digest mode)
        confirmed = analyze_findings(findings, G, repo_path)
        save_confirmed(confirmed)
        result["confirmed_count"] = len(confirmed)
        result["confirmed"]       = confirmed

        # 6 — Patcher
        patch_result = run_patcher(confirmed, repo_path, all_cves=all_cves)
        result["dep_bump"]     = bool(patch_result.get("dep_bump"))
        result["code_patches"] = len(patch_result.get("code_patches", []))

        # 7 — Tests
        test_results = run_tests(patch_result, confirmed, repo_path)
        save_test_results(test_results)
        result["tests_passed"] = test_results.get("all_passed", False)

        # 8 — Verifier
        verify_results = run_verifier(patch_result, confirmed, repo_path)
        save_verifier_results(verify_results)
        result["verify_passed"] = verify_results.get("passed", False)

        # 9 — GitHub PR
        pr_result = run_github_pr(
            patch_result=patch_result,
            confirmed=confirmed,
            all_cves=all_cves,
            test_results=test_results,
            verify_results=verify_results,
            repo_path=repo_path,
        )
        save_pr_result(pr_result)
        result["pr_url"]    = pr_result.get("pr_url")
        result["pr_branch"] = pr_result.get("branch")
        result["pr_skip"]   = pr_result.get("skipped", False)
        result["pr_reason"] = pr_result.get("reason", "")

    except Exception as e:
        result["error"]     = str(e)
        result["traceback"] = traceback.format_exc()

    return result


def _print_repo_summary(r: dict):
    """Print one-repo section of the digest."""
    repo_name = r.get("repo_name", r.get("repo_path", "unknown"))
    repo_path = r.get("repo_path", "")

    print(_c(f"Repo: {repo_path}", BOLD) + _c(f"  ({repo_name})", DIM))
    print("─" * 56)

    if r.get("error"):
        print(_c(f"  ✗  Pipeline error: {r['error']}", RED))
        # Print traceback dimmed for log files
        for line in r.get("traceback", "").splitlines():
            print(_c(f"     {line}", DIM))
        print()
        return

    if r.get("skipped"):
        print(_c(f"  –  Skipped: {r.get('skip_reason', 'unknown')}", DIM))
        print()
        return

    cve_count  = r.get("cve_count", 0)
    confirmed  = r.get("confirmed", [])
    cves       = r.get("cves", [])

    if cve_count == 0:
        print(_c("  ✓  No CVEs found — stack looks clean", GREEN))
    else:
        # Count by severity
        by_sev: dict[str, list] = {}
        for c in cves:
            sev = c.get("severity", "UNKNOWN")
            by_sev.setdefault(sev, []).append(c)

        print(f"  CVEs found: {_c(str(cve_count), BOLD)}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            group = by_sev.get(sev, [])
            if not group:
                continue
            color = SEV_COLOR.get(sev, "")
            for c in group:
                cve_id  = c.get("cve_id", "")
                pkg     = c.get("package", "")
                is_conf = any(x.get("cve_id") == cve_id for x in confirmed)
                conf_tag = _c("  [CONFIRMED EXPLOITABLE]", RED) if is_conf else ""
                print(f"    {_c(f'{sev:8s}', color)}  {cve_id}  →  {pkg}{conf_tag}")

    # Patch summary
    if r.get("dep_bump") or r.get("code_patches", 0) > 0:
        patches = []
        if r.get("dep_bump"):
            patches.append("dep bump")
        if r.get("code_patches", 0) > 0:
            patches.append(f"{r['code_patches']} code patch(es)")
        print(f"\n  Patches generated: {', '.join(patches)}")

    # PR
    if r.get("pr_url"):
        print(f"  PR raised:   {_c(r['pr_url'], CYAN, BOLD)}")
    elif r.get("pr_skip") and r.get("pr_reason"):
        reason = r["pr_reason"]
        if "already patched" in reason.lower():
            print(_c(f"  PR skipped:  {reason}", DIM))
        elif cve_count > 0:
            print(_c(f"  PR skipped:  {reason}", YELLOW))

    # Test / verify flags
    if not r.get("tests_passed", True):
        print(_c("  ⚠  Tests failing — PR raised as draft", YELLOW))
    if not r.get("verify_passed", True):
        print(_c("  ⚠  Semgrep verification failed", YELLOW))

    print()
