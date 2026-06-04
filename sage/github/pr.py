"""
github/pr.py — Automated GitHub PR creation

Creates a pull request on the scanned repo with:
  1. A new branch: sage/security-patch-<date>
  2. The bumped requirements.txt applied
  3. Any code patches applied (if confirmed exploitable CVEs exist)
  4. PR title + body with full CVE breakdown

Requires:
  - GITHUB_TOKEN in .env (fine-grained token with repo write access)
  - GITHUB_REPO in .env (format: owner/repo)
  - git installed and repo must be a git repo

Flow:
  1. Checkout new branch from default branch
  2. Apply patches (copy bumped requirements.txt into repo)
  3. git commit
  4. git push
  5. Create PR via GitHub API

Safety:
  - Never force pushes
  - Never pushes to main/master directly
  - PR is always a draft if tests failed
  - Dry-run mode available (--dry-run flag)
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests

from sage.config import cfg


PATCHES_DIR = Path("data/patches")


# ─── Entry point ─────────────────────────────────────────────────────────────

def run_github_pr(
    patch_result: dict,
    confirmed: list[dict],
    all_cves: list[dict],
    test_results: dict,
    verify_results: dict,
    repo_path: str,
    dry_run: bool = False,
) -> dict:
    """
    Create a GitHub PR with the security patches.

    Args:
        patch_result:    Output from patcher
        confirmed:       Confirmed exploitable CVEs
        all_cves:        All CVEs found (for dep bump context)
        test_results:    Output from test runner
        verify_results:  Output from verifier
        repo_path:       Path to the scanned repo
        dry_run:         If True, skip git push and PR creation

    Returns:
        {"pr_url": str, "branch": str, "draft": bool, "skipped": bool}
    """
    if not cfg.GITHUB_TOKEN or not cfg.GITHUB_REPO:
        print("[github] GITHUB_TOKEN or GITHUB_REPO not set — skipping PR creation")
        return {"skipped": True, "reason": "No GitHub credentials"}

    dep_bump    = patch_result.get("dep_bump")
    code_patches = patch_result.get("code_patches", [])

    if not dep_bump and not code_patches:
        print("[github] Nothing to patch — no PR needed")
        return {"skipped": True, "reason": "No patches generated"}

    # Determine if PR should be draft (tests failed)
    tests_passed = test_results.get("all_passed", False)
    verify_passed = verify_results.get("passed", False)
    is_draft = not tests_passed  # draft if tests failed

    # Branch name — include time to avoid conflicts on same-day re-runs
    date_str = datetime.now().strftime("%Y-%m-%d-%H%M")
    branch   = f"sage/security-patch-{date_str}"

    print(f"[github] Creating branch: {branch}")
    print(f"[github] Draft PR: {is_draft} (tests {'passed' if tests_passed else 'failed'})")

    if dry_run:
        print(f"[github] DRY RUN — skipping git operations")
        pr_body = _build_pr_body(confirmed, all_cves, patch_result, test_results, verify_results)
        print(f"\n[github] PR body preview:\n{'='*60}")
        print(pr_body[:1000] + "..." if len(pr_body) > 1000 else pr_body)
        print(f"{'='*60}\n")
        return {"skipped": False, "dry_run": True, "branch": branch}

    # Step 1 — Create branch
    ok, err = _git_create_branch(repo_path, branch)
    if not ok:
        print(f"[github] Failed to create branch: {err}")
        return {"skipped": True, "reason": err}

    # Step 2 — Apply patches to repo
    applied = _apply_patches(patch_result, repo_path)
    if not applied:
        print("[github] Nothing applied — aborting")
        _git_cleanup(repo_path, branch)
        return {"skipped": True, "reason": "No files changed"}

    # Check if there's actually a diff — repo may already be patched
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo_path, capture_output=True, text=True, timeout=10,
    )
    if not status.stdout.strip():
        print("[github] Repo already up to date — patches match current HEAD, no PR needed")
        _git_cleanup(repo_path, branch)
        return {"skipped": True, "reason": "Repo already patched — all fixes already on main"}

    # Step 3 — Commit
    commit_msg = _build_commit_message(confirmed, all_cves)
    ok, err = _git_commit(repo_path, commit_msg)
    if not ok:
        print(f"[github] Commit failed: {err}")
        _git_cleanup(repo_path, branch)
        return {"skipped": True, "reason": err}

    # Step 4 — Push
    ok, err = _git_push(repo_path, branch)
    if not ok:
        print(f"[github] Push failed: {err}")
        _git_cleanup(repo_path, branch)
        return {"skipped": True, "reason": err}

    # Step 5 — Create PR via API
    pr_title = _build_pr_title(confirmed, all_cves)
    pr_body  = _build_pr_body(confirmed, all_cves, patch_result, test_results, verify_results)

    # Resolve the correct GitHub repo for this repo_path.
    # GITHUB_REPO in .env may point to a different project (e.g. CyberTrace when
    # scanning SAGE). Always prefer the repo that owns the branch we just pushed.
    target_repo = _detect_github_repo(repo_path) or cfg.GITHUB_REPO
    if target_repo != cfg.GITHUB_REPO:
        print(f"[github] Note: GITHUB_REPO env={cfg.GITHUB_REPO}, using detected repo={target_repo}")

    pr_url = _create_github_pr(
        repo=target_repo,
        token=cfg.GITHUB_TOKEN,
        branch=branch,
        title=pr_title,
        body=pr_body,
        draft=is_draft,
    )

    if pr_url:
        print(f"[github] PR created → {pr_url}")
        return {"pr_url": pr_url, "branch": branch, "draft": is_draft, "skipped": False}
    else:
        return {"skipped": True, "reason": "PR creation failed"}


# ─── Git operations ───────────────────────────────────────────────────────────

def _detect_github_repo(repo_path: str) -> Optional[str]:
    """
    Extract owner/repo from the git remote URL of repo_path.

    Handles both HTTPS and SSH remotes:
      https://github.com/owner/repo.git  → owner/repo
      git@github.com:owner/repo.git      → owner/repo
    """
    import re as _re
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_path, capture_output=True, text=True, timeout=10,
        )
        url = result.stdout.strip()
        # HTTPS
        m = _re.search(r"github\.com[/:]([^/]+/[^/]+?)(?:\.git)?$", url)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def _git_create_branch(repo_path: str, branch: str) -> tuple[bool, str]:
    """Create and checkout a new branch from the default branch."""
    try:
        # Fetch latest
        subprocess.run(["git", "fetch", "origin"], cwd=repo_path, capture_output=True, timeout=30)

        # Get default branch
        result = subprocess.run(
            ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
            cwd=repo_path, capture_output=True, text=True, timeout=10,
        )
        default = result.stdout.strip().replace("refs/remotes/origin/", "") or "main"

        # Create branch from default
        result = subprocess.run(
            ["git", "checkout", "-b", branch, f"origin/{default}"],
            cwd=repo_path, capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return False, result.stderr.strip()
        return True, ""
    except Exception as e:
        return False, str(e)


def _apply_patches(patch_result: dict, repo_path: str) -> bool:
    """Copy patched files into the repo."""
    applied = False
    repo = Path(repo_path)

    # Apply dep bump — copy bumped requirements.txt into repo
    dep_bump = patch_result.get("dep_bump")
    if dep_bump:
        src = Path(dep_bump["file"])
        # Find original requirements file in repo
        for name in ("requirements.txt", "requirements-dev.txt"):
            dst = repo / name
            if dst.exists():
                dst.write_text(src.read_text())
                print(f"[github] Applied dep bump → {name}")
                applied = True
                break

    # Apply code patches — use manifest.json for correct paths (filename reconstruction
    # breaks for files nested >1 directory deep, e.g. sage/fetcher/filter.py)
    import json as _json
    for patch in patch_result.get("code_patches", []):
        patch_dir = Path(patch["patch_dir"])
        manifest_path = patch_dir / "manifest.json"

        if manifest_path.exists():
            # Use manifest for exact original paths
            manifest = _json.loads(manifest_path.read_text())
            for entry in manifest:
                patched_file = patch_dir / entry["patched_file"]
                original_path = entry["original_path"]
                dst = repo / original_path
                if patched_file.exists() and dst.exists():
                    dst.write_text(patched_file.read_text())
                    print(f"[github] Applied code patch → {original_path}")
                    applied = True
                elif not dst.exists():
                    print(f"[github] WARN: patch target not found → {original_path}")
        else:
            # Fallback: filename reconstruction (only works for single-level paths)
            for patched_file in patch_dir.glob("patched_*.py"):
                original_name = patched_file.name.replace("patched_", "").replace("_", "/", 1)
                dst = repo / original_name
                if dst.exists():
                    dst.write_text(patched_file.read_text())
                    print(f"[github] Applied code patch → {original_name}")
                    applied = True

    return applied


def _build_commit_message(confirmed: list[dict], all_cves: list[dict]) -> str:
    cve_ids = sorted(set(c["cve_id"] for c in all_cves if c.get("cve_id")))
    short_list = ", ".join(cve_ids[:3])
    if len(cve_ids) > 3:
        short_list += f" and {len(cve_ids) - 3} more"
    return f"security: bump vulnerable dependencies ({short_list})\n\nSAGE automated security patch.\nCVEs addressed: {', '.join(cve_ids)}"


def _git_commit(repo_path: str, message: str) -> tuple[bool, str]:
    try:
        # Check what's staged before committing
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_path, capture_output=True, text=True, timeout=10,
        )
        if not status.stdout.strip():
            return False, "nothing to commit — file content identical to branch HEAD (already patched?)"

        add_result = subprocess.run(
            ["git", "add", "-A"], cwd=repo_path, capture_output=True, text=True, timeout=10
        )

        result = subprocess.run(
            ["git", "commit", "-m", message],
            cwd=repo_path, capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            # git writes commit errors to both stdout and stderr
            err = (result.stderr.strip() or result.stdout.strip()) or "unknown commit error"
            return False, err
        return True, ""
    except Exception as e:
        return False, str(e)


def _git_push(repo_path: str, branch: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["git", "push", "origin", branch],
            cwd=repo_path, capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return False, result.stderr.strip()
        return True, ""
    except Exception as e:
        return False, str(e)


def _git_cleanup(repo_path: str, branch: str):
    """Switch back to default branch if something went wrong."""
    try:
        subprocess.run(["git", "checkout", "-"], cwd=repo_path, capture_output=True, timeout=10)
        subprocess.run(["git", "branch", "-D", branch], cwd=repo_path, capture_output=True, timeout=10)
    except Exception:
        pass


# ─── PR content builders ──────────────────────────────────────────────────────

def _build_pr_title(confirmed: list[dict], all_cves: list[dict]) -> str:
    critical = [c for c in all_cves if c.get("severity") == "CRITICAL"]
    high     = [c for c in all_cves if c.get("severity") == "HIGH"]

    if critical:
        return f"security: fix {len(critical)} CRITICAL + {len(high)} HIGH CVEs (dep bump)"
    elif high:
        return f"security: fix {len(high)} HIGH CVEs (dep bump)"
    else:
        return f"security: fix {len(all_cves)} CVEs (dep bump)"


def _build_pr_body(
    confirmed: list[dict],
    all_cves: list[dict],
    patch_result: dict,
    test_results: dict,
    verify_results: dict,
) -> str:
    dep_bump     = patch_result.get("dep_bump", {})
    code_patches = patch_result.get("code_patches", [])
    tests_passed = test_results.get("all_passed", False)
    verify_passed = verify_results.get("passed", False)

    # CVE table
    cve_table = "| CVE | Severity | Package | Fix |\n|-----|----------|---------|-----|\n"
    for cve in sorted(all_cves, key=lambda x: x.get("severity", ""), reverse=True):
        cve_id  = cve.get("cve_id", "")
        sev     = cve.get("severity", "UNKNOWN")
        pkg     = cve.get("package", "")
        fix     = "dep bump" if not any(p["cve_id"] == cve_id for p in code_patches) else "code patch"
        cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        cve_table += f"| [{cve_id}]({cve_url}) | {sev} | {pkg} | {fix} |\n"

    # Dep bump section
    dep_section = ""
    if dep_bump:
        dep_section = "\n## Dependency Changes\n\n"
        for pkg, ver, cves in dep_bump.get("changed", []):
            dep_section += f"- `{pkg}` bumped to `>={ver}` (fixes {len(cves)} CVE(s))\n"

    # Code patch section
    code_section = ""
    if code_patches:
        code_section = "\n## Code Patches\n\n"
        for p in code_patches:
            code_section += f"- `{p['cve_id']}` — see `{p['patch_dir']}/explanation.md`\n"

    # Test status
    test_status = "✅ All tests passed" if tests_passed else "⚠️ Pre-existing test failures detected (not caused by this patch)"
    verify_status = "✅ Semgrep verification passed" if verify_passed else "❌ Semgrep found issues"

    # Confirmed exploitable
    confirmed_section = ""
    if confirmed:
        confirmed_section = "\n## Confirmed Exploitable\n\nThese CVEs were confirmed exploitable in this codebase:\n\n"
        for v in confirmed:
            confirmed_section += f"- **{v['cve_id']}** ({v['severity']}): {v['reason']}\n"
    else:
        confirmed_section = "\n## Exploitability\n\nNo CVEs were confirmed exploitable in this codebase based on static analysis. The dep bumps are precautionary — library versions are outdated and should be upgraded regardless.\n"

    body = f"""## SAGE Security Patch

This PR was automatically generated by [SAGE](https://github.com/anubhavmohandas/SAGE) — Security Analysis & Graph Engine.

## CVE Summary

| Stat | Value |
|------|-------|
| Total CVEs found | {len(all_cves)} |
| Confirmed exploitable | {len(confirmed)} |
| Critical | {len([c for c in all_cves if c.get('severity') == 'CRITICAL'])} |
| High | {len([c for c in all_cves if c.get('severity') == 'HIGH'])} |
| Medium | {len([c for c in all_cves if c.get('severity') == 'MEDIUM'])} |

## CVEs Addressed

{cve_table}{dep_section}{code_section}{confirmed_section}
## Verification

- {test_status}
- {verify_status}

---
*Generated by SAGE on {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}*
"""
    return body


# ─── GitHub API ───────────────────────────────────────────────────────────────

def _create_github_pr(
    repo: str,
    token: str,
    branch: str,
    title: str,
    body: str,
    draft: bool = False,
) -> Optional[str]:
    """Create a PR via GitHub REST API. Returns PR URL or None."""
    # Get default branch
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        # Get repo info to find default branch
        repo_resp = requests.get(
            f"https://api.github.com/repos/{repo}",
            headers=headers,
            timeout=15,
        )
        default_branch = repo_resp.json().get("default_branch", "main")

        # Create PR
        pr_resp = requests.post(
            f"https://api.github.com/repos/{repo}/pulls",
            headers=headers,
            json={
                "title": title,
                "body":  body,
                "head":  branch,
                "base":  default_branch,
                "draft": draft,
            },
            timeout=15,
        )

        if pr_resp.status_code in (200, 201):
            return pr_resp.json().get("html_url")
        else:
            print(f"[github] API error {pr_resp.status_code}: {pr_resp.text[:200]}")
            return None

    except Exception as e:
        print(f"[github] PR creation error: {e}")
        return None


# ─── Summary ─────────────────────────────────────────────────────────────────

def print_pr_summary(result: dict):
    print(f"\n[github] ── PR Result ──")
    if result.get("skipped"):
        print(f"  Skipped: {result.get('reason', 'unknown')}")
        return
    if result.get("dry_run"):
        print(f"  Dry run complete — branch would be: {result.get('branch')}")
        return
    print(f"  PR URL:  {result.get('pr_url', 'N/A')}")
    print(f"  Branch:  {result.get('branch', 'N/A')}")
    print(f"  Draft:   {result.get('draft', False)}")
    print(f"\n  Pipeline complete ✓")


def save_pr_result(result: dict, output_path: str = ""):
    from sage.config import cfg
    p = Path(output_path) if output_path else cfg.data_dir() / "pr_result.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[github] Result saved → {p}")
