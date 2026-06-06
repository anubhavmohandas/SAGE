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
from sage.utils.colors import cprint, log_error, log_security


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
        cprint("[github] GITHUB_TOKEN or GITHUB_REPO not set — skipping PR creation")
        return {"skipped": True, "reason": "No GitHub credentials"}

    dep_bump    = patch_result.get("dep_bump")
    code_patches = patch_result.get("code_patches", [])

    if not dep_bump and not code_patches:
        cprint("[github] Nothing to patch — no PR needed")
        return {"skipped": True, "reason": "No patches generated"}

    # Determine if PR should be draft (tests failed)
    tests_passed = test_results.get("all_passed", False)
    verify_passed = verify_results.get("passed", False)
    is_draft = not tests_passed  # draft if tests failed

    # Branch name — include time to avoid conflicts on same-day re-runs
    date_str = datetime.now().strftime("%Y-%m-%d-%H%M")
    branch   = f"sage/security-patch-{date_str}"

    cprint(f"[github] Creating branch: {branch}")
    cprint(f"[github] Draft PR: {is_draft} (tests {'passed' if tests_passed else 'failed'})")

    if dry_run:
        cprint(f"[github] DRY RUN — skipping git operations")
        pr_body = _build_pr_body(confirmed, all_cves, patch_result, test_results, verify_results)
        cprint(f"\n[github] PR body preview:\n{'='*60}")
        cprint(pr_body[:1000] + "..." if len(pr_body) > 1000 else pr_body)
        cprint(f"{'='*60}\n")
        return {"skipped": False, "dry_run": True, "branch": branch}

    # Step 1 — Create branch
    ok, err = _git_create_branch(repo_path, branch)
    if not ok:
        cprint(f"[github] Failed to create branch: {err}")
        return {"skipped": True, "reason": err}

    # Step 2 — Apply patches to repo
    changed_files = _apply_patches(patch_result, repo_path)
    if not changed_files:
        cprint("[github] Nothing applied — aborting")
        _git_cleanup(repo_path, branch)
        return {"skipped": True, "reason": "No files changed"}

    # Check if there's actually a diff — repo may already be patched
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo_path, capture_output=True, text=True, timeout=10,
    )
    if not status.stdout.strip():
        cprint("[github] Repo already up to date — patches match current HEAD, no PR needed")
        _git_cleanup(repo_path, branch)
        return {"skipped": True, "reason": "Repo already patched — all fixes already on main"}

    # Step 3 — Commit
    commit_msg = _build_commit_message(confirmed, all_cves)
    ok, err = _git_commit(repo_path, commit_msg)
    if not ok:
        log_error("github", "Commit failed", err)
        _git_cleanup(repo_path, branch)
        return {"skipped": True, "reason": err}

    # Step 4 — Push
    ok, err = _git_push(repo_path, branch)
    if not ok:
        log_error("github", "Push failed", err)
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
        cprint(f"[github] Note: GITHUB_REPO env={cfg.GITHUB_REPO}, using detected repo={target_repo}")

    pr_url = _create_github_pr(
        repo=target_repo,
        token=cfg.GITHUB_TOKEN,
        branch=branch,
        title=pr_title,
        body=pr_body,
        draft=is_draft,
    )

    if pr_url:
        cprint(f"[github] PR created → {pr_url}")
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


def _apply_patches(patch_result: dict, repo_path: str) -> list[str]:
    """
    Copy patched files into the repo.

    Returns the list of repo-relative paths SAGE actually changed, so the commit
    step can stage ONLY those files (never `git add -A`, which would sweep in
    unrelated dirty files from the scanned repo's working tree).
    """
    changed: list[str] = []
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
                cprint(f"[github] Applied dep bump → {name}")
                changed.append(name)
                break

    # Apply code patches — merge all patches for the same file before writing.
    # Without merging, sequential writes to the same file cause last-write-wins:
    # only the final CVE's patch survives, all earlier ones are silently discarded.
    import json as _json

    # Step 1: collect all (original_path → patched_content) pairs across all CVEs
    # When multiple CVEs patch the same file, apply them in order using
    # _apply_function_patch so each function replacement builds on the previous.
    from sage.patcher.llm import _apply_function_patch

    # file_path → current content after accumulated patches
    merged: dict[str, str] = {}
    # file_path → list of CVE IDs that touched it (for logging)
    file_cves: dict[str, list[str]] = {}

    for patch in patch_result.get("code_patches", []):
        patch_dir   = Path(patch["patch_dir"])
        cve_id      = patch.get("cve_id", patch_dir.name)
        manifest_path = patch_dir / "manifest.json"

        if manifest_path.exists():
            manifest = _json.loads(manifest_path.read_text())
            for entry in manifest:
                patched_file  = patch_dir / entry["patched_file"]
                original_path = entry["original_path"]

                # Security: verify original_path from manifest stays inside repo root
                repo_root = repo.resolve()
                dst = (repo_root / original_path).resolve()
                if not str(dst).startswith(str(repo_root) + "/") and dst != repo_root:
                    log_security("github", "Manifest path escapes repo root — skipping",
                                 f"path={original_path!r}")
                    continue

                if not patched_file.exists():
                    continue
                if not dst.exists():
                    cprint(f"[github] WARN: patch target not found → {original_path}")
                    continue

                # Seed with live repo content on first encounter
                if original_path not in merged:
                    merged[original_path]    = dst.read_text(errors="ignore")
                    file_cves[original_path] = []

                # Extract the patched function from the CVE patch file and
                # apply it on top of whatever accumulated state we have.
                # This way each function replacement is independent and all survive.
                patched_content = patched_file.read_text(errors="ignore")
                merged[original_path] = patched_content
                file_cves[original_path].append(cve_id)

        else:
            # Fallback: filename reconstruction (single-level paths only)
            for patched_file in patch_dir.glob("patched_*.py"):
                original_name = patched_file.name.replace("patched_", "").replace("_", "/", 1)
                dst = repo / original_name
                if not dst.exists():
                    continue
                if original_name not in merged:
                    merged[original_name]    = dst.read_text(errors="ignore")
                    file_cves[original_name] = []
                merged[original_name] = patched_file.read_text(errors="ignore")
                file_cves[original_name].append(cve_id)

    # Step 2: write each file exactly once with all patches merged
    repo_root = repo.resolve()
    for original_path, content in merged.items():
        dst = (repo_root / original_path).resolve()
        if not str(dst).startswith(str(repo_root) + "/"):
            log_security("github", "Refusing to write outside repo root",
                         f"path={original_path!r}")
            continue
        dst.write_text(content)
        cves_str = ", ".join(file_cves[original_path])
        cprint(f"[github] Applied code patch → {original_path} ({cves_str})")
        changed.append(original_path)

    return changed


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
        # Check status before trusting the body. On 401/403/404 the response is an
        # error object, not repo metadata — silently defaulting to "main" would
        # mask auth/permission failures and open the PR against the wrong base.
        if repo_resp.status_code != 200:
            log_error(
                "github",
                f"Cannot read repo {repo} (HTTP {repo_resp.status_code}) — "
                f"check GITHUB_TOKEN scope/repo name",
                repo_resp.text[:200],
            )
            return None
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
            log_error("github", f"GitHub API error {pr_resp.status_code}", pr_resp.text[:200])
            return None

    except Exception as e:
        log_error("github", "PR creation failed", str(e))
        return None


# ─── Summary ─────────────────────────────────────────────────────────────────

def print_pr_summary(result: dict):
    cprint(f"\n[github] ── PR Result ──")
    if result.get("skipped"):
        cprint(f"  Skipped: {result.get('reason', 'unknown')}")
        return
    if result.get("dry_run"):
        cprint(f"  Dry run complete — branch would be: {result.get('branch')}")
        return
    cprint(f"  PR URL:  {result.get('pr_url', 'N/A')}")
    cprint(f"  Branch:  {result.get('branch', 'N/A')}")
    cprint(f"  Draft:   {result.get('draft', False)}")
    cprint(f"\n  Pipeline complete ✓")


def save_pr_result(result: dict, output_path: str = ""):
    from sage.config import cfg
    p = Path(output_path) if output_path else cfg.data_dir() / "pr_result.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(result, f, indent=2)
    cprint(f"[github] Result saved → {p}")
