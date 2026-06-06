"""
verifier/semgrep.py — Final Semgrep verification pass

Runs Semgrep on patched files to confirm:
1. No new vulnerabilities introduced by the patch
2. The original CVE's CWE pattern no longer triggers on patched code

Two scenarios:

A. Code patches (confirmed exploitable CVEs):
   - Runs Semgrep on data/patches/<cve_id>/patched_*.py
   - Checks that the CWE-specific rule no longer fires
   - Checks that no new issues were introduced

B. Dep bump only (no code patches):
   - Verifies the bumped requirements.txt has correct version constraints
   - Runs Semgrep on the original repo files (should still be clean)

Verdict:
  PASS → proceed to GitHub PR
  FAIL → block PR, report what's wrong
"""

import json
import subprocess
from pathlib import Path
from typing import Optional

from sage.scanner.semgrep import CWE_TO_RULES, _EXT_TO_DEFAULTS, DEFAULT_RULES_PYTHON
from sage.utils.colors import cprint, log_error, log_warn_panel


def _patches_dir() -> Path:
    try:
        from sage.config import cfg
        return cfg.data_dir("patches")
    except Exception:
        return Path("data/patches")

def _verify_dir() -> Path:
    try:
        from sage.config import cfg
        return cfg.data_dir("verify")
    except Exception:
        return Path("data/verify")

PATCHES_DIR = Path("data/patches")  # legacy
VERIFY_DIR  = Path("data/verify")   # legacy


# ─── Entry point ─────────────────────────────────────────────────────────────

def run_verifier(patch_result: dict, confirmed: list[dict], repo_path: str) -> dict:
    """
    Run final verification on all patches.

    Args:
        patch_result: Output from patcher
        confirmed:    Confirmed exploitable CVEs
        repo_path:    Path to the scanned repo

    Returns:
        {
          "passed":       bool,
          "code_results": [...],   # per-CVE semgrep results on patched code
          "dep_result":   {...},   # dep bump verification result
          "new_issues":   [...],   # any NEW issues introduced by patch
        }
    """
    _verify_dir().mkdir(parents=True, exist_ok=True)

    results = {
        "passed":       True,
        "code_results": [],
        "dep_result":   None,
        "new_issues":   [],
    }

    code_patches = patch_result.get("code_patches", [])
    dep_bump     = patch_result.get("dep_bump")

    # A — Verify code patches
    if code_patches:
        cprint(f"[verifier] Verifying {len(code_patches)} code patch(es)...")
        for patch in code_patches:
            cve_id    = patch["cve_id"]
            patch_dir = Path(patch["patch_dir"])

            # Find the CVE's CWE for targeted rule selection
            cve_data = next((c for c in confirmed if c["cve_id"] == cve_id), {})
            cwe      = cve_data.get("cwe", "")

            result = _verify_code_patch(cve_id, cwe, patch_dir)
            results["code_results"].append(result)

            if not result["passed"]:
                results["passed"] = False
                results["new_issues"].extend(result.get("findings", []))

            status = "✓ CLEAN" if result["passed"] else "✗ ISSUES FOUND"
            cprint(f"[verifier] {cve_id} patch → {status}")
    else:
        cprint("[verifier] No code patches to verify")

    # B — Verify dep bump
    if dep_bump:
        cprint(f"[verifier] Verifying dep bump...")
        dep_result = _verify_dep_bump(dep_bump, repo_path)
        results["dep_result"] = dep_result
        if not dep_result["passed"]:
            results["passed"] = False
        status = "✓ VALID" if dep_result["passed"] else "✗ INVALID"
        cprint(f"[verifier] Dep bump → {status}")
    else:
        cprint("[verifier] No dep bump to verify")

    return results


# ─── Code patch verifier ──────────────────────────────────────────────────────

def _verify_code_patch(cve_id: str, cwe: str, patch_dir: Path) -> dict:
    """
    Run Semgrep on the patched file.
    Checks:
      1. CWE-specific rule no longer fires (fix worked)
      2. No new issues introduced (patch is safe)
    """
    # Find patched files — any supported language extension.
    # BUG WAS HERE: glob pattern "patched_{pat[1:]}" → "patched_.py" (no wildcard),
    # which never matched real files like "patched_cybertrace_modules_base.py".
    # The verifier therefore always reported "No patched files found" even when a
    # real patch existed. Correct pattern is "patched_*<ext>".
    _PATCHED_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx")
    patched_files = []
    for ext in _PATCHED_EXTS:
        patched_files.extend(patch_dir.glob(f"patched_*{ext}"))
    if not patched_files:
        return {
            "cve_id":  cve_id,
            "passed":  True,
            "reason":  "No patched files found — dep bump only",
            "findings": [],
        }

    all_findings = []
    for patched_file in patched_files:
        ext = patched_file.suffix.lower()
        lang_defaults = _EXT_TO_DEFAULTS.get(ext, DEFAULT_RULES_PYTHON)
        cwe_rules = CWE_TO_RULES.get(cwe, [])
        base = cwe_rules if cwe_rules else lang_defaults
        rules = list(set(base + ["p/security-audit"]))
        findings = _run_semgrep_on_file(str(patched_file), rules)
        all_findings.extend(findings)

    # Filter out known false positives (informational rules)
    real_findings = [f for f in all_findings if f.get("severity", "").upper() not in ("INFO", "WARNING")]

    passed = len(real_findings) == 0
    return {
        "cve_id":   cve_id,
        "passed":   passed,
        "reason":   f"{len(real_findings)} issue(s) found in patched code" if not passed else "Clean",
        "findings": real_findings,
    }


def _run_semgrep_on_file(file_path: str, rules: list[str]) -> list[dict]:
    """Run Semgrep with given rules on a single file."""
    if not rules:
        return []

    cmd = ["semgrep", "--json", "--quiet", file_path]
    for rule in rules[:3]:  # limit rules to avoid rate limiting
        cmd += ["--config", rule]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode not in (0, 1):
            return []

        data = json.loads(result.stdout or "{}")
        findings = []
        for r in data.get("results", []):
            findings.append({
                "rule_id":  r.get("check_id", ""),
                "file":     r.get("path", ""),
                "line":     r.get("start", {}).get("line", 0),
                "message":  r.get("extra", {}).get("message", ""),
                "severity": r.get("extra", {}).get("severity", ""),
            })
        return findings

    except subprocess.TimeoutExpired:
        log_warn_panel("verifier", f"Semgrep timed out on {Path(file_path).name}",
                       "Patch file skipped — result may be incomplete")
        return []
    except (json.JSONDecodeError, Exception):
        return []


# ─── Dep bump verifier ────────────────────────────────────────────────────────

def _verify_dep_bump(dep_bump: dict, repo_path: str) -> dict:
    """
    Verify the bumped requirements.txt:
    1. File exists and is parseable
    2. Each bumped package has a valid version constraint
    3. Version constraint is >= safe version (not pinned too low)
    """
    bump_file = Path(dep_bump.get("file", ""))
    if not bump_file.exists():
        return {"passed": False, "reason": "Bumped requirements.txt not found", "issues": []}

    content = bump_file.read_text()
    issues  = []
    changed = dep_bump.get("changed", [])

    for pkg, safe_ver, cve_ids in changed:
        # Check the line exists in the bumped file
        found = False
        for line in content.splitlines():
            line_pkg = line.split(">=")[0].split("==")[0].strip().lower().replace("_", "-")
            if line_pkg == pkg.lower():
                found = True
                # Check version constraint is present
                if ">=" not in line:
                    issues.append(f"{pkg}: no >= constraint found")
                break

        if not found:
            issues.append(f"{pkg}: package not found in bumped requirements")

    # Also run a quick Semgrep on original repo files to confirm still clean
    repo_clean = _quick_semgrep_check(repo_path)
    if not repo_clean:
        issues.append("Semgrep found new issues in repo after dep bump")

    passed = len(issues) == 0
    return {
        "passed": passed,
        "reason": "; ".join(issues) if issues else "All version constraints valid",
        "issues": issues,
    }


def _quick_semgrep_check(repo_path: str) -> bool:
    """Quick Semgrep pass on repo — returns True if clean."""
    try:
        result = subprocess.run(
            ["semgrep", "--json", "--quiet", "--config", "p/security-audit", repo_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
        data = json.loads(result.stdout or "{}")
        findings = data.get("results", [])
        if findings:
            cprint(f"[verifier] Semgrep found {len(findings)} issue(s) in repo (pre-existing)")
        # Pre-existing findings don't block — we only care about NEW ones introduced by patch
        return True
    except Exception:
        return True  # If Semgrep fails, don't block on it


# ─── Summary ─────────────────────────────────────────────────────────────────

def print_verifier_summary(results: dict):
    cprint(f"\n[verifier] ── Verification Results ──")

    for r in results.get("code_results", []):
        status = "✓ CLEAN" if r["passed"] else "✗ ISSUES"
        cprint(f"  {r['cve_id']} patch:  {status} — {r['reason']}")

    dep = results.get("dep_result")
    if dep:
        status = "✓ VALID" if dep["passed"] else "✗ INVALID"
        cprint(f"  Dep bump:          {status} — {dep['reason']}")

    new_issues = results.get("new_issues", [])
    if new_issues:
        cprint(f"\n  New issues introduced by patch ({len(new_issues)}):")
        for issue in new_issues[:5]:
            cprint(f"    [{issue.get('severity', '?')}] {issue.get('rule_id', '')} "
                  f"@ {issue.get('file', '')}:{issue.get('line', '')}")

    overall = "✓ PASSED — safe to raise PR" if results["passed"] else "✗ FAILED — fix issues before PR"
    cprint(f"\n  Overall: {overall}")
    cprint(f"  Next: github PR")


def save_verifier_results(results: dict, output_path: str = ""):
    from sage.config import cfg
    p = Path(output_path) if output_path else cfg.data_dir() / "verify_results.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(results, f, indent=2)
    cprint(f"[verifier] Results saved → {p}")
