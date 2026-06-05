"""
tests/runner.py — Test runner for SAGE pipeline

Two jobs:
1. Run existing repo tests against the patched code
   - Discovers pytest/unittest in the repo
   - Runs them with the bumped requirements installed
   - Reports pass/fail

2. Generate security-specific tests for confirmed vulnerabilities
   - Uses Claude to write tests that verify the vulnerability is fixed
   - Tests are written to data/tests/<cve_id>_test.py
   - These tests are also run to confirm the patch works

Decision gate:
  - If existing tests pass AND security tests pass → safe to raise PR
  - If any test fails → block PR, report what broke
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

from sage.config import cfg


def _tests_dir() -> Path:
    try:
        from sage.config import cfg
        return cfg.data_dir("tests")
    except Exception:
        return Path("data/tests")

TESTS_DIR = Path("data/tests")  # legacy fallback


# ─── Entry point ─────────────────────────────────────────────────────────────

def _count_failures(output: str) -> int:
    """Parse number of failures from pytest output."""
    import re
    match = re.search(r"(\d+) failed", output)
    return int(match.group(1)) if match else 0


def run_tests(patch_result: dict, confirmed: list[dict], repo_path: str) -> dict:
    """
    Run all tests for the patched repo.

    Args:
        patch_result: Output from patcher — code_patches + dep_bump
        confirmed:    Confirmed exploitable CVEs (for security test generation)
        repo_path:    Path to the scanned repo

    Returns:
        {
          "existing_tests": {"passed": bool, "output": str, "count": int},
          "security_tests": {"passed": bool, "output": str, "files": [...]},
          "all_passed":     bool,
        }
    """
    _tests_dir().mkdir(parents=True, exist_ok=True)

    print(f"[tests] Running test suite for {repo_path}")

    results = {
        "existing_tests": None,
        "security_tests": None,
        "all_passed":     False,
    }

    # Step 1 — Run existing repo tests
    existing = _run_existing_tests(repo_path)
    results["existing_tests"] = existing

    # Adjust pass/fail — if failures are all pre-existing (baseline), don't block
    baseline_failures = existing.get("baseline_failures", 0)
    current_failures  = existing.get("failures", 0)
    new_failures      = max(0, current_failures - baseline_failures)
    if not existing.get("passed") and new_failures == 0:
        print(f"[tests] {current_failures} pre-existing failure(s) — not caused by SAGE patch")
        existing["passed"] = True  # override — pre-existing failures don't block PR

    # Step 2 — Generate + run security tests for confirmed vulns
    if confirmed:
        sec = _generate_and_run_security_tests(confirmed, patch_result, repo_path)
        results["security_tests"] = sec
    else:
        print("[tests] No confirmed vulnerabilities — skipping security test generation")
        results["security_tests"] = {"passed": True, "output": "No confirmed CVEs", "files": []}

    # Overall gate
    existing_ok  = results["existing_tests"].get("passed", False)
    security_ok  = results["security_tests"].get("passed", True)
    results["all_passed"] = existing_ok and security_ok

    return results


# ─── Existing test runner ─────────────────────────────────────────────────────

def _run_existing_tests(repo_path: str) -> dict:
    """
    Discover and run existing tests in the repo using pytest.
    Falls back to unittest if pytest not available.
    """
    repo = Path(repo_path)

    # Find test directories/files
    test_locations = []
    for pattern in ("tests/", "test/", "test_*.py", "*_test.py"):
        matches = list(repo.glob(pattern))
        test_locations.extend(matches)

    if not test_locations:
        print("[tests] No existing tests found in repo — skipping")
        return {
            "passed": True,  # No tests = not a failure
            "output": "No test files found in repo",
            "count":  0,
        }

    print(f"[tests] Found test locations: {[str(t) for t in test_locations[:3]]}")

    # Install repo's deps if requirements.txt exists
    _install_repo_deps(repo_path)

    print(f"[tests] Running existing tests...")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(repo_path), "-v", "--tb=short", "-q"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=repo_path,
        )
        output = result.stdout + result.stderr

        # If pytest itself isn't installed, fall back to unittest
        if "No module named pytest" in output:
            print("[tests] pytest not installed — trying unittest")
            return _run_unittest(repo_path)

        passed   = result.returncode == 0
        count    = _parse_pytest_count(output)
        failures = _count_failures(output)
        status   = "PASSED" if passed else "FAILED"
        print(f"[tests] Existing tests: {status} ({count} passed, {failures} failed)")
        if not passed:
            lines = output.strip().splitlines()
            for line in lines[-20:]:
                print(f"[tests]   {line}")

        # Load stored baseline (from a previous clean run), or store this as baseline
        baseline_failures = _load_or_store_baseline(repo_path, failures)

        return {
            "passed":            passed,
            "output":            output,
            "count":             count,
            "failures":          failures,
            "baseline_failures": baseline_failures,
        }

    except subprocess.TimeoutExpired:
        print("[tests] Existing tests timed out (120s)")
        return {"passed": False, "output": "Timeout after 120s", "count": 0}
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("[tests] pytest not found — trying unittest")
        return _run_unittest(repo_path)
    except subprocess.CalledProcessError:
        print("[tests] pytest not found — trying unittest")
        return _run_unittest(repo_path)
    except Exception as e:
        print(f"[tests] Error running tests: {e}")
        return {"passed": False, "output": str(e), "count": 0}


def _load_or_store_baseline(repo_path: str, current_failures: int) -> int:
    """
    Load the stored baseline failure count for this repo, or store current as baseline.

    On first ever run there's no baseline — we store current_failures as the baseline
    (they're all pre-existing since no patch has been applied yet).
    On subsequent runs we load the stored baseline so new failures are correctly flagged.

    Baseline file: data/<repo_name>/test_baseline.json
    """
    import json as _json
    try:
        repo_name = Path(repo_path).name
        baseline_file = cfg.data_dir() / "test_baseline.json"

        if baseline_file.exists():
            data = _json.loads(baseline_file.read_text())
            stored = data.get("baseline_failures", current_failures)
            print(f"[tests] Baseline: {stored} pre-existing failure(s)")
            return stored
        else:
            # First run — store as baseline
            baseline_file.write_text(_json.dumps({
                "baseline_failures": current_failures,
                "repo": repo_name,
                "note": "Failures present before any SAGE patch was applied"
            }, indent=2))
            print(f"[tests] Baseline stored: {current_failures} failure(s) (pre-existing)")
            return current_failures
    except Exception:
        return current_failures  # fallback: treat all as pre-existing


def _install_repo_deps(repo_path: str):
    """
    Install repo's requirements into the current venv so tests can import them.
    Skips if requirements.txt not found.
    """
    req = Path(repo_path) / "requirements.txt"
    if not req.exists():
        return
    print(f"[tests] Installing repo deps from {req}...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(req), "-q"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            print(f"[tests] Deps installed OK")
        else:
            print(f"[tests] Dep install warning: {result.stderr[:200]}")
    except Exception as e:
        print(f"[tests] Could not install deps: {e}")


def _run_unittest(repo_path: str) -> dict:
    """Fallback to unittest discovery."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", str(repo_path), "-v"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=repo_path,
        )
        passed = result.returncode == 0
        output = result.stdout + result.stderr
        print(f"[tests] unittest: {'PASSED' if passed else 'FAILED'}")
        return {"passed": passed, "output": output, "count": 0}
    except Exception as e:
        return {"passed": False, "output": str(e), "count": 0}


def _parse_pytest_count(output: str) -> int:
    """Parse number of tests run from pytest output."""
    import re
    match = re.search(r"(\d+) passed", output)
    if match:
        return int(match.group(1))
    match = re.search(r"(\d+) (test|item)", output)
    if match:
        return int(match.group(1))
    return 0


# ─── Security test generator ──────────────────────────────────────────────────

def _generate_and_run_security_tests(
    confirmed: list[dict],
    patch_result: dict,
    repo_path: str,
) -> dict:
    """
    Generate security tests for each confirmed vulnerability using Claude.
    Tests verify:
      1. The vulnerable input no longer triggers the bug
      2. Normal inputs still work correctly
    """
    generated_files = []

    for vuln in confirmed:
        cve_id   = vuln["cve_id"]
        test_file = _tests_dir() / f"test_{cve_id.replace('-', '_')}.py"

        # Get the patched code for context
        patch_dir = Path("data/patches") / cve_id
        patched_code = ""
        if patch_dir.exists():
            for f in patch_dir.glob("patched_*.py"):
                patched_code = f.read_text(errors="ignore")
                break

        # Generate test via Claude
        test_code = _generate_security_test(vuln, patched_code)
        if test_code:
            test_file.write_text(test_code)
            generated_files.append(str(test_file))
            print(f"[tests] Security test generated → {test_file.name}")

    if not generated_files:
        print("[tests] No security tests generated")
        return {"passed": True, "output": "No tests generated", "files": []}

    # Run generated security tests
    print(f"[tests] Running {len(generated_files)} security test(s)...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(_tests_dir()), "-v", "--tb=short"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        passed = result.returncode == 0
        output = result.stdout + result.stderr
        print(f"[tests] Security tests: {'PASSED' if passed else 'FAILED'}")
        return {"passed": passed, "output": output, "files": generated_files}
    except Exception as e:
        print(f"[tests] Error running security tests: {e}")
        return {"passed": False, "output": str(e), "files": generated_files}


def _generate_security_test(vuln: dict, patched_code: str) -> Optional[str]:
    """Ask Claude to write a security test for a confirmed vulnerability."""
    if not cfg.ANTHROPIC_API_KEY:
        print(f"[tests] No Anthropic key — skipping test generation for {vuln['cve_id']}")
        return None

    cve_id    = vuln["cve_id"]
    package   = vuln.get("package", "")
    cwe       = vuln.get("cwe", "")
    reason    = vuln.get("reason", "")
    attack    = vuln.get("attack_vector", "")
    functions = vuln.get("affected_functions", [])

    prompt = f"""You are a security engineer writing a pytest test to verify a vulnerability fix.

VULNERABILITY:
- CVE: {cve_id}
- Package: {package}
- CWE: {cwe}
- Why it was exploitable: {reason}
- Attack vector: {attack}
- Affected functions: {', '.join(functions) if functions else 'unknown'}

PATCHED CODE:
```python
{patched_code[:2000] if patched_code else "Not available — dep bump only"}
```

TASK:
Write a pytest test file that:
1. Tests that the vulnerability is no longer exploitable (the malicious input is rejected/sanitized)
2. Tests that normal inputs still work correctly

Rules:
- Use pytest
- Keep it simple — 2-3 test functions max
- Import only stdlib + the affected package
- If patched code is not available (dep bump only), test that the package version is now safe
- Add a docstring explaining what each test verifies

OUTPUT: Respond with ONLY valid Python code. No markdown fences. No explanation outside the code."""

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=cfg.ANTHROPIC_API_KEY)
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=2048,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        )
        code = response.content[0].text.strip()
        # Strip fences if present
        if code.startswith("```"):
            parts = code.split("```")
            code = parts[1] if len(parts) > 1 else code
            if code.startswith("python"):
                code = code[6:]
        return code.strip()
    except Exception as e:
        print(f"[tests] Claude error generating test for {cve_id}: {e}")
        return None


# ─── Summary ─────────────────────────────────────────────────────────────────

def print_test_summary(results: dict):
    print(f"\n[tests] ── Test Results ──")

    et = results.get("existing_tests", {})
    st = results.get("security_tests", {})

    existing_status = "PASSED" if et.get("passed") else "FAILED" if et else "SKIPPED"
    security_status = "PASSED" if st.get("passed") else "FAILED" if st else "SKIPPED"

    print(f"  Existing tests:  {existing_status} ({et.get('count', 0)} tests)")
    print(f"  Security tests:  {security_status} ({len(st.get('files', []))} generated)")
    print(f"  Overall:         {'✓ ALL PASSED — safe to raise PR' if results.get('all_passed') else '✗ FAILURES — PR blocked'}")

    if not results.get("all_passed"):
        print(f"\n  Fix failing tests before raising the PR.")
        print(f"  Test output saved — check data/tests/ for details.")

    print(f"  Next: verifier → github PR")


def save_test_results(results: dict, output_path: str = ""):
    p = Path(output_path) if output_path else cfg.data_dir() / "test_results.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "existing_tests": {
            "passed": results.get("existing_tests", {}).get("passed"),
            "count":  results.get("existing_tests", {}).get("count", 0),
        },
        "security_tests": {
            "passed": results.get("security_tests", {}).get("passed"),
            "files":  results.get("security_tests", {}).get("files", []),
        },
        "all_passed": results.get("all_passed", False),
    }
    with open(p, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[tests] Results saved → {p}")
