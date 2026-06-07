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
import os
import sys
from pathlib import Path
from typing import Optional

from sage.config import cfg
from sage.utils.colors import cprint


# ─── Security: clean environment for executing untrusted code ──────────────────
#
# H1 mitigation. SAGE installs the scanned repo's dependencies (pip runs its
# build hooks) and runs its tests + LLM-generated test code as child processes.
# Child processes inherit the parent's environment by default — which means a
# malicious setup.py or test could read SAGE's API keys/tokens straight out of
# os.environ and exfiltrate them, even though .env is never leaked to git.
#
# Defence: every subprocess that runs scanned-repo or LLM-generated code is
# launched with a scrubbed environment built from an ALLOWLIST. Only known-safe
# variables pass through; anything else (including any future secret you add to
# .env) is excluded by default rather than by remembering to deny it.
#
# This is a backstop, NOT a sandbox. The real isolation is: scan untrusted repos
# in a disposable VM / container (see README "Running on untrusted repos").

# Vars genuinely needed for pip/pytest/python to function.
_ENV_ALLOWLIST = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "PWD", "TMPDIR", "TEMP", "TMP",
    "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM",
    # Python / virtualenv
    "PYTHONPATH", "PYTHONHOME", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE",
    "VIRTUAL_ENV", "PYENV_ROOT", "PYENV_VERSION",
    # pip behaviour (no secrets) — keep proxy/cache/index config working
    "PIP_CACHE_DIR", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_NO_CACHE_DIR",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "no_proxy",
    # Windows essentials
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "APPDATA", "LOCALAPPDATA",
    "PROGRAMFILES", "PROGRAMDATA", "COMSPEC", "PATHEXT", "NUMBER_OF_PROCESSORS",
})


def _clean_env() -> dict:
    """
    Return an environment dict containing only allowlisted variables.

    Used for every subprocess that executes untrusted (scanned-repo or
    LLM-generated) code, so SAGE's secrets are never exposed to that code.
    """
    return {k: v for k, v in os.environ.items() if k in _ENV_ALLOWLIST}


def _untrusted_exec_warning(repo_path: str) -> None:
    """Print an honest, one-time-ish warning before executing scanned code."""
    cprint(
        "\n[tests] ⚠️  SECURITY: SAGE is about to EXECUTE code from the scanned "
        f"repo ({repo_path})\n"
        "[tests]    This runs its dependency build hooks (pip) and its tests on "
        "THIS machine.\n"
        "[tests]    SAGE's own API keys are scrubbed from these subprocesses, "
        "but this is NOT a sandbox.\n"
        "[tests]    For UNTRUSTED repos, run SAGE inside a disposable VM/"
        "container instead.\n"
    )


# Security-test generation prompt. Shared by API mode (sent to the LLM) and
# manual mode (exported to a file for you to paste into Claude).
_TEST_PROMPT_TEMPLATE = """You are a security engineer writing a pytest test to verify a vulnerability fix.

VULNERABILITY:
- CVE: {cve_id}
- Package: {package}
- CWE: {cwe}
- Why it was exploitable: {reason}
- Attack vector: {attack}
- Affected functions: {functions}

PATCHED CODE:
```python
{patched}
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
- For async cleanup (e.g. closing aiohttp sessions), use `asyncio.run(session.close())` — NEVER use `asyncio.get_event_loop().run_until_complete(...)` as it is deprecated and raises RuntimeError on Python 3.10+
- Target Python 3.10+ compatibility

OUTPUT: Respond with ONLY valid Python code. No markdown fences. No explanation outside the code."""


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

    cprint(f"[tests] Running test suite for {repo_path}")

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
        cprint(f"[tests] {current_failures} pre-existing failure(s) — not caused by SAGE patch")
        existing["passed"] = True  # override — pre-existing failures don't block PR

    # Step 2 — Generate + run security tests for confirmed vulns
    if confirmed:
        sec = _generate_and_run_security_tests(confirmed, patch_result, repo_path)
        results["security_tests"] = sec
    else:
        cprint("[tests] No confirmed vulnerabilities — skipping security test generation")
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
        cprint("[tests] No existing tests found in repo — skipping")
        return {
            "passed": True,  # No tests = not a failure
            "output": "No test files found in repo",
            "count":  0,
        }

    cprint(f"[tests] Found test locations: {[str(t) for t in test_locations[:3]]}")

    # SECURITY: from here on we execute scanned-repo code. Warn + scrub env.
    _untrusted_exec_warning(repo_path)

    # Install repo's deps if requirements.txt exists
    _install_repo_deps(repo_path)

    cprint(f"[tests] Running existing tests...")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(repo_path), "-v", "--tb=short", "-q"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=repo_path,
            env=_clean_env(),  # SECURITY: no SAGE secrets in scanned-code env
        )
        output = result.stdout + result.stderr

        # If pytest itself isn't installed, fall back to unittest
        if "No module named pytest" in output:
            cprint("[tests] pytest not installed — trying unittest")
            return _run_unittest(repo_path)

        passed   = result.returncode == 0
        count    = _parse_pytest_count(output)
        failures = _count_failures(output)
        status   = "PASSED" if passed else "FAILED"
        cprint(f"[tests] Existing tests: {status} ({count} passed, {failures} failed)")
        if not passed:
            lines = output.strip().splitlines()
            for line in lines[-20:]:
                cprint(f"[tests]   {line}")

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
        cprint("[tests] Existing tests timed out (120s)")
        return {"passed": False, "output": "Timeout after 120s", "count": 0}
    except (FileNotFoundError, subprocess.CalledProcessError):
        cprint("[tests] pytest not found — trying unittest")
        return _run_unittest(repo_path)
    except subprocess.CalledProcessError:
        cprint("[tests] pytest not found — trying unittest")
        return _run_unittest(repo_path)
    except Exception as e:
        cprint(f"[tests] Error running tests: {e}")
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
            cprint(f"[tests] Baseline: {stored} pre-existing failure(s)")
            return stored
        else:
            # First run — store as baseline
            baseline_file.write_text(_json.dumps({
                "baseline_failures": current_failures,
                "repo": repo_name,
                "note": "Failures present before any SAGE patch was applied"
            }, indent=2))
            cprint(f"[tests] Baseline stored: {current_failures} failure(s) (pre-existing)")
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
    cprint(f"[tests] Installing repo deps from {req}...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(req), "-q"],
            capture_output=True,
            text=True,
            timeout=120,
            env=_clean_env(),  # SECURITY: pip runs build hooks — no SAGE secrets
        )
        if result.returncode == 0:
            cprint(f"[tests] Deps installed OK")
        else:
            cprint(f"[tests] Dep install warning: {result.stderr[:200]}")
    except Exception as e:
        cprint(f"[tests] Could not install deps: {e}")


def _run_unittest(repo_path: str) -> dict:
    """Fallback to unittest discovery."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", str(repo_path), "-v"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=repo_path,
            env=_clean_env(),  # SECURITY: no SAGE secrets in scanned-code env
        )
        passed = result.returncode == 0
        output = result.stdout + result.stderr
        cprint(f"[tests] unittest: {'PASSED' if passed else 'FAILED'}")
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

        # Get the patched code for context. Use the REPO-SCOPED patches dir
        # (data/<repo>/patches/<cve>), not the legacy data/patches — otherwise the
        # patched code is never found and tests are generated without context.
        patch_dir = cfg.data_dir("patches", cve_id)
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
            cprint(f"[tests] Security test generated → {test_file.name}")

    if not generated_files:
        cprint("[tests] No security tests generated")
        return {"passed": True, "output": "No tests generated", "files": []}

    # Run generated security tests
    cprint(f"[tests] Running {len(generated_files)} security test(s)...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(_tests_dir()), "-v", "--tb=short"],
            capture_output=True,
            text=True,
            timeout=60,
            env=_clean_env(),  # SECURITY: LLM-generated tests — no SAGE secrets
        )
        passed = result.returncode == 0
        output = result.stdout + result.stderr
        cprint(f"[tests] Security tests: {'PASSED' if passed else 'FAILED'}")
        return {"passed": passed, "output": output, "files": generated_files}
    except Exception as e:
        cprint(f"[tests] Error running security tests: {e}")
        return {"passed": False, "output": str(e), "files": generated_files}


def _build_test_prompt(vuln: dict, patched_code: str) -> str:
    """Build the security-test generation prompt (shared by API and manual modes)."""
    cve_id    = vuln["cve_id"]
    package   = vuln.get("package", "")
    cwe       = vuln.get("cwe", "")
    reason    = vuln.get("reason", "")
    attack    = vuln.get("attack_vector", "")
    functions = vuln.get("affected_functions", [])
    return _TEST_PROMPT_TEMPLATE.format(
        cve_id=cve_id, package=package, cwe=cwe, reason=reason, attack=attack,
        functions=', '.join(functions) if functions else 'unknown',
        patched=patched_code[:2000] if patched_code else "Not available — dep bump only",
    )


def _manual_test(vuln: dict, patched_code: str) -> Optional[str]:
    """
    Manual-mode test generation: export a prompt and reuse a saved test file.

    Mirrors the patcher's manual flow. We need security tests in manual mode too
    (verification doesn't depend on the LLM, but test *generation* does) — so SAGE
    exports a prompt for you to paste into Claude, and reads back the test you save.
    Reuse is gated on CONTENT (a real .py test), not timestamp.
    """
    import sys
    cve_id     = vuln["cve_id"]
    td         = _tests_dir()
    prompt_file = td / f"test_prompt_{cve_id.replace('-', '_')}.txt"
    test_file   = td / f"test_{cve_id.replace('-', '_')}.py"

    # Reuse an existing test if it has real content (not empty/placeholder).
    if test_file.exists():
        existing = test_file.read_text(errors="ignore").strip()
        if existing and ("def test" in existing or "import" in existing):
            cprint(f"[tests] {cve_id} → reusing saved security test")
            return existing

    prompt = _build_test_prompt(vuln, patched_code)
    prompt_file.write_text(prompt)

    if not sys.stdin.isatty():
        cprint(f"[tests] {cve_id} — test prompt exported (manual mode), skipping")
        return None

    cprint(f"\n[tests] ── Manual security test needed: {cve_id} ──")
    cprint(f"  Prompt saved → {prompt_file.resolve()}")
    cprint(f"  1. Paste into Claude / ChatGPT")
    cprint(f"  2. Save the Python test to:")
    cprint(f"     {test_file.resolve()}")
    cprint(f"  Press Enter when saved  |  S to skip this CVE")

    import select
    while True:
        ready, _, _ = select.select([sys.stdin], [], [], 3.0)
        if ready:
            choice = sys.stdin.readline().strip().lower()
            if choice == "s":
                cprint(f"[tests] Skipping test for {cve_id}")
                return None
            break
        if test_file.exists() and test_file.read_text(errors="ignore").strip():
            break
        cprint(f"  Waiting for {test_file.name}...", end="\r", flush=True)

    if test_file.exists():
        code = test_file.read_text(errors="ignore").strip()
        if code:
            cprint(f"[tests] {cve_id} → manual security test loaded")
            return code
    return None


def _generate_security_test(vuln: dict, patched_code: str) -> Optional[str]:
    """Ask Claude to write a security test for a confirmed vulnerability."""
    # Manual mode: export prompt + reuse saved test (no API call).
    if getattr(cfg, "llm_mode", "api") == "manual":
        return _manual_test(vuln, patched_code)
    if not cfg.ANTHROPIC_API_KEY:
        cprint(f"[tests] No Anthropic key — skipping test generation for {vuln['cve_id']}")
        return None

    prompt = _build_test_prompt(vuln, patched_code)

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
        cprint(f"[tests] Claude error generating test for {vuln['cve_id']}: {e}")
        return None


# ─── Summary ─────────────────────────────────────────────────────────────────

def print_test_summary(results: dict):
    cprint(f"\n[tests] ── Test Results ──")

    et = results.get("existing_tests", {})
    st = results.get("security_tests", {})

    existing_status = "PASSED" if et.get("passed") else "FAILED" if et else "SKIPPED"
    security_status = "PASSED" if st.get("passed") else "FAILED" if st else "SKIPPED"

    cprint(f"  Existing tests:  {existing_status} ({et.get('count', 0)} tests)")
    cprint(f"  Security tests:  {security_status} ({len(st.get('files', []))} generated)")
    cprint(f"  Overall:         {'✓ ALL PASSED — safe to raise PR' if results.get('all_passed') else '✗ FAILURES — PR blocked'}")

    if not results.get("all_passed"):
        cprint(f"\n  Fix failing tests before raising the PR.")
        cprint(f"  Test output saved — check data/tests/ for details.")

    cprint(f"  Next: verifier → github PR")


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
    cprint(f"[tests] Results saved → {p}")
