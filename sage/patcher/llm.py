"""
patcher/llm.py — Automated patch generation

Two patch strategies depending on what the analyzer confirmed:

1. CODE PATCH (confirmed exploitable):
   - Claude reads the vulnerable function
   - Generates a targeted code fix
   - Writes patched file to data/patches/<cve_id>/

2. DEP BUMP (outdated dep, not exploitable in code):
   - Reads requirements.txt / pyproject.toml from repo
   - Bumps affected package version to safe minimum
   - Writes patched requirements to data/patches/requirements.txt

The patcher never modifies the repo directly.
It writes patches to data/patches/ — the verifier and github modules apply them.

Patch output structure:
  data/patches/
    requirements.txt          ← bumped deps (always generated if any CVEs found)
    CVE-XXXX/
      original.py             ← original file
      patched.py              ← Claude's fix
      diff.patch              ← unified diff
      explanation.md          ← what changed and why
"""

import json
import subprocess
from pathlib import Path
from typing import Optional

from sage.config import cfg
from sage.utils.colors import cprint, log_error, log_security, log_warn_panel
from sage.utils.validate import validate_patcher_response


def _patches_dir() -> Path:
    try:
        from sage.config import cfg
        return cfg.data_dir("patches")
    except Exception:
        return Path("data/patches")

PATCHES_DIR = Path("data/patches")  # legacy fallback


# ─── Entry point ─────────────────────────────────────────────────────────────

def run_patcher(confirmed: list[dict], repo_path: str, all_cves: list[dict] = None):
    """
    Main patcher entry point.

    Args:
        confirmed:  List of confirmed-exploitable CVEs from analyzer.
        repo_path:  Path to the scanned repo.
        all_cves:   All CVEs (from DB) for dep bump, even non-exploitable ones.
                    If None, only confirmed CVEs get dep bumps.
    """
    pd = _patches_dir()

    cprint(f"[patcher] {len(confirmed)} confirmed exploitable CVE(s) → code patches")

    # 1. Code patches for confirmed exploitable CVEs
    code_patches = []
    for vuln in confirmed:
        patch = _generate_code_patch(vuln, repo_path)
        if patch:
            code_patches.append(patch)

    # 2. Dep bump — for ALL CVEs with a known safe version (not just confirmed)
    cves_for_bump = all_cves if all_cves else confirmed
    req_patch = _generate_dep_bump(cves_for_bump, repo_path)

    # Summary
    cprint(f"\n[patcher] ── Patch Summary ──")
    cprint(f"  Code patches generated: {len(code_patches)}")
    cprint(f"  Dep bump generated:     {'yes' if req_patch else 'no'}")
    cprint(f"  Output → {pd.resolve()}/")

    return {
        "code_patches": code_patches,
        "dep_bump": req_patch,
    }


# ─── Code patch ──────────────────────────────────────────────────────────────

def _generate_code_patch(vuln: dict, repo_path: str) -> Optional[dict]:
    """
    Ask Claude to generate a code-level fix for a confirmed vulnerability.
    Writes original + patched file + diff + explanation to data/patches/<cve_id>/
    """
    cve_id    = vuln["cve_id"]
    package   = vuln.get("package", "")
    cwe       = vuln.get("cwe", "")
    reason    = vuln.get("reason", "")
    rec       = vuln.get("recommendation", "")
    attack    = vuln.get("attack_vector", "")
    functions = vuln.get("affected_functions", [])
    fn_codes  = vuln.get("function_codes", [])

    if not fn_codes and not functions:
        cprint(f"[patcher] {cve_id} — no function code available, skipping code patch")
        return None

    patch_dir = _patches_dir() / cve_id
    patch_dir.mkdir(parents=True, exist_ok=True)

    # Build prompt for Claude
    prompt = _build_patch_prompt(
        cve_id=cve_id,
        package=package,
        cwe=cwe,
        reason=reason,
        attack_vector=attack,
        recommendation=rec,
        function_codes=fn_codes,
    )

    # Call Claude for the patch
    response = _call_claude_for_patch(prompt, cve_id)
    if not response:
        return None

    # Write patch files
    _write_patch_files(patch_dir, vuln, repo_path, response)

    cprint(f"[patcher] {cve_id} → code patch written to {patch_dir}/")
    return {
        "cve_id":    cve_id,
        "patch_dir": str(patch_dir),
        "files":     response.get("patched_files", []),
    }


def _build_patch_prompt(
    cve_id: str,
    package: str,
    cwe: str,
    reason: str,
    attack_vector: str,
    recommendation: str,
    function_codes: list[dict],
) -> str:
    code_section = ""
    for fc in function_codes[:5]:
        code_section += f"\nFile: {fc['file']} — function: {fc['function']}\n"
        code_section += "```python\n"
        code_section += fc["code"]
        code_section += "\n```\n"

    return f"""You are a security engineer. Generate a minimal, safe code patch for a confirmed vulnerability.

VULNERABILITY:
- CVE: {cve_id}
- Package: {package}
- CWE: {cwe}
- Why it's exploitable: {reason}
- Attack vector: {attack_vector}
- Recommended fix: {recommendation}

VULNERABLE CODE:
{code_section}

TASK:
Generate the minimal patch to fix this vulnerability. Rules:
- Change ONLY what is necessary to fix the vulnerability
- Do not refactor unrelated code
- Preserve all existing functionality
- Add a comment explaining the security fix

OUTPUT: Respond with ONLY valid JSON. No text before or after. No markdown fences.

{{
  "patched_files": [
    {{
      "file": "relative/path/to/file.py",
      "original_function": "function_name",
      "patched_code": "complete patched function code here",
      "explanation": "one paragraph explaining what changed and why"
    }}
  ],
  "summary": "one sentence summary of the fix"
}}"""


def _call_claude_for_patch(prompt: str, cve_id: str) -> Optional[dict]:
    """
    Call Claude (Sonnet) for patch generation.
    Falls back to manual export if no API key or credits exhausted.
    """
    import sys

    # Check for API key first
    if not cfg.ANTHROPIC_API_KEY and not cfg.GEMINI_API_KEY:
        return _manual_patch(prompt, cve_id)

    # Try Gemini first (free tier), then Claude
    result = _call_gemini_for_patch(prompt, cve_id)
    if result:
        return result

    if cfg.ANTHROPIC_API_KEY:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=cfg.ANTHROPIC_API_KEY)
            response = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=4096,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            raw = raw.strip()
            result = json.loads(raw)
            result = validate_patcher_response(result, cve_id)
            if result is None:
                return None
            cprint(f"[patcher] {cve_id} (Claude Sonnet) → patch generated: {result.get('summary', '')[:80]}")
            return result
        except Exception as e:
            cprint(f"[patcher] Claude error for {cve_id}: {e}")

    # Both APIs failed — fall back to manual
    return _manual_patch(prompt, cve_id)


def _call_gemini_for_patch(prompt: str, cve_id: str) -> Optional[dict]:
    """Try Gemini for patch generation (free tier)."""
    if not cfg.GEMINI_API_KEY:
        return None
    try:
        try:
            from google import genai as google_genai
            client = google_genai.Client(api_key=cfg.GEMINI_API_KEY)
            response = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt,
                config={"temperature": 0.1, "max_output_tokens": 4096},
            )
            raw = response.text.strip()
        except ImportError:
            import warnings, google.generativeai as genai
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                genai.configure(api_key=cfg.GEMINI_API_KEY)
                model = genai.GenerativeModel("gemini-2.0-flash",
                    generation_config={"temperature": 0.1, "max_output_tokens": 4096})
                raw = model.generate_content(prompt).text.strip()

        import re as _re
        raw = _re.sub(r'^```(?:json)?\s*', '', raw)
        raw = _re.sub(r'\s*```$', '', raw).strip()
        result = json.loads(raw)
        result = validate_patcher_response(result, cve_id)
        if result is None:
            return None
        cprint(f"[patcher] {cve_id} (Gemini) → patch generated: {result.get('summary', '')[:80]}")
        return result
    except Exception as e:
        if "429" in str(e) or "quota" in str(e).lower():
            log_warn_panel("patcher", f"Gemini quota exhausted for {cve_id}",
                           "Will fall back to Claude or manual patch")
        else:
            log_error("patcher", f"Gemini error for {cve_id}", str(e))
        return None


def _manual_patch(prompt: str, cve_id: str) -> Optional[dict]:
    """
    No API available or quota exhausted — export prompt, wait for manual response.
    Interactive: pauses and waits. Non-interactive: exports and skips.
    """
    import sys
    patches_dir = _patches_dir()
    prompt_file   = patches_dir / f"patch_prompt_{cve_id}.txt"
    response_file = patches_dir / f"patch_response_{cve_id}.json"

    # Already have a saved response — load it
    if response_file.exists():
        try:
            result = json.loads(response_file.read_text())
            result = validate_patcher_response(result, cve_id)
            if result is None:
                return None
            cprint(f"[patcher] {cve_id} → loaded manual patch response")
            return result
        except Exception as e:
            log_error("patcher", f"{cve_id} — invalid response JSON", str(e))
            return None

    # Export prompt file
    prompt_file.write_text(prompt)

    if not sys.stdin.isatty():
        # Non-interactive (CI/cron) — export and skip, pipeline continues
        cprint(f"[patcher] {cve_id} — prompt exported (no API), skipping code patch")
        cprint(f"  Run export_patches.sh to bundle and send to AI")
        return None

    # Interactive — pause and wait
    cprint(f"\n[patcher] ── Manual patch needed: {cve_id} ──")
    cprint(f"  Prompt saved → {prompt_file.resolve()}")
    cprint(f"  1. Open the file above and paste into Claude / ChatGPT")
    cprint(f"  2. Save the JSON response to:")
    cprint(f"     {response_file.resolve()}")
    cprint(f"  Press Enter when saved  |  S to skip this CVE")

    import select
    while True:
        ready, _, _ = select.select([sys.stdin], [], [], 3.0)
        if ready:
            choice = sys.stdin.readline().strip().lower()
            if choice == "s":
                cprint(f"[patcher] Skipping {cve_id}")
                return None
            break
        # Check if file appeared
        if response_file.exists():
            break
        cprint(f"  Waiting for {response_file.name}...", end="\r", flush=True)

    if response_file.exists():
        try:
            result = json.loads(response_file.read_text())
            result = validate_patcher_response(result, cve_id)
            if result is None:
                return None
            cprint(f"[patcher] {cve_id} → manual patch loaded")
            return result
        except Exception as e:
            log_error("patcher", f"{cve_id} — invalid JSON in manual response", str(e))
    return None


def _write_patch_files(patch_dir: Path, vuln: dict, repo_path: str, response: dict):
    """Write original, patched, diff, and explanation files."""
    cve_id = vuln["cve_id"]
    fn_codes = vuln.get("function_codes", [])

    for pf in response.get("patched_files", []):
        file_rel  = pf.get("file", "")
        func_name = pf.get("original_function", "")
        patched   = pf.get("patched_code", "")
        expl      = pf.get("explanation", "")

        # Security: resolve and verify path stays inside repo root
        repo_root     = Path(repo_path).resolve()
        original_path = (repo_root / file_rel).resolve()
        if not str(original_path).startswith(str(repo_root) + "/") and original_path != repo_root:
            log_security("patcher", "LLM-supplied path escapes repo root — skipping",
                         f"file_rel={file_rel!r}")
            continue

        original_code = ""
        if original_path.exists():
            original_code = original_path.read_text(errors="ignore")

        # Safe filename
        safe_name = file_rel.replace("/", "_").replace("\\", "_")

        # Write original
        (patch_dir / f"original_{safe_name}").write_text(original_code)

        # Write patched — replace function in original file content
        patched_full = _apply_function_patch(original_code, func_name, patched)
        (patch_dir / f"patched_{safe_name}").write_text(patched_full)

        # Write manifest entry so github/pr.py can reconstruct paths correctly
        # (filename-based reconstruction breaks for nested paths like sage/fetcher/filter.py)
        manifest_path = patch_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else []
        manifest.append({"patched_file": f"patched_{safe_name}", "original_path": file_rel})
        manifest_path.write_text(json.dumps(manifest, indent=2))

        # Generate diff
        diff = _generate_diff(
            original_code,
            patched_full,
            f"a/{file_rel}",
            f"b/{file_rel}",
        )
        (patch_dir / f"{safe_name}.patch").write_text(diff)

        # Write explanation
        (patch_dir / "explanation.md").write_text(
            f"# Patch: {cve_id}\n\n"
            f"**File:** `{file_rel}`  \n"
            f"**Function:** `{func_name}`\n\n"
            f"## What changed\n\n{expl}\n\n"
            f"## Summary\n\n{response.get('summary', '')}\n"
        )


def _apply_function_patch(original_source: str, func_name: str, patched_func: str) -> str:
    """Replace a function in source with the patched version using AST."""
    import ast

    try:
        tree = ast.parse(original_source)
        lines = original_source.splitlines(keepends=True)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == func_name:
                    start = node.lineno - 1
                    end   = node.end_lineno
                    # Preserve indentation of original
                    indent = len(lines[start]) - len(lines[start].lstrip())
                    indented = "\n".join(
                        " " * indent + l if l.strip() else l
                        for l in patched_func.splitlines()
                    )
                    new_lines = lines[:start] + [indented + "\n"] + lines[end:]
                    return "".join(new_lines)
    except Exception:
        pass

    # Fallback — append patch as comment if AST fails
    return original_source + f"\n\n# SAGE PATCH for {func_name}:\n{patched_func}\n"


def _generate_diff(original: str, patched: str, from_file: str, to_file: str) -> str:
    """Generate unified diff between original and patched."""
    import difflib
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=from_file,
        tofile=to_file,
    )
    return "".join(diff)


# ─── Dep bump ─────────────────────────────────────────────────────────────────

def _clamp_to_pypi(package: str, requested_version: str) -> str:
    """
    Check if requested_version exists on PyPI. If not, return the latest
    published version instead so we never write an impossible constraint.
    Falls back to requested_version silently on network errors.
    """
    import requests as _req
    from packaging.version import Version as _V, InvalidVersion
    try:
        resp = _req.get(f"https://pypi.org/pypi/{package}/json", timeout=8)
        if resp.status_code != 200:
            return requested_version
        releases = list(resp.json().get("releases", {}).keys())
        # Filter to stable releases only
        stable = []
        for r in releases:
            try:
                v = _V(r)
                if not v.is_prerelease and not v.is_devrelease:
                    stable.append(v)
            except InvalidVersion:
                pass
        if not stable:
            return requested_version
        latest = str(max(stable))
        try:
            if _V(requested_version) > _V(latest):
                return latest
        except InvalidVersion:
            return latest
    except Exception:
        pass
    return requested_version


def _generate_dep_bump(cves: list[dict], repo_path: str) -> Optional[dict]:
    """
    Read requirements.txt from repo and bump affected package versions.

    Determines safe minimum version from CVE affected_range field.
    Writes bumped requirements.txt to data/patches/requirements.txt.
    """
    req_file = _find_requirements_file(repo_path)
    if not req_file:
        cprint("[patcher] No requirements.txt or pyproject.toml found — skipping dep bump")
        return None

    original_content = req_file.read_text()
    lines = original_content.splitlines()

    # Build package → safe version map from CVEs
    bumps = {}  # package_lower → (safe_version, [cve_ids])
    for cve in cves:
        pkg    = cve.get("package", "").lower().replace("_", "-")
        rng    = cve.get("affected_range", "")
        cve_id = cve.get("cve_id", "")
        if not pkg:
            continue
        safe = _extract_safe_version(rng)
        if safe:
            if pkg not in bumps:
                bumps[pkg] = (safe, [])
            else:
                # Take the highest safe version across all CVEs for this package
                from packaging.version import Version
                try:
                    if Version(safe) > Version(bumps[pkg][0]):
                        bumps[pkg] = (safe, bumps[pkg][1])
                except Exception:
                    pass
            bumps[pkg][1].append(cve_id)

    if not bumps:
        cprint("[patcher] No version constraints found in CVE data — skipping dep bump")
        return None

    # Validate safe versions exist on PyPI — clamp to latest published if not
    for pkg in list(bumps.keys()):
        safe_ver, cve_ids = bumps[pkg]
        actual = _clamp_to_pypi(pkg, safe_ver)
        if actual != safe_ver:
            cprint(f"[patcher] {pkg}: safe version {safe_ver} not on PyPI — clamped to {actual}")
        bumps[pkg] = (actual, cve_ids)

    # Rewrite requirements lines
    new_lines = []
    changed = []
    already_written = set()  # prevent duplicate output lines for same package
    import re as _re
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue

        # Parse package name from line (handle pkg==x, pkg>=x, pkg, pkg[extra])
        m = _re.match(r'^([A-Za-z0-9_\-]+)(\[[^\]]+\])?', stripped)
        pkg_name = m.group(1).strip().lower().replace("_", "-") if m else ""
        extras   = m.group(2) or "" if m else ""  # e.g. [speedups]
        if pkg_name in bumps:
            if pkg_name in already_written:
                # Duplicate line for same package — skip it
                continue
            safe_ver, cve_ids = bumps[pkg_name]
            # Deduplicate CVE list
            unique_cves = sorted(set(cve_ids))
            # Preserve extras (e.g. aiohttp[speedups]>=3.13.3)
            base_name = m.group(1).strip() if m else pkg_name
            new_line = f"{base_name}{extras}>={safe_ver}  # SAGE: {', '.join(unique_cves)}"
            new_lines.append(new_line)
            already_written.add(pkg_name)
            changed.append((pkg_name, safe_ver, unique_cves))
            cprint(f"[patcher] Bumping {pkg_name} → >={safe_ver} ({len(unique_cves)} CVEs)")
        else:
            new_lines.append(line)

    if not changed:
        cprint("[patcher] No matching packages found in requirements file")
        return None

    new_content = "\n".join(new_lines) + "\n"

    # Write to repo-scoped patches dir
    pd = _patches_dir()
    out_path = pd / "requirements.txt"
    out_path.write_text(new_content)

    # Also write a diff
    diff = _generate_diff(original_content, new_content, "a/requirements.txt", "b/requirements.txt")
    (pd / "requirements.patch").write_text(diff)

    cprint(f"[patcher] Dep bump written → {out_path}")
    cprint(f"[patcher] Diff written     → {pd}/requirements.patch")

    return {
        "file":    str(out_path),
        "changed": changed,
    }


def _find_requirements_file(repo_path: str) -> Optional[Path]:
    """Find requirements.txt or pyproject.toml in repo root."""
    for name in ("requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile"):
        p = Path(repo_path) / name
        if p.exists():
            return p
    return None


def _extract_safe_version(affected_range: str) -> Optional[str]:
    """
    Extract safe minimum version from CVE affected_range string.

    Handles both strict (<) and inclusive (<=) upper bounds:
      "<3.13.4"      → "3.13.4"      (first version NOT affected)
      "<=3.13.3"     → "3.13.4"      (bump patch by 1 — <=X means X is still bad)
      ">=3.0,<3.9"   → "3.9"
      ">=2.0,<=2.8.3" → "2.8.4"
      ""              → None
    """
    import re
    from packaging.version import Version

    if not affected_range:
        return None

    # Prefer strict upper bound: <X.Y.Z → safe version is X.Y.Z
    strict = re.findall(r"(?<!<)<\s*([\d.]+)", affected_range)  # < but not <=
    # Separate: find <=X.Y.Z
    inclusive = re.findall(r"<=\s*([\d.]+)", affected_range)

    if strict:
        return strict[-1]

    if inclusive:
        # Bump the patch component by 1
        try:
            v = Version(inclusive[-1])
            parts = list(v.release)
            while len(parts) < 3:
                parts.append(0)
            parts[-1] += 1
            return ".".join(str(p) for p in parts)
        except Exception:
            return inclusive[-1]  # fallback: return as-is

    return None


# ─── Summary ─────────────────────────────────────────────────────────────────

def print_patch_summary(result: dict):
    code_patches = result.get("code_patches", [])
    dep_bump     = result.get("dep_bump")

    cprint(f"\n[patcher] ── Patch Output ──")

    if code_patches:
        cprint(f"\n  Code patches ({len(code_patches)}):")
        for p in code_patches:
            cprint(f"    {p['cve_id']} → {p['patch_dir']}/")
    else:
        cprint("  No code patches (no confirmed exploitable CVEs)")

    if dep_bump:
        cprint(f"\n  Dep bump → {dep_bump['file']}")
        for pkg, ver, cves in dep_bump["changed"]:
            cprint(f"    {pkg} → >={ver}  ({', '.join(cves)})")
    else:
        cprint("  No dep bump generated")

    cprint(f"\n  Next: run tests → verifier → github PR")
