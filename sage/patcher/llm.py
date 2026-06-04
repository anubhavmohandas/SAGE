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


PATCHES_DIR = Path("data/patches")


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
    PATCHES_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[patcher] {len(confirmed)} confirmed exploitable CVE(s) → code patches")

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
    print(f"\n[patcher] ── Patch Summary ──")
    print(f"  Code patches generated: {len(code_patches)}")
    print(f"  Dep bump generated:     {'yes' if req_patch else 'no'}")
    print(f"  Output → {PATCHES_DIR.resolve()}/")

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
        print(f"[patcher] {cve_id} — no function code available, skipping code patch")
        return None

    patch_dir = PATCHES_DIR / cve_id
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

    print(f"[patcher] {cve_id} → code patch written to {patch_dir}/")
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
    """Call Claude (Sonnet) for patch generation — best code quality."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=cfg.ANTHROPIC_API_KEY)
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            temperature=0.1,  # low temp for deterministic code
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()
        # Strip fences
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()
        result = json.loads(raw)
        print(f"[patcher] {cve_id} (Claude Sonnet) → patch generated: {result.get('summary', '')[:80]}")
        return result
    except Exception as e:
        print(f"[patcher] Claude error for {cve_id}: {e}")
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

        # Read original file
        original_path = Path(repo_path) / file_rel
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

def _generate_dep_bump(cves: list[dict], repo_path: str) -> Optional[dict]:
    """
    Read requirements.txt from repo and bump affected package versions.

    Determines safe minimum version from CVE affected_range field.
    Writes bumped requirements.txt to data/patches/requirements.txt.
    """
    req_file = _find_requirements_file(repo_path)
    if not req_file:
        print("[patcher] No requirements.txt or pyproject.toml found — skipping dep bump")
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
        print("[patcher] No version constraints found in CVE data — skipping dep bump")
        return None

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
            print(f"[patcher] Bumping {pkg_name} → >={safe_ver} ({len(unique_cves)} CVEs)")
        else:
            new_lines.append(line)

    if not changed:
        print("[patcher] No matching packages found in requirements file")
        return None

    new_content = "\n".join(new_lines) + "\n"

    # Write to patches dir
    out_path = PATCHES_DIR / "requirements.txt"
    out_path.write_text(new_content)

    # Also write a diff
    diff = _generate_diff(original_content, new_content, "a/requirements.txt", "b/requirements.txt")
    (PATCHES_DIR / "requirements.patch").write_text(diff)

    print(f"[patcher] Dep bump written → {out_path}")
    print(f"[patcher] Diff written     → {PATCHES_DIR}/requirements.patch")

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

    Examples:
      "<3.13.3"     → "3.13.3"
      ">=3.0,<3.9"  → "3.9"
      "<8.3.3"      → "8.3.3"
      ""            → None
    """
    import re
    if not affected_range:
        return None
    # Find all "<X.Y.Z" patterns — safe version is the upper bound
    matches = re.findall(r"<\s*([\d.]+)", affected_range)
    if matches:
        return matches[-1]  # take the last upper bound
    return None


# ─── Summary ─────────────────────────────────────────────────────────────────

def print_patch_summary(result: dict):
    code_patches = result.get("code_patches", [])
    dep_bump     = result.get("dep_bump")

    print(f"\n[patcher] ── Patch Output ──")

    if code_patches:
        print(f"\n  Code patches ({len(code_patches)}):")
        for p in code_patches:
            print(f"    {p['cve_id']} → {p['patch_dir']}/")
    else:
        print("  No code patches (no confirmed exploitable CVEs)")

    if dep_bump:
        print(f"\n  Dep bump → {dep_bump['file']}")
        for pkg, ver, cves in dep_bump["changed"]:
            print(f"    {pkg} → >={ver}  ({', '.join(cves)})")
    else:
        print("  No dep bump generated")

    print(f"\n  Next: run tests → verifier → github PR")
