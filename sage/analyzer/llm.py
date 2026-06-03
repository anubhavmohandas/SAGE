"""
analyzer/llm.py — Manual LLM vulnerability confirmation

Instead of calling an API, this module:
  1. Exports a human-readable prompt file per CVE → data/prompts/CVE-XXXX.txt
  2. Reads your manual response (JSON) from → data/responses/CVE-XXXX.json
  3. Skips CVEs with no response file (treated as unconfirmed)

Workflow:
  1. Run pipeline → prompts generated in data/prompts/
  2. Open each prompt, paste into Claude chat
  3. Copy Claude's JSON response into data/responses/CVE-XXXX.json
  4. Re-run pipeline → reads responses, continues to patcher

Response schema (paste this into Claude chat along with the prompt):
{
  "vulnerable": true or false,
  "confidence": 0.0 to 1.0,
  "reason": "one sentence",
  "affected_functions": ["fn1", "fn2"],
  "attack_vector": "how attacker could exploit, or empty string",
  "recommendation": "specific fix, or empty string"
}
"""

import json
from pathlib import Path
from typing import Optional


PROMPTS_DIR  = Path("data/prompts")
RESPONSES_DIR = Path("data/responses")


# ─── Main analysis function ───────────────────────────────────────────────────

def analyze_findings(findings: list[dict], G, repo_path: str) -> list[dict]:
    """
    Export prompt files for each CVE, then read any existing manual responses.

    First call: generates prompts, returns [] (no responses yet).
    Subsequent calls: reads responses you've dropped in, returns confirmed list.
    """
    PROMPTS_DIR.mkdir(parents=True, exist_ok=True)
    RESPONSES_DIR.mkdir(parents=True, exist_ok=True)

    # Group findings by CVE
    by_cve = {}
    for f in findings:
        cve_id = f["cve_id"]
        by_cve.setdefault(cve_id, []).append(f)

    # Also include CVEs with no Semgrep finding
    cve_nodes = [n for n in G.nodes() if n.startswith("cve:")]
    for cve_node in cve_nodes:
        cve_id = cve_node.replace("cve:", "")
        if cve_id not in by_cve:
            by_cve[cve_id] = []

    print(f"[analyzer] {len(by_cve)} CVEs to analyze (manual mode)")

    confirmed = []
    new_prompts = 0
    skipped = 0

    for cve_id, cve_findings in by_cve.items():
        response_file = RESPONSES_DIR / f"{cve_id}.json"

        # If response exists — read it
        if response_file.exists():
            result = _read_response(cve_id, cve_findings, G)
            if result:
                confirmed.append(result)
            continue

        # No response — export prompt if not already done
        prompt_file = PROMPTS_DIR / f"{cve_id}.txt"
        if not prompt_file.exists():
            _export_prompt(cve_id, cve_findings, G, repo_path)
            new_prompts += 1
        else:
            skipped += 1

    total_with_prompts = len(list(PROMPTS_DIR.glob("*.txt")))
    total_with_responses = len(list(RESPONSES_DIR.glob("*.json")))

    print(f"[analyzer] Prompts exported: {new_prompts} new  |  {skipped} already existed")
    print(f"[analyzer] Responses read:   {total_with_responses}/{total_with_prompts}")
    print(f"[analyzer] Confirmed: {len(confirmed)}/{len(by_cve)} CVEs exploitable")

    if new_prompts > 0 or (total_with_prompts > total_with_responses):
        pending = total_with_prompts - total_with_responses
        print(f"\n[analyzer] ── Manual review needed ──")
        print(f"  {pending} CVE(s) awaiting your review.")
        print(f"  Prompts → {PROMPTS_DIR.resolve()}/")
        print(f"  1. Open each CVE-XXXX.txt")
        print(f"  2. Paste into Claude chat")
        print(f"  3. Save Claude's JSON response as {RESPONSES_DIR.resolve()}/CVE-XXXX.json")
        print(f"  4. Re-run: python3 main.py --synapse <repo>")

    return confirmed


# ─── Prompt export ────────────────────────────────────────────────────────────

def _export_prompt(cve_id: str, findings: list[dict], G, repo_path: str):
    """Build and save the analysis prompt for a CVE."""
    from sage.synapse.mapper import get_blast_radius

    cve_node = f"cve:{cve_id}"
    if not G.has_node(cve_node):
        return

    node_data  = G.nodes[cve_node]
    severity   = node_data.get("severity", "UNKNOWN")
    package    = node_data.get("package", "")
    cwe        = node_data.get("cwe", "")
    affected_r = node_data.get("affected_range", "")

    blast = get_blast_radius(G, cve_node)
    if not blast:
        return

    exposed_functions = blast.get("exposed_functions", [])
    exposed_files     = blast.get("exposed_files", [])

    function_codes = _extract_function_codes(exposed_functions, repo_path, G)
    if not function_codes and exposed_files:
        function_codes = _extract_file_snippets(exposed_files, repo_path, package)

    if not function_codes and not findings:
        return  # nothing to analyze

    prompt = _build_prompt(
        cve_id=cve_id,
        severity=severity,
        package=package,
        cwe=cwe,
        affected_range=affected_r,
        function_codes=function_codes,
        semgrep_findings=findings,
    )

    prompt_file = PROMPTS_DIR / f"{cve_id}.txt"
    prompt_file.write_text(prompt)
    print(f"[analyzer] Prompt saved → {prompt_file}")


def _build_prompt(
    cve_id: str,
    severity: str,
    package: str,
    cwe: str,
    affected_range: str,
    function_codes: list[dict],
    semgrep_findings: list[dict],
) -> str:
    code_section = ""
    if function_codes:
        code_section = "\n\nEXPOSED FUNCTIONS IN CODEBASE:\n"
        for fc in function_codes[:5]:
            code_section += f"\nFile: {fc['file']} — {fc['function']}\n"
            code_section += "```python\n"
            code_section += fc["code"]
            code_section += "\n```\n"
    else:
        code_section = "\n\nNO FUNCTION CODE AVAILABLE — analyze based on library usage pattern only.\n"

    semgrep_section = ""
    if semgrep_findings:
        semgrep_section = "\n\nSEMGREP FINDINGS:\n"
        for f in semgrep_findings:
            semgrep_section += (
                f"- Rule: {f.get('rule_id', 'unknown')}\n"
                f"  File: {f.get('file', '')}:{f.get('line', '')}\n"
                f"  Message: {f.get('message', '')}\n"
                f"  Code: {f.get('code', '')}\n"
            )
    else:
        semgrep_section = "\n\nSEMGREP FINDINGS: None.\n"

    return f"""You are a security vulnerability analyst. Determine if this CVE is actually exploitable in this specific codebase.

CVE INFORMATION:
- CVE ID: {cve_id}
- Severity: {severity}
- Affected package: {package}
- Affected versions: {affected_range}
- CWE: {cwe or 'Not specified'}
{code_section}{semgrep_section}

TASK:
Is this CVE exploitable given how the library is actually used in the code above?
Consider: can user-controlled input reach the vulnerable code path?

RULES:
- Base answer ONLY on the code shown
- If no function code, base on library usage pattern
- Be conservative — if uncertain, mark vulnerable with low confidence

OUTPUT: Respond with ONLY valid JSON. No text before or after. No markdown fences.

{{
  "vulnerable": true or false,
  "confidence": 0.0 to 1.0,
  "reason": "one sentence explaining your decision",
  "affected_functions": ["function_name1"],
  "attack_vector": "how an attacker could exploit this, or empty string if not vulnerable",
  "recommendation": "specific fix recommendation, or empty string if not vulnerable"
}}"""


# ─── Response reader ──────────────────────────────────────────────────────────

def _read_response(cve_id: str, findings: list[dict], G) -> Optional[dict]:
    """Read a manually saved response JSON for a CVE."""
    response_file = RESPONSES_DIR / f"{cve_id}.json"
    try:
        response = json.loads(response_file.read_text())
    except Exception as e:
        print(f"[analyzer] Bad response file for {cve_id}: {e}")
        return None

    if not response.get("vulnerable", False):
        print(f"[analyzer] {cve_id} → NOT exploitable "
              f"({response.get('confidence', 0):.1f}): {response.get('reason', '')[:80]}")
        return None

    cve_node  = f"cve:{cve_id}"
    node_data = G.nodes.get(cve_node, {})

    print(f"[analyzer] {cve_id} → CONFIRMED exploitable "
          f"(confidence: {response.get('confidence', 0):.1f})")

    return {
        "cve_id":             cve_id,
        "severity":           node_data.get("severity", "UNKNOWN"),
        "package":            node_data.get("package", ""),
        "cwe":                node_data.get("cwe", ""),
        "affected_range":     node_data.get("affected_range", ""),
        "vulnerable":         True,
        "confidence":         response.get("confidence", 0.0),
        "reason":             response.get("reason", ""),
        "affected_functions": response.get("affected_functions", []),
        "attack_vector":      response.get("attack_vector", ""),
        "recommendation":     response.get("recommendation", ""),
        "semgrep_findings":   findings,
    }


# ─── Save results ─────────────────────────────────────────────────────────────

def save_confirmed(confirmed: list[dict], output_path: str = "data/confirmed.json"):
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(confirmed, f, indent=2)
    print(f"[analyzer] Confirmed vulnerabilities saved → {output_path}")


def print_analysis_summary(confirmed: list[dict]):
    if not confirmed:
        print("[analyzer] No exploitable vulnerabilities confirmed.")
        return

    print(f"\n[analyzer] ── Confirmed Vulnerabilities ──")
    for v in confirmed:
        print(f"\n  [{v['severity']:8s}] {v['cve_id']}")
        print(f"  Package:    {v['package']} {v['affected_range']}")
        print(f"  Confidence: {v['confidence']:.0%}")
        print(f"  Reason:     {v['reason']}")
        if v.get("attack_vector"):
            print(f"  Attack:     {v['attack_vector']}")
        if v.get("recommendation"):
            print(f"  Fix:        {v['recommendation']}")


# ─── Code extraction (unchanged) ─────────────────────────────────────────────

def _extract_function_codes(exposed_functions, repo_path, G):
    results = []
    for func_node_id in exposed_functions[:5]:
        if not G.has_node(func_node_id):
            continue
        node = G.nodes[func_node_id]
        rel_file  = node.get("file", "")
        func_name = node.get("name", "")
        line_num  = node.get("line", 0)
        if not rel_file or not func_name:
            continue
        abs_path = Path(repo_path) / rel_file
        if not abs_path.exists():
            continue
        code = _extract_function_source(abs_path, func_name, line_num)
        if code:
            results.append({"file": rel_file, "function": func_name, "line": line_num, "code": code})
    return results


def _extract_file_snippets(exposed_files, repo_path, package):
    results = []
    for rel_file in exposed_files[:3]:
        abs_path = Path(repo_path) / rel_file
        if not abs_path.exists():
            continue
        try:
            lines = abs_path.read_text(errors="ignore").splitlines()
            pkg_clean = package.replace("_", "-").lower()
            relevant = []
            for i, line in enumerate(lines):
                if package.lower() in line.lower() or pkg_clean in line.lower():
                    start = max(0, i - 2)
                    end   = min(len(lines), i + 5)
                    relevant.extend(lines[start:end])
                    relevant.append("...")
            if relevant:
                results.append({
                    "file": rel_file,
                    "function": f"(file-level usage of {package})",
                    "line": 0,
                    "code": "\n".join(relevant[:40]),
                })
        except Exception:
            continue
    return results


def _extract_function_source(file_path: Path, func_name: str, line_num: int) -> str:
    import ast
    try:
        source = file_path.read_text(errors="ignore")
        lines  = source.splitlines()
        tree   = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == func_name:
                    return "\n".join(lines[node.lineno - 1:node.end_lineno])
        if line_num > 0:
            return "\n".join(lines[max(0, line_num - 1):min(len(lines), line_num + 20)])
    except Exception:
        pass
    return ""
