"""
analyzer/llm.py — LLM vulnerability confirmation

Takes Semgrep findings (or CVEs with no Semgrep finding) and asks
Claude to confirm whether the code is actually vulnerable.

This is the "second opinion" stage. Semgrep is pattern-based —
it can miss context. Claude reads the actual function code and
reasons about whether the vulnerability is exploitable given
how the library is actually being used.

Two scenarios this handles:

1. Semgrep found something:
   → Send the flagged code + CVE to Claude
   → Claude confirms: real finding or false positive?

2. Semgrep found nothing:
   → Send the function code + CVE to Claude anyway
   → Claude confirms: safe because of how it's used, or
     missed by Semgrep's patterns?

Teaching note — why structured output matters:
    We tell Claude to respond ONLY in JSON with a strict schema.
    No free text. No explanation outside the JSON.
    The pipeline reads the JSON directly — no parsing of prose.

    If Claude says "hmm, it looks like..." — the pipeline breaks.
    If Claude says {"vulnerable": true, "confidence": 0.9} — it works.

    This is the prompt contract principle from our design decisions.

Teaching note — why we send function code, not full file:
    Synapse already told us WHICH functions are in the blast radius.
    We send only those functions to Claude — not the whole file.
    Smaller context = faster + cheaper + more accurate.
    Claude doesn't need to read 500 lines to judge 20 lines.
"""

import json
from pathlib import Path
from typing import Optional

import anthropic

from sage.config import cfg


# Anthropic client — initialized once, reused
_client = None

def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=cfg.ANTHROPIC_API_KEY)
    return _client


# ─── Main analysis function ───────────────────────────────────────────────────

def analyze_findings(findings: list[dict], G, repo_path: str) -> list[dict]:
    """
    Run LLM analysis on all scanner findings.

    For each CVE in the blast radius:
      - Extract the exposed function code from the repo
      - Ask Claude: is this actually vulnerable?
      - Return confirmed findings only

    Args:
        findings:  List of Semgrep findings from scanner/semgrep.py
        G:         Synapse knowledge graph
        repo_path: Path to the repo

    Returns:
        List of confirmed vulnerability dicts, ready for the patcher.
    """
    confirmed = []

    # Group findings by CVE
    by_cve = {}
    for f in findings:
        cve_id = f["cve_id"]
        by_cve.setdefault(cve_id, []).append(f)

    # Also analyze CVEs with NO Semgrep finding — Semgrep misses things
    cve_nodes = [n for n in G.nodes() if n.startswith("cve:")]
    for cve_node in cve_nodes:
        cve_id = cve_node.replace("cve:", "")
        if cve_id not in by_cve:
            by_cve[cve_id] = []  # empty = no Semgrep finding, still analyze

    print(f"[analyzer] Analyzing {len(by_cve)} CVEs with Claude...")

    for cve_id, cve_findings in by_cve.items():
        result = analyze_single_cve(cve_id, cve_findings, G, repo_path)
        if result:
            confirmed.append(result)

    print(f"[analyzer] Confirmed: {len(confirmed)}/{len(by_cve)} CVEs actually exploitable")
    return confirmed


def analyze_single_cve(
    cve_id: str,
    findings: list[dict],
    G,
    repo_path: str,
) -> Optional[dict]:
    """
    Ask Claude whether a specific CVE is exploitable in this codebase.

    Returns a confirmed finding dict, or None if not exploitable.
    """
    from sage.synapse.mapper import get_blast_radius

    cve_node = f"cve:{cve_id}"
    if not G.has_node(cve_node):
        return None

    node_data  = G.nodes[cve_node]
    severity   = node_data.get("severity", "UNKNOWN")
    package    = node_data.get("package", "")
    cwe        = node_data.get("cwe", "")
    affected_r = node_data.get("affected_range", "")

    # Get blast radius — which functions are exposed
    blast = get_blast_radius(G, cve_node)
    if not blast:
        return None

    exposed_functions = blast.get("exposed_functions", [])
    exposed_files     = blast.get("exposed_files", [])

    # Extract actual function code from repo
    function_codes = _extract_function_codes(exposed_functions, repo_path, G)

    if not function_codes and not findings:
        # Nothing to analyze — skip
        return None

    # Build the prompt
    prompt = _build_analysis_prompt(
        cve_id=cve_id,
        severity=severity,
        package=package,
        cwe=cwe,
        affected_range=affected_r,
        function_codes=function_codes,
        semgrep_findings=findings,
    )

    # Call Claude
    response = _call_claude(prompt, cve_id)
    if not response:
        return None

    # Build confirmed finding if vulnerable
    if response.get("vulnerable", False):
        return {
            "cve_id":           cve_id,
            "severity":         severity,
            "package":          package,
            "cwe":              cwe,
            "affected_range":   affected_r,
            "vulnerable":       True,
            "confidence":       response.get("confidence", 0.0),
            "reason":           response.get("reason", ""),
            "affected_functions": response.get("affected_functions", []),
            "attack_vector":    response.get("attack_vector", ""),
            "recommendation":   response.get("recommendation", ""),
            "semgrep_findings": findings,
            "function_codes":   function_codes,
        }

    print(f"[analyzer] {cve_id} → NOT exploitable "
          f"(confidence: {response.get('confidence', 0):.1f}): "
          f"{response.get('reason', '')[:80]}")
    return None


# ─── Prompt builder ───────────────────────────────────────────────────────────

def _build_analysis_prompt(
    cve_id: str,
    severity: str,
    package: str,
    cwe: str,
    affected_range: str,
    function_codes: list[dict],
    semgrep_findings: list[dict],
) -> str:
    """
    Build the structured analysis prompt for Claude.

    Teaching note:
        Notice the prompt structure:
        1. Role — tell Claude what it is
        2. Task — exactly what to do
        3. Data — CVE info + code (structured, not prose)
        4. Output format — strict JSON schema
        5. Rules — what NOT to do

        This is the "prompt contract" pattern. Claude knows exactly
        what input it's getting and exactly what output is expected.
    """

    # Format function codes for the prompt
    code_section = ""
    if function_codes:
        code_section = "\n\nEXPOSED FUNCTIONS IN CODEBASE:\n"
        for fc in function_codes[:5]:  # max 5 functions to stay within context
            code_section += f"\nFile: {fc['file']} — {fc['function']}\n"
            code_section += "```python\n"
            code_section += fc["code"]
            code_section += "\n```\n"
    else:
        code_section = "\n\nNO FUNCTION CODE AVAILABLE — analyze based on library usage pattern only.\n"

    # Format Semgrep findings
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
        semgrep_section = "\n\nSEMGREP FINDINGS: None — Semgrep found no matching patterns.\n"

    return f"""You are a security vulnerability analyst. Your job is to determine if a CVE is actually exploitable in a specific codebase based on how the affected library is used.

CVE INFORMATION:
- CVE ID: {cve_id}
- Severity: {severity}
- Affected package: {package}
- Affected versions: {affected_range}
- CWE: {cwe or 'Not specified'}
{code_section}{semgrep_section}

TASK:
Analyze whether this CVE is exploitable in this specific codebase given:
1. How the affected library is actually used in the exposed functions
2. Whether the vulnerable code path can be triggered
3. The Semgrep findings (if any)

RULES:
- Base your answer ONLY on the code shown, not on general assumptions
- If no function code is available, base answer on library usage pattern
- Be conservative — if uncertain, mark as vulnerable with low confidence
- Consider: is there user-controlled input reaching the vulnerable code path?

OUTPUT: Respond with ONLY valid JSON. No text before or after. No markdown fences.

{{
  "vulnerable": true or false,
  "confidence": 0.0 to 1.0,
  "reason": "one sentence explaining your decision",
  "affected_functions": ["function_name1", "function_name2"],
  "attack_vector": "how an attacker could exploit this, or empty string if not vulnerable",
  "recommendation": "specific fix recommendation, or empty string if not vulnerable"
}}"""


# ─── Claude API call ──────────────────────────────────────────────────────────

def _call_claude(prompt: str, cve_id: str) -> Optional[dict]:
    """
    Send prompt to Claude and parse the JSON response.

    Uses claude-sonnet — fast, accurate for code analysis.
    Temperature 0.2 — low randomness for consistent security judgments.

    Teaching note:
        We use a low temperature (0.2) for security analysis.
        High temperature = more creative = more hallucination risk.
        For binary decisions (vulnerable: true/false), we want
        deterministic, consistent answers.
    """
    try:
        client = _get_client()
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            temperature=0.2,
            messages=[{"role": "user", "content": prompt}],
        )

        raw = response.content[0].text.strip()

        # Strip markdown fences if Claude adds them despite instructions
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        result = json.loads(raw)
        print(f"[analyzer] {cve_id} → vulnerable={result.get('vulnerable')} "
              f"confidence={result.get('confidence', 0):.2f}")
        return result

    except json.JSONDecodeError as e:
        print(f"[analyzer] JSON parse error for {cve_id}: {e}")
        print(f"[analyzer] Raw response: {raw[:200]}")
        return None
    except anthropic.AuthenticationError:
        print("[analyzer] Invalid Anthropic API key. Check .env")
        return None
    except Exception as e:
        print(f"[analyzer] Error analyzing {cve_id}: {e}")
        return None


# ─── Code extraction ──────────────────────────────────────────────────────────

def _extract_function_codes(
    exposed_functions: list[str],
    repo_path: str,
    G,
) -> list[dict]:
    """
    Extract the actual source code of exposed functions from the repo.

    Teaching note:
        Synapse gives us function node IDs like:
        "func:cybertrace/network.py:fetch_data"

        We parse the file and line number from the graph node,
        then extract the function source code using Python's ast module.

        We send actual code to Claude — not just function names.
        Claude can't reason about vulnerability without seeing the code.
    """
    results = []

    for func_node_id in exposed_functions[:5]:  # limit to 5
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
            results.append({
                "file":     rel_file,
                "function": func_name,
                "line":     line_num,
                "code":     code,
            })

    return results


def _extract_function_source(file_path: Path, func_name: str, line_num: int) -> str:
    """
    Extract a function's source code from a Python file.

    Uses ast to find the function, then extracts lines.
    Falls back to line-based extraction if ast fails.
    """
    import ast

    try:
        source = file_path.read_text(errors="ignore")
        lines  = source.splitlines()
        tree   = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == func_name:
                    start = node.lineno - 1
                    end   = node.end_lineno
                    return "\n".join(lines[start:end])

        # Fallback: extract ~20 lines around the known line number
        if line_num > 0:
            start = max(0, line_num - 1)
            end   = min(len(lines), line_num + 20)
            return "\n".join(lines[start:end])

    except Exception:
        pass

    return ""


# ─── Save results ─────────────────────────────────────────────────────────────

def save_confirmed(confirmed: list[dict], output_path: str = "data/confirmed.json"):
    """Save confirmed vulnerabilities for the patcher."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(confirmed, f, indent=2)
    print(f"[analyzer] Confirmed vulnerabilities saved → {output_path}")


def print_analysis_summary(confirmed: list[dict]):
    """Print human-readable analysis summary."""
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
