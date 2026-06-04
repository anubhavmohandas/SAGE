"""
analyzer/llm.py — LLM vulnerability confirmation (API + manual modes)

At runtime, asks whether you have an API key available:
  [y] API mode   — Gemini 2.0 Flash primary, Anthropic Haiku fallback,
                   exponential backoff on 429.
  [n] Manual mode — exports prompt files to data/prompts/CVE-XXXX.txt.
                    You paste into Claude chat, save the JSON response to
                    data/responses/CVE-XXXX.json, re-run to continue.

Manual response schema:
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

# Severity → Claude model mapping. CRITICAL gets Opus for best analysis quality;
# HIGH/MEDIUM/LOW use Sonnet (5x cheaper, fast enough for triage).
SEVERITY_MODEL = {
    "CRITICAL": "claude-opus-4-6",
    "HIGH":     "claude-sonnet-4-6",
    "MEDIUM":   "claude-sonnet-4-6",
    "LOW":      "claude-sonnet-4-6",
    "UNKNOWN":  "claude-sonnet-4-6",
}


def _model_for_severity(severity: str) -> str:
    return SEVERITY_MODEL.get(severity.upper(), "claude-sonnet-4-6")


def _ask_mode() -> str:
    """
    Determine analysis mode. In non-interactive environments (CI, cron, scheduled tasks)
    defaults to API mode automatically. Only prompts when running in a real terminal.
    """
    import sys
    # Non-interactive: stdin is not a TTY (CI, cron, pipe) — default to API
    if not sys.stdin.isatty():
        print("[analyzer] Non-interactive environment detected — using API mode")
        return "api"

    print("\n[analyzer] ── Analysis Mode ──")
    print("  Do you have a Gemini or Anthropic API key available for analysis?")
    print("  [y] Yes — use API  |  [n] No — export prompts for manual review")
    while True:
        choice = input("  Your choice (y/n): ").strip().lower()
        if choice in ("y", "yes"):
            return "api"
        if choice in ("n", "no"):
            return "manual"
        print("  Please enter y or n.")


def analyze_findings(findings: list[dict], G, repo_path: str) -> list[dict]:
    """
    Determine analysis mode, then run accordingly.

    API mode:   calls Gemini 2.0 Flash (with Anthropic fallback) per CVE.
                Model is severity-gated: CRITICAL → Opus, others → Sonnet.
    Manual mode: exports prompt files → you paste into Claude chat → drop JSON responses.
    Non-interactive (CI/cron): always uses API mode without prompting.
    """
    mode = _ask_mode()
    if mode == "api":
        return _analyze_api(findings, G, repo_path)
    return _analyze_manual(findings, G, repo_path)


def _analyze_api(findings: list[dict], G, repo_path: str) -> list[dict]:
    """API mode — Gemini primary, Anthropic fallback, exponential backoff on 429."""
    by_cve = _group_by_cve(findings, G)
    print(f"[analyzer] Analyzing {len(by_cve)} CVEs via API...")
    confirmed = []
    for cve_id, cve_findings in by_cve.items():
        result = _analyze_single_cve_api(cve_id, cve_findings, G, repo_path)
        if result:
            confirmed.append(result)
    print(f"[analyzer] Confirmed: {len(confirmed)}/{len(by_cve)} CVEs actually exploitable")
    return confirmed


def _analyze_manual(findings: list[dict], G, repo_path: str) -> list[dict]:
    """
    Manual mode — export prompts, read existing responses.

    First run: generates prompts, returns [].
    Subsequent runs: reads responses you've saved, returns confirmed list.
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


# ─── Shared helpers ──────────────────────────────────────────────────────────

def _group_by_cve(findings: list[dict], G) -> dict:
    """Group Semgrep findings by CVE ID, and include CVEs with no findings."""
    by_cve = {}
    for f in findings:
        by_cve.setdefault(f["cve_id"], []).append(f)
    for cve_node in G.nodes():
        if cve_node.startswith("cve:"):
            cve_id = cve_node.replace("cve:", "")
            by_cve.setdefault(cve_id, [])
    return by_cve


# ─── API mode internals ───────────────────────────────────────────────────────

def _analyze_single_cve_api(cve_id: str, findings: list[dict], G, repo_path: str) -> Optional[dict]:
    from sage.synapse.mapper import get_blast_radius
    from sage.config import cfg

    cve_node = f"cve:{cve_id}"
    if not G.has_node(cve_node):
        return None

    node_data  = G.nodes[cve_node]
    severity   = node_data.get("severity", "UNKNOWN")
    package    = node_data.get("package", "")
    cwe        = node_data.get("cwe", "")
    affected_r = node_data.get("affected_range", "")

    blast = get_blast_radius(G, cve_node)
    if not blast:
        return None

    function_codes = _extract_function_codes(blast.get("exposed_functions", []), repo_path, G)
    if not function_codes:
        function_codes = _extract_file_snippets(blast.get("exposed_files", []), repo_path, package)
    if not function_codes and not findings:
        print(f"[analyzer] {cve_id} — no code to analyze, skipping")
        return None

    prompt = _build_prompt(cve_id, severity, package, cwe, affected_r, function_codes, findings)

    response = _call_llm_api(prompt, cve_id, cfg, severity)
    if not response:
        return None

    if response.get("vulnerable", False):
        return {
            "cve_id":             cve_id,
            "severity":           severity,
            "package":            package,
            "cwe":                cwe,
            "affected_range":     affected_r,
            "vulnerable":         True,
            "confidence":         response.get("confidence", 0.0),
            "reason":             response.get("reason", ""),
            "affected_functions": response.get("affected_functions", []),
            "attack_vector":      response.get("attack_vector", ""),
            "recommendation":     response.get("recommendation", ""),
            "semgrep_findings":   findings,
            # Pass function_codes to patcher so it has actual code to patch
            "function_codes":     function_codes,
        }

    print(f"[analyzer] {cve_id} → NOT exploitable "
          f"({response.get('confidence', 0):.1f}): {response.get('reason', '')[:80]}")
    return None


def _call_llm_api(prompt: str, cve_id: str, cfg, severity: str = "MEDIUM") -> Optional[dict]:
    """Gemini primary, Anthropic fallback. Claude model is severity-gated."""
    if cfg.GEMINI_API_KEY:
        result = _call_gemini(prompt, cve_id, cfg)
        if result is not None:
            return result
        if cfg.ANTHROPIC_API_KEY:
            print(f"[analyzer] Falling back to Claude for {cve_id}")
            return _call_claude(prompt, cve_id, cfg, severity)
        return None
    elif cfg.ANTHROPIC_API_KEY:
        return _call_claude(prompt, cve_id, cfg, severity)
    print(f"[analyzer] No API key available for {cve_id}")
    return None


def _call_gemini(prompt: str, cve_id: str, cfg) -> Optional[dict]:
    import time
    try:
        import google.generativeai as genai
    except ImportError:
        print("[analyzer] google-generativeai not installed.")
        return None

    genai.configure(api_key=cfg.GEMINI_API_KEY)
    model = genai.GenerativeModel(
        model_name="gemini-2.0-flash",
        generation_config={"temperature": 0.2, "max_output_tokens": 1024},
    )
    raw = ""
    for attempt in range(4):
        try:
            response = model.generate_content(prompt)
            raw = _strip_fences(response.text.strip())
            result = json.loads(raw)
            print(f"[analyzer] {cve_id} (Gemini) → vulnerable={result.get('vulnerable')} "
                  f"confidence={result.get('confidence', 0):.2f} | {result.get('reason','')[:80]}")
            time.sleep(4)
            return result
        except json.JSONDecodeError as e:
            print(f"[analyzer] JSON parse error for {cve_id}: {e} | raw: {raw[:200]}")
            return None
        except Exception as e:
            err = str(e)
            if "429" in err or "quota" in err.lower() or "rate" in err.lower():
                if attempt < 3:
                    wait = 5 * (2 ** attempt)
                    print(f"[analyzer] Gemini 429 for {cve_id} — retry in {wait}s ({attempt+1}/3)")
                    time.sleep(wait)
                else:
                    print(f"[analyzer] Gemini quota exhausted for {cve_id} — falling back")
                    return None
            else:
                print(f"[analyzer] Gemini error for {cve_id}: {e}")
                return None
    return None


def _call_claude(prompt: str, cve_id: str, cfg, severity: str = "MEDIUM") -> Optional[dict]:
    """Call Claude with severity-gated model: CRITICAL → Opus, others → Sonnet."""
    model = _model_for_severity(severity)
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=cfg.ANTHROPIC_API_KEY)
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            temperature=0.2,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = _strip_fences(response.content[0].text.strip())
        result = json.loads(raw)
        print(f"[analyzer] {cve_id} (Claude/{model.split('-')[1]}) → vulnerable={result.get('vulnerable')} "
              f"confidence={result.get('confidence', 0):.2f}")
        return result
    except Exception as e:
        print(f"[analyzer] Claude error for {cve_id}: {e}")
        return None


def _strip_fences(raw: str) -> str:
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return raw.strip()


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
