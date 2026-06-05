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
from sage.utils.colors import cprint


def _prompts_dir() -> Path:
    try:
        from sage.config import cfg
        return cfg.data_dir("prompts")
    except Exception:
        return Path("data/prompts")

def _responses_dir() -> Path:
    try:
        from sage.config import cfg
        return cfg.data_dir("responses")
    except Exception:
        return Path("data/responses")

PROMPTS_DIR  = Path("data/prompts")   # legacy fallback
RESPONSES_DIR = Path("data/responses") # legacy fallback


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
    Determine analysis mode.

    Non-interactive (CI/cron/pipe): always API if keys present, else manual.
    Interactive: always ask — even if keys are present. Quota may be exhausted,
    user may prefer manual copy-paste, or may want to save credits.
    """
    import sys
    from sage.config import cfg

    has_api_key = bool(cfg.ANTHROPIC_API_KEY or cfg.GEMINI_API_KEY)

    # Non-interactive: no prompt, decide automatically
    if not sys.stdin.isatty():
        mode = "api" if has_api_key else "manual"
        cprint(f"[analyzer] Non-interactive — {mode} mode")
        return mode

    # Interactive: always ask
    cprint("\n[analyzer] ── Analysis Mode ──")
    if has_api_key:
        model_hint = "Gemini" if cfg.GEMINI_API_KEY else "Claude"
        cprint(f"  API keys detected ({model_hint} available)")
    else:
        cprint("  No API keys found in .env")
    cprint("  [1] API mode   — call LLM automatically")
    cprint("  [2] Manual mode — generate prompt files, paste into Claude, save responses")
    while True:
        choice = input("  Your choice (1/2): ").strip()
        if choice == "1":
            return "api"
        if choice == "2":
            return "manual"
        cprint("  Please enter 1 or 2.")


def analyze_findings(
    findings: list[dict],
    G,
    repo_path: str,
    reach_results: Optional[list[dict]] = None,
) -> list[dict]:
    """
    Determine analysis mode, then run accordingly.

    API mode:   calls Gemini 2.0 Flash (with Anthropic fallback) per CVE.
                Model is severity-gated: CRITICAL → Opus, others → Sonnet.
    Manual mode: exports prompt files → you paste into Claude chat → drop JSON responses.
    Non-interactive (CI/cron): always uses API mode without prompting.

    reach_results: optional output from reachability.analyze_reachability() —
                   passed as context into prompts for more accurate exploitability decisions.
    """
    mode = _ask_mode()
    if mode == "api":
        return _analyze_api(findings, G, repo_path, reach_results)
    return _analyze_manual(findings, G, repo_path, reach_results)


def _analyze_api(
    findings: list[dict],
    G,
    repo_path: str,
    reach_results: Optional[list[dict]] = None,
) -> list[dict]:
    """API mode — Gemini primary, Anthropic fallback, exponential backoff on 429."""
    by_cve = _group_by_cve(findings, G)
    # Index reachability by cve_id for fast lookup
    reach_by_cve: dict[str, list[dict]] = {}
    if reach_results:
        for r in reach_results:
            reach_by_cve[r["cve_id"]] = r.get("paths", [])
    cprint(f"[analyzer] Analyzing {len(by_cve)} CVEs via API...")
    confirmed = []
    for cve_id, cve_findings in by_cve.items():
        result = _analyze_single_cve_api(
            cve_id, cve_findings, G, repo_path,
            reach_paths=reach_by_cve.get(cve_id),
        )
        if result:
            confirmed.append(result)
    cprint(f"[analyzer] Confirmed: {len(confirmed)}/{len(by_cve)} CVEs actually exploitable")
    return confirmed


def _analyze_manual(
    findings: list[dict],
    G,
    repo_path: str,
    reach_results: Optional[list[dict]] = None,
) -> list[dict]:
    """
    Manual mode — export prompts, read existing responses.

    First run: generates prompts, returns [].
    Subsequent runs: reads responses you've saved, returns confirmed list.
    """
    _prompts_dir().mkdir(parents=True, exist_ok=True)
    _responses_dir().mkdir(parents=True, exist_ok=True)

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

    cprint(f"[analyzer] {len(by_cve)} CVEs to analyze (manual mode)")

    confirmed = []
    new_prompts = 0
    skipped = 0

    for cve_id, cve_findings in by_cve.items():
        response_file = _responses_dir() / f"{cve_id}.json"

        # If response exists — read it
        if response_file.exists():
            result = _read_response(cve_id, cve_findings, G, repo_path)
            if result:
                confirmed.append(result)
            continue

        # No response — export prompt if not already done
        prompt_file = _prompts_dir() / f"{cve_id}.txt"
        reach_by_cve: dict[str, list[dict]] = {}
        if reach_results:
            for r in reach_results:
                reach_by_cve[r["cve_id"]] = r.get("paths", [])
        if not prompt_file.exists():
            _export_prompt(
                cve_id, cve_findings, G, repo_path,
                reach_paths=reach_by_cve.get(cve_id),
            )
            new_prompts += 1
        else:
            skipped += 1

    total_with_prompts = len(list(_prompts_dir().glob("*.txt")))
    total_with_responses = len(list(_responses_dir().glob("*.json")))

    cprint(f"[analyzer] Prompts exported: {new_prompts} new  |  {skipped} already existed")
    cprint(f"[analyzer] Responses read:   {total_with_responses}/{total_with_prompts}")
    cprint(f"[analyzer] Confirmed: {len(confirmed)}/{len(by_cve)} CVEs exploitable")

    if new_prompts > 0 or (total_with_prompts > total_with_responses):
        pending = total_with_prompts - total_with_responses
        pending_files = sorted([
            f for f in _prompts_dir().glob("*.txt")
            if not (_responses_dir() / f.name.replace(".txt", ".json")).exists()
        ])
        cprint(f"\n[analyzer] ── Manual review needed ──")
        cprint(f"  {pending} CVE(s) awaiting your review.\n")
        for pf in pending_files:
            cprint(f"  ┌─ {pf.name} ─────────────────────────────────────────")
            cprint(f"  │  cat \"{pf.resolve()}\"")
            resp_path = _responses_dir() / pf.name.replace(".txt", ".json")
            cprint(f"  │  Paste content into Claude → save response as:")
            cprint(f"  │  \"{resp_path.resolve()}\"")
            cprint(f"  └────────────────────────────────────────────────────\n")
        # Wait for user to paste responses, then continue automatically
        _wait_for_responses(pending_files, by_cve, G)
        # Re-read all responses after user confirms
        confirmed = []
        for cve_id in by_cve:
            response_file = _responses_dir() / f"{cve_id}.json"
            if response_file.exists():
                result = _read_response(cve_id, by_cve[cve_id], G, repo_path)
                if result:
                    confirmed.append(result)
        cprint(f"[analyzer] Confirmed after review: {len(confirmed)}/{len(by_cve)} CVEs exploitable")

    return confirmed


def _wait_for_responses(pending_files: list, by_cve: dict, G):
    """
    Pause the pipeline and wait for the user to paste responses.
    Watches for new response files and continues once all are present,
    or when the user presses Enter to continue with whatever is saved.
    """
    import sys, time

    # Non-interactive — can't wait, just continue
    if not sys.stdin.isatty():
        return

    responses_dir = _responses_dir()
    total = len(pending_files)

    cprint(f"\n[analyzer] ── Pipeline paused — waiting for responses ──")
    cprint(f"  Open each prompt file, paste into Claude, save the JSON response.")
    cprint(f"  The pipeline will continue automatically once all {total} response(s) are saved.")
    cprint(f"  Or press Enter at any time to continue with responses saved so far.\n")

    while True:
        # Check how many are done
        done = sum(
            1 for pf in pending_files
            if (responses_dir / pf.name.replace(".txt", ".json")).exists()
        )
        remaining = total - done

        if remaining == 0:
            cprint(f"\n[analyzer] All {total} response(s) received — continuing pipeline...")
            break

        cprint(f"  [{done}/{total} saved]  Waiting... (press Enter to continue anyway)", end="\r", flush=True)

        # Non-blocking check: poll every 3s, but also catch Enter
        import select
        ready, _, _ = select.select([sys.stdin], [], [], 3.0)
        if ready:
            sys.stdin.readline()  # consume the Enter
            cprint(f"\n[analyzer] Continuing with {done}/{total} responses saved...")
            break


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

def _analyze_single_cve_api(
    cve_id: str,
    findings: list[dict],
    G,
    repo_path: str,
    reach_paths: Optional[list[dict]] = None,
) -> Optional[dict]:
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
        cprint(f"[analyzer] {cve_id} — no code to analyze, skipping")
        return None

    prompt = _build_prompt(cve_id, severity, package, cwe, affected_r, function_codes, findings, reach_paths)

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

    cprint(f"[analyzer] {cve_id} → NOT exploitable "
          f"({response.get('confidence', 0):.1f}): {response.get('reason', '')[:80]}")
    return None


def _call_llm_api(prompt: str, cve_id: str, cfg, severity: str = "MEDIUM") -> Optional[dict]:
    """Gemini primary, Anthropic fallback. Claude model is severity-gated."""
    if cfg.GEMINI_API_KEY:
        result = _call_gemini(prompt, cve_id, cfg)
        if result is not None:
            return result
        # Only fall back to Claude if Gemini quota exhausted — not on every 429
        # (Gemini 429 = rate limit, not quota; wait and retry instead)
        if cfg.ANTHROPIC_API_KEY:
            cprint(f"[analyzer] Falling back to Claude for {cve_id}")
            result = _call_claude(prompt, cve_id, cfg, severity)
            if result is None:
                cprint(f"[analyzer] Both APIs failed for {cve_id} — skipping")
            return result
        return None
    elif cfg.ANTHROPIC_API_KEY:
        return _call_claude(prompt, cve_id, cfg, severity)
    cprint(f"[analyzer] No API key available for {cve_id}")
    return None


def _call_gemini(prompt: str, cve_id: str, cfg) -> Optional[dict]:
    import time

    # Try new google-genai SDK first (recommended), fall back to deprecated generativeai
    try:
        from google import genai as google_genai
        return _call_gemini_new_sdk(prompt, cve_id, cfg, google_genai)
    except ImportError:
        pass

    # Deprecated SDK fallback
    try:
        import google.generativeai as genai
    except ImportError:
        cprint("[analyzer] Neither google-genai nor google-generativeai installed.")
        return None

    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        genai.configure(api_key=cfg.GEMINI_API_KEY)
        model = genai.GenerativeModel(
            model_name="gemini-2.0-flash",
            generation_config={"temperature": 0.2, "max_output_tokens": 1024},
        )

    raw = ""
    for attempt in range(4):
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                # Try flash-lite first (higher free tier quota), fall back to flash
                try:
                    lite_model = genai.GenerativeModel(
                        model_name="gemini-2.0-flash-lite",
                        generation_config={"temperature": 0.2, "max_output_tokens": 1024},
                    )
                    response = lite_model.generate_content(prompt)
                except Exception:
                    response = model.generate_content(prompt)
            raw = _strip_fences(response.text.strip())
            result = json.loads(raw)
            cprint(f"[analyzer] {cve_id} (Gemini) → vulnerable={result.get('vulnerable')} "
                  f"confidence={result.get('confidence', 0):.2f} | {result.get('reason','')[:80]}")
            time.sleep(5)  # 5s between calls — stay under free tier 15 req/min
            return result
        except json.JSONDecodeError as e:
            cprint(f"[analyzer] JSON parse error for {cve_id}: {e} | raw: {raw[:200]}")
            return None
        except Exception as e:
            err = str(e)
            if "429" in err or "quota" in err.lower() or "rate" in err.lower():
                if attempt < 3:
                    wait = 15 * (2 ** attempt)  # 15s, 30s, 60s — generous backoff
                    cprint(f"[analyzer] Gemini 429 for {cve_id} — retry in {wait}s ({attempt+1}/3)")
                    time.sleep(wait)
                else:
                    cprint(f"[analyzer] Gemini quota exhausted for {cve_id} — skipping")
                    return None
            else:
                cprint(f"[analyzer] Gemini error for {cve_id}: {e}")
                return None
    return None


def _call_gemini_new_sdk(prompt: str, cve_id: str, cfg, genai_module) -> Optional[dict]:
    """Use the new google-genai SDK (replaces deprecated google-generativeai)."""
    import time
    client = genai_module.Client(api_key=cfg.GEMINI_API_KEY)
    # Try models in order of free-tier quota availability
    models_to_try = ["gemini-2.0-flash-lite", "gemini-2.0-flash", "gemini-1.5-flash"]
    raw = ""
    for attempt in range(4):
        try:
            response = None
            last_err = None
            for model_name in models_to_try:
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config={"temperature": 0.2, "max_output_tokens": 1024},
                    )
                    break
                except Exception as me:
                    if "429" in str(me) or "quota" in str(me).lower():
                        last_err = me
                        continue
                    raise
            if response is None:
                raise last_err
            raw = _strip_fences(response.text.strip())
            result = json.loads(raw)
            cprint(f"[analyzer] {cve_id} (Gemini) → vulnerable={result.get('vulnerable')} "
                  f"confidence={result.get('confidence', 0):.2f} | {result.get('reason','')[:80]}")
            time.sleep(5)
            return result
        except json.JSONDecodeError as e:
            cprint(f"[analyzer] JSON parse error for {cve_id}: {e} | raw: {raw[:200]}")
            return None
        except Exception as e:
            err = str(e)
            if "429" in err or "quota" in err.lower() or "rate" in err.lower():
                if attempt < 3:
                    wait = 15 * (2 ** attempt)
                    cprint(f"[analyzer] Gemini 429 for {cve_id} — retry in {wait}s ({attempt+1}/3)")
                    time.sleep(wait)
                else:
                    cprint(f"[analyzer] Gemini quota exhausted for {cve_id} — skipping")
                    return None
            else:
                cprint(f"[analyzer] Gemini error for {cve_id}: {e}")
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
        cprint(f"[analyzer] {cve_id} (Claude/{model.split('-')[1]}) → vulnerable={result.get('vulnerable')} "
              f"confidence={result.get('confidence', 0):.2f}")
        return result
    except Exception as e:
        cprint(f"[analyzer] Claude error for {cve_id}: {e}")
        return None


def _strip_fences(raw: str) -> str:
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return raw.strip()


# ─── Prompt export ────────────────────────────────────────────────────────────

def _export_prompt(
    cve_id: str,
    findings: list[dict],
    G,
    repo_path: str,
    reach_paths: Optional[list[dict]] = None,
):
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
        reach_paths=reach_paths,
    )

    prompt_file = _prompts_dir() / f"{cve_id}.txt"
    prompt_file.write_text(prompt)
    cprint(f"[analyzer] Prompt saved → {prompt_file}")


def _build_prompt(
    cve_id: str,
    severity: str,
    package: str,
    cwe: str,
    affected_range: str,
    function_codes: list[dict],
    semgrep_findings: list[dict],
    reach_paths: Optional[list[dict]] = None,
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

    # Reachability section — the key context that distinguishes exploitable from theoretical
    reach_section = ""
    if reach_paths:
        reach_section = "\n\nREACHABILITY ANALYSIS (call paths from entry points to vulnerable library):\n"
        for p in reach_paths[:5]:
            arrow = " → ".join(p["path"])
            reach_section += f"  [{p['entry_type']:14s}]  {arrow}\n"
        reach_section += "\nNote: these are static call paths. Dynamic dispatch may add or remove paths.\n"
    else:
        reach_section = "\n\nREACHABILITY ANALYSIS: No direct call paths found from entry points to this library.\n"

    return f"""You are a security vulnerability analyst. Determine if this CVE is actually exploitable in this specific codebase.

CVE INFORMATION:
- CVE ID: {cve_id}
- Severity: {severity}
- Affected package: {package}
- Affected versions: {affected_range}
- CWE: {cwe or 'Not specified'}
{code_section}{semgrep_section}{reach_section}

TASK:
Is this CVE exploitable given how the library is actually used in the code above?
Consider:
1. Can user-controlled input reach the vulnerable code path?
2. Do the reachability paths lead through user-facing entry points?
3. Does the code use the specific vulnerable API/function of the library?

RULES:
- Base answer ONLY on the code shown
- If no function code, base on library usage pattern
- If reachability paths exist but don't go through user-facing entry points, lower confidence
- Be conservative — if uncertain, mark vulnerable with low confidence

OUTPUT: Respond with ONLY valid JSON. No text before or after. No markdown fences.

{{
  "vulnerable": true or false,
  "confidence": 0.0 to 1.0,
  "reason": "one sentence explaining your decision",
  "affected_functions": ["function_name1"],
  "attack_vector": "how an attacker could reach the vulnerable code, or empty string if not vulnerable",
  "recommendation": "specific fix recommendation, or empty string if not vulnerable"
}}"""


# ─── Response reader ──────────────────────────────────────────────────────────

def _read_response(cve_id: str, findings: list[dict], G, repo_path: str = "") -> Optional[dict]:
    """Read a manually saved response JSON for a CVE."""
    response_file = _responses_dir() / f"{cve_id}.json"
    try:
        response = json.loads(response_file.read_text())
    except Exception as e:
        cprint(f"[analyzer] Bad response file for {cve_id}: {e}")
        return None

    if not response.get("vulnerable", False):
        cprint(f"[analyzer] {cve_id} → NOT exploitable "
              f"({response.get('confidence', 0):.1f}): {response.get('reason', '')[:80]}")
        return None

    cve_node  = f"cve:{cve_id}"
    node_data = G.nodes.get(cve_node, {})

    cprint(f"[analyzer] {cve_id} → CONFIRMED exploitable "
          f"(confidence: {response.get('confidence', 0):.1f})")

    # Re-extract function source so the patcher has actual code to patch.
    # The live API path includes function_codes in its return dict; manual mode
    # previously dropped it here, causing the patcher to emit an empty VULNERABLE
    # CODE block and skip code-level patches entirely.
    function_codes: list[dict] = []
    if repo_path:
        from sage.synapse.mapper import get_blast_radius
        blast = get_blast_radius(G, cve_node)
        if blast:
            function_codes = _extract_function_codes(
                blast.get("exposed_functions", []), repo_path, G
            )
            if not function_codes:
                function_codes = _extract_file_snippets(
                    blast.get("exposed_files", []),
                    repo_path,
                    node_data.get("package", ""),
                )

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
        "function_codes":     function_codes,
    }


# ─── Save results ─────────────────────────────────────────────────────────────

def save_confirmed(confirmed: list[dict], output_path: str = ""):
    from sage.config import cfg
    p = Path(output_path) if output_path else cfg.data_dir() / "confirmed.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(confirmed, f, indent=2)
    cprint(f"[analyzer] Confirmed vulnerabilities saved → {p}")


def print_analysis_summary(confirmed: list[dict]):
    if not confirmed:
        cprint("[analyzer] No exploitable vulnerabilities confirmed.")
        return

    cprint(f"\n[analyzer] ── Confirmed Vulnerabilities ──")
    for v in confirmed:
        cprint(f"\n  [{v['severity']:8s}] {v['cve_id']}")
        cprint(f"  Package:    {v['package']} {v['affected_range']}")
        cprint(f"  Confidence: {v['confidence']:.0%}")
        cprint(f"  Reason:     {v['reason']}")
        if v.get("attack_vector"):
            cprint(f"  Attack:     {v['attack_vector']}")
        if v.get("recommendation"):
            cprint(f"  Fix:        {v['recommendation']}")


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
