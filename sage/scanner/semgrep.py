"""
scanner/semgrep.py — Static analysis using Semgrep

Runs Semgrep ONLY on functions exposed by CVEs.
Not the whole codebase — just the blast radius.

Teaching note — why Semgrep over just running payloads:
    Payload testing: "does input X crash the app?"
    Semgrep:         "is the CODE PATTERN vulnerable?"

    Semgrep catches:
      - SQL injection pattern (string concat + query)
      - Command injection (subprocess + user input)
      - Path traversal (open() + user input)
      - XSS patterns, insecure deserialization, etc.

    It works even if the specific payload hasn't been invented yet.
    Pattern-based = future-proof.

Teaching note — CWE to Semgrep rule mapping:
    NVD CVEs have CWE IDs. Semgrep has rule packs per CWE.
    CWE-89  (SQL injection)      → p/sql-injection
    CWE-79  (XSS)                → p/xss
    CWE-78  (Command injection)  → p/command-injection
    CWE-22  (Path traversal)     → p/path-traversal
    CWE-400 (ReDoS)              → p/regex
    CWE-502 (Deserialization)    → p/deserialization
    Default fallback             → p/python (general Python rules)
"""

import json
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Optional

from sage.synapse.mapper import get_blast_radius


# CWE → Semgrep rule pack mapping
CWE_TO_RULES = {
    "CWE-89":  ["p/sql-injection"],                        # SQL Injection
    "CWE-79":  ["p/xss"],                                  # XSS
    "CWE-78":  ["p/command-injection"],                    # OS Command Injection
    "CWE-77":  ["p/command-injection"],                    # Command Injection (generic)
    "CWE-22":  ["p/path-traversal"],                       # Path Traversal
    "CWE-400": ["p/regex", "p/security-audit"],            # ReDoS / Resource exhaustion
    "CWE-502": ["p/deserialization"],                      # Unsafe Deserialization
    "CWE-918": ["p/ssrf"],                                 # SSRF
    "CWE-611": ["p/xss"],                                  # XXE
    "CWE-20":  ["p/security-audit", "p/owasp-top-ten"],   # Improper Input Validation
    "CWE-200": ["p/secrets", "p/security-audit"],          # Info Exposure
    "CWE-312": ["p/secrets"],                              # Cleartext storage of sensitive info
    "CWE-327": ["p/cryptography"],                         # Weak crypto algorithm
    "CWE-330": ["p/cryptography"],                         # Insufficient randomness
    "CWE-601": ["p/security-audit"],                       # Open Redirect
    "CWE-94":  ["p/security-audit"],                       # Code Injection
    "CWE-611": ["p/security-audit"],                       # XML Injection
    "CWE-703": ["p/security-audit"],                       # Improper error handling
    "CWE-295": ["p/security-audit"],                       # Improper cert validation
}

# Library-specific rule packs — run these ON TOP of CWE rules
# when that library is in the blast radius
LIBRARY_RULES = {
    "aiohttp":      ["p/aiohttp"],
    "flask":        ["p/flask"],
    "django":       ["p/django"],
    "requests":     ["p/ssrf"],
    "dnspython":    ["p/regex"],
    "sqlalchemy":   ["p/sql-injection"],
    "jwt":          ["p/jwt"],
    "pyjwt":        ["p/jwt"],
    "cryptography": ["p/cryptography"],
    "paramiko":     ["p/security-audit"],
    "urllib3":      ["p/ssrf"],
    "httpx":        ["p/ssrf"],
}

DEFAULT_RULES = ["p/python", "p/security-audit", "p/owasp-top-ten"]


def scan_blast_radius(G, repo_path: str) -> list[dict]:
    """
    Run Semgrep on functions exposed by CVEs in the graph.

    Args:
        G:         The Synapse knowledge graph (with CVE nodes attached)
        repo_path: Path to the repo being scanned

    Returns:
        List of findings dicts:
        [
          {
            "cve_id":       "CVE-2025-69223",
            "file":         "cybertrace/network.py",
            "function":     "fetch_data()",
            "line":         42,
            "rule_id":      "python.aiohttp.security...",
            "severity":     "HIGH",
            "message":      "Potential SSRF via aiohttp...",
            "fix":          "Use allowlist for URLs",
          },
          ...
        ]

    Teaching note:
        We return findings per CVE — not just a flat list.
        This tells the LLM analyzer exactly WHICH CVE each finding
        relates to, which improves patch quality significantly.
    """
    all_findings = []

    # Get all CVE nodes from graph
    cve_nodes = [n for n in G.nodes() if n.startswith("cve:")]
    if not cve_nodes:
        print("[scanner] No CVE nodes in graph. Run fetcher + mapper first.")
        return []

    print(f"[scanner] Scanning blast radius for {len(cve_nodes)} CVEs...")

    for cve_node in cve_nodes:
        cve_id = cve_node.replace("cve:", "")
        blast  = get_blast_radius(G, cve_node)
        if not blast:
            continue

        exposed_files = blast.get("exposed_files", [])
        if not exposed_files:
            continue

        # Get CWE from graph node — stored directly now
        node_data = G.nodes[cve_node]
        cwe = node_data.get("cwe", "") or _extract_cwe(node_data.get("info", ""))

        # Pick rules: CWE-based + library-specific, deduplicated
        rules = list(CWE_TO_RULES.get(cwe, DEFAULT_RULES))

        # Add library-specific rules on top
        affected_lib = blast.get("affected_library", "")
        lib_rules = LIBRARY_RULES.get(affected_lib, [])
        for r in lib_rules:
            if r not in rules:
                rules.append(r)

        print(f"[scanner] {cve_id} ({cwe or 'no CWE'}) → "
              f"{len(exposed_files)} files, lib={affected_lib} → rules: {rules}")

        # Run Semgrep on each exposed file
        for rel_file in exposed_files:
            abs_file = os.path.join(repo_path, rel_file)
            if not os.path.exists(abs_file):
                continue

            findings = _run_semgrep(abs_file, rules, cve_id)
            all_findings.extend(findings)

    print(f"[scanner] Total findings: {len(all_findings)}")
    return all_findings


def _run_semgrep(file_path: str, rules: list[str], cve_id: str) -> list[dict]:
    """
    Run Semgrep on a single file with the given rule packs.

    Teaching note:
        We run Semgrep as a subprocess — it's a CLI tool.
        --json flag gives us machine-readable output.
        --quiet suppresses progress output.
        --no-git-ignore makes it scan even if file is gitignored.

        We capture stdout (results) and stderr (errors) separately.
        If Semgrep crashes, we log and continue — never crash the pipeline.
    """
    findings = []

    for rule in rules:
        try:
            cmd = [
                "semgrep",
                "--config", rule,
                "--json",
                "--quiet",
                "--no-git-ignore",
                file_path,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,  # 60s timeout per file per rule
            )

            if result.returncode not in (0, 1):
                # 0 = no findings, 1 = findings found, anything else = error
                print(f"[scanner] Semgrep error on {file_path}: {result.stderr[:200]}")
                continue

            if not result.stdout.strip():
                continue

            data = json.loads(result.stdout)
            for match in data.get("results", []):
                findings.append(_parse_finding(match, cve_id, rule))

        except subprocess.TimeoutExpired:
            print(f"[scanner] Semgrep timed out on {file_path}")
        except json.JSONDecodeError:
            print(f"[scanner] Could not parse Semgrep output for {file_path}")
        except FileNotFoundError:
            print("[scanner] Semgrep not found. Install: pip3 install semgrep")
            break
        except Exception as e:
            print(f"[scanner] Unexpected error: {e}")

    return findings


def _parse_finding(match: dict, cve_id: str, rule: str) -> dict:
    """
    Parse a single Semgrep match into our finding format.

    Teaching note:
        Semgrep's JSON output has a specific structure.
        We flatten it into our own format so the rest of the
        pipeline doesn't need to know about Semgrep internals.
        This is called an "adapter pattern" — normalize external
        data into your own schema at the boundary.
    """
    extra    = match.get("extra", {})
    metadata = extra.get("metadata", {})
    location = match.get("path", "")
    start    = match.get("start", {})

    return {
        "cve_id":    cve_id,
        "file":      location,
        "line":      start.get("line", 0),
        "col":       start.get("col", 0),
        "rule_id":   match.get("check_id", rule),
        "severity":  extra.get("severity", "UNKNOWN").upper(),
        "message":   extra.get("message", "").strip(),
        "fix":       metadata.get("fix", ""),
        "cwe":       metadata.get("cwe", ""),
        "code":      extra.get("lines", "").strip(),
        "rule_pack": rule,
    }


def _extract_cwe(info: str) -> Optional[str]:
    """
    Extract CWE ID from node info string.
    e.g. "HIGH severity\nAffects: aiohttp\nCWE-400" → "CWE-400"
    """
    import re
    match = re.search(r"CWE-\d+", info)
    return match.group(0) if match else None


def save_findings(findings: list[dict], output_path: str = "data/findings.json"):
    """
    Save Semgrep findings to JSON for the next pipeline stage (LLM analyzer).

    Teaching note:
        Each pipeline stage writes its output to a JSON file.
        The next stage reads from it.
        This means stages are decoupled — you can re-run any stage
        independently without running the whole pipeline.
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"[scanner] Findings saved → {output_path}")


def print_findings_summary(findings: list[dict]):
    """Print a human-readable summary of findings."""
    if not findings:
        print("[scanner] No findings. Code looks clean for these CVE patterns.")
        return

    print(f"\n[scanner] ── Findings Summary ──")
    by_severity = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "WARNING", "INFO"]:
        if sev in by_severity:
            print(f"  {sev:10s} {by_severity[sev]}")

    print(f"\n  Top findings:")
    for finding in findings[:5]:
        print(f"  [{finding['severity']:8s}] {finding['file']}:{finding['line']}")
        print(f"             {finding['message'][:80]}")
        print(f"             CVE: {finding['cve_id']}")
        print()
