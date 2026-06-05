<img width="2752" height="1536" alt="Security_Analysis_and_Graph_Engine" src="https://github.com/user-attachments/assets/65578d8a-b384-4ba9-af52-908947895c16" />

# SAGE — Security Analysis & Graph Engine

> **Your codebase as a knowledge graph. CVEs as signals on top of it.**

SAGE is an autonomous security pipeline that scans repositories, maps their structure into an interactive knowledge graph, finds CVEs affecting the stack, confirms exploitability with AI, generates patches, and raises GitHub PRs — all from one command.

```bash
python3 main.py --repo /path/to/your/repo
```

---

## 🌐 Live Demo

[**→ Synapse Visualization**](https://anubhavmohandas.github.io/SAGE)

---

## What makes SAGE different

Most security tools answer: *"Library X has CVE-Y."*

SAGE answers: *"Function `fetch_json()` in `cybertrace/modules/base.py` calls `aiohttp`, which has 18 CVEs — here's the exact call chain, here's the blast radius, here's the patch."*

The graph is the codebase. CVEs are badges on nodes that already exist.

---

## Pipeline

```
Repo
 │
 ├─  1. STACK DETECT    — reads requirements.txt / package.json / pyproject.toml / Pipfile
 ├─  2. CVE FETCH       — pulls analysed CVEs from NVD (lastModified window)
 ├─  3. CVE FILTER      — matches NVD CPE strings against your stack
 ├─  4. SYNAPSE PARSE   — tree-sitter AST → files + functions + imports graph
 ├─  5. CVE OVERLAY     — attaches CVE nodes to library nodes in the graph
 ├─  6. GRAPH EXPORT    — synapse_graph.json + index.html (self-contained viz)
 ├─  7. SCANNER         — semgrep on blast-radius files only (45 CWEs, 30 library packs)
 ├─  8. ANALYZER        — LLM confirms exploitability (CRITICAL→Opus, others→Sonnet)
 ├─  9. PATCHER         — dep bump + code patch generation
 ├─ 10. TESTS           — runs existing test suite, detects pre-existing baseline failures
 ├─ 11. VERIFIER        — final semgrep pass post-patch
 └─ 12. GITHUB PR       — timestamped branch + PR with full CVE table
```

---

## Synapse — Knowledge Graph

The graph opens on the repo root and lets you drill down:

```
repo (purple)
 └─ file: cybertrace/modules/base.py
     ├─ function: fetch_json()  ──USES──► lib: aiohttp
     ├─ function: _create_session()       └─► CVE-2026-34520 [CRITICAL]
     └─ lib: aiohttp ──────────────────────► CVE-2025-69223 [HIGH]
                                           ► CVE-2025-69224 [MEDIUM]
                                           ► ... 16 more
```

**Node types:**

| Color | Type | Meaning |
|---|---|---|
| 🟣 Purple | REPO | Repository root — entry point |
| 🔵 Blue | FILE | Source file |
| 🟢 Green | FUNCTION | Function/method definition |
| 🟠 Orange | LIBRARY | Third-party dependency |
| 🔴 Red | CVE | Vulnerability — size = severity |

**Interactions:**
- Click any node to drill in
- Hover a CVE → attack path traces back to entry point in red
- `ESC` / `←` to go back, `R` to reset, `S` to save PNG, scroll to zoom
- Light / dark mode toggle, edge relationship labels on hover

---

## Setup

```bash
git clone https://github.com/anubhavmohandas/SAGE
cd SAGE
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add your API keys
```

**.env keys:**

```
NVD_API_KEY=       # https://nvd.nist.gov/developers/request-an-api-key
ANTHROPIC_API_KEY= # https://console.anthropic.com
GEMINI_API_KEY=    # optional — used as primary analyzer, Anthropic as fallback
GITHUB_TOKEN=      # repo:write scope (Contents + Pull requests)
GITHUB_REPO=       # owner/repo
```

---

## Usage

```bash
# Full pipeline — scan a repo
python3 main.py --repo /path/to/repo

# Wider CVE window (default is 1 day)
python3 main.py --repo /path/to/repo --days 30

# Build knowledge graph only (skip CVE fetch)
python3 main.py --synapse /path/to/repo

# Look up a specific CVE
python3 main.py --cve CVE-2026-34520

# Show pipeline status
python3 main.py --status
```

The graph is always written to `demos/<repo>_<date>/index.html`. Open it in any browser — no server needed.

---

## Analyzer — Dual Mode

SAGE works with or without API keys.

**API mode** — Gemini 2.0 Flash (free tier, 15 RPM) as primary analyzer with exponential backoff. Falls back to Anthropic if Gemini quota exhausted.

**Manual mode** — No API key needed. SAGE exports `data/prompts/CVE-XXXX.txt` for each CVE. Paste into any LLM, save the JSON response to `data/responses/CVE-XXXX.json`, re-run. Pipeline picks up where it left off.

Manual response schema:
```json
{
  "vulnerable": true,
  "confidence": 0.85,
  "reason": "...",
  "affected_functions": ["fetch_data", "_create_session"],
  "attack_vector": "...",
  "recommendation": "..."
}
```

---

## Severity-gated model selection

| Severity | Model | Rationale |
|---|---|---|
| CRITICAL | `claude-opus-4-6` | Highest stakes — best analysis |
| HIGH | `claude-sonnet-4-6` | Strong enough, 5× cheaper |
| MEDIUM | `claude-sonnet-4-6` | Fast triage |
| LOW | `claude-sonnet-4-6` | Minimal cost |

---

## Patcher strategy

| Scenario | Action |
|---|---|
| CVE with known safe version, no confirmed exploitable code | Dep bump only — bumps `requirements.txt` with `>=safe_version` |
| CVE confirmed exploitable by LLM | Code patch via Claude Sonnet + dep bump. Patch written to `data/patches/CVE-XXXX/` |
| `pkg[extras]` in requirements (e.g. `aiohttp[speedups]`) | Extras preserved — regex extracts base name + extras separately |

---

## Architecture

```
sage/
├── fetcher/
│   ├── nvd.py        NVD API client — paginated, rate-limited, lastModDate window
│   ├── filter.py     Stack detection + CPE matching + alias table (30+ packages)
│   └── store.py      SQLite CVE store — dedup, CWE storage, pipeline status
├── synapse/
│   ├── parser.py     tree-sitter AST — files, functions, imports, calls + regex fallback
│   ├── mapper.py     CVE overlay — blast radius trace, AFFECTS edges
│   └── export.py     Graph serialisation + self-contained index.html generation
├── scanner/
│   └── semgrep.py    45 CWEs mapped, 30 library-specific rule packs
├── analyzer/
│   └── llm.py        Exploitability confirmation — dual mode, severity-gated models
├── patcher/
│   └── llm.py        Dep bump + code patch + diff + manifest
├── tests/
│   └── runner.py     Existing test suite runner — baseline failure detection
├── verifier/
│   └── semgrep.py    Post-patch semgrep pass + dep bump validation
└── github/
    └── pr.py         Timestamped branch + PR creation, CVE table in body
```

---

## Semgrep coverage

**45 CWEs across 10 categories:**

| Category | CWEs |
|---|---|
| Injection | CWE-89, 79, 78, 77, 88, 94, 95, 96, 643 |
| Path / File | CWE-22, 23, 36, 434, 73 |
| Crypto / Secrets | CWE-327, 326, 330, 331, 312, 319, 798, 259 |
| Auth / Access | CWE-284, 285, 287, 306, 307, 384, 613 |
| Deserialization | CWE-502, 119, 125, 787 |
| Network / SSRF | CWE-918, 611, 601, 295 |
| DoS / Resource | CWE-400, 770, 776, 835 |
| Info Exposure | CWE-200, 209, 532, 779 |
| Header / Protocol | CWE-113, 444, 116 |
| Input Validation | CWE-20, 74, 409 |

**30 library-specific rule packs** covering: aiohttp, flask, django, fastapi, requests, httpx, sqlalchemy, pymongo, jwt, cryptography, pyyaml, pickle, jinja2, subprocess, and more.

---

## CVE matching

SAGE uses NVD's `lastModified` window (not `publishedDate`) so it catches CVEs that were recently analysed — NVD only adds CPE data after analysis, which can be days after publication. Unanalysed CVEs (`Received`, `Awaiting Analysis`) are skipped.

Package name normalisation handles NVD's inconsistent CPE naming:

```python
"anthropic-sdk"    → matches "anthropic"
"python-requests"  → matches "requests"
"aio_libs_aiohttp" → matches "aiohttp"
```

---

## Test baseline detection

Many repos have pre-existing test failures unrelated to SAGE's patches. Naive gating would permanently block security PRs.

SAGE detects baseline failures before patching and excludes them from the gate. Only failures *introduced by SAGE* block the PR.

| Scenario | SAGE action |
|---|---|
| 49 pass, 1 pre-existing failure | Baseline detected → override PASSED → PR not blocked |
| 49 pass, 1 new failure from patch | New failure → PR blocked → human review |
| No test suite | Marked PASSED (no tests ≠ failure) → PR raised |

---

## Validation — CyberTrace

SAGE has scanned itself and [CyberTrace](https://github.com/anubhavmohandas/CyberTrace). Example end-to-end output:

```
Stack detected:   aiohttp, click, rich, dnspython, phonenumbers, python-dotenv, python-whois
CVEs found:       33 total from NVD, 24 attached to graph
                  CRITICAL×3  HIGH×9  MEDIUM×12
Semgrep:          0 findings (correct — client-only CLI, no server-side exposure)
Confirmed:        0/24 exploitable (correct — no user-controlled input to vuln paths)
Dep bump:         aiohttp >=3.9.0 → >=3.13.3 (18 CVEs)
                  click >=8.0.0 → >=8.3.3 (1 CVE)
Tests:            49 passed, 1 pre-existing failure (baseline detected, PR not blocked)
Verifier:         PASSED
GitHub PR:        https://github.com/anubhavmohandas/CyberTrace/pull/1
```

---

## Roadmap

**Near-term**

- [ ] **Morning digest** — scheduled daily scan, terminal summary, optional Slack/email alert. Batch decisions once a day, not real-time noise.
- [ ] **Dog food** — SAGE scans SAGE. Raises a PR on its own repo when deps are outdated. Eats its own cooking.
- [ ] **JS/TS support** — `package.json` + `npm audit` CVE mapping. `filter.py` already has `_parse_package_json` as a stub.
- [ ] **CVE delta** — only alert on CVEs new since the last scan. Eliminates duplicate noise on repeat runs.

**Medium-term**

- [ ] **Multi-repo** — scan an entire GitHub org, unified knowledge graph across repos, cross-repo blast radius.
- [ ] **Go + Rust support** — `go.mod` / `Cargo.toml` stack detection, language-specific tree-sitter grammars.
- [ ] **Dashboard + Alerts** — visual CVE status per repo, severity-gated Slack/email for CRITICAL findings, full audit log.
- [ ] **Synapse viz polish** — tunable `max_neighbours`, deeper drill-down depth control, pinned nodes, timeline view.

**Long-term**

- [ ] **NYX integration** — ships as `nyx/tools/osint/sage/` in Phase 3 of NYX. SAGE becomes the static analysis and vulnerability intelligence module of a broader autonomous security pipeline.
- [ ] **Transitive dependency traversal** — follow indirect deps, not just direct requirements. Surface CVEs two levels deep.
- [ ] **SBOM export** — generate CycloneDX / SPDX software bill of materials from the Synapse graph.
- [ ] **IDE plugin** — VS Code extension that renders the Synapse graph inline and highlights vulnerable call chains in the editor.

---

## Built with

- [tree-sitter](https://tree-sitter.github.io) — AST parsing across languages
- [NetworkX](https://networkx.org) — graph construction and traversal
- [Semgrep](https://semgrep.dev) — static analysis, CWE-mapped rules
- [NVD API](https://nvd.nist.gov/developers/vulnerabilities) — CVE data
- [Anthropic Claude](https://anthropic.com) — exploitability analysis and patch generation
- [Google Gemini](https://ai.google.dev) — primary analyzer (free tier)
- Canvas API — the Synapse visualisation is pure vanilla JS, zero dependencies

---

*SAGE v2.0 — All 12 pipeline stages complete. First real PR raised on CyberTrace. 🛡️*
