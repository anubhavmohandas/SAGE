![Uploading image.png…]()

# SAGE — Security Analysis & Graph Engine

> **Your codebase as a knowledge graph. CVEs as signals on top of it.**

SAGE is an autonomous security pipeline that scans repositories, maps their structure into an interactive knowledge graph, finds CVEs affecting the stack, confirms exploitability with AI, generates patches, and raises GitHub PRs — all from one command.


```
python3 main.py --repo /path/to/your/repo
```

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
 ├─ 1. STACK DETECT    — reads requirements.txt / package.json
 ├─ 2. CVE FETCH       — pulls analysed CVEs from NVD (lastModified window)
 ├─ 3. CVE FILTER      — matches NVD CPE strings against your stack
 ├─ 4. SYNAPSE PARSE   — tree-sitter AST → files + functions + imports graph
 ├─ 5. CVE OVERLAY     — attaches CVE nodes to library nodes in the graph
 ├─ 6. GRAPH EXPORT    — synapse_graph.json + index.html (self-contained viz)
 ├─ 7. SCANNER         — semgrep on blast-radius files
 ├─ 8. ANALYZER        — LLM confirms exploitability (CRITICAL→Opus, others→Sonnet)
 ├─ 9. PATCHER         — dep bump + code patch generation
 ├─ 10. TESTS          — runs existing test suite
 ├─ 11. VERIFIER       — final semgrep pass post-patch
 └─ 12. GITHUB PR      — timestamped branch + PR with full context
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
GITHUB_TOKEN=      # repo:write scope
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

The graph is always written to `demos/<repo>_<date>/index.html`. Open it in any browser.

---

## Architecture

```
sage/
├── fetcher/
│   ├── nvd.py        NVD API client — paginated, rate-limited, lastModDate window
│   ├── filter.py     Stack detection + CPE matching + alias table
│   └── store.py      SQLite CVE store
├── synapse/
│   ├── parser.py     tree-sitter AST parser — files, functions, imports, calls
│   ├── mapper.py     CVE overlay — attaches CVE nodes to library nodes
│   └── export.py     Graph serialisation + index.html generation
├── scanner/
│   └── semgrep.py    Semgrep on blast-radius files, CWE-mapped rules
├── analyzer/
│   └── llm.py        Exploitability confirmation — severity-gated model selection
├── patcher/
│   └── llm.py        Dep bump + code patch + manifest for exact path reconstruction
├── tests/
│   └── runner.py     Existing test suite runner
├── verifier/
│   └── semgrep.py    Post-patch semgrep verification
└── github/
    └── pr.py         Branch + PR creation, already-patched detection
```

---

## Severity-gated model selection

The analyzer uses different Claude models based on CVE severity to balance cost and quality:

| Severity | Model | Rationale |
|---|---|---|
| CRITICAL | `claude-opus-4-6` | Highest stakes — best analysis |
| HIGH | `claude-sonnet-4-6` | Strong enough, 5× cheaper |
| MEDIUM | `claude-sonnet-4-6` | Fast triage |
| LOW | `claude-sonnet-4-6` | Minimal cost |

Gemini 2.0 Flash is used as primary when a key is available, with Claude as fallback.

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

## What was scanned

SAGE has scanned itself and CyberTrace. Example output:

```
CyberTrace — 259 nodes, 18 CVEs on aiohttp (1 CRITICAL, 5 HIGH, 12 MEDIUM)
SAGE itself — 164 nodes, 1 CVE on python-dotenv (MEDIUM)
```

---

## Roadmap

- [ ] Morning digest — scheduled daily scan with terminal summary
- [ ] JS/TS support — `package.json` stack detection (filter.py has `_parse_package_json`)
- [ ] Multi-repo — scan an org, unified graph across repos
- [ ] CVE delta — only alert on new CVEs since last scan

---

## Built with

- [tree-sitter](https://tree-sitter.github.io) — AST parsing across languages
- [NetworkX](https://networkx.org) — graph construction and traversal
- [Semgrep](https://semgrep.dev) — static analysis, CWE-mapped rules
- [NVD API](https://nvd.nist.gov/developers/vulnerabilities) — CVE data
- [Anthropic Claude](https://anthropic.com) — exploitability analysis and patch generation
- Canvas API — the Synapse visualisation is pure vanilla JS, no dependencies
