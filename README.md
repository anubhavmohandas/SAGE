<img width="2752" height="1536" alt="Security_Analysis_and_Graph_Engine" src="https://github.com/user-attachments/assets/65578d8a-b384-4ba9-af52-908947895c16" />

# SAGE — Security Analysis & Graph Engine

> **Your codebase as a knowledge graph. CVEs as signals on top of it.**

SAGE is an autonomous security pipeline that scans repositories, maps their structure into an interactive knowledge graph, finds CVEs affecting the stack, confirms exploitability with AI, generates patches, and raises GitHub PRs — all from one command.

```bash
bash sage_scan.sh          # asks for a repo path or GitHub URL, then scans
```

**[→ Full walkthrough: scan → graph → AI patches → PR](#walkthrough--one-scan-start-to-finish)**

---

## 🌐 Live Demo

[**→ Synapse Visualization**](./Media/Security_graph_diagram_animation_202606060821.mp4)

---

## What makes SAGE different

Most security tools answer: *"Library X has CVE-Y."*

SAGE answers: *"Function `fetch_json()` in `cybertrace/modules/base.py` calls `aiohttp`, which has 18 CVEs — here's the blast radius, here's the patch."*

Reachability analysis traces call paths from entry points to the vulnerable library (same-file call-chain resolution today; cross-file resolution is on the roadmap), and feeds those paths to the analyzer as exploitability context.

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
 ├─ ── GATE ─────────── — shows the issues, asks before anything gets written
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

## Setup — one time

```bash
git clone https://github.com/anubhavmohandas/SAGE
cd SAGE
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Then fill in `.env`:

| Key | Required? | What it does |
|---|---|---|
| `ANTHROPIC_API_KEY` | **Yes** | SAGE refuses to start without it ([sage/config.py](sage/config.py)). Manual mode never *calls* the API, but the key must be present. Get one at [console.anthropic.com](https://console.anthropic.com). |
| `NVD_API_KEY` | No | Faster CVE fetch. Without it NVD rate-limits you to 5 requests / 30s. [Request a free key](https://nvd.nist.gov/developers/request-an-api-key). |
| `GITHUB_TOKEN` | No | Needed only for the final PR step. Use a **fine-grained** token: Contents + Pull requests, scoped to the target repo. Without it SAGE finishes everything else and skips PR creation. |
| `GITHUB_REPO` | No | Fallback PR target (`owner/repo`) for repos with no git remote. The scanned repo's own remote always wins. |

---

## Walkthrough — one scan, start to finish

> ⚠️ **SAGE executes code from the repo it scans** (dependency install + tests). Safe for your own repos; run untrusted repos in a disposable VM/container. See [Security](#️-security-sage-executes-scanned-repo-code).

### Step 1 — Start the scan

```bash
bash sage_scan.sh
```

It asks two questions:

```
Which repo do you want to scan?
  Repo path or URL: _

    https://github.com/owner/repo   → shallow-cloned to a temp dir, deleted after the run
    /Users/you/projects/MyApp       → scanned in place

Scan window (days of CVE history to fetch)
  [1] 1 day   — today's CVEs only (fast)
  [2] 7 days  — last week (recommended)
  [3] 30 days — last month (thorough)
  [4] Custom
  Choice (1/2/3/4) [default: 2]: _
```

Answer them up front to skip the prompts:

```bash
bash sage_scan.sh /path/to/repo
bash sage_scan.sh https://github.com/owner/repo
bash sage_scan.sh /path/to/repo --days 30       # extra flags pass through to main.py
```

Windows: `powershell -File sage_scan.ps1` (same prompts).

### Step 2 — The graph appears

Stack detect → CVE fetch → filter → tree-sitter parse → CVE overlay → export. Two files land:

```
data/<repo>/synapse_graph.json          raw graph (nodes + edges + CVE overlay)
demos/<repo>_<YYYY-MM-DD>/index.html    self-contained visualisation
```

Open the `index.html` in any browser — no server, no build step, data is embedded. The terminal prints the exact `file://` path. The pipeline keeps running while you explore it.

### Step 3 — Choose how CVEs get analysed

The pipeline stops and asks:

```
[analyzer] ── Analysis Mode ──
  [1] API mode    — call LLM automatically
  [2] Manual mode — generate prompt files, paste into Claude, save responses
  Your choice (1/2): _
```

- **`1` API mode** — SAGE calls Claude itself. Nothing else to do but answer the gate in Step 5; skip Steps 4 and 6.
- **`2` Manual mode** — the choice applies to the **whole pipeline** (analyzer + patcher + security tests). Zero API calls, zero credits burned. The pipeline **pauses and waits** for your files.

**One terminal, no scripts.** SAGE bundles the prompts, opens both files for you, and picks the reply up the moment you save it.

### Step 4 — Analysis: copy the bundle, paste the reply, save

The pipeline pauses and opens two files:

```
[analyzer] ── Manual review needed ──
  8 CVE(s) awaiting your review.

[analyzer] ── 8 CVE(s), one paste ──
  Bundle → data/CyberTrace/all_prompts.txt
  1. Copy the bundle that just opened → paste into Claude / ChatGPT
     data/CyberTrace/all_prompts.txt
  2. Paste the whole reply into the file that opened beside it and save:
     data/CyberTrace/all_responses.txt
  3. SAGE continues by itself on save  |  Enter to check now  |  S to skip

  Waiting for all_responses.txt...
```

Copy the bundle into any LLM — it already carries the required output format, so don't add
instructions of your own. Paste the entire reply into the second file, hit save, and the run
continues on its own:

```
[sage] Reply detected — continuing
  ✓ CVE-2026-34513  [vulnerable]  confidence=85%
  ✓ CVE-2026-34516  [clean]       confidence=90%
[analyzer] Imported 8/8 response(s)
```

Each section is validated before it's written — a malformed one is reported and dropped, and
only those CVEs fall back to the old per-file wait. `S` skips the review entirely; typing a
path uses that file instead, if you saved the reply somewhere else.

Under the hood: one prompt per CVE at `data/<repo>/prompts/CVE-XXXX-XXXXX.txt`, one response expected at `data/<repo>/responses/CVE-XXXX-XXXXX.json`. You can write those by hand, or still use `export_prompts.sh` / `import_responses.sh` — same files, same format. Response schema:

```json
{
  "vulnerable": true,
  "confidence": 0.85,
  "reason": "one sentence",
  "affected_functions": ["fetch_data", "_create_session"],
  "attack_vector": "how an attacker reaches it, or empty string",
  "recommendation": "fix, or empty string"
}
```

Windows: `export_prompts.ps1` / `.bat`, `import_responses.ps1` / `.bat`.

### Step 5 — The gate: patch, or stop here

Everything so far only *read* the repo. Everything after this writes patches, installs
dependencies, runs the repo's test suite and pushes a branch — so the pipeline stops and
shows you what it found:

```
============================================================
  Analysis complete — what happens next writes code
============================================================
  Confirmed exploitable:  3
    [CRITICAL] CVE-2026-34513 → aiohttp
    [HIGH    ] CVE-2025-69223 → aiohttp
    [MEDIUM  ] CVE-2026-22815 → requests
  CVEs eligible for dependency bump: 18

  Continuing runs: patch generation → tests → verifier → GitHub PR.
  Stopping keeps the graph and findings already saved on disk.

  Generate patches now? [y/N]: _
```

- **`n`** (or Enter) — the run ends right there. Graph, findings and analysis stay on disk;
  nothing was patched, tested or pushed. Re-run the same command and answer `y` when ready.
- **`y`** — patch generation starts immediately. No separate export/import step.

Non-interactive runs (`--digest`, cron, piped stdin) never see this prompt and always continue.

**In manual mode, `y` bundles every patch prompt into one file** — same copy-paste-save loop
as Step 4, one paste for the whole run instead of one pause per CVE:

```
[patcher] ── Manual patches: 3 CVE(s), one paste ──
  Bundle → data/CyberTrace/patches/all_patch_prompts.txt
  1. Copy the bundle that just opened → paste into Claude / ChatGPT
  2. Paste the whole reply into the file that opened beside it and save:
     data/CyberTrace/patches/all_patch_responses.json
  3. SAGE continues by itself on save  |  Enter to check now  |  S to skip

[sage] Reply detected — continuing
  ✓ CVE-2026-34513 → 2 file(s)
[patcher] Imported 3/3 patch response(s)
```

The pipeline splits the reply itself and carries straight on to the tests.
`export_patches.sh` / `import_patches.sh` still work on the same files if you prefer
running them by hand.

Files: `data/<repo>/patches/patch_prompt_<CVE>.txt` in, `data/<repo>/patches/patch_response_<CVE>.json` out. Applied patches and diffs land in `data/<repo>/patches/<CVE>/`. Patch schema:

```json
{
  "patched_files": [
    {
      "file": "relative/path.py",
      "original_function": "fetch_json",
      "patched_code": "complete patched function",
      "explanation": "what changed and why"
    }
  ],
  "summary": "one sentence"
}
```

Dependency bumps need no AI — SAGE writes those to `requirements.txt` itself.

### Step 6 — Security tests (manual mode only)

No bundler here; SAGE asks one CVE at a time:

```
[tests] ── Manual security test needed: CVE-2026-34513 ──
  Prompt saved → data/CyberTrace/tests/test_prompt_CVE_2026_34513.txt
  1. Paste into Claude / ChatGPT
  2. Save the Python test to:
     data/CyberTrace/tests/test_CVE_2026_34513.py
  Press Enter when saved  |  S to skip this CVE
```

Note the **underscores** in these filenames (`CVE_2026_34513`), unlike the hyphens used for prompts and patches. Press `S` to skip a CVE's test.

### Step 7 — Tests, verification, PR — automatic

No further input. SAGE runs the repo's existing suite (with [baseline failure detection](#test-baseline-detection)), runs the generated security tests, re-runs Semgrep on the patched code, then opens the PR:

```
GitHub PR:  https://github.com/owner/repo/pull/1   [ready]
```

The PR is a **draft** unless every confirmed CVE produced a patch *and* all tests pass — SAGE says which condition forced the draft.

### Where everything lands

```
data/<repo>/
├── sage.db                  CVE store (SQLite)
├── synapse_graph.json       knowledge graph
├── findings.json            Semgrep results
├── confirmed.json           CVEs the AI confirmed exploitable
├── reachability.json        call paths → vulnerable libs
├── prompts/CVE-*.txt        Step 4 in
├── responses/CVE-*.json     Step 4 out
├── patches/                 Step 5 in/out + applied diffs
├── tests/                   Step 6 prompts + generated tests
├── verify/                  post-patch Semgrep pass
└── pr_result.json           PR URL + status

demos/<repo>_<date>/index.html    the graph
```

### Resuming a run

Everything on disk is reused, so an interrupted manual run picks up where it left off:

```bash
python3 main.py --synapse /path/to/repo    # skips CVE fetch, reuses saved responses/patches
```

Only files with real content count — empty or stale leftovers from a previous run are ignored and re-requested.

---

## Direct CLI (scripting)

`sage_scan.sh` is a wrapper around `main.py`. Call it directly when you don't want the prompts:

```bash
# Full pipeline
python3 main.py --repo /path/to/repo

# Repo you don't have locally — shallow-cloned to a temp dir, scanned, deleted.
# Results stay in data/<repo_name>/.
python3 main.py --repo https://github.com/owner/repo

# Wider CVE window (default is 1 day)
python3 main.py --repo /path/to/repo --days 30

# Knowledge graph only — no CVE fetch
python3 main.py --synapse /path/to/repo

# Look up a specific CVE
python3 main.py --cve CVE-2026-34520

# Pipeline status
python3 main.py --status

# Non-interactive multi-repo run (no prompts — API mode if keys present)
python3 main.py --digest /path/to/repo1 /path/to/repo2 --days 7
```

Piped or non-interactive runs never prompt: they use API mode if `ANTHROPIC_API_KEY` is set, export prompt files and skip otherwise.

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
| CVE confirmed exploitable by LLM | Code patch (Claude Sonnet in API mode, or manual prompt in manual mode) + dep bump. Patch written to `data/<repo>/patches/CVE-XXXX/` |
| `pkg[extras]` in requirements (e.g. `aiohttp[speedups]`) | Extras preserved — regex extracts base name + extras separately |

---

## Tests, verification & PR gating

After patching, SAGE runs the repo's existing tests and generates a **security test** per confirmed CVE. To stay reliable across Python versions and avoid hallucinated library APIs, generated security tests assert the **patched dependency version is installed** rather than reconstructing exploits. (This proves the upstream fix is present — the appropriate check for dependency CVEs. It does not reproduce the exploit.)

The PR is opened as a **draft** unless *both* are true: existing + security tests pass, **and** every confirmed CVE actually produced a patch. If patch generation failed or tests fail, SAGE forces a draft and states why — it never presents an empty or unverified patch as a ready-to-merge PR.

---

## ⚠️ Security: SAGE executes scanned-repo code

To verify patches, SAGE installs the scanned repo's dependencies (`pip`, which runs build hooks) and runs its tests on the host. A malicious or compromised target repo can therefore run code on your machine. SAGE launches these subprocesses with its own API keys/tokens **scrubbed from the environment**, so scanned code cannot read your secrets — but this is a backstop, not a sandbox.

- **Your own / trusted repos** → fine on your normal machine.
- **Untrusted / third-party repos** → run SAGE inside a disposable VM or container. (Full sandboxing is on the roadmap.)

Use a **fine-grained** GitHub token scoped to the target repo (Contents + Pull requests), never a classic full-`repo` PAT.

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
Confirmed:        0/24 exploitable (note: this run predates the reachability
                  engine fix — analysis was based on Semgrep + code context only;
                  re-validation with live reachability paths pending)
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
- Canvas API — the Synapse visualisation is pure vanilla JS, zero dependencies

---

*SAGE v2.0 — All 12 pipeline stages complete. First real PR raised on CyberTrace. 🛡️*
