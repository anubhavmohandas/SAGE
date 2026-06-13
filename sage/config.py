"""
config.py — SAGE configuration loader

Loads all environment variables from .env at startup.
Hard-fails with a clear error if any required key is missing.
Nothing in SAGE imports keys directly — everything goes through this module.

Usage:
    from sage.config import cfg
    cprint(cfg.NVD_API_KEY)
    cprint(cfg.data_dir())  # repo-scoped data directory

Per-repo data isolation:
    Each scanned repo gets its own data subdirectory so that scanning
    multiple repos doesn't mix CVEs, prompts, patches, or graph files.

    Layout:
        data/
          SAGE/           ← SAGE scanning itself
            sage.db
            synapse_graph.json
            prompts/
            responses/
            patches/
            ...
          CyberTrace/     ← CyberTrace scan
            sage.db
            ...

    Call cfg.set_repo(repo_path) at the start of each pipeline run.
    All modules that call cfg.data_dir() automatically use the right folder.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv
from sage.utils.colors import cprint

# Load .env file into environment
load_dotenv()


@dataclass
class Config:
    NVD_API_KEY: str
    ANTHROPIC_API_KEY: str
    GITHUB_TOKEN: str
    GITHUB_REPO: str
    _repo_name: str = field(default="default", repr=False)
    # Pipeline-wide LLM mode, set once by the analyzer ("api" or "manual").
    # Patcher and test generator MUST respect this so that choosing manual mode
    # never silently calls the API (and never burns credits/quota you didn't ask
    # to spend). Default "api" preserves prior non-interactive behaviour.
    llm_mode: str = field(default="api")

    def set_repo(self, repo_path: str) -> None:
        """
        Set the active repo context.
        All subsequent cfg.data_dir() calls return data/<repo_name>/.

        Source-of-truth rule: the scanned repo's OWN git remote is authoritative
        for the PR target. GITHUB_REPO from .env is only a fallback for repos with
        no remote. This guarantees SAGE can never open a PR against a repo other
        than the one it actually scanned — and removes the previous double-prompt
        (this method asked, and sage_scan.sh asked) which could disagree.
        """
        self._repo_name = Path(repo_path).name or "default"

        detected = _detect_github_repo_from_path(repo_path)
        if detected:
            if detected != self.GITHUB_REPO:
                cprint(f"[SAGE] PR target = {detected} (from scanned repo's git remote; "
                       f".env GITHUB_REPO={self.GITHUB_REPO or 'unset'} ignored)")
            self.GITHUB_REPO = detected
        elif self.GITHUB_REPO:
            cprint(f"[SAGE] No git remote on scanned repo — falling back to "
                   f".env GITHUB_REPO={self.GITHUB_REPO}")
        # else: no remote and no .env → pr.py will skip PR creation (no target)

    def data_dir(self, *subdirs: str) -> Path:
        """
        Return the repo-scoped data directory, creating it if needed.

        Examples:
            cfg.data_dir()                → data/SAGE/
            cfg.data_dir("prompts")       → data/SAGE/prompts/
            cfg.data_dir("patches", cve)  → data/SAGE/patches/CVE-XXXX/
        """
        base = Path("data") / self._repo_name
        if subdirs:
            base = base.joinpath(*subdirs)
        base.mkdir(parents=True, exist_ok=True)
        return base


def _detect_github_repo_from_path(repo_path: str) -> str:
    """Extract owner/repo from git remote of repo_path."""
    import re, subprocess
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_path, capture_output=True, text=True, timeout=10,
        )
        url = result.stdout.strip()
        m = re.search(r"github\.com[/:]([^/]+/[^/]+?)(?:\.git)?$", url)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def load_config() -> Config:
    """
    Load and validate all required environment variables.
    Raises a clear error immediately if anything is missing —
    better to fail at startup than halfway through a pipeline run.
    """
    missing = []

    NVD_API_KEY       = os.getenv("NVD_API_KEY", "")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    GITHUB_TOKEN      = os.getenv("GITHUB_TOKEN", "")
    GITHUB_REPO       = os.getenv("GITHUB_REPO", "")

    # NVD key is optional (works without it, just rate-limited to 5 req/30s)
    if not GITHUB_TOKEN:
        missing.append("GITHUB_TOKEN")
    if not GITHUB_REPO:
        missing.append("GITHUB_REPO")
    if not ANTHROPIC_API_KEY:
        missing.append("ANTHROPIC_API_KEY")

    if missing:
        raise EnvironmentError(
            f"\n[SAGE] Missing required environment variables: {', '.join(missing)}\n"
            f"Copy .env.example to .env and fill in your keys.\n"
        )

    if not NVD_API_KEY:
        cprint("[SAGE] Warning: NVD_API_KEY not set. Rate limited to 5 requests/30s.")
        cprint("[SAGE] Get a free key at: nvd.nist.gov/developers/request-an-api-key\n")

    return Config(
        NVD_API_KEY=NVD_API_KEY,
        ANTHROPIC_API_KEY=ANTHROPIC_API_KEY,
        GITHUB_TOKEN=GITHUB_TOKEN,
        GITHUB_REPO=GITHUB_REPO,
        _repo_name="default",
    )


# Single instance — import this everywhere
cfg = load_config()
