"""
config.py — SAGE configuration loader

Loads all environment variables from .env at startup.
Hard-fails with a clear error if any required key is missing.
Nothing in SAGE imports keys directly — everything goes through this module.

Usage:
    from sage.config import cfg
    print(cfg.NVD_API_KEY)
"""

import os
from dataclasses import dataclass
from dotenv import load_dotenv

# Load .env file into environment
load_dotenv()


@dataclass
class Config:
    NVD_API_KEY: str
    ANTHROPIC_API_KEY: str
    GEMINI_API_KEY: str
    GITHUB_TOKEN: str
    GITHUB_REPO: str


def load_config() -> Config:
    """
    Load and validate all required environment variables.
    Raises a clear error immediately if anything is missing —
    better to fail at startup than halfway through a pipeline run.
    """
    missing = []

    NVD_API_KEY       = os.getenv("NVD_API_KEY", "")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")
    GITHUB_TOKEN      = os.getenv("GITHUB_TOKEN", "")
    GITHUB_REPO       = os.getenv("GITHUB_REPO", "")

    # NVD key is optional (works without it, just rate-limited to 5 req/30s)
    # Gemini key is optional — falls back to Anthropic if not set
    if not GITHUB_TOKEN:
        missing.append("GITHUB_TOKEN")
    if not GITHUB_REPO:
        missing.append("GITHUB_REPO")
    if not ANTHROPIC_API_KEY and not GEMINI_API_KEY:
        missing.append("ANTHROPIC_API_KEY or GEMINI_API_KEY (at least one required)")

    if missing:
        raise EnvironmentError(
            f"\n[SAGE] Missing required environment variables: {', '.join(missing)}\n"
            f"Copy .env.example to .env and fill in your keys.\n"
        )

    if not NVD_API_KEY:
        print("[SAGE] Warning: NVD_API_KEY not set. Rate limited to 5 requests/30s.")
        print("[SAGE] Get a free key at: nvd.nist.gov/developers/request-an-api-key\n")

    return Config(
        NVD_API_KEY=NVD_API_KEY,
        ANTHROPIC_API_KEY=ANTHROPIC_API_KEY,
        GEMINI_API_KEY=GEMINI_API_KEY,
        GITHUB_TOKEN=GITHUB_TOKEN,
        GITHUB_REPO=GITHUB_REPO,
    )


# Single instance — import this everywhere
cfg = load_config()
