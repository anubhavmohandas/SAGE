"""
repo_source.py — accept a GitHub URL anywhere SAGE accepts a repo path.

A GitHub URL is shallow-cloned into a temp directory, scanned like any local
repo, and deleted when the run ends. Results survive the cleanup: everything
the pipeline produces is written under data/<repo_name>/, not into the clone.

Accepted forms:
    https://github.com/owner/repo(.git)
    github.com/owner/repo
    git@github.com:owner/repo.git
    /any/local/path            ← unchanged, no clone

Usage:
    path, tmp = resolve_repo(user_input)
    try:
        ...scan path...
    finally:
        cleanup(tmp)
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from sage.utils.colors import cprint

# github.com only — not a generic git-URL resolver. Keeping the host fixed means
# a pasted URL can never make SAGE clone from an internal//private host.
_GITHUB_RE = re.compile(
    r"^(?:https?://)?(?:git@)?github\.com[/:]"
    r"(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)

CLONE_TIMEOUT = 180  # seconds


def parse_github_url(s: str):
    """Return (owner, repo) for a GitHub URL, or None if it isn't one."""
    m = _GITHUB_RE.match(s.strip())
    if not m:
        return None
    owner, repo = m.group("owner"), m.group("repo")
    # "." / ".." would escape the temp dir when used as the clone directory name.
    if repo in (".", "..") or owner in (".", ".."):
        return None
    return owner, repo


def is_github_url(s: str) -> bool:
    return parse_github_url(s) is not None


def clone_to_temp(owner: str, repo: str) -> str:
    """
    Shallow-clone github.com/owner/repo into a temp dir. Returns the repo path.
    Raises RuntimeError on failure.
    """
    tmpdir = tempfile.mkdtemp(prefix="sage-clone-")
    # Clone into <tmp>/<repo> so cfg.set_repo() scopes data/ by the real repo
    # name instead of "sage-clone-8f2a1b".
    dest = os.path.join(tmpdir, repo)

    # URL is rebuilt from the parsed owner/repo, never passed through raw, so
    # nothing in the input can reach git as a flag or as credentials. "--" ends
    # option parsing anyway; GIT_TERMINAL_PROMPT=0 makes a private repo fail
    # fast instead of hanging on a username prompt.
    url = f"https://github.com/{owner}/{repo}.git"
    cprint(f"[SAGE] Cloning {url} → {dest}")

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--", url, dest],
            capture_output=True, text=True, timeout=CLONE_TIMEOUT,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except FileNotFoundError:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError("git is not installed — cannot clone a GitHub URL")
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError(f"clone timed out after {CLONE_TIMEOUT}s")

    if result.returncode != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError(result.stderr.strip() or "git clone failed")

    cprint(f"[SAGE] Cloned {owner}/{repo} (temp copy, removed after the scan)")
    return dest


def resolve_repo(s: str):
    """
    Turn user input into a local repo path.

    Returns (repo_path, tmpdir_to_clean) — tmpdir_to_clean is None for local
    paths. Exits with a clear message if the URL won't clone or the path
    doesn't exist.
    """
    parsed = parse_github_url(s)
    if parsed:
        try:
            path = clone_to_temp(*parsed)
        except RuntimeError as e:
            cprint(f"[SAGE] Clone failed: {e}")
            sys.exit(1)
        return path, str(Path(path).parent)

    path = os.path.abspath(os.path.expanduser(s.strip()))
    if not os.path.isdir(path):
        cprint(f"[SAGE] Not a directory or GitHub URL: {s}")
        sys.exit(1)
    return path, None


def cleanup(*tmpdirs) -> None:
    """Remove temp clone directories. Safe to call with None entries."""
    for d in tmpdirs:
        if d:
            shutil.rmtree(d, ignore_errors=True)
            cprint(f"[SAGE] Removed temp clone: {d}")


def _self_check() -> None:
    assert parse_github_url("https://github.com/psf/requests") == ("psf", "requests")
    assert parse_github_url("http://github.com/psf/requests/") == ("psf", "requests")
    assert parse_github_url("github.com/psf/requests.git") == ("psf", "requests")
    assert parse_github_url("git@github.com:psf/requests.git") == ("psf", "requests")
    assert parse_github_url("  github.com/psf/requests  ") == ("psf", "requests")
    # Not GitHub repos / not URLs at all
    for bad in [
        "/Users/me/projects/app",
        "./app",
        "gitlab.com/psf/requests",
        "https://evil.com/github.com/psf/requests",
        "https://github.com/psf",                      # no repo
        "https://github.com/psf/requests/issues/1",    # not a repo root
        "https://github.com/psf/../etc",               # traversal attempt
        "--upload-pack=touch /tmp/pwned",              # flag smuggling
    ]:
        assert parse_github_url(bad) is None, bad
    print("repo_source self-check OK")


if __name__ == "__main__":
    _self_check()
