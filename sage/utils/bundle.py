"""
bundle.py — one paste instead of N, for manual (no-API) runs.

Both manual stages have the same shape: several per-CVE prompts go out, one
combined reply comes back. This writes the outgoing bundle and splits the
incoming reply, in the exact '=== CVE-XXXX-XXXXX ===' format that
export_prompts.sh / import_responses.sh / export_patches.sh / import_patches.sh
already use — so replies produced either way parse identically.

Used by:
    sage/analyzer/llm.py  — exploitability verdicts
    sage/patcher/llm.py   — code patches
"""

import json
import re
from pathlib import Path

from sage.utils.colors import cprint

_SPLIT_RE = re.compile(
    r"===\s*(CVE-[\w-]+)\s*===\s*\n([\s\S]*?)(?====\s*CVE-|$)", re.IGNORECASE
)


def write_bundle(path: Path, header: str, tasks: list) -> Path:
    """Write `tasks` — a list of (cve_id, prompt) — into one file for pasting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = header + "".join(
        f"======================================\n"
        f"TASK: {cve_id}\n"
        f"======================================\n{prompt}\n\n"
        for cve_id, prompt in tasks
    )
    path.write_text(body)
    return path


def split_bundle_response(text: str, only_cve: str = "") -> dict:
    """
    Split a combined AI reply into {cve_id: dict}.

    Accepts the '=== CVE-x ===' bundle format, and falls back to a bare JSON
    object when a single CVE was asked for and the reply carries no marker.
    Malformed sections are reported and dropped, never raised.
    """
    out = {}
    for m in _SPLIT_RE.finditer(text):
        cve_id = m.group(1).strip().upper()
        body = re.sub(r"^```(?:json)?\s*", "", m.group(2).strip())
        body = re.sub(r"\s*```$", "", body).strip()
        brace = re.search(r"\{[\s\S]*\}", body)
        if not brace:
            cprint(f"  [!] {cve_id} — no JSON found in that section")
            continue
        try:
            out[cve_id] = json.loads(brace.group(0))
        except json.JSONDecodeError as e:
            cprint(f"  [!] {cve_id} — invalid JSON: {e}")

    if not out and only_cve:
        brace = re.search(r"\{[\s\S]*\}", text)
        if brace:
            try:
                out[only_cve.upper()] = json.loads(brace.group(0))
            except json.JSONDecodeError as e:
                cprint(f"  [!] {only_cve} — invalid JSON: {e}")
    return out


_PLACEHOLDER = (
    "Paste the AI's full reply here — replace this line — then save the file.\n"
    "SAGE is watching this file and continues on its own the moment you do.\n"
)


def open_in_editor(path: Path) -> None:
    """Open a file with the OS default handler. Silent no-op if that fails."""
    import subprocess
    import sys

    try:
        if sys.platform == "darwin":
            subprocess.run(["open", str(path)], capture_output=True, timeout=10)
        elif sys.platform.startswith("win"):
            import os
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            subprocess.run(["xdg-open", str(path)], capture_output=True, timeout=10)
    except Exception:
        pass  # opening is a convenience — the printed path is the real contract


def collect_reply(bundle: Path, reply: Path, what: str) -> "Path | None":
    """
    Hand off the bundle and wait for the reply, without leaving the pipeline.

    Opens the bundle (to copy into Claude) and a blank reply file (to paste
    back into), then blocks until that file is saved with something other than
    the placeholder — no path to type, no second terminal.

    Enter re-checks immediately, a typed path uses that file instead, S skips.
    Returns None when skipped, when the run isn't interactive, or when nothing
    usable was saved.
    """
    import sys
    import threading

    if not sys.stdin.isatty():
        cprint(f"  Non-interactive — bundle written, skipping {what} this run")
        return None

    reply.parent.mkdir(parents=True, exist_ok=True)
    reply.write_text(_PLACEHOLDER)

    open_in_editor(bundle)
    open_in_editor(reply)

    cprint(f"  1. Copy the bundle that just opened → paste into Claude / ChatGPT")
    cprint(f"     {bundle.resolve()}")
    cprint(f"  2. Paste the whole reply into the file that opened beside it and save:")
    cprint(f"     {reply.resolve()}")
    cprint(f"  3. SAGE continues by itself on save  |  Enter to check now  |  S to skip\n")

    typed: list[str] = []
    entered = threading.Event()

    def _watch_stdin():
        try:
            typed.append(sys.stdin.readline().strip())
        except Exception:
            pass
        entered.set()

    threading.Thread(target=_watch_stdin, daemon=True).start()

    def _saved() -> bool:
        try:
            return reply.read_text().strip() not in ("", _PLACEHOLDER.strip())
        except OSError:
            return False

    while True:
        if _saved():
            cprint(f"\n[sage] Reply detected — continuing")
            return reply

        if entered.wait(timeout=2.0):
            answer = typed[0] if typed else ""
            if answer.lower() == "s":
                cprint(f"[sage] Skipping {what}")
                return None
            if answer:
                path = Path(answer).expanduser()
                if path.is_file():
                    return path
                cprint(f"[sage] Not found: {path} — skipping {what}")
                return None
            if _saved():
                return reply
            cprint(f"[sage] Nothing pasted yet — skipping {what}")
            return None

        cprint(f"  Waiting for {reply.name}...", end="\r", flush=True)


def _self_check() -> None:
    reply = """Here you go.

=== CVE-2021-44228 ===
```json
{"vulnerable": true, "confidence": 0.9, "reason": "r"}
```
=== CVE-2022-1111 ===
{"patched_files": [{"file": "b.py"}], "summary": "s"}
"""
    out = split_bundle_response(reply)
    assert set(out) == {"CVE-2021-44228", "CVE-2022-1111"}, out
    assert out["CVE-2021-44228"]["confidence"] == 0.9
    assert out["CVE-2022-1111"]["patched_files"][0]["file"] == "b.py"

    # Single pending CVE, model replied with bare JSON and no marker
    bare = '{"vulnerable": false, "confidence": 0.2, "reason": "r"}'
    assert split_bundle_response(bare, only_cve="cve-2023-9")["CVE-2023-9"]["confidence"] == 0.2
    assert split_bundle_response(bare) == {}          # no marker, no hint → nothing
    assert split_bundle_response("no json here") == {}
    assert split_bundle_response("=== CVE-1-1 ===\nnot json") == {}
    assert split_bundle_response("=== CVE-1-1 ===\n{bad json}") == {}

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = write_bundle(Path(d) / "b.txt", "HEAD\n", [("CVE-1-1", "prompt one")])
        text = p.read_text()
        assert text.startswith("HEAD\n") and "TASK: CVE-1-1" in text and "prompt one" in text
    print("bundle self-check OK")


if __name__ == "__main__":
    _self_check()
