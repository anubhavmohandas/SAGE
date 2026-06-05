"""
utils/colors.py — Colored terminal output for SAGE

Uses rich for all output. Every module imports from here — never print() directly.
Severity colors match industry standard (red=critical, orange=high, yellow=medium, blue=low).
"""

from rich.console import Console
from rich.theme import Theme
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich import box

# Global console — single instance used everywhere
_theme = Theme({
    "critical": "bold red",
    "high":     "bold yellow",
    "medium":   "yellow",
    "low":      "bold blue",
    "info":     "dim white",
    "success":  "bold green",
    "fail":     "bold red",
    "warn":     "bold yellow",
    "header":   "bold cyan",
    "module":   "bold magenta",
    "cve":      "bold red",
    "pkg":      "bold cyan",
    "path":     "dim cyan",
    "count":    "bold white",
})

console = Console(theme=_theme)


# ─── Severity coloring ────────────────────────────────────────────────────────

SEVERITY_STYLE = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "UNKNOWN":  "info",
}

def severity_badge(sev: str) -> Text:
    style = SEVERITY_STYLE.get(sev.upper(), "info")
    return Text(f"[{sev:8s}]", style=style)


# ─── Section headers ──────────────────────────────────────────────────────────

def print_banner(title: str, subtitle: str = ""):
    console.print()
    console.rule(f"[header]  {title}  [/header]", style="cyan")
    if subtitle:
        console.print(f"  [dim]{subtitle}[/dim]")
    console.print()


def print_step(step: str, total: str, msg: str):
    console.print(f"[module]\\[SAGE][/module] Step {step}/{total} — {msg}")


# ─── Module-specific printers ─────────────────────────────────────────────────

def log(module: str, msg: str, style: str = ""):
    tag = f"[module]\\[{module}][/module]"
    if style:
        console.print(f"{tag} [{style}]{msg}[/{style}]")
    else:
        console.print(f"{tag} {msg}")


def log_success(module: str, msg: str):
    log(module, msg, "success")


def log_warn(module: str, msg: str):
    log(module, msg, "warn")


def log_fail(module: str, msg: str):
    log(module, msg, "fail")


def log_cve(module: str, cve_id: str, severity: str, msg: str):
    style = SEVERITY_STYLE.get(severity.upper(), "info")
    sev_text = Text(f"[{severity:8s}]", style=style)
    console.print(f"[module]\\[{module}][/module] ", sev_text, f" [cve]{cve_id}[/cve] — {msg}", sep="")


# ─── Summary tables ───────────────────────────────────────────────────────────

def print_cve_table(cves: list[dict]):
    """Print a colored CVE summary table."""
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("CVE ID",    style="cve",  no_wrap=True)
    table.add_column("Severity",  no_wrap=True)
    table.add_column("Package",   style="pkg")
    table.add_column("Affected",  style="dim")

    for cve in cves:
        sev   = cve.get("severity", "UNKNOWN")
        style = SEVERITY_STYLE.get(sev.upper(), "info")
        table.add_row(
            cve.get("cve_id", ""),
            Text(sev, style=style),
            cve.get("package", ""),
            cve.get("affected_range", ""),
        )
    console.print(table)


def print_blast_table(blasts: list[dict]):
    """Print blast radius summary."""
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("CVE",      style="cve",    no_wrap=True)
    table.add_column("Library",  style="pkg")
    table.add_column("Files",    justify="right")
    table.add_column("Functions",justify="right")

    for b in blasts:
        table.add_row(
            b.get("cve_id", ""),
            b.get("affected_library", ""),
            str(len(b.get("exposed_files", []))),
            str(len(b.get("exposed_functions", []))),
        )
    console.print(table)


def print_patch_table(dep_bump: dict):
    """Print dep bump summary."""
    if not dep_bump:
        return
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Package",  style="pkg")
    table.add_column("Safe Version")
    table.add_column("CVEs Fixed", justify="right")

    for pkg, ver, cves in dep_bump.get("changed", []):
        table.add_row(pkg, f">={ver}", str(len(cves)))
    console.print(table)


def print_pipeline_result(passed: bool, msg: str):
    style = "success" if passed else "fail"
    icon  = "✓" if passed else "✗"
    console.print(f"\n  [{style}]{icon} {msg}[/{style}]")


# ─── Made by Anubhav footer ──────────────────────────────────────────────────

def print_made_by():
    """
    Gradient 'Made by Anubhav' footer — shown at pipeline start/end.
    Gradient: deep purple → cyan → near-white.
    Degrades gracefully on dumb terminals (rich catches exceptions internally).
    """
    from rich.text import Text
    from rich.align import Align

    gradient = [
        (138, 43, 226),
        (99,   0, 255),
        (0,   80, 255),
        (0,  160, 240),
        (0,  210, 210),
        (100, 230, 230),
        (200, 240, 255),
    ]
    label = "  ⚡ Made by Anubhav  "
    t = Text()
    n = len(gradient)
    for i, ch in enumerate(label):
        idx = min(int(i / len(label) * n), n - 1)
        r, g, b = gradient[idx]
        t.append(ch, style=f"rgb({r},{g},{b}) bold")

    try:
        console.print()
        console.print(Align.center(t))
        console.print()
    except Exception:
        print("\n  ⚡ Made by Anubhav\n")


# ─── Smart color print — drop-in replacement for print() ─────────────────────
# Import this as `from sage.utils.colors import cprint` and use instead of print().
# Automatically applies color based on message content — no code changes needed.

import re as _re

_ERROR_PAT   = _re.compile(r'error|failed|fail\b|✗|traceback|exception|invalid|not found|cannot|rejected', _re.I)
_SUCCESS_PAT = _re.compile(r'✓|success|passed|created|written|saved|migrated|complete|ok\b|done\b|loaded|applied|bumping|generated', _re.I)
_WARN_PAT    = _re.compile(r'warning|warn\b|skipping|quota|429|fallback|clamped|deprecated|pre-existing', _re.I)
_INFO_PAT    = _re.compile(r'^\[(?:store|fetcher|filter|mapper|synapse|scanner|analyzer|patcher|tests|verifier|github|reach|export|sage)\]', _re.I)
_CVE_PAT     = _re.compile(r'CVE-\d{4}-\d+')
_CRITICAL_PAT = _re.compile(r'CRITICAL|critical')
_HIGH_PAT    = _re.compile(r'\bHIGH\b')
_MEDIUM_PAT  = _re.compile(r'\bMEDIUM\b')

def cprint(*args, **kwargs):
    """
    Drop-in replacement for print() that auto-colors output based on content.
    Severity keywords, errors, successes — all get appropriate colors.
    Falls back to plain print if rich is unavailable.
    """
    msg = " ".join(str(a) for a in args)

    try:
        # Pick style based on content
        if _ERROR_PAT.search(msg):
            style = "bold red"
        elif _SUCCESS_PAT.search(msg):
            style = "bold green"
        elif _WARN_PAT.search(msg):
            style = "yellow"
        elif _CRITICAL_PAT.search(msg):
            style = "bold red"
        elif _HIGH_PAT.search(msg):
            style = "bold yellow"
        elif _MEDIUM_PAT.search(msg):
            style = "yellow"
        elif _INFO_PAT.match(msg):
            style = "dim white"
        else:
            style = ""

        # Escape rich markup chars in the message
        safe = msg.replace("[", "\\[")

        if style:
            console.print(f"[{style}]{safe}[/{style}]", **{k:v for k,v in kwargs.items() if k in ('end','sep')})
        else:
            console.print(safe, **{k:v for k,v in kwargs.items() if k in ('end','sep')})
    except Exception:
        print(*args, **kwargs)
