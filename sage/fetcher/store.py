"""
fetcher/store.py — SQLite storage for CVEs

Tracks every CVE SAGE has seen and processed.
Ensures we never process the same CVE twice.
Tracks status through the pipeline.

Teaching note — why SQLite:
    We chose SQLite over Postgres/MySQL because:
    - Zero setup — no server, no install, just a file
    - stdlib — sqlite3 is built into Python
    - Portable — the DB is one file, easy to backup/delete
    - Sufficient — SAGE processes hundreds of CVEs/day, not millions

Teaching note — pipeline statuses:
    new       → just fetched, not yet analyzed
    analyzing → Semgrep + LLM in progress
    patched   → patch generated, tests running
    pr_raised → PR created on GitHub
    skipped   → not relevant after deeper analysis
    failed    → something went wrong, needs human review
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


# DB file location — repo-scoped at runtime via cfg.data_dir()
_LEGACY_DB_PATH = Path("data/sage.db")


def _db_path() -> Path:
    """Return the repo-scoped DB path (data/<repo_name>/sage.db)."""
    try:
        from sage.config import cfg
        return cfg.data_dir() / "sage.db"
    except Exception:
        return _LEGACY_DB_PATH


def _get_connection() -> sqlite3.Connection:
    """
    Get a database connection.
    Creates the data/<repo>/ directory and DB file if they don't exist.
    """
    p = _db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initialize the database schema.
    Safe to call multiple times — uses CREATE TABLE IF NOT EXISTS.
    Call this once at SAGE startup.
    """
    conn = _get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id          TEXT PRIMARY KEY,
            severity        TEXT,
            package         TEXT,
            installed_ver   TEXT,
            affected_range  TEXT,
            cwe             TEXT,
            status          TEXT DEFAULT 'new',
            raw_json        TEXT,
            created_at      TEXT,
            updated_at      TEXT
        )
    """)

    # Add cwe column if upgrading from older schema
    try:
        conn.execute("ALTER TABLE cves ADD COLUMN cwe TEXT")
        conn.commit()
    except Exception:
        pass  # Column already exists

    # Index for fast status lookups — we'll query "WHERE status = 'new'" often
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_status ON cves(status)
    """)

    conn.commit()
    conn.close()
    print("[store] Database initialized.")

    # One-time migration: copy CVEs from legacy data/sage.db into the scoped DB,
    # then delete the legacy file so it stops being confusing.
    scoped = _db_path()
    legacy = _LEGACY_DB_PATH
    if scoped != legacy and legacy.exists() and scoped.exists():
        try:
            scoped_conn = sqlite3.connect(str(scoped))
            count = scoped_conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
            scoped_conn.close()
            if count == 0:
                import shutil as _shutil
                _shutil.copy2(str(legacy), str(scoped))
                migrated = sqlite3.connect(str(scoped))
                n = migrated.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
                migrated.close()
                if n > 0:
                    print(f"[store] Migrated {n} CVEs from legacy data/sage.db → {scoped}")
            # Delete legacy DB once all known repo DBs are populated
            # (safe to remove — all data is in scoped DBs now)
            _maybe_delete_legacy(legacy)
        except Exception:
            pass  # Migration is best-effort — never break startup


def _maybe_delete_legacy(legacy: Path):
    """
    Delete the legacy data/sage.db once every scoped DB under data/ has been populated.
    Only deletes if all subdirectories under data/ have their own sage.db.
    """
    try:
        data_dir = legacy.parent
        scoped_dbs = list(data_dir.rglob("*/sage.db"))
        if not scoped_dbs:
            return
        # Check all scoped DBs have at least some CVEs
        all_populated = True
        for db in scoped_dbs:
            c = sqlite3.connect(str(db))
            n = c.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
            c.close()
            if n == 0:
                all_populated = False
                break
        if all_populated:
            legacy.unlink()
            print(f"[store] Legacy data/sage.db removed — all repo DBs populated")
    except Exception:
        pass


def save_cve(cve_entry: dict):
    """
    Save a CVE to the database.
    If the CVE already exists, skip it (deduplication).

    Teaching note:
        INSERT OR IGNORE means: if a CVE with this ID already exists,
        do nothing. This is our dedup mechanism.
        We never want to process the same CVE twice — it wastes
        LLM calls and might raise duplicate PRs.
    """
    cve      = cve_entry.get("cve", {})
    cve_id   = cve.get("id", "UNKNOWN")
    match    = cve_entry.get("sage_match", {})
    now      = datetime.now(timezone.utc).isoformat()
    cwe      = _extract_cwe(cve)

    conn = _get_connection()
    conn.execute("""
        INSERT OR IGNORE INTO cves
            (cve_id, severity, package, installed_ver, affected_range,
             cwe, status, raw_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'new', ?, ?, ?)
    """, (
        cve_id,
        match.get("severity", "UNKNOWN"),
        match.get("package", ""),
        match.get("installed_version", ""),
        match.get("affected_range", ""),
        cwe,
        json.dumps(cve_entry),
        now,
        now,
    ))
    conn.commit()
    conn.close()


def save_cves(cve_entries: list[dict]):
    """Batch save multiple CVEs."""
    new_count = 0
    for entry in cve_entries:
        cve_id = entry.get("cve", {}).get("id", "")
        if not is_known(cve_id):
            save_cve(entry)
            new_count += 1

    print(f"[store] Saved {new_count} new CVEs ({len(cve_entries) - new_count} already known).")


def is_known(cve_id: str) -> bool:
    """Check if we've already seen this CVE."""
    conn = _get_connection()
    row  = conn.execute(
        "SELECT cve_id FROM cves WHERE cve_id = ?", (cve_id,)
    ).fetchone()
    conn.close()
    return row is not None


def _extract_cwe(cve: dict) -> str:
    """
    Extract CWE ID from NVD CVE record.
    NVD stores CWEs in cve.weaknesses[].description[].value
    e.g. "CWE-89", "CWE-400"
    """
    try:
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-") and val != "CWE-noinfo" and val != "CWE-Other":
                    return val
    except Exception:
        pass
    return ""


def get_new_cves() -> list[dict]:
    """
    Get all CVEs with status 'new' — ready for analysis.
    Returns list of dicts with CVE metadata.
    """
    conn = _get_connection()
    rows = conn.execute(
        "SELECT * FROM cves WHERE status = 'new' ORDER BY created_at ASC"
    ).fetchall()
    conn.close()

    return [dict(row) for row in rows]


def update_status(cve_id: str, status: str):
    """
    Update the pipeline status of a CVE.

    Valid statuses: new, analyzing, patched, pr_raised, skipped, failed
    """
    now  = datetime.now(timezone.utc).isoformat()
    conn = _get_connection()
    conn.execute(
        "UPDATE cves SET status = ?, updated_at = ? WHERE cve_id = ?",
        (status, now, cve_id)
    )
    conn.commit()
    conn.close()


def get_summary() -> dict:
    """
    Return a count of CVEs by status — useful for the morning digest.

    Returns:
        {"new": 3, "patched": 1, "pr_raised": 2, "failed": 0, ...}
    """
    conn  = _get_connection()
    rows  = conn.execute(
        "SELECT status, COUNT(*) as count FROM cves GROUP BY status"
    ).fetchall()
    conn.close()

    return {row["status"]: row["count"] for row in rows}
