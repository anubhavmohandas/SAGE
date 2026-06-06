"""
utils/validate.py — LLM response schema validation

All JSON responses from LLMs (analyzer, patcher) pass through here before
being used by the rest of the pipeline.

Why this matters:
  - LLMs hallucinate wrong types ("vulnerable": "yes" instead of True)
  - Prompt injection via CVE descriptions could produce malicious JSON
  - Malformed responses crash the pipeline mid-run silently
  - Patcher consumes file paths from LLM output — must be clean strings

Design:
  - Reject on wrong type, not just missing key
  - Coerce only safe cases (e.g. 1/0 → bool, "0.9" → float)
  - Log exactly what failed and why
  - Always return None on failure — never let bad data through
"""

from __future__ import annotations
import re
from typing import Optional
from sage.utils.colors import cprint, log_error, log_security


# ── Analyzer response ─────────────────────────────────────────────────────────
#
# Expected schema:
# {
#   "vulnerable":      bool           (required)
#   "confidence":      float 0.0-1.0  (required)
#   "reason":          str            (required)
#   "recommendation":  str            (optional, default "")
#   "attack_vector":   str            (optional, default "")
# }

def validate_analyzer_response(raw: dict, cve_id: str) -> Optional[dict]:
    """
    Validate and normalise an analyzer LLM response dict.

    Returns a clean dict on success, None on any validation failure.
    Never raises — all errors are logged and return None.
    """
    if not isinstance(raw, dict):
        log_error("validate", f"{cve_id}: analyzer response is not a dict",
                  f"got {type(raw).__name__}")
        return None

    # Empty {} = failed/placeholder response, not a valid verdict.
    if not raw:
        log_error("validate", f"{cve_id}: analyzer response is empty ({{}})",
                  "Treating as failure, not as a verdict")
        return None

    # ── vulnerable (bool, required) ───────────────────────────────────────────
    vulnerable = raw.get("vulnerable")
    if isinstance(vulnerable, bool):
        pass  # ideal
    elif isinstance(vulnerable, int) and vulnerable in (0, 1):
        vulnerable = bool(vulnerable)  # 1/0 → True/False
    elif isinstance(vulnerable, str) and vulnerable.lower() in ("true", "false", "yes", "no"):
        vulnerable = vulnerable.lower() in ("true", "yes")
    else:
        cprint(f"[validate] {cve_id}: 'vulnerable' must be bool, got {vulnerable!r}")
        return None

    # ── confidence (float 0.0-1.0, required) ─────────────────────────────────
    confidence = raw.get("confidence")
    if isinstance(confidence, bool):
        cprint(f"[validate] {cve_id}: 'confidence' must be float, got bool")
        return None
    if isinstance(confidence, str):
        try:
            confidence = float(confidence)
        except ValueError:
            cprint(f"[validate] {cve_id}: 'confidence' not parseable as float: {confidence!r}")
            return None
    if not isinstance(confidence, (int, float)):
        cprint(f"[validate] {cve_id}: 'confidence' must be float, got {type(confidence).__name__}")
        return None
    confidence = float(confidence)
    if not (0.0 <= confidence <= 1.0):
        cprint(f"[validate] {cve_id}: 'confidence' out of range [0,1]: {confidence}")
        # Clamp rather than reject — some models return 0-100
        if 0.0 <= confidence <= 100.0:
            confidence = confidence / 100.0
        else:
            return None

    # ── reason (str, required, non-empty) ────────────────────────────────────
    reason = raw.get("reason", "")
    if not isinstance(reason, str):
        cprint(f"[validate] {cve_id}: 'reason' must be str, got {type(reason).__name__}")
        return None
    reason = reason.strip()
    if not reason:
        cprint(f"[validate] {cve_id}: 'reason' is empty")
        return None

    # ── optional string fields ────────────────────────────────────────────────
    recommendation = _safe_str(raw.get("recommendation", ""), cve_id, "recommendation")
    attack_vector  = _safe_str(raw.get("attack_vector", ""),  cve_id, "attack_vector")

    return {
        "vulnerable":     vulnerable,
        "confidence":     confidence,
        "reason":         reason,
        "recommendation": recommendation,
        "attack_vector":  attack_vector,
    }


# ── Patcher response ──────────────────────────────────────────────────────────
#
# Expected schema:
# {
#   "patched_files": [           (required, list)
#     {
#       "file":              str  (required, non-empty, no path traversal)
#       "original_function": str  (required)
#       "patched_code":      str  (required, non-empty)
#       "explanation":       str  (optional)
#     },
#     ...
#   ],
#   "summary":       str         (optional)
#   "dep_changes":   list        (optional)
# }

def validate_patcher_response(raw: dict, cve_id: str) -> Optional[dict]:
    """
    Validate and normalise a patcher LLM response dict.

    Returns a clean dict on success, None on any validation failure.
    The 'file' field in each patched_files entry is sanitised against
    path traversal — any entry that fails is dropped (not fatal).
    """
    if not isinstance(raw, dict):
        log_error("validate", f"{cve_id}: patcher response is not a dict",
                  f"got {type(raw).__name__}")
        return None

    # Empty {} means the LLM call failed or a placeholder file was saved — it is
    # NOT a valid "no patch needed" answer. Reject so the caller can tell the
    # difference between a real fix and a silent no-op.
    if not raw:
        log_error("validate", f"{cve_id}: patcher response is empty ({{}})",
                  "Treating as failure, not as 'no patch needed'")
        return None

    # ── patched_files (list, required) ───────────────────────────────────────
    patched_files_raw = raw.get("patched_files")
    if patched_files_raw is None:
        cprint(f"[validate] {cve_id}: patcher response missing 'patched_files'")
        return None
    if not isinstance(patched_files_raw, list):
        cprint(f"[validate] {cve_id}: 'patched_files' must be list, got {type(patched_files_raw).__name__}")
        return None

    clean_files = []
    for i, entry in enumerate(patched_files_raw):
        cleaned = _validate_patch_entry(entry, cve_id, i)
        if cleaned is not None:
            clean_files.append(cleaned)

    if not clean_files and patched_files_raw:
        # All entries failed validation (e.g. all were path traversal attempts)
        # Return empty list — patcher will proceed with dep-bump only, which is safe
        log_error("validate", f"{cve_id}: all patched_files entries failed validation",
                  "No code patches will apply — dep-bump will still proceed")

    # ── optional fields ───────────────────────────────────────────────────────
    summary     = _safe_str(raw.get("summary", ""),     cve_id, "summary")
    dep_changes = raw.get("dep_changes", [])
    if not isinstance(dep_changes, list):
        dep_changes = []

    return {
        "patched_files": clean_files,
        "summary":       summary,
        "dep_changes":   dep_changes,
    }


def _validate_patch_entry(entry: dict, cve_id: str, idx: int) -> Optional[dict]:
    """Validate a single entry in patched_files. Returns None to drop the entry."""
    if not isinstance(entry, dict):
        cprint(f"[validate] {cve_id}: patched_files[{idx}] is not a dict — dropped")
        return None

    # file (str, required, path-safe)
    file_rel = entry.get("file", "")
    if not isinstance(file_rel, str) or not file_rel.strip():
        cprint(f"[validate] {cve_id}: patched_files[{idx}].file missing or not str — dropped")
        return None
    file_rel = file_rel.strip()
    if _is_path_traversal(file_rel):
        log_security("validate", f"{cve_id}: path traversal attempt in LLM response — dropped",
                     f"patched_files[{idx}].file = {file_rel!r}")
        return None

    # original_function (str, required)
    original_function = entry.get("original_function", "")
    if not isinstance(original_function, str):
        cprint(f"[validate] {cve_id}: patched_files[{idx}].original_function not str — dropped")
        return None

    # patched_code (str, required, non-empty)
    patched_code = entry.get("patched_code", "")
    if not isinstance(patched_code, str) or not patched_code.strip():
        cprint(f"[validate] {cve_id}: patched_files[{idx}].patched_code empty or not str — dropped")
        return None

    # explanation (str, optional)
    explanation = _safe_str(entry.get("explanation", ""), cve_id, f"patched_files[{idx}].explanation")

    return {
        "file":              file_rel,
        "original_function": original_function.strip(),
        "patched_code":      patched_code,
        "explanation":       explanation,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_str(val, cve_id: str, field: str) -> str:
    """Coerce to str safely, return '' on failure."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val.strip()
    if isinstance(val, (int, float, bool)):
        return str(val)
    cprint(f"[validate] {cve_id}: field '{field}' unexpected type {type(val).__name__}, coercing to ''")
    return ""


def _is_path_traversal(path: str) -> bool:
    """
    Return True if the path looks like an attempt to escape the repo root.

    Catches:
      ../../etc/passwd
      /etc/passwd          (absolute path)
      ..\\Windows\\system32 (Windows-style)
      %2e%2e%2f            (URL-encoded)
    """
    # Absolute path
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        return True
    # URL decode then check
    try:
        from urllib.parse import unquote
        decoded = unquote(path)
    except Exception:
        decoded = path
    # Parent dir traversal
    normalised = decoded.replace("\\", "/")
    parts = normalised.split("/")
    if ".." in parts:
        return True
    # Null byte injection
    if "\x00" in path:
        return True
    return False
