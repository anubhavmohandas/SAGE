"""
fetcher/npm.py — Fetch vulnerability advisories for Node.js packages

Uses the GitHub Advisory Database (GHSA) GraphQL API as primary source —
it covers npm, PyPI, Go, etc. and is free without auth.
Falls back to the npm audit bulk API for packages that GHSA misses.

Why GHSA over npm audit:
  - npm audit requires a full package-lock.json and posts to npm's servers
  - GHSA lets us query by ecosystem + package name without any package file
  - GHSA has near-100% coverage of npm CVEs (it feeds the NVD npm records)

API docs:
  https://docs.github.com/en/graphql/reference/objects#securityvulnerability
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
from sage.utils.colors import cprint


GHSA_GRAPHQL = "https://api.github.com/graphql"
NPM_AUDIT    = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"

# How many packages to batch per GHSA query (GraphQL alias trick)
GHSA_BATCH = 10


def fetch_npm_advisories(
    packages: dict[str, str],
    days: int = 1,
) -> list[dict]:
    """
    Fetch advisories for the given npm packages.

    Args:
        packages:  {name: version} from _parse_package_json()
        days:      look-back window (matches NVD fetch window)

    Returns:
        List of advisory dicts in SAGE's internal format (same shape as NVD matches):
        {
            "sage_match": {
                "cve_id":            "CVE-2024-XXXX" or "GHSA-xxxx-xxxx-xxxx",
                "package":           "express",
                "installed_version": "4.17.1",
                "affected_range":    ">=4.0.0,<4.19.2",
                "severity":          "HIGH",
                "ecosystem":         "npm",
            }
        }
    """
    if not packages:
        return []

    results: list[dict] = []
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Try GHSA first (no token needed, but rate-limited to 60/hr unauthenticated)
    github_token = os.getenv("GITHUB_TOKEN")
    advisories = _fetch_ghsa(packages, since, token=github_token)

    # If GHSA returned nothing (rate limit, no token), fall back to npm audit API
    if not advisories:
        advisories = _fetch_npm_audit(packages)

    for adv in advisories:
        pkg       = adv.get("package", "")
        installed = packages.get(pkg, "unknown")
        results.append({
            "sage_match": {
                "cve_id":            adv.get("cve_id") or adv.get("ghsa_id", "UNKNOWN"),
                "package":           pkg,
                "installed_version": installed,
                "affected_range":    adv.get("affected_range", ""),
                "severity":          adv.get("severity", "UNKNOWN"),
                "ecosystem":         "npm",
                "summary":           adv.get("summary", ""),
            }
        })

    return results


# ─── GHSA GraphQL fetcher ─────────────────────────────────────────────────────

def _fetch_ghsa(
    packages: dict[str, str],
    since: datetime,
    token: Optional[str] = None,
) -> list[dict]:
    """
    Query GitHub Advisory Database for npm packages.
    Batches packages into groups of GHSA_BATCH using GraphQL aliases.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept":       "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    results: list[dict] = []
    pkg_list = list(packages.keys())

    for i in range(0, len(pkg_list), GHSA_BATCH):
        batch = pkg_list[i : i + GHSA_BATCH]
        query = _build_ghsa_query(batch)

        try:
            resp = requests.post(
                GHSA_GRAPHQL,
                headers=headers,
                json={"query": query},
                timeout=20,
            )
            if resp.status_code == 401:
                cprint("[npm] GHSA: unauthenticated rate limit — set GITHUB_TOKEN for higher limits")
                break
            if resp.status_code != 200:
                cprint(f"[npm] GHSA error {resp.status_code}")
                break

            data = resp.json().get("data", {})
            for alias_key, vuln_data in data.items():
                if not vuln_data or not vuln_data.get("nodes"):
                    continue
                pkg_name = alias_key.replace("pkg_", "").replace("_", "-")
                # Try exact name first, then normalized
                actual_name = pkg_name
                for p in batch:
                    if p.lower().replace("-", "_") == pkg_name.replace("-", "_"):
                        actual_name = p
                        break

                for node in vuln_data["nodes"]:
                    adv = _parse_ghsa_node(node, actual_name, since)
                    if adv:
                        results.append(adv)

            time.sleep(0.2)  # be polite to GHSA

        except Exception as e:
            cprint(f"[npm] GHSA fetch error: {e}")

    return results


def _build_ghsa_query(packages: list[str]) -> str:
    """
    Build a GraphQL query that aliases one securityVulnerabilities call per package.
    Each alias is named pkg_<normalized_name>.
    """
    aliases = []
    for pkg in packages:
        # GraphQL field names can't have hyphens — normalize
        alias = "pkg_" + pkg.lower().replace("-", "_").replace(".", "_").replace("@", "").replace("/", "_")
        aliases.append(f"""
  {alias}: securityVulnerabilities(
    ecosystem: NPM
    package: "{pkg}"
    first: 20
  ) {{
    nodes {{
      advisory {{
        ghsaId
        identifiers {{ type value }}
        summary
        severity
        publishedAt
        updatedAt
      }}
      vulnerableVersionRange
      firstPatchedVersion {{ identifier }}
      package {{ name }}
    }}
  }}""")

    return "query {" + "\n".join(aliases) + "\n}"


def _parse_ghsa_node(node: dict, pkg_name: str, since: datetime) -> Optional[dict]:
    """Extract a flat advisory dict from a GHSA node."""
    adv = node.get("advisory", {})

    # Check recency — use updatedAt so we catch re-analyzed advisories
    updated_str = adv.get("updatedAt") or adv.get("publishedAt", "")
    if updated_str:
        try:
            updated = datetime.fromisoformat(updated_str.replace("Z", "+00:00"))
            if updated < since:
                return None
        except ValueError:
            pass

    # Extract CVE ID if present, else use GHSA ID
    cve_id  = None
    ghsa_id = adv.get("ghsaId", "")
    for ident in adv.get("identifiers", []):
        if ident.get("type") == "CVE":
            cve_id = ident["value"]
            break

    severity = adv.get("severity", "UNKNOWN").upper()
    # GHSA uses MODERATE not MEDIUM
    if severity == "MODERATE":
        severity = "MEDIUM"

    vuln_range    = node.get("vulnerableVersionRange", "") or ""
    first_patched = node.get("firstPatchedVersion", {})
    patched_ver   = first_patched.get("identifier", "") if first_patched else ""

    # Build affected_range in packaging specifier format
    affected_range = _ghsa_range_to_specifier(vuln_range, patched_ver)

    return {
        "package":        pkg_name,
        "cve_id":         cve_id,
        "ghsa_id":        ghsa_id,
        "severity":       severity,
        "summary":        adv.get("summary", ""),
        "affected_range": affected_range,
        "patched_ver":    patched_ver,
    }


def _ghsa_range_to_specifier(vuln_range: str, patched_ver: str) -> str:
    """
    Convert GHSA vulnerable range to packaging-compatible specifier.

    GHSA format:  ">= 4.0.0, < 4.19.2"
    Output:       ">=4.0.0,<4.19.2"

    If vuln_range is empty but patched_ver is known:
    Output:       "<patched_ver"
    """
    if vuln_range:
        # Normalize spaces around operators
        import re
        normalized = re.sub(r"\s*(>=|<=|>|<|=)\s*", r"\1", vuln_range)
        return normalized.replace(" ", "")
    if patched_ver:
        return f"<{patched_ver}"
    return ""


# ─── npm audit fallback ───────────────────────────────────────────────────────

def _fetch_npm_audit(packages: dict[str, str]) -> list[dict]:
    """
    POST to the npm audit bulk API.
    No auth required. Returns advisories for exact package versions.

    API format: POST {"<pkg>": ["<version>"]}
    """
    if not packages:
        return []

    payload = {name: [ver] for name, ver in packages.items() if ver != "any"}

    try:
        resp = requests.post(
            NPM_AUDIT,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=20,
        )
        if resp.status_code != 200:
            cprint(f"[npm] npm audit API error {resp.status_code}")
            return []

        data = resp.json()
        results: list[dict] = []

        for pkg_name, advisories in data.items():
            for adv_id, adv in advisories.items():
                sev = adv.get("severity", "unknown").upper()
                if sev == "MODERATE":
                    sev = "MEDIUM"

                # Extract CVE IDs
                cves = adv.get("cves", [])
                cve_id = cves[0] if cves else None

                # Build range from findings
                findings = adv.get("findings", [])
                ranges: list[str] = []
                for f in findings:
                    for r in f.get("paths", []):
                        pass
                vuln_versions = adv.get("vulnerable_versions", "")
                patched       = adv.get("patched_versions", "")

                results.append({
                    "package":        pkg_name,
                    "cve_id":         cve_id,
                    "ghsa_id":        adv.get("github_advisory_id", ""),
                    "severity":       sev,
                    "summary":        adv.get("title", ""),
                    "affected_range": vuln_versions,
                    "patched_ver":    patched,
                })

        return results

    except Exception as e:
        cprint(f"[npm] npm audit fetch error: {e}")
        return []
