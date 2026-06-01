"""
fetcher/filter.py — Stack detection and CVE filtering

Two jobs:
  1. Detect what libraries a repo uses and at what versions
  2. Filter the raw CVE list down to only CVEs that affect this repo's stack

Teaching note — why this matters:
  NVD returns ~500 CVEs per day across ALL software.
  A typical Python repo uses maybe 20-30 libraries.
  Without filtering, we'd send 500 CVEs to the LLM.
  With filtering, we send maybe 2-5. That's the 60-70% cost saving.

Teaching note — the version matching problem:
  WRONG:  "2.9.0" > "2.10.0"  → True (string comparison, WRONG)
  RIGHT:  Version("2.9.0") < Version("2.10.0")  → True (packaging library)
  Always use the `packaging` library for version comparisons.

Teaching note — CPE vs PyPI naming:
  NVD uses CPE names like "python-requests" or "requests_library"
  PyPI uses "requests"
  We do fuzzy matching — normalize both sides to lowercase, strip hyphens/underscores.
"""

import os
import json
import re
from pathlib import Path
from typing import Optional
from packaging.version import Version
from packaging.specifiers import SpecifierSet


# ─── Stack Detection ──────────────────────────────────────────────────────────

def detect_stack(repo_path: str) -> dict[str, str]:
    """
    Scan a repo and return all detected packages with their versions.

    Checks (in order):
      - requirements.txt (Python)
      - requirements-dev.txt, requirements-prod.txt (Python variants)
      - pyproject.toml (Python modern)
      - setup.py (Python legacy)
      - package.json (Node/JS)
      - Pipfile (Python Pipenv)

    Returns:
        Dict of {package_name: version_string}
        e.g. {"requests": "2.28.0", "flask": "2.3.2"}

    Teaching note:
        Some repos have no dependency files at all (like GHOST — pure vanilla JS).
        We return an empty dict in that case, not an error.
        The pipeline continues — we just report "no dependencies found".
    """
    path = Path(repo_path)
    packages = {}

    # Python — requirements.txt variants
    for req_file in ["requirements.txt", "requirements-dev.txt",
                     "requirements-prod.txt", "requirements-test.txt"]:
        req_path = path / req_file
        if req_path.exists():
            found = _parse_requirements_txt(req_path)
            packages.update(found)
            print(f"[filter] Found {len(found)} packages in {req_file}")

    # Python — pyproject.toml
    pyproject = path / "pyproject.toml"
    if pyproject.exists():
        found = _parse_pyproject_toml(pyproject)
        packages.update(found)
        print(f"[filter] Found {len(found)} packages in pyproject.toml")

    # Python — Pipfile
    pipfile = path / "Pipfile"
    if pipfile.exists():
        found = _parse_pipfile(pipfile)
        packages.update(found)
        print(f"[filter] Found {len(found)} packages in Pipfile")

    # Node/JS — package.json
    package_json = path / "package.json"
    if package_json.exists():
        found = _parse_package_json(package_json)
        packages.update(found)
        print(f"[filter] Found {len(found)} packages in package.json")

    # Browser extension — manifest.json (no deps, but detect the ecosystem)
    manifest = path / "manifest.json"
    if manifest.exists() and not packages:
        print("[filter] Detected browser extension (manifest.json). No package dependencies.")

    if not packages:
        print("[filter] No dependency files found in repo.")

    return packages


def _parse_requirements_txt(path: Path) -> dict[str, str]:
    """
    Parse requirements.txt format.

    Handles:
      requests==2.28.0          → {"requests": "2.28.0"}
      flask>=2.0,<3.0           → {"flask": ">=2.0,<3.0"}
      numpy                     → {"numpy": "any"}
      # comments and blank lines → ignored
      -r other-requirements.txt → ignored (don't recurse for now)

    Teaching note:
        Exact pins (==) are ideal — we know exactly what version.
        Range specs (>=, <) mean "somewhere in this range" — we store the full spec.
        No version at all means "latest at install time" — stored as "any".
    """
    packages = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            # Skip comments, blank lines, flags
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Strip inline comments
            line = line.split("#")[0].strip()
            if not line:
                continue

            # Parse package name and version spec
            # Splits on ==, >=, <=, !=, ~=, >
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([=><!~].+)?$", line)
            if match:
                name    = match.group(1).lower().replace("-", "_")
                version = match.group(2).strip() if match.group(2) else "any"
                # Extract exact version from == pin
                if version.startswith("=="):
                    version = version[2:].strip()
                packages[name] = version

    return packages


def _parse_package_json(path: Path) -> dict[str, str]:
    """
    Parse Node.js package.json.
    Reads both 'dependencies' and 'devDependencies'.

    Teaching note:
        Node versions use ^ and ~ prefixes:
        ^1.2.3 = compatible with 1.x.x (same major)
        ~1.2.3 = compatible with 1.2.x (same minor)
        We strip these and store the base version for matching.
    """
    packages = {}
    try:
        with open(path) as f:
            data = json.load(f)

        for section in ["dependencies", "devDependencies", "peerDependencies"]:
            for name, version in data.get(section, {}).items():
                # Normalize: strip ^, ~, >, = prefixes
                clean_version = re.sub(r"^[\^~>=<]", "", version).strip()
                packages[name.lower()] = clean_version

    except (json.JSONDecodeError, KeyError) as e:
        print(f"[filter] Warning: Could not parse package.json: {e}")

    return packages


def _parse_pyproject_toml(path: Path) -> dict[str, str]:
    """
    Parse pyproject.toml (PEP 517/518).
    Looks for [project] dependencies section.

    Teaching note:
        pyproject.toml is the modern Python standard.
        It's replacing setup.py and requirements.txt.
        Many new projects use it exclusively.
    """
    packages = {}
    try:
        # Use basic line parsing — avoid adding toml dep for simple cases
        # Python 3.11+ has tomllib in stdlib
        try:
            import tomllib
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except ImportError:
            try:
                import tomli as tomllib
                with open(path, "rb") as f:
                    data = tomllib.load(f)
            except ImportError:
                print("[filter] Warning: tomllib not available, skipping pyproject.toml")
                return packages

        deps = data.get("project", {}).get("dependencies", [])
        for dep in deps:
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([=><!~].+)?$", dep.strip())
            if match:
                name    = match.group(1).lower().replace("-", "_")
                version = match.group(2).strip() if match.group(2) else "any"
                if version.startswith("=="):
                    version = version[2:].strip()
                packages[name] = version

    except Exception as e:
        print(f"[filter] Warning: Could not parse pyproject.toml: {e}")

    return packages


def _parse_pipfile(path: Path) -> dict[str, str]:
    """
    Parse Pipenv Pipfile.
    Basic parsing — reads [packages] and [dev-packages] sections.
    """
    packages = {}
    current_section = None

    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("[packages]"):
                    current_section = "packages"
                elif line.startswith("[dev-packages]"):
                    current_section = "dev-packages"
                elif line.startswith("["):
                    current_section = None
                elif current_section and "=" in line:
                    parts = line.split("=", 1)
                    name    = parts[0].strip().lower().replace("-", "_")
                    version = parts[1].strip().strip('"').strip("'")
                    if version == "*":
                        version = "any"
                    packages[name] = version
    except Exception as e:
        print(f"[filter] Warning: Could not parse Pipfile: {e}")

    return packages


# ─── CVE Filtering ────────────────────────────────────────────────────────────

def filter_relevant_cves(raw_cves: list[dict], stack: dict[str, str]) -> list[dict]:
    """
    Filter raw NVD CVE list to only CVEs that affect packages in this repo's stack.

    Args:
        raw_cves: Raw CVE dicts from nvd.py
        stack:    Package dict from detect_stack()

    Returns:
        Filtered list of CVE dicts with added 'sage_match' metadata

    Teaching note:
        NVD CVE records have a 'configurations' field with CPE (Common Platform
        Enumeration) strings. These look like:
          cpe:2.3:a:python-requests:requests:2.28.0:*:*:*:*:*:*:*
        We extract the package name and version range from these and match
        against the repo's stack.

        CPE package names don't always match PyPI names exactly.
        We normalize both sides: lowercase, replace hyphens/underscores.
    """
    if not stack:
        print("[filter] Empty stack — no CVEs can match. Returning 0 results.")
        return []

    relevant = []
    for cve_entry in raw_cves:
        match = _matches_stack(cve_entry, stack)
        if match:
            # Attach our match metadata to the CVE for downstream use
            cve_entry["sage_match"] = match
            relevant.append(cve_entry)

    print(f"[filter] {len(relevant)}/{len(raw_cves)} CVEs matched your stack")

    # Debug: show what package names NVD actually uses
    # so we can tune our matching if 0 results come back
    if len(relevant) == 0 and raw_cves:
        print("[filter] Debug — sampling CPE names from first 50 CVEs:")
        seen = set()
        for entry in raw_cves[:50]:
            cve = entry.get("cve", {})
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe in node.get("cpeMatch", []):
                        parts = cpe.get("criteria", "").split(":")
                        if len(parts) >= 5:
                            vendor  = parts[3]
                            product = parts[4]
                            key = f"{vendor}:{product}"
                            if key not in seen:
                                seen.add(key)
        # Check if any of our packages appear in the CPE names
        stack_names = list(raw_cves[0].keys()) if raw_cves else []
        for pkg in stack.keys():
            matches = [k for k in seen if pkg.replace("_","-") in k or pkg in k]
            if matches:
                print(f"[filter]   '{pkg}' found in CPEs: {matches[:3]}")

    return relevant


def _matches_stack(cve_entry: dict, stack: dict[str, str]) -> Optional[dict]:
    """
    Check if a single CVE affects any package in the stack.

    Returns a match dict if relevant, None if not.

    Match dict format:
    {
        "package":          "requests",
        "installed_version": "2.28.0",
        "affected_range":   ">=2.0.0,<2.29.0",
        "cve_id":           "CVE-2023-XXXXX",
        "severity":         "HIGH"
    }
    """
    cve = cve_entry.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    # Get severity
    severity = _extract_severity(cve)

    # Get affected packages from CVE configurations
    affected_packages = _extract_affected_packages(cve)

    for affected in affected_packages:
        pkg_name     = affected.get("name", "").lower().replace("-", "_")
        version_spec = affected.get("version_spec", "")

        # Check against every package in our stack
        for our_pkg, our_version in stack.items():
            our_pkg_norm = our_pkg.lower().replace("-", "_")

            # Fuzzy name match — CPE names vary
            if not _names_match(pkg_name, our_pkg_norm):
                continue

            # Name matched — now check version
            if our_version == "any":
                # We don't know exact version — flag as potential match
                return {
                    "package":           our_pkg,
                    "installed_version": "unknown",
                    "affected_range":    version_spec,
                    "cve_id":            cve_id,
                    "severity":          severity,
                    "confidence":        "low",  # version unknown
                }

            # Version known — check if it falls in affected range
            if _version_affected(our_version, version_spec):
                return {
                    "package":           our_pkg,
                    "installed_version": our_version,
                    "affected_range":    version_spec,
                    "cve_id":            cve_id,
                    "severity":          severity,
                    "confidence":        "high",
                }

    return None


def _names_match(cpe_name: str, pkg_name: str) -> bool:
    """
    Fuzzy match between CPE package name and repo package name.

    Examples that should match:
      "python_requests" == "requests"   → True
      "requests"        == "requests"   → True
      "django"          == "django"     → True
      "django"          == "flask"      → False

    Teaching note:
        CPE names often have ecosystem prefixes like "python_" or "nodejs_".
        We strip those and compare the base name.
    """
    # Normalize
    cpe  = re.sub(r"^(python_|nodejs_|node_|ruby_|php_)", "", cpe_name)
    pkg  = re.sub(r"^(python_|nodejs_|node_|ruby_|php_)", "", pkg_name)

    return cpe == pkg or cpe in pkg or pkg in cpe


def _version_affected(installed: str, spec: str) -> bool:
    """
    Check if the installed version falls within the CVE's affected range.

    Uses the `packaging` library — PEP 440 compliant.
    NEVER use string comparison for versions.

    Examples:
        _version_affected("2.28.0", ">=2.0.0,<2.29.0") → True
        _version_affected("2.29.0", ">=2.0.0,<2.29.0") → False
        _version_affected("2.28.0", "")                  → True (assume affected if no spec)
    """
    if not spec or not installed:
        return True  # No spec = assume affected (conservative)

    try:
        # Clean up the installed version string
        installed_clean = re.sub(r"[^0-9.]", "", installed)
        if not installed_clean:
            return True  # Can't parse — assume affected

        v = Version(installed_clean)
        s = SpecifierSet(spec)
        return v in s

    except Exception:
        # If we can't parse versions, assume affected (conservative)
        return True


def _extract_severity(cve: dict) -> str:
    """Extract CVSS severity from CVE record."""
    try:
        metrics = cve.get("metrics", {})
        # Try CVSS v3.1 first, then v3.0, then v2.0
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                return metrics[key][0]["cvssData"].get("baseSeverity", "UNKNOWN")
    except (KeyError, IndexError):
        pass
    return "UNKNOWN"


def _extract_affected_packages(cve: dict) -> list[dict]:
    """
    Extract affected package names and version ranges from CVE configurations.

    NVD CVE structure is deeply nested. This navigates it and returns
    a flat list of {name, version_spec} dicts.

    Teaching note:
        NVD CVE records have a 'configurations' array.
        Each configuration has 'nodes'.
        Each node has 'cpeMatch' entries.
        Each cpeMatch has a CPE string and version range fields.

        CPE string format: cpe:2.3:a:vendor:product:version:...
        We extract 'product' as the package name.
    """
    packages = []
    configurations = cve.get("configurations", [])

    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue

                cpe_str = cpe_match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = cpe_str.split(":")
                if len(parts) >= 5:
                    product = parts[4].lower()
                else:
                    continue

                # Build version specifier from NVD range fields
                version_spec = _build_version_spec(cpe_match)

                packages.append({
                    "name":         product,
                    "version_spec": version_spec,
                })

    return packages


def _build_version_spec(cpe_match: dict) -> str:
    """
    Build a packaging-compatible version specifier from NVD CPE match fields.

    NVD provides:
      versionStartIncluding: "2.0.0"   → >=2.0.0
      versionStartExcluding: "2.0.0"   → >2.0.0
      versionEndIncluding:   "2.28.0"  → <=2.28.0
      versionEndExcluding:   "2.29.0"  → <2.29.0
    """
    parts = []

    if v := cpe_match.get("versionStartIncluding"):
        parts.append(f">={v}")
    elif v := cpe_match.get("versionStartExcluding"):
        parts.append(f">{v}")

    if v := cpe_match.get("versionEndIncluding"):
        parts.append(f"<={v}")
    elif v := cpe_match.get("versionEndExcluding"):
        parts.append(f"<{v}")

    return ",".join(parts)
