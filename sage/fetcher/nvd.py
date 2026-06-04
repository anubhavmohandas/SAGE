"""
fetcher/nvd.py — NVD API client

Fetches CVEs from the National Vulnerability Database (NVD).
Handles rate limiting, pagination, and retries automatically.

NVD API docs: https://nvd.nist.gov/developers/vulnerabilities

Rate limits:
  Without API key: 5 requests per 30 seconds
  With API key:   50 requests per 30 seconds

Teaching note:
  NVD returns CVEs in pages of max 2000 each.
  A single day can have 500+ new CVEs.
  We always paginate — never assume one request gets everything.
"""

import time
import requests
from datetime import datetime, timedelta, timezone
from typing import Optional

from sage.config import cfg

# NVD API base URL
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limit: sleep between requests
# With key: 50 req/30s = 1 req per 0.6s → use 0.7s to be safe
# Without key: 5 req/30s = 1 req per 6s → use 6.5s to be safe
SLEEP_WITH_KEY    = 0.7
SLEEP_WITHOUT_KEY = 6.5

# Max retries on transient failures (429, 503)
MAX_RETRIES = 3
RETRY_BACKOFF = 10  # seconds to wait on rate limit hit


def _headers() -> dict:
    """
    Build request headers.
    NVD uses apiKey as a header, not a query param.
    """
    headers = {"Accept": "application/json"}
    if cfg.NVD_API_KEY:
        headers["apiKey"] = cfg.NVD_API_KEY
    return headers


def _sleep():
    """Sleep between requests to respect rate limits."""
    delay = SLEEP_WITH_KEY if cfg.NVD_API_KEY else SLEEP_WITHOUT_KEY
    time.sleep(delay)


def fetch_cves_since(days: int = 1) -> list[dict]:
    """
    Fetch all CVEs published in the last N days from NVD.

    Args:
        days: How many days back to look. Default 1 = yesterday's CVEs.

    Returns:
        List of raw CVE dicts from NVD API.

    Teaching note:
        NVD API has a hard limit of 120 days per request window.
        For anything over 120 days, we split into 100-day chunks
        and merge the results. This is transparent to the caller.
    """
    NVD_MAX_WINDOW = 100  # stay under 120-day limit with buffer

    now = datetime.now(timezone.utc)
    all_cves = []

    # Split into chunks if needed
    remaining = days
    chunk_end = now
    chunks = []

    while remaining > 0:
        chunk_days = min(remaining, NVD_MAX_WINDOW)
        chunk_start = chunk_end - timedelta(days=chunk_days)
        chunks.append((chunk_start, chunk_end))
        chunk_end = chunk_start
        remaining -= chunk_days

    # Fetch each chunk (oldest first for cleaner output)
    chunks.reverse()
    print(f"[fetcher] Fetching {days} days in {len(chunks)} chunk(s)...")

    for chunk_start, chunk_end in chunks:
        chunk_cves = _fetch_window(chunk_start, chunk_end)
        all_cves.extend(chunk_cves)
        if len(chunks) > 1:
            _sleep()

    print(f"[fetcher] Total CVEs fetched: {len(all_cves)}")
    return all_cves


def _fetch_window(start: datetime, end: datetime) -> list[dict]:
    """Fetch CVEs for a single time window (max 120 days)."""
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    pub_start = start.strftime(fmt)
    pub_end   = end.strftime(fmt)

    print(f"[fetcher] Window: {pub_start[:10]} → {pub_end[:10]}")

    all_cves = []
    start_index = 0
    results_per_page = 2000

    while True:
        params = {
            # Use lastModDate so we catch CVEs that were recently analysed,
            # not just recently published — NVD only adds CPE data after analysis.
            "lastModStartDate": pub_start,
            "lastModEndDate":   pub_end,
            "startIndex":       start_index,
            "resultsPerPage":   results_per_page,
        }

        data = _make_request(params)
        if data is None:
            print("[fetcher] Failed to fetch page — stopping.")
            break

        vulnerabilities = data.get("vulnerabilities", [])
        all_cves.extend(vulnerabilities)

        total_results  = data.get("totalResults", 0)
        fetched_so_far = start_index + len(vulnerabilities)
        print(f"[fetcher] {fetched_so_far}/{total_results} CVEs fetched")

        if fetched_so_far >= total_results:
            break

        start_index = fetched_so_far
        _sleep()

    return all_cves


def fetch_cve_by_id(cve_id: str) -> Optional[dict]:
    """
    Fetch a single CVE by its ID.

    Args:
        cve_id: e.g. "CVE-2021-44228" (Log4Shell)

    Returns:
        CVE dict or None if not found.
    """
    params = {"cveId": cve_id}
    data = _make_request(params)
    if data is None:
        return None

    vulns = data.get("vulnerabilities", [])
    return vulns[0] if vulns else None


def _make_request(params: dict, retry: int = 0) -> Optional[dict]:
    """
    Make a single request to NVD API with retry logic.

    Teaching note:
        HTTP 429 = rate limited. We wait and retry.
        HTTP 503 = NVD server overloaded. We wait and retry.
        Any other error = log and return None (don't crash the pipeline).

    Args:
        params: Query parameters for the request.
        retry:  Current retry count (used internally for recursion).

    Returns:
        Parsed JSON response dict, or None on failure.
    """
    try:
        response = requests.get(
            NVD_BASE,
            headers=_headers(),
            params=params,
            timeout=30,
        )

        # Rate limited
        if response.status_code == 429:
            if retry < MAX_RETRIES:
                wait = RETRY_BACKOFF * (retry + 1)
                print(f"[fetcher] Rate limited (429). Waiting {wait}s before retry {retry+1}/{MAX_RETRIES}...")
                time.sleep(wait)
                return _make_request(params, retry + 1)
            else:
                print("[fetcher] Rate limit retries exhausted.")
                return None

        # NVD server overloaded
        if response.status_code == 503:
            if retry < MAX_RETRIES:
                wait = RETRY_BACKOFF * (retry + 1)
                print(f"[fetcher] NVD unavailable (503). Waiting {wait}s before retry {retry+1}/{MAX_RETRIES}...")
                time.sleep(wait)
                return _make_request(params, retry + 1)
            else:
                print("[fetcher] NVD unavailable after retries.")
                return None

        response.raise_for_status()
        return response.json()

    except requests.exceptions.Timeout:
        print("[fetcher] Request timed out.")
        return None
    except requests.exceptions.ConnectionError:
        print("[fetcher] Connection error — check internet connection.")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[fetcher] HTTP error: {e}")
        return None
    except Exception as e:
        print(f"[fetcher] Unexpected error: {e}")
        return None
