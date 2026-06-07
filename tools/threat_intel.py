"""threat_intel_lookup: the agent's single vulnerability-enrichment interface.

Two interchangeable backends behind one function signature:
  - "cache"  (default): reads data/cache/cves.json, matches by service tag.
  - "oracle": queries the local Oracle 23ai instance via AI Vector Search.

Switch with the THREAT_BACKEND environment variable. The agent calls this
function and never touches the backend directly, so the backend can be swapped
without modifying agent code.

Hard rule: this function only returns CVEs present in the source data.
It never invents CVE IDs.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_CACHE_FILE = Path(__file__).parent.parent / "data" / "cache" / "cves.json"
_cache: list[dict] | None = None


def _load_cache() -> list[dict]:
    global _cache
    if _cache is None:
        if not _CACHE_FILE.exists():
            raise FileNotFoundError(
                f"Threat cache not found: {_CACHE_FILE}. "
                "Run 'python -m data.fetch_cache' to build it."
            )
        _cache = json.loads(_CACHE_FILE.read_text())
    return _cache


def _cache_lookup(service: str) -> list[dict]:
    """Match CVEs by service tag prefix (case-insensitive)."""
    service_lower = service.lower()
    records = _load_cache()
    matched = []
    for rec in records:
        tag = rec.get("service_tag", "").lower()
        # Match if the service string contains any word from the tag or vice versa
        tag_words = set(tag.split())
        svc_words = set(service_lower.split())
        if tag_words & svc_words:
            matched.append(
                {
                    "id": rec["id"],
                    "cvss": float(rec.get("cvss", 0)),
                    "epss": float(rec.get("epss", 0)),
                    "kev": bool(rec.get("kev", False)),
                    "description": rec.get("description", ""),
                }
            )
    return matched


def _oracle_lookup(service: str) -> list[dict]:
    from tools.oracle_backend import lookup

    return lookup(service)


def threat_intel_lookup(service: str) -> list[dict]:
    """Return known CVEs for a service string.

    Each record has: id, cvss, epss, kev, description.
    Returns an empty list when no matching CVEs are found.
    """
    backend = os.getenv("THREAT_BACKEND", "cache").lower()
    if backend == "oracle":
        try:
            return _oracle_lookup(service)
        except Exception as exc:
            print(
                f"[netguard] Oracle lookup failed, falling back to cache: {exc}",
                file=sys.stderr,
            )
            return _cache_lookup(service)
    return _cache_lookup(service)
