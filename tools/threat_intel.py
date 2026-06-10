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

# Ordered (substring, product_key) patterns; the first hit wins, so specific
# product names come before the vendor words they contain ("struts" before
# "apache"). Bare protocol names (SSH, HTTP) get their own keys so a generic
# banner never matches a specific product's CVEs.
_PRODUCT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("struts", "apache_struts"),
    ("tomcat", "apache_tomcat"),
    ("httpd", "apache_httpd"),
    ("apache", "apache_httpd"),
    ("openssh", "openssh"),
    ("vsftpd", "vsftpd"),
    ("proftpd", "proftpd"),
    ("openssl", "openssl"),
    ("nginx", "nginx"),
    ("mysql", "mysql"),
    ("postgres", "postgresql"),
    ("mongodb", "mongodb"),
    ("redis", "redis"),
    ("elasticsearch", "elasticsearch"),
    ("samba", "smb"),
    ("smb", "smb"),
    ("rdp", "rdp"),
    ("telnet", "telnet"),
    ("vnc", "vnc"),
    ("ftp", "ftp"),
    ("ssh", "ssh"),
    ("https", "https"),
    ("http", "http"),
)


def product_key(service: str) -> str:
    """Normalize a service string to a precise product key (e.g. 'apache_httpd').

    Returns "" for unrecognized products: an unknown service must match no
    CVEs rather than fall back to fuzzy matching.
    """
    s = service.lower()
    for needle, key in _PRODUCT_PATTERNS:
        if needle in s:
            return key
    return ""


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
    """Match CVEs whose product key equals the scanned service's product key.

    Product-exact matching: "Apache httpd" never matches an "Apache Struts"
    CVE on the shared vendor word. Records without an explicit product field
    derive one from their service_tag.
    """
    svc_product = product_key(service)
    if not svc_product:
        return []
    records = _load_cache()
    matched = []
    for rec in records:
        rec_product = rec.get("product") or product_key(rec.get("service_tag", ""))
        if rec_product == svc_product:
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
