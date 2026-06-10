"""Pull CVE threat data from NVD, FIRST EPSS, and CISA KEV and write a local cache.

Run directly to build data/cache/ before running load_oracle.py:
    python -m data.fetch_cache

The cache is gitignored and consumed by tools/threat_intel.py (Layer 1)
and data/load_oracle.py (Layer 2).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

CACHE_DIR = Path(__file__).parent / "cache"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# CVEs to cache for the demo, keyed by service tag. Each entry carries the
# precise product key the lookup matches on (tools/threat_intel.product_key);
# matching is product-exact, never token overlap.
DEMO_TARGETS: dict[str, tuple[str, list[str]]] = {
    "Apache httpd 2.4.49": ("apache_httpd", ["CVE-2021-41773", "CVE-2021-42013"]),
    "vsftpd 2.3.4": ("vsftpd", ["CVE-2011-2523"]),
    "OpenSSH 7.4": ("openssh", ["CVE-2023-38408", "CVE-2016-0777"]),
    "OpenSSL 1.0.1": ("openssl", ["CVE-2014-0160"]),
    "Apache Struts 2.3.5": ("apache_struts", ["CVE-2017-5638"]),
    "ProFTPD 1.3.3": ("proftpd", ["CVE-2010-4221"]),
    "nginx 1.18.0": ("nginx", ["CVE-2021-23017"]),
    "OpenSSH 8.9": ("openssh", []),
    "nginx 1.24.0": ("nginx", []),
    "Apache httpd 2.4.54": ("apache_httpd", []),
}


def _nvd_headers() -> dict[str, str]:
    key = os.getenv("NVD_API_KEY", "")
    return {"apiKey": key} if key else {}


def fetch_nvd(cve_id: str) -> dict | None:
    """Fetch one CVE from NVD and return {id, cvss, description}."""
    try:
        r = requests.get(
            NVD_API,
            params={"cveId": cve_id},
            headers=_nvd_headers(),
            timeout=15,
        )
        r.raise_for_status()
        items = r.json().get("vulnerabilities", [])
        if not items:
            return None
        cve = items[0]["cve"]
        metrics = cve.get("metrics", {})
        cvss = 0.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0]["cvssData"]["baseScore"]
                break
        descs = cve.get("descriptions", [])
        description = next((d["value"] for d in descs if d["lang"] == "en"), "")
        return {"id": cve_id, "cvss": cvss, "description": description}
    except Exception as exc:
        print(f"  NVD error for {cve_id}: {exc}")
        return None


def fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for a list of CVE IDs. Returns {cve_id: epss_score}."""
    if not cve_ids:
        return {}
    try:
        r = requests.get(
            EPSS_API,
            params={"cve": ",".join(cve_ids)},
            timeout=15,
        )
        r.raise_for_status()
        return {d["cve"]: float(d["epss"]) for d in r.json().get("data", [])}
    except Exception as exc:
        print(f"  EPSS error: {exc}")
        return {}


def fetch_kev() -> set[str]:
    """Return the set of CVE IDs on the CISA Known Exploited Vulnerabilities list."""
    try:
        r = requests.get(KEV_URL, timeout=20)
        r.raise_for_status()
        return {v["cveID"] for v in r.json().get("vulnerabilities", [])}
    except Exception as exc:
        print(f"  KEV error: {exc}")
        return set()


def build_cache() -> None:
    """Fetch all demo targets and write data/cache/cves.json."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    print("Fetching CISA KEV catalog...")
    kev = fetch_kev()
    print(f"  {len(kev)} known-exploited CVEs")

    all_cve_ids: list[str] = []
    for _product, ids in DEMO_TARGETS.values():
        all_cve_ids.extend(ids)
    all_cve_ids = list(dict.fromkeys(all_cve_ids))

    print(f"Fetching EPSS for {len(all_cve_ids)} CVEs...")
    epss_scores = fetch_epss(all_cve_ids)

    records: list[dict] = []
    for service_tag, (product, cve_ids) in DEMO_TARGETS.items():
        for cve_id in cve_ids:
            print(f"  NVD: {cve_id}")
            nvd = fetch_nvd(cve_id)
            if nvd is None:
                continue
            records.append(
                {
                    "id": cve_id,
                    "service_tag": service_tag,
                    "product": product,
                    "cvss": nvd["cvss"],
                    "epss": epss_scores.get(cve_id, 0.0),
                    "kev": cve_id in kev,
                    "description": nvd["description"],
                }
            )
            time.sleep(0.6)  # NVD rate limit: ~5 req/s without key, 50/s with key

    out = CACHE_DIR / "cves.json"
    out.write_text(json.dumps(records, indent=2))
    print(f"\nCached {len(records)} CVE records -> {out}")


if __name__ == "__main__":
    build_cache()
