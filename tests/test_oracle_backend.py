"""Oracle Layer 2 backend tests: product-keyed AI Vector Search retrieval.

These run only when the Oracle 23ai container is reachable and cve_knowledge
is populated (data/load_oracle.py); otherwise every test is skipped so the
suite stays green on machines running only the cache backend.

The retrieval contract under test mirrors the cache backend's guarantees:
exact product-key candidate filtering (no cross-product false positives)
with cosine VECTOR_DISTANCE supplying the ranking.
"""

from __future__ import annotations

import pytest


def _oracle_available() -> bool:
    try:
        from tools.oracle_backend import _connect

        con = _connect()
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM cve_knowledge")
        row = cur.fetchone()
        cur.close()
        con.close()
        return bool(row and row[0])
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _oracle_available(),
    reason="Oracle 23ai not reachable or cve_knowledge not loaded",
)


def _lookup(service: str) -> list[dict]:
    from tools.oracle_backend import lookup

    return lookup(service)


def test_apache_httpd_returns_exactly_its_kev_cves():
    records = _lookup("Apache httpd 2.4.49")
    ids = {r["id"] for r in records}
    assert ids == {"CVE-2021-41773", "CVE-2021-42013"}, ids
    assert all(r["kev"] for r in records)


def test_apache_httpd_never_returns_struts_cve():
    """Vector similarity must not leak Apache Struts CVEs on the word 'apache'."""
    ids = {r["id"] for r in _lookup("Apache httpd 2.4.49")}
    assert "CVE-2017-5638" not in ids


def test_openssh_returns_exactly_its_cves():
    ids = {r["id"] for r in _lookup("OpenSSH 6.6")}
    assert ids == {"CVE-2023-38408", "CVE-2016-0777"}, ids


def test_nginx_returns_exactly_its_cve():
    ids = {r["id"] for r in _lookup("nginx 1.18.0")}
    assert ids == {"CVE-2021-23017"}, ids


def test_unknown_service_returns_nothing():
    assert _lookup("WeirdCustomDaemon 0.1") == []


def test_generic_protocol_banner_returns_nothing():
    """A bare 'SSH' banner must not inherit OpenSSH CVEs."""
    assert _lookup("SSH") == []


def test_results_ranked_by_vector_similarity():
    records = _lookup("Apache httpd 2.4.49")
    sims = [r["similarity"] for r in records]
    assert sims == sorted(sims, reverse=True)


def test_oracle_agrees_with_cache_backend():
    """Both backends must return the same CVE sets for the demo services."""
    from tools.threat_intel import _cache_lookup

    for service in ("Apache httpd 2.4.49", "OpenSSH 6.6", "nginx 1.18.0"):
        oracle_ids = {r["id"] for r in _lookup(service)}
        cache_ids = {r["id"] for r in _cache_lookup(service)}
        assert oracle_ids == cache_ids, f"{service}: {oracle_ids} != {cache_ids}"
