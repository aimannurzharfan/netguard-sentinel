"""Integration tests for the triage pipeline using cached threat data.

These tests require data/cache/cves.json to exist. Run data/fetch_cache.py first.
They are skipped automatically when the cache is absent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

CACHE = Path(__file__).parent.parent / "data" / "cache" / "cves.json"
requires_cache = pytest.mark.skipif(not CACHE.exists(), reason="data/cache/cves.json not built yet")

EXPOSED_SCAN = json.dumps({
    "host": "10.0.0.5",
    "ports": [
        {"port": 80,  "service": "Apache httpd", "version": "2.4.49", "banner": "Apache/2.4.49"},
        {"port": 21,  "service": "vsftpd",        "version": "2.3.4",  "banner": "220 vsftpd 2.3.4"},
        {"port": 22,  "service": "OpenSSH",       "version": "7.4",    "banner": ""},
    ]
})

CLEAN_SCAN = json.dumps({
    "host": "10.0.0.20",
    "ports": [
        {"port": 22,  "service": "OpenSSH", "version": "8.9",    "banner": ""},
        {"port": 443, "service": "nginx",    "version": "1.24.0", "banner": ""},
    ]
})

NOISY_SCAN = (Path(__file__).parent.parent / "samples" / "host_noisy.json").read_text()


@requires_cache
def test_exposed_host_kev_ranks_first():
    """CVE-2021-41773 (CISA KEV, EPSS ~0.97) must be priority 1 on the exposed host."""
    from agent.agent import triage
    from agent.schema import validate, to_json

    result = triage(EXPOSED_SCAN)
    raw = json.loads(to_json(result))

    ok, err = validate(raw)
    assert ok, f"Output failed schema validation: {err}"

    # Priority 1 finding must contain CVE-2021-41773
    top = next((f for f in result.findings if f.priority == 1), None)
    assert top is not None
    kev_ids = [c.id for c in top.cves if c.kev]
    assert "CVE-2021-41773" in kev_ids, (
        f"Expected CVE-2021-41773 (KEV) to be in priority-1 finding, got: {[c.id for c in top.cves]}"
    )


@requires_cache
def test_exposed_host_attack_path_present():
    """Exposed host must produce a non-empty attack path with at least one step."""
    from agent.agent import triage

    result = triage(EXPOSED_SCAN)
    assert result.attack_path is not None
    assert len(result.attack_path.steps) >= 1
    assert result.attack_path.narrative
    assert result.attack_path.break_point


@requires_cache
def test_clean_host_invents_no_cves():
    """Clean host must not invent CVE IDs absent from the cache."""
    from agent.agent import triage

    result = triage(CLEAN_SCAN)
    cache_ids = {r["id"] for r in json.loads(CACHE.read_text())}

    for finding in result.findings:
        for cve in finding.cves:
            assert cve.id in cache_ids, (
                f"CVE {cve.id} was invented -- not present in threat cache"
            )


@requires_cache
def test_host_risk_score_in_range():
    from agent.agent import triage

    for scan in (EXPOSED_SCAN, CLEAN_SCAN):
        result = triage(scan)
        assert 0 <= result.host_risk_score <= 100


def test_invalid_json_raises():
    from agent.agent import triage

    with pytest.raises(ValueError, match="not valid JSON"):
        triage("not json")


@requires_cache
def test_exposure_override_fires():
    """MySQL and Redis bound to 0.0.0.0 on an internet host must be elevated.

    host_noisy.json has exposure=internet and bind_address=0.0.0.0 on MySQL:3306
    and Redis:6379. Without CVE data those would rank last; the override must move
    them ahead of the CVE-scored services to reflect their real-world danger.
    """
    from agent.agent import triage

    result = triage(NOISY_SCAN)
    priority_by_port = {f.port: f.priority for f in result.findings}

    # Both sensitive DBs must be elevated to the top two slots.
    assert priority_by_port.get(3306, 99) <= 2, (
        f"MySQL (3306) should be priority <= 2 after elevation, got {priority_by_port.get(3306)}"
    )
    assert priority_by_port.get(6379, 99) <= 2, (
        f"Redis (6379) should be priority <= 2 after elevation, got {priority_by_port.get(6379)}"
    )

    # The rationale must say why the finding was elevated.
    mysql_f = next(f for f in result.findings if f.port == 3306)
    assert "elevated" in mysql_f.rationale

    # The remediation command must be an iptables DROP targeting port 3306.
    assert "iptables" in mysql_f.remediation_command
    assert "3306" in mysql_f.remediation_command


@requires_cache
def test_exposure_override_no_fire_without_data():
    """Override must not change priorities when exposure data is absent from the scan.

    EXPOSED_SCAN contains no 'exposure' key and no 'bind_address' fields, so the
    override must leave the composite ranking unchanged and Apache stays priority 1.
    """
    from agent.agent import triage

    result = triage(EXPOSED_SCAN)

    top = next((f for f in result.findings if f.priority == 1), None)
    assert top is not None
    assert "Apache" in top.service, (
        f"Apache should still be priority 1 without exposure data, got {top.service}"
    )

    for f in result.findings:
        assert "elevated:" not in f.rationale, (
            f"No finding should have an override rationale without exposure data, "
            f"but found: {f.rationale}"
        )


@requires_cache
def test_noisy_composite_differs_from_naive_cvss():
    """Composite priority must differ from raw-CVSS ordering on the noisy sample.

    ProFTPD 1.3.3 has the highest CVSS (10.0) but no KEV and moderate EPSS,
    so it should rank #1 in naive CVSS order but drop in composite priority.
    OpenSSL 1.0.1 (Heartbleed) has lower CVSS (7.5) but KEV + high EPSS,
    so it should rank higher by composite than by CVSS.
    """
    from agent.agent import triage

    result = triage(NOISY_SCAN)

    assert len(result.naive_cvss_order) >= 2, "naive_cvss_order must be populated"

    # Naive order: ProFTPD (CVSS 10.0) must be at the top.
    assert result.naive_cvss_order[0].port == 21, (
        f"Expected ProFTPD (port 21) first by CVSS, got port {result.naive_cvss_order[0].port}"
    )

    # Composite order: ProFTPD must NOT be priority 1 (KEV services outrank it).
    composite_ports = [f.port for f in result.findings]
    assert composite_ports[0] != 21, (
        "ProFTPD should not be composite priority 1; a KEV service must outrank it"
    )

    # OpenSSL/Heartbleed (port 443) must rank higher in composite than in naive CVSS.
    naive_ports = [e.port for e in result.naive_cvss_order]
    composite_rank_443 = next((i for i, f in enumerate(result.findings) if f.port == 443), None)
    naive_rank_443 = next((i for i, e in enumerate(naive_ports) if e == 443), None)
    assert composite_rank_443 is not None and naive_rank_443 is not None
    assert composite_rank_443 < naive_rank_443, (
        f"OpenSSL/Heartbleed (port 443) should rank higher by composite "
        f"(rank {composite_rank_443 + 1}) than by CVSS (rank {naive_rank_443 + 1})"
    )
