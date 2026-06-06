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
