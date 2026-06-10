"""Tests for the Foundry (Phi-4-mini-instruct) integration path.

Guarded by requires_foundry so they only execute when FOUNDRY_ENDPOINT (or
FOUNDRY_PROJECT_ENDPOINT), FOUNDRY_MODEL_DEPLOYMENT, and FOUNDRY_API_KEY are set.
All existing tests continue to run with Foundry unconfigured.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent import foundry_client

requires_foundry = pytest.mark.skipif(
    not foundry_client.is_configured(),
    reason="Foundry not configured (FOUNDRY_ENDPOINT / FOUNDRY_MODEL_DEPLOYMENT / FOUNDRY_API_KEY)",
)

# Each of these triages through the live model; deselect from the default run.
slow = pytest.mark.slow

requires_cache = pytest.mark.skipif(
    not (Path(__file__).parent.parent / "data" / "cache" / "cves.json").exists(),
    reason="data/cache/cves.json not built yet",
)

EXPOSED_SCAN = json.dumps(
    {
        "host": "10.0.0.5",
        "ports": [
            {
                "port": 80,
                "service": "Apache httpd",
                "version": "2.4.49",
                "banner": "Apache/2.4.49",
            },
            {
                "port": 21,
                "service": "vsftpd",
                "version": "2.3.4",
                "banner": "220 vsftpd 2.3.4",
            },
            {"port": 22, "service": "OpenSSH", "version": "7.4", "banner": ""},
        ],
    }
)


@slow
@requires_foundry
@requires_cache
def test_foundry_triage_returns_valid_schema():
    """Foundry triage result must pass schema validation."""
    from agent.agent import triage
    from agent.schema import to_json, validate

    result = triage(EXPOSED_SCAN)
    raw = json.loads(to_json(result))
    ok, err = validate(raw)
    assert ok, f"Schema validation failed: {err}"


@slow
@requires_foundry
@requires_cache
def test_foundry_triage_cve_41773_ranks_priority_one():
    """CVE-2021-41773 (CISA KEV, EPSS ~0.97) must be in the priority-1 finding."""
    from agent.agent import triage

    result = triage(EXPOSED_SCAN)
    top = next((f for f in result.findings if f.priority == 1), None)
    assert top is not None, "No finding has priority 1"
    kev_ids = [c.id for c in top.cves if c.kev]
    assert "CVE-2021-41773" in kev_ids, (
        f"CVE-2021-41773 (KEV) should be in priority-1 finding; got CVEs: {[c.id for c in top.cves]}"
    )


@slow
@requires_foundry
@requires_cache
def test_foundry_triage_attack_path_present():
    """Foundry response must include a non-empty attack path with a narrative."""
    from agent.agent import triage

    result = triage(EXPOSED_SCAN)
    assert result.attack_path is not None, "attack_path must be present"
    assert result.attack_path.narrative, "attack_path.narrative must be non-empty"
    assert result.attack_path.break_point, "attack_path.break_point must be non-empty"


@slow
@requires_foundry
@requires_cache
def test_foundry_no_invented_cves():
    """No CVE IDs in the Foundry triage result may be absent from the threat cache."""
    from agent.agent import triage

    cache_path = Path(__file__).parent.parent / "data" / "cache" / "cves.json"
    cache_ids = {r["id"] for r in json.loads(cache_path.read_text())}

    result = triage(EXPOSED_SCAN)
    for finding in result.findings:
        for cve in finding.cves:
            assert cve.id in cache_ids, (
                f"CVE {cve.id} in finding for port {finding.port} is not in the threat cache"
            )


@slow
@requires_foundry
@requires_cache
def test_foundry_backend_label():
    """threat_backend must indicate Foundry was used."""
    from agent.agent import triage

    result = triage(EXPOSED_SCAN)
    assert result.threat_backend.startswith("foundry"), (
        f"Expected threat_backend to start with 'foundry', got '{result.threat_backend}'"
    )


def test_parse_foundry_response_strips_think_blocks():
    """parse_foundry_response must handle <think> reasoning blocks."""
    from agent.agent import parse_foundry_response

    raw = (
        "<think>Let me reason through this carefully...</think>\n"
        '{"host": "x", "host_risk_score": 50, "summary": "ok", '
        '"findings": [{"port": 80, "service": "Apache httpd", "version": "2.4.49", '
        '"cves": [], "contextual_severity": "low", "mitre": [], "rationale": "r", '
        '"remediation": "rem", "remediation_command": "", "bind_address": "", "priority": 1}], '
        '"attack_path": null, "tool_calls": []}'
    )
    result = parse_foundry_response(raw)
    assert result is not None
    assert result["host"] == "x"
    assert result["findings"][0]["port"] == 80


def test_parse_foundry_response_handles_code_fence():
    """parse_foundry_response must extract JSON from markdown code fences."""
    from agent.agent import parse_foundry_response

    raw = (
        "Here is the result:\n"
        "```json\n"
        '{"host": "y", "host_risk_score": 30, "summary": "ok", '
        '"findings": [{"port": 22, "service": "OpenSSH", "version": "7.4", '
        '"cves": [], "contextual_severity": "low", "mitre": [], "rationale": "r", '
        '"remediation": "rem", "remediation_command": "", "bind_address": "", "priority": 1}], '
        '"attack_path": null, "tool_calls": []}\n'
        "```"
    )
    result = parse_foundry_response(raw)
    assert result is not None
    assert result["host"] == "y"


def test_parse_foundry_response_returns_none_on_garbage():
    """parse_foundry_response must return None when no JSON is present."""
    from agent.agent import parse_foundry_response

    assert parse_foundry_response("no json here at all") is None
    assert parse_foundry_response("<think>thinking...</think> still no json") is None
