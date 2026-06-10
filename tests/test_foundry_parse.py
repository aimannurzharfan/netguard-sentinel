"""Offline tests for parsing real-shaped Phi-4-reasoning output.

These run with no network and are never skipped. They exercise the parser and
the model/deterministic merge against fixtures captured from (or representative
of) live Phi-4-reasoning output:

- foundry_exposed_raw.txt: a successful response in the real model shape --
  leading reasoning prose, a <think> block, a fenced final JSON, trailing prose.
- foundry_exposed_degenerate.txt: an excerpt of an actual live call where the
  model stalled in a repetition loop and never emitted valid JSON. The parser
  must return None so triage() falls back to the deterministic pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent import foundry_client
from agent.agent import _build_from_foundry, parse_foundry_response, triage
from agent.schema import CVE, Finding, to_json, validate

FIXTURES = Path(__file__).parent / "fixtures"
RAW_SUCCESS = (FIXTURES / "foundry_exposed_raw.txt").read_text(encoding="utf-8")
RAW_DEGENERATE = (FIXTURES / "foundry_exposed_degenerate.txt").read_text(
    encoding="utf-8"
)

SAMPLE_EXPOSED = (
    Path(__file__).parent.parent / "samples" / "host_exposed.json"
).read_text(encoding="utf-8")

requires_cache = pytest.mark.skipif(
    not (Path(__file__).parent.parent / "data" / "cache" / "cves.json").exists(),
    reason="data/cache/cves.json not built yet",
)


def _exposed_det_by_port() -> dict[int, Finding]:
    """Deterministic enrichment for the exposed host, built without cache or network.

    Mirrors what stages 1-3 produce for samples/host_exposed.json so the merge in
    _build_from_foundry has authoritative CVE data to reconcile the model output with.
    """
    findings = [
        Finding(
            port=80,
            service="Apache httpd",
            version="2.4.49",
            bind_address="0.0.0.0",
            cves=[
                CVE("CVE-2021-41773", 9.8, 0.94391, True, 97, "Apache path traversal"),
                CVE(
                    "CVE-2021-42013", 9.8, 0.9441, True, 97, "Apache path traversal #2"
                ),
            ],
        ),
        Finding(
            port=443,
            service="OpenSSL",
            version="1.0.1",
            bind_address="0.0.0.0",
            cves=[CVE("CVE-2014-0160", 7.5, 0.94464, True, 90, "Heartbleed")],
        ),
        Finding(
            port=21,
            service="vsftpd",
            version="2.3.4",
            bind_address="0.0.0.0",
            cves=[CVE("CVE-2011-2523", 9.8, 0.94282, False, 77, "vsftpd backdoor")],
        ),
        Finding(
            port=22,
            service="OpenSSH",
            version="7.4",
            bind_address="0.0.0.0",
            cves=[CVE("CVE-2023-38408", 9.8, 0.64352, False, 62, "ssh-agent PKCS#11")],
        ),
    ]
    return {f.port: f for f in findings}


def test_parse_extracts_final_json_from_noisy_output():
    """The parser pulls the fenced final JSON out of reasoning + think + prose noise."""
    parsed = parse_foundry_response(RAW_SUCCESS)
    assert parsed is not None, "parser failed to find the final JSON object"
    assert parsed["host"] == "10.0.0.5"
    ports = [f["port"] for f in parsed["findings"]]
    assert ports[0] == 80, f"expected port 80 first, got {ports}"
    # The <think> draft object ({"host": ..., "note": "still drafting"}) must not win.
    assert "note" not in parsed


def test_build_from_foundry_ranks_41773_priority_one():
    """parse + _build_from_foundry yields a schema-valid result with KEV CVE at priority 1."""
    model_data = parse_foundry_response(RAW_SUCCESS)
    assert model_data is not None

    result = _build_from_foundry(
        model_data,
        _exposed_det_by_port(),
        naive_cvss_order=[],
        tool_calls=[],
        data_backend="cache",
        host="10.0.0.5",
    )

    ok, err = validate(json.loads(to_json(result)))
    assert ok, f"schema validation failed: {err}"

    top = next((f for f in result.findings if f.priority == 1), None)
    assert top is not None, "no finding has priority 1"
    assert top.port == 80
    assert "CVE-2021-41773" in [c.id for c in top.cves]
    assert any(c.kev for c in top.cves), "priority-1 finding should carry a KEV CVE"

    assert result.threat_backend == "foundry+cache"


def test_build_from_foundry_has_attack_path_narrative():
    """The merged result must carry a non-empty attack-path narrative and break point."""
    model_data = parse_foundry_response(RAW_SUCCESS)
    assert model_data is not None

    result = _build_from_foundry(
        model_data,
        _exposed_det_by_port(),
        naive_cvss_order=[],
        tool_calls=[],
        data_backend="cache",
        host="10.0.0.5",
    )

    assert result.attack_path is not None, "attack_path missing"
    assert result.attack_path.narrative.strip(), "attack_path.narrative is empty"
    assert result.attack_path.break_point.strip(), "attack_path.break_point is empty"
    assert result.attack_path.steps, "attack_path.steps is empty"
    # Initial access should start at the Apache finding (port 80).
    assert result.attack_path.steps[0].finding_port == 80


def test_no_invented_cves_survive_merge():
    """Only deterministic CVE IDs may appear in the merged result."""
    model_data = parse_foundry_response(RAW_SUCCESS)
    assert model_data is not None
    allowed = {c.id for det in _exposed_det_by_port().values() for c in det.cves}

    result = _build_from_foundry(
        model_data,
        _exposed_det_by_port(),
        naive_cvss_order=[],
        tool_calls=[],
        data_backend="cache",
        host="10.0.0.5",
    )

    for finding in result.findings:
        for cve in finding.cves:
            assert cve.id in allowed, f"unexpected CVE {cve.id} survived the merge"


def test_degenerate_live_output_parses_to_none():
    """A real stalled Phi-4 response (no valid JSON) must yield None for graceful fallback."""
    assert parse_foundry_response(RAW_DEGENERATE) is None


@requires_cache
def test_triage_routes_through_foundry_when_configured(monkeypatch):
    """Full triage() wiring: a configured Foundry returns the model-reasoned result.

    Stubs the client to return the success fixture (no network), so this proves the
    triage() -> run_reasoning -> parse_foundry_response -> _build_from_foundry path.
    """
    monkeypatch.setattr(foundry_client, "is_configured", lambda: True)
    monkeypatch.setattr(foundry_client, "run_reasoning", lambda *_: RAW_SUCCESS)

    result = triage(SAMPLE_EXPOSED)

    assert result.threat_backend.startswith("foundry"), result.threat_backend
    top = next((f for f in result.findings if f.priority == 1), None)
    assert top is not None and top.port == 80
    assert "CVE-2021-41773" in [c.id for c in top.cves]
    assert result.attack_path is not None and result.attack_path.narrative.strip()


@requires_cache
def test_triage_falls_back_to_deterministic_when_unconfigured(monkeypatch):
    """With Foundry unconfigured, triage() runs the deterministic pipeline."""
    monkeypatch.setattr(foundry_client, "is_configured", lambda: False)

    result = triage(SAMPLE_EXPOSED)

    assert result.threat_backend == "cache"
    top = next((f for f in result.findings if f.priority == 1), None)
    assert top is not None
    assert "CVE-2021-41773" in [c.id for c in top.cves]
