"""Unit tests for schema validation and serialisation."""

import json
from agent.schema import AttackPath, AttackStep, CVE, Finding, MitreTechnique, ToolCall, TriageResult, to_json, validate


def _minimal_result() -> TriageResult:
    return TriageResult(
        host="10.0.0.1",
        host_risk_score=50,
        summary="test",
        findings=[
            Finding(
                port=80,
                service="Apache httpd",
                version="2.4.49",
                cves=[CVE(id="CVE-2021-41773", cvss=7.5, epss=0.97, kev=True, composite_score=91, summary="path traversal")],
                contextual_severity="critical",
                mitre=[MitreTechnique(technique="T1190", name="Exploit Public-Facing Application", tactic="Initial Access")],
                rationale="on CISA KEV, EPSS 97%",
                remediation="upgrade Apache to 2.4.62",
                priority=1,
            )
        ],
        attack_path=AttackPath(
            narrative="Attacker exploits Apache for initial access.",
            steps=[AttackStep(finding_port=80, technique="T1190", tactic="Initial Access")],
            break_point="Patch Apache first.",
        ),
        tool_calls=[ToolCall(tool="threat_intel_lookup", input="Apache httpd 2.4.49", result_summary="1 CVE, 1 KEV")],
    )


class TestToJson:
    def test_produces_valid_json(self):
        result = _minimal_result()
        raw = to_json(result)
        parsed = json.loads(raw)
        assert parsed["host"] == "10.0.0.1"

    def test_includes_attack_path(self):
        raw = to_json(_minimal_result())
        parsed = json.loads(raw)
        assert "attack_path" in parsed
        assert parsed["attack_path"]["steps"][0]["technique"] == "T1190"

    def test_cve_fields_present(self):
        raw = to_json(_minimal_result())
        cve = json.loads(raw)["findings"][0]["cves"][0]
        for key in ("id", "cvss", "epss", "kev", "composite_score", "summary"):
            assert key in cve, f"Missing CVE field: {key}"


class TestValidate:
    def test_valid_payload_passes(self):
        raw = json.loads(to_json(_minimal_result()))
        ok, err = validate(raw)
        assert ok, err

    def test_missing_host_fails(self):
        raw = json.loads(to_json(_minimal_result()))
        del raw["host"]
        ok, _ = validate(raw)
        assert not ok

    def test_missing_cve_field_fails(self):
        raw = json.loads(to_json(_minimal_result()))
        del raw["findings"][0]["cves"][0]["composite_score"]
        ok, _ = validate(raw)
        assert not ok
