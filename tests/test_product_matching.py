"""Regression tests for product-exact CVE matching and no-CVE handling.

Covers the four correctness bugs:
1. Token-overlap matching leaked Apache Struts CVEs into Apache httpd findings.
2. No-CVE services must return an empty CVE list and the standard rationale,
   and model prose must never reference a CVE outside the host's enriched set.
3. No-CVE services map to T1046 Network Service Discovery, assigned by code.

All tests run offline against the cache backend (no network, no model calls).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.agent import _build_from_foundry, triage
from agent.schema import CVE, Finding
from tools.threat_intel import _cache_lookup, product_key, threat_intel_lookup

CACHE = Path(__file__).parent.parent / "data" / "cache" / "cves.json"
requires_cache = pytest.mark.skipif(
    not CACHE.exists(), reason="data/cache/cves.json not built yet"
)


@pytest.fixture(autouse=True)
def cache_backend(monkeypatch):
    monkeypatch.setenv("THREAT_BACKEND", "cache")


# --------------------------------------------------------------------------- #
# product_key normalization                                                     #
# --------------------------------------------------------------------------- #


def test_product_key_distinguishes_apache_products():
    assert product_key("Apache httpd 2.4.49") == "apache_httpd"
    assert product_key("Apache Struts 2.3.5") == "apache_struts"
    assert product_key("Apache Tomcat 9.0") == "apache_tomcat"
    assert product_key("Apache") == "apache_httpd"
    assert product_key("apache_httpd") != product_key("apache_struts")


def test_product_key_common_services():
    assert product_key("OpenSSH 7.4") == "openssh"
    assert product_key("vsftpd 2.3.4") == "vsftpd"
    assert product_key("ProFTPD 1.3.3") == "proftpd"
    assert product_key("MySQL 8.0") == "mysql"
    assert product_key("SMB") == "smb"
    assert product_key("Samba 4.17") == "smb"


def test_product_key_generic_protocols_do_not_alias_products():
    # A bare protocol banner must never inherit a specific product's CVEs.
    assert product_key("SSH") != "openssh"
    assert product_key("HTTP") != "apache_httpd"
    assert product_key("FTP") not in ("vsftpd", "proftpd")


def test_product_key_unknown_service_is_empty():
    assert product_key("WeirdCustomDaemon 0.1") == ""


# --------------------------------------------------------------------------- #
# Cache lookup: product-exact, never token overlap                              #
# --------------------------------------------------------------------------- #


@requires_cache
def test_apache_httpd_never_returns_struts_cve():
    """Issue 1: 'Apache httpd' must not match the Struts CVE on the word 'apache'."""
    ids = {c["id"] for c in _cache_lookup("Apache httpd 2.4.49")}
    assert ids == {"CVE-2021-41773", "CVE-2021-42013"}, ids
    assert "CVE-2017-5638" not in ids


@requires_cache
def test_struts_still_returns_its_own_cve():
    ids = {c["id"] for c in _cache_lookup("Apache Struts 2.3.5")}
    assert ids == {"CVE-2017-5638"}


@requires_cache
def test_clean_services_return_no_cves():
    """Issue 2: services with no cached CVEs return an empty list, never a borrowed one."""
    for service in ("MySQL 8.0", "SMB", "Redis 7.0", "UnknownService 1.0"):
        assert threat_intel_lookup(service) == [], f"'{service}' should match no CVEs"


# --------------------------------------------------------------------------- #
# Triage pipeline: no-CVE findings                                              #
# --------------------------------------------------------------------------- #

MIXED_SCAN = json.dumps(
    {
        "host": "10.0.0.7",
        "ports": [
            {"port": 80, "service": "Apache httpd", "version": "2.4.49", "banner": ""},
            {"port": 3306, "service": "MySQL", "version": "8.0", "banner": ""},
            {"port": 445, "service": "SMB", "version": "", "banner": ""},
        ],
    }
)


@requires_cache
def test_no_cve_findings_have_empty_cves_and_standard_rationale():
    result = triage(MIXED_SCAN)
    for port in (3306, 445):
        f = next(f for f in result.findings if f.port == port)
        assert f.cves == [], f"port {port} should have no CVEs, got {f.cves}"
        assert f.rationale == "No known vulnerabilities match this service version."


@requires_cache
def test_no_cve_findings_get_t1046_discovery():
    """Issue 3: no-CVE services map to T1046 under Discovery, nothing else."""
    result = triage(MIXED_SCAN)
    for port in (3306, 445):
        f = next(f for f in result.findings if f.port == port)
        assert [m.technique for m in f.mitre] == ["T1046"]
        assert f.mitre[0].tactic == "Discovery"
        assert f.mitre[0].name == "Network Service Discovery"


@requires_cache
def test_no_foreign_cve_in_any_finding_text():
    """No finding's prose may mention a CVE that is not in the host's CVE set."""
    import re

    result = triage(MIXED_SCAN)
    host_ids = {c.id for f in result.findings for c in f.cves}
    cve_re = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
    for f in result.findings:
        for text in (f.rationale, f.remediation, f.remediation_command):
            for mention in cve_re.findall(text):
                assert mention.upper() in host_ids, (
                    f"Foreign CVE {mention} in port {f.port} text: {text!r}"
                )


# --------------------------------------------------------------------------- #
# Foundry merge: scrub model prose and ignore model MITRE                       #
# --------------------------------------------------------------------------- #


def _det_by_port() -> dict[int, Finding]:
    from agent.agent import _map_mitre

    apache = Finding(
        port=80,
        service="Apache httpd",
        version="2.4.49",
        cves=[CVE("CVE-2021-41773", 9.8, 0.94, True, 97, "path traversal")],
        rationale="on CISA KEV, EPSS 94%, composite 97",
        remediation="upgrade Apache httpd to 2.4.62 or later",
        remediation_command="sudo apt-get install --only-upgrade apache2",
    )
    apache.mitre = _map_mitre(apache.service, True)
    mysql = Finding(
        port=3306,
        service="MySQL",
        version="8.0",
        cves=[],
        rationale="No known vulnerabilities match this service version.",
        remediation="upgrade MySQL; bind to 127.0.0.1 unless remote access is required",
    )
    mysql.mitre = _map_mitre(mysql.service, False)
    return {80: apache, 3306: mysql}


MODEL_DATA = {
    "host": "10.0.0.7",
    "host_risk_score": 90,
    "summary": "Apache httpd is critically exposed via CVE-2021-41773.",
    "findings": [
        {
            "port": 80,
            "priority": 1,
            "contextual_severity": "critical",
            "mitre": [
                {
                    "technique": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access",
                }
            ],
            "rationale": "CVE-2021-41773 is on KEV with high EPSS.",
            "remediation": "Patch Apache to fix CVE-2021-41773.",
            # Fabricated package name and version pin; the merge must ignore it.
            "remediation_command": "sudo apt-get install httpd=2.4.99",
        },
        {
            "port": 3306,
            "priority": 2,
            "contextual_severity": "high",
            # The model invents an obfuscation technique and a Struts CVE here.
            "mitre": [
                {
                    "technique": "T1027.002",
                    "name": "Software Packing",
                    "tactic": "Defense Evasion",
                }
            ],
            "rationale": "MySQL is affected by CVE-2017-5638 like Struts.",
            "remediation": "Apply the CVE-2017-5638 content-type filter.",
            "remediation_command": "",
        },
    ],
    "attack_path": {
        "narrative": "Attacker exploits Apache httpd on port 80 for initial access.",
        "steps": [
            {"finding_port": 80, "technique": "T1059", "tactic": "Execution"},
            {
                "finding_port": 3306,
                "technique": "T1027.002",
                "tactic": "Defense Evasion",
            },
        ],
        "break_point": "Patch Apache httpd on port 80.",
    },
    "tool_calls": [],
}


def test_merge_scrubs_foreign_cve_from_prose():
    result = _build_from_foundry(
        json.loads(json.dumps(MODEL_DATA)),
        _det_by_port(),
        naive_cvss_order=[],
        tool_calls=[],
        data_backend="cache",
        host="10.0.0.7",
    )
    mysql = next(f for f in result.findings if f.port == 3306)
    assert "CVE-2017-5638" not in mysql.rationale
    assert "CVE-2017-5638" not in mysql.remediation
    assert mysql.rationale == "No known vulnerabilities match this service version."


def test_merge_uses_deterministic_remediation_command():
    """The shell command always comes from the deterministic pipeline, never the
    model, so a fabricated package name or version pin can never reach the UI."""
    result = _build_from_foundry(
        json.loads(json.dumps(MODEL_DATA)),
        _det_by_port(),
        naive_cvss_order=[],
        tool_calls=[],
        data_backend="cache",
        host="10.0.0.7",
    )
    apache = next(f for f in result.findings if f.port == 80)
    assert apache.remediation_command == "sudo apt-get install --only-upgrade apache2"
    assert "httpd=2.4.99" not in apache.remediation_command
    # Legitimate same-host CVE mentions survive.
    apache = next(f for f in result.findings if f.port == 80)
    assert "CVE-2021-41773" in apache.rationale


def test_merge_ignores_model_mitre_entirely():
    result = _build_from_foundry(
        json.loads(json.dumps(MODEL_DATA)),
        _det_by_port(),
        naive_cvss_order=[],
        tool_calls=[],
        data_backend="cache",
        host="10.0.0.7",
    )
    mysql = next(f for f in result.findings if f.port == 3306)
    assert [m.technique for m in mysql.mitre] == ["T1046"]
    apache = next(f for f in result.findings if f.port == 80)
    assert all(not m.technique.startswith("T1027") for m in apache.mitre)


def test_merge_attack_path_uses_deterministic_techniques_only():
    result = _build_from_foundry(
        json.loads(json.dumps(MODEL_DATA)),
        _det_by_port(),
        naive_cvss_order=[],
        tool_calls=[],
        data_backend="cache",
        host="10.0.0.7",
    )
    assert result.attack_path is not None
    ports = [s.finding_port for s in result.attack_path.steps]
    assert 3306 not in ports, "no-CVE service must not appear as an attack step"
    for step in result.attack_path.steps:
        assert step.technique == "T1190", (
            f"step technique must come from the code map, got {step.technique}"
        )


# --------------------------------------------------------------------------- #
# Foundry merge: KEV status is code-authoritative                               #
# --------------------------------------------------------------------------- #


def _kev_mix_det_by_port() -> dict[int, Finding]:
    """One genuine KEV finding (Apache) and one non-KEV finding (OpenSSH)."""
    from agent.agent import _map_mitre

    apache = Finding(
        port=80,
        service="Apache httpd",
        version="2.4.49",
        cves=[CVE("CVE-2021-41773", 9.8, 0.94, True, 97, "path traversal")],
        rationale="on CISA KEV, EPSS 94%, composite 97",
        remediation="upgrade Apache httpd to 2.4.62 or later",
        remediation_command="sudo apt-get install --only-upgrade apache2",
    )
    apache.mitre = _map_mitre(apache.service, True)
    openssh = Finding(
        port=22,
        service="OpenSSH",
        version="9.3p1",
        cves=[CVE("CVE-2023-38408", 9.8, 0.64, False, 62, "ssh-agent PKCS#11")],
        rationale="EPSS 64%, CVSS 9.8, composite 62",
        remediation="upgrade OpenSSH and enforce key-based authentication",
        remediation_command="sudo apt-get install --only-upgrade openssh-server",
    )
    openssh.mitre = _map_mitre(openssh.service, True)
    return {80: apache, 22: openssh}


def _kev_mix_model_data(ssh_rationale: str, narrative: str) -> dict:
    return {
        "host": "10.0.0.9",
        "host_risk_score": 85,
        "summary": "Internet-facing Apache with a KEV path traversal flaw.",
        "findings": [
            {
                "port": 80,
                "priority": 1,
                "contextual_severity": "critical",
                "rationale": "CVE-2021-41773 is on CISA KEV with composite 97.",
                "remediation": "Patch Apache httpd.",
            },
            {
                "port": 22,
                "priority": 2,
                "contextual_severity": "high",
                "rationale": ssh_rationale,
                "remediation": "Upgrade OpenSSH.",
            },
        ],
        "attack_path": {
            "narrative": narrative,
            "steps": [
                {"finding_port": 80, "technique": "T1190", "tactic": "Initial Access"},
                {
                    "finding_port": 22,
                    "technique": "T1021.004",
                    "tactic": "Lateral Movement",
                },
            ],
            "break_point": "Patch Apache httpd on port 80.",
        },
        "tool_calls": [],
    }


def test_merge_scrubs_false_kev_claim_from_rationale():
    """A rationale calling a kev=False CVE 'KEV' is replaced with deterministic text."""
    model_data = _kev_mix_model_data(
        ssh_rationale="CVE-2023-38408 is on CISA KEV with composite 62.",
        narrative="Attacker exploits Apache httpd on port 80 for initial access.",
    )
    result = _build_from_foundry(
        model_data,
        _kev_mix_det_by_port(),
        naive_cvss_order=[],
        tool_calls=[],
        data_backend="cache",
        host="10.0.0.9",
    )
    openssh = next(f for f in result.findings if f.port == 22)
    assert "KEV" not in openssh.rationale
    assert openssh.rationale == "EPSS 64%, CVSS 9.8, composite 62"


def test_merge_keeps_true_kev_claim_in_rationale():
    """A KEV claim about a CVE whose kev flag is true survives the merge."""
    model_data = _kev_mix_model_data(
        ssh_rationale="High EPSS and CVSS but not on KEV; composite 62.",
        narrative="Attacker exploits Apache httpd on port 80 for initial access.",
    )
    result = _build_from_foundry(
        model_data,
        _kev_mix_det_by_port(),
        naive_cvss_order=[],
        tool_calls=[],
        data_backend="cache",
        host="10.0.0.9",
    )
    apache = next(f for f in result.findings if f.port == 80)
    assert apache.rationale == "CVE-2021-41773 is on CISA KEV with composite 97."


def test_merge_keeps_negated_kev_mention():
    """'not on KEV' is a denial, not a claim, and must not trigger the scrub."""
    model_data = _kev_mix_model_data(
        ssh_rationale="CVE-2023-38408 is not on KEV; composite 62.",
        narrative="Attacker exploits Apache httpd on port 80 for initial access.",
    )
    result = _build_from_foundry(
        model_data,
        _kev_mix_det_by_port(),
        naive_cvss_order=[],
        tool_calls=[],
        data_backend="cache",
        host="10.0.0.9",
    )
    openssh = next(f for f in result.findings if f.port == 22)
    assert openssh.rationale == "CVE-2023-38408 is not on KEV; composite 62."


def test_merge_scrubs_false_kev_claim_from_attack_narrative():
    """A narrative calling a kev=False CVE 'KEV' falls back to the deterministic path."""
    model_data = _kev_mix_model_data(
        ssh_rationale="High EPSS and CVSS; composite 62.",
        narrative=(
            "Attacker exploits CVE-2023-38408, an actively exploited KEV flaw "
            "in OpenSSH, then pivots to Apache httpd."
        ),
    )
    result = _build_from_foundry(
        model_data,
        _kev_mix_det_by_port(),
        naive_cvss_order=[],
        tool_calls=[],
        data_backend="cache",
        host="10.0.0.9",
    )
    assert result.attack_path is not None
    assert "KEV" not in result.attack_path.narrative
    assert "CVE-2023-38408" not in result.attack_path.narrative
    # The deterministic path starts at the Apache (Initial Access) finding.
    assert result.attack_path.steps[0].finding_port == 80


def test_live_fixture_false_kev_rationales_are_scrubbed():
    """The captured Phi-4 fixture calls two kev=False CVEs 'KEV'; the merge must fix both."""
    from agent.agent import parse_foundry_response

    fixtures = Path(__file__).parent / "fixtures"
    raw = (fixtures / "foundry_exposed_raw.txt").read_text(encoding="utf-8")
    model_data = parse_foundry_response(raw)
    assert model_data is not None

    det_by_port = {
        80: Finding(
            port=80,
            service="Apache httpd",
            version="2.4.49",
            cves=[
                CVE("CVE-2021-41773", 9.8, 0.94, True, 97, "path traversal"),
                CVE("CVE-2021-42013", 9.8, 0.94, True, 97, "path traversal #2"),
            ],
            rationale="on CISA KEV, EPSS 94%, composite 97",
        ),
        443: Finding(
            port=443,
            service="OpenSSL",
            version="1.0.1",
            cves=[CVE("CVE-2014-0160", 7.5, 0.94, True, 90, "Heartbleed")],
            rationale="on CISA KEV, EPSS 94%, composite 90",
        ),
        21: Finding(
            port=21,
            service="vsftpd",
            version="2.3.4",
            cves=[CVE("CVE-2011-2523", 9.8, 0.94, False, 77, "vsftpd backdoor")],
            rationale="EPSS 94%, CVSS 9.8, composite 77",
        ),
        22: Finding(
            port=22,
            service="OpenSSH",
            version="7.4",
            cves=[CVE("CVE-2023-38408", 9.8, 0.64, False, 62, "ssh-agent PKCS#11")],
            rationale="EPSS 64%, CVSS 9.8, composite 62",
        ),
    }
    result = _build_from_foundry(
        model_data,
        det_by_port,
        naive_cvss_order=[],
        tool_calls=[],
        data_backend="cache",
        host="10.0.0.5",
    )
    for port in (21, 22):
        finding = next(f for f in result.findings if f.port == port)
        assert "KEV" not in finding.rationale, (
            f"port {port} rationale still claims KEV: {finding.rationale!r}"
        )
    for port in (80, 443):
        finding = next(f for f in result.findings if f.port == port)
        assert "KEV" in finding.rationale, (
            f"port {port} should keep its true KEV claim: {finding.rationale!r}"
        )
