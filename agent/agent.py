"""NetGuard Sentinel agent -- six-step reasoning pipeline (spec §6, §7).

Layer 1 (local): the pipeline runs as deterministic Python.
    All six steps are implemented here without an LLM call.

Layer 2 (Foundry, Day 4): uncomment the Foundry path at the bottom of triage().
    agent/foundry_client.py is the only file that changes.
"""

from __future__ import annotations

import json
import os

from agent import prompts
from agent.schema import (
    AttackPath,
    AttackStep,
    CVE,
    Finding,
    MitreTechnique,
    NaiveCvssEntry,
    ToolCall,
    TriageResult,
)
from tools.scoring import composite, contextual_severity
from tools.threat_intel import threat_intel_lookup

# MITRE ATT&CK technique lookup by service keyword.
# Each entry: (technique_id, technique_name, tactic).
_MITRE: dict[str, list[tuple[str, str, str]]] = {
    "apache":        [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "httpd":         [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "nginx":         [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "iis":           [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "tomcat":        [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "struts":        [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "http":          [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "https":         [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "ssh":           [("T1021.004", "Remote Services: SSH", "Lateral Movement")],
    "openssh":       [("T1021.004", "Remote Services: SSH", "Lateral Movement")],
    "ftp":           [("T1190", "Exploit Public-Facing Application", "Initial Access"),
                      ("T1078", "Valid Accounts", "Initial Access")],
    "vsftpd":        [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "proftpd":       [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "smb":           [("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement")],
    "rdp":           [("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement")],
    "telnet":        [("T1021", "Remote Services", "Lateral Movement")],
    "mysql":         [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "postgres":      [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "postgresql":    [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "mongodb":       [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "redis":         [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "elasticsearch": [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "openssl":       [("T1190", "Exploit Public-Facing Application", "Initial Access")],
}

_TACTIC_ORDER = {
    "Reconnaissance": 0, "Resource Development": 1, "Initial Access": 2,
    "Execution": 3, "Persistence": 4, "Privilege Escalation": 5,
    "Defense Evasion": 6, "Credential Access": 7, "Discovery": 8,
    "Lateral Movement": 9, "Collection": 10,
    "Command and Control": 11, "Exfiltration": 12, "Impact": 13,
}

_REMEDIATIONS: dict[str, str] = {
    "apache":    "upgrade Apache httpd to 2.4.62 or later",
    "httpd":     "upgrade Apache httpd to 2.4.62 or later",
    "nginx":     "upgrade nginx to 1.26.x (mainline) or 1.24.x (stable)",
    "openssh":   "upgrade OpenSSH and enforce key-based authentication; disable password auth",
    "vsftpd":    "replace vsftpd 2.3.4 (backdoored); close port 21 or migrate to SFTP",
    "proftpd":   "upgrade ProFTPD to 1.3.8 or later; restrict to localhost if not externally needed",
    "ftp":       "disable plain FTP; replace with SFTP or FTPS",
    "openssl":   "upgrade OpenSSL to 3.x; replace TLS 1.0/1.1 configurations",
    "struts":    "upgrade Apache Struts to 6.x; apply content-type filtering",
    "mysql":     "upgrade MySQL; bind to 127.0.0.1 unless remote access is required",
    "postgres":  "upgrade PostgreSQL; restrict pg_hba.conf to trusted hosts",
    "mongodb":   "upgrade MongoDB; enable authentication and bind to localhost",
    "redis":     "upgrade Redis; bind to 127.0.0.1; enable requirepass",
    "smb":       "disable SMBv1; patch to current; restrict to internal networks only",
    "rdp":       "enable Network Level Authentication; restrict source IPs; use MFA",
    "telnet":    "disable Telnet; replace with SSH",
}


# Sensitive data-store ports: exposure to the internet is its own critical risk
# regardless of whether a matching CVE exists in the cache.
_SENSITIVE_DB_PORTS: frozenset[int] = frozenset({3306, 5432, 6379, 27017})

# Services that should only exist on internal networks; deprioritise them when
# the scan confirms the host is internal-only.
_INTERNAL_ONLY_PORTS: frozenset[int] = frozenset({445})

# Copy-pasteable remediation commands keyed by service keyword (lowercase).
_REMEDIATION_COMMANDS: dict[str, str] = {
    "apache":  "sudo apt-get install --only-upgrade apache2",
    "httpd":   "sudo apt-get install --only-upgrade apache2",
    "nginx":   "sudo apt-get install --only-upgrade nginx",
    "openssh": "sudo apt-get install --only-upgrade openssh-server",
    "vsftpd":  "sudo systemctl disable --now vsftpd",
    "proftpd": "sudo systemctl stop proftpd && sudo apt-get remove --purge proftpd",
    "openssl": "sudo apt-get install --only-upgrade openssl",
    "telnet":  "sudo systemctl disable --now telnetd",
    "smb":     "sudo apt-get install --only-upgrade samba",
    "rdp":     "sudo ufw deny 3389/tcp",
    "struts":  "mvn versions:use-latest-releases  # then rebuild and redeploy",
}


def _remediation_command(service: str, port: int, bind_address: str, exposure: str) -> str:
    """Return a single copy-pasteable command for the most impactful remediation step."""
    svc_lower = service.lower()
    internet_exposed = (bind_address == "0.0.0.0") or (exposure == "internet")
    # Exposed data-store: block the port immediately.
    if port in _SENSITIVE_DB_PORTS and internet_exposed:
        return f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP"
    for keyword, cmd in _REMEDIATION_COMMANDS.items():
        if keyword in svc_lower:
            return cmd
    return ""


def _apply_exposure_override(findings: list[Finding], exposure: str) -> None:
    """Reorder findings based on network exposure data actually present in the scan.

    Elevates sensitive data-store services (MySQL, PostgreSQL, Redis, MongoDB)
    when bind_address == '0.0.0.0' or the scan-level exposure is 'internet'.
    Downgrades SMB when the host is confirmed internal-only.

    Does nothing if neither exposure nor any bind_address is present in the scan,
    so scans without this context are unaffected.
    """
    any_bind = any(f.bind_address for f in findings)
    if not exposure and not any_bind:
        return

    elevated: list[Finding] = []
    normal: list[Finding] = []
    downgraded: list[Finding] = []

    for f in findings:
        internet_exposed = (f.bind_address == "0.0.0.0") or (exposure == "internet")
        if f.port in _SENSITIVE_DB_PORTS and internet_exposed:
            bind_note = f"bind_address {f.bind_address}" if f.bind_address else "internet-exposed host"
            f.rationale = (
                f"elevated: {f.service} on port {f.port} reachable from internet "
                f"({bind_note}); " + f.rationale
            )
            elevated.append(f)
        elif f.port in _INTERNAL_ONLY_PORTS and exposure == "internal":
            f.rationale = "downgraded: SMB on confirmed internal host; " + f.rationale
            downgraded.append(f)
        else:
            normal.append(f)

    if not elevated and not downgraded:
        return

    findings.clear()
    findings.extend(elevated + normal + downgraded)
    for i, f in enumerate(findings):
        f.priority = i + 1


def _map_mitre(service: str) -> list[MitreTechnique]:
    svc_lower = service.lower()
    techniques: list[MitreTechnique] = []
    seen: set[str] = set()
    for keyword, entries in _MITRE.items():
        if keyword in svc_lower:
            for tid, name, tactic in entries:
                if tid not in seen:
                    techniques.append(MitreTechnique(technique=tid, name=name, tactic=tactic))
                    seen.add(tid)
    return techniques


def _remediation_text(service: str, cves: list[CVE]) -> str:
    svc_lower = service.lower()
    for keyword, text in _REMEDIATIONS.items():
        if keyword in svc_lower:
            return text
    if cves:
        return f"patch or upgrade {service.split()[0]} to the latest release"
    return "verify service configuration and apply available security updates"


def _rationale(cves: list[CVE]) -> str:
    if not cves:
        return "no known CVEs found for this version"
    top = max(cves, key=lambda c: c.composite_score)
    parts = []
    if top.kev:
        parts.append("on CISA KEV")
    if top.epss >= 0.5:
        parts.append(f"EPSS {top.epss:.0%}")
    if top.cvss >= 9.0:
        parts.append(f"CVSS {top.cvss}")
    parts.append(f"composite {top.composite_score}")
    return ", ".join(parts) if parts else f"composite {top.composite_score}"


def _build_attack_path(findings: list[Finding]) -> AttackPath | None:
    exploitable = [f for f in findings if f.cves]
    if not exploitable:
        return None

    # Sort by tactic order to chain the path chronologically.
    def tactic_rank(f: Finding) -> int:
        if not f.mitre:
            return 99
        return min(_TACTIC_ORDER.get(m.tactic, 99) for m in f.mitre)

    ordered = sorted(exploitable, key=tactic_rank)

    steps = []
    for f in ordered:
        if f.mitre:
            m = min(f.mitre, key=lambda x: _TACTIC_ORDER.get(x.tactic, 99))
            steps.append(AttackStep(
                finding_port=f.port,
                technique=m.technique,
                tactic=m.tactic,
            ))

    if not steps:
        return None

    # Narrative
    entry = ordered[0]
    entry_name = f"{entry.service} on port {entry.port}"
    if len(ordered) == 1:
        narrative = (
            f"Attacker exploits {entry_name} for initial access. "
            f"No clear lateral movement path identified from remaining findings."
        )
        break_point = (
            f"Patching {entry.service} (port {entry.port}) eliminates the only "
            f"known entry point."
        )
    else:
        pivot = ordered[1]
        pivot_name = f"{pivot.service} on port {pivot.port}"
        narrative = (
            f"Attacker exploits {entry_name} to gain initial access, "
            f"then pivots via {pivot_name}."
        )
        if len(ordered) > 2:
            extras = ", ".join(f"{f.service} (port {f.port})" for f in ordered[2:])
            narrative += f" Further progression possible through {extras}."
        break_point = (
            f"Patching {entry.service} (port {entry.port}) severs the path at step 1, "
            f"the highest-leverage fix."
        )

    return AttackPath(narrative=narrative, steps=steps, break_point=break_point)


def _host_risk_score(findings: list[Finding]) -> int:
    scores = sorted(
        (max((c.composite_score for c in f.cves), default=0) for f in findings),
        reverse=True,
    )
    top = scores[:3]
    if not top:
        return 0
    return round(sum(top) / len(top))


def _parse_scan(scan_json: str) -> dict:
    try:
        return json.loads(scan_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Scan input is not valid JSON: {exc}") from exc


# --------------------------------------------------------------------------- #
# Public entry point                                                            #
# --------------------------------------------------------------------------- #

def triage(scan_input: str) -> TriageResult:
    """Run the six-step triage pipeline on a scan JSON string.

    Layer 1 (local): runs deterministically without a Foundry call.
    Day 4: to use Foundry, uncomment the block at the end of this function
    and implement agent/foundry_client.run_agent().
    """
    scan = _parse_scan(scan_input)
    host = scan.get("host", "unknown")
    ports = scan.get("ports", [])
    exposure = scan.get("exposure", "")
    threat_backend = os.getenv("THREAT_BACKEND", "cache").lower()

    findings: list[Finding] = []
    tool_calls: list[ToolCall] = []

    # Stage 1 + 2: parse and enrich
    for p in ports:
        port_num = int(p.get("port", 0))
        service = p.get("service", "")
        version = p.get("version", "")
        bind_address = p.get("bind_address", "")
        service_str = f"{service} {version}".strip()

        raw_cves = threat_intel_lookup(service_str)
        kev_count = sum(1 for c in raw_cves if c.get("kev"))
        tool_calls.append(ToolCall(
            tool="threat_intel_lookup",
            input=service_str,
            result_summary=f"{len(raw_cves)} CVEs, {kev_count} KEV",
        ))

        # Stage 3: score
        cves: list[CVE] = []
        for raw in raw_cves:
            score = composite(raw["cvss"], raw["epss"], raw["kev"])
            cves.append(CVE(
                id=raw["id"],
                cvss=raw["cvss"],
                epss=raw["epss"],
                kev=raw["kev"],
                composite_score=score,
                summary=raw.get("description", "")[:120],
            ))
        cves.sort(key=lambda c: c.composite_score, reverse=True)

        # Stage 3: contextual severity for the finding
        top_score = cves[0].composite_score if cves else 0
        top_kev = any(c.kev for c in cves)
        severity = contextual_severity(top_score, top_kev)

        mitre = _map_mitre(service)
        findings.append(Finding(
            port=port_num,
            service=service,
            version=version,
            bind_address=bind_address,
            cves=cves,
            contextual_severity=severity,
            mitre=mitre,
            rationale=_rationale(cves),
            remediation=_remediation_text(service, cves),
            remediation_command=_remediation_command(service, port_num, bind_address, exposure),
        ))

    # Stage 4: rank worst-first
    findings.sort(
        key=lambda f: (
            max((c.composite_score for c in f.cves), default=0),
            any(c.kev for c in f.cves),
            max((c.epss for c in f.cves), default=0.0),
        ),
        reverse=True,
    )
    for i, f in enumerate(findings):
        f.priority = i + 1

    # Exposure override: elevate sensitive data-stores exposed to the internet;
    # downgrade internal-only services on confirmed internal hosts.
    _apply_exposure_override(findings, exposure)

    # Naive CVSS ranking (for UI comparison: what CVSS alone would tell you).
    naive_cvss_order = sorted(
        [
            NaiveCvssEntry(
                port=f.port,
                service=f.service,
                cvss=max((c.cvss for c in f.cves), default=0.0),
            )
            for f in findings
        ],
        key=lambda e: e.cvss,
        reverse=True,
    )

    # Stage 5: attack path
    attack_path = _build_attack_path(findings)

    # Stage 6: host risk score + summary
    risk = _host_risk_score(findings)
    if risk >= 80:
        summary = f"Host {host} is at critical risk: multiple actively exploited vulnerabilities present."
    elif risk >= 60:
        summary = f"Host {host} has high risk: exploitable services require urgent patching."
    elif risk >= 35:
        summary = f"Host {host} has moderate risk: some findings need attention."
    elif risk > 0:
        summary = f"Host {host} has low risk: no actively exploited vulnerabilities found."
    else:
        summary = f"Host {host}: no known vulnerabilities matched the detected services."

    # FOUNDRY SEAM (Day 4): replace the local pipeline above with:
    #
    #   from agent import foundry_client
    #   raw = foundry_client.run_agent(
    #       system_prompt=prompts.SYSTEM_PROMPT,
    #       user_message=prompts.build_user_prompt(scan_input),
    #   )
    #   return parse_foundry_response(raw)  # implement parse_foundry_response()
    #
    # The local pipeline stays as a fallback if Foundry is not configured.
    _ = prompts  # referenced above in the seam comment; suppress unused-import warning

    return TriageResult(
        host=host,
        host_risk_score=risk,
        summary=summary,
        findings=findings,
        naive_cvss_order=naive_cvss_order,
        attack_path=attack_path,
        tool_calls=tool_calls,
        threat_backend=threat_backend,
    )
