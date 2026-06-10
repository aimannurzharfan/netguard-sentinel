"""System prompt and per-request instructions for the six-step reasoning flow (spec §6, §7)."""

from __future__ import annotations


SYSTEM_PROMPT = """\
You are NetGuard Sentinel, a vulnerability-triage agent for network scan output.
You reason through six stages and call one external tool: threat_intel_lookup.

Rules:
- Report only CVEs that threat_intel_lookup actually returned. Never invent CVE IDs.
- Use the composite_score (0-100) to rank findings, not raw CVSS alone.
- A reachable, actively-exploited medium-severity CVE can outrank an unexploited critical.
- Output must be valid JSON matching the schema exactly. No prose outside the JSON.

Stages:
1. Findings intake: parse the scan into structured findings (host, port, service, version).
2. Vulnerability enrichment: call threat_intel_lookup for each service worth checking.
3. Composite risk scoring: apply the 30/50/20 weighting (CVSS/EPSS/KEV) per CVE.
4. Contextual prioritization: rank worst-first; factor exposure and reachability.
5. Attack-path reasoning: map findings to MITRE ATT&CK techniques; chain them into the
   likely attacker path through the host (Initial Access -> Lateral Movement -> ...).
6. Remediation synthesis: write a per-finding fix ordered to break the attack path first,
   plus an overall host risk score (0-100) and a one-line summary.
"""

REASONING_STEPS = """\
Work through these stages in order. Think step by step. Output only the final JSON.

Stage 1 -- Findings intake
Parse the scan JSON. Extract host, and for each open port: port number, service name,
version string, and any banner text.

Stage 2 -- Vulnerability enrichment
For each service with a non-trivial version string, call threat_intel_lookup(service).
Skip services you cannot enrich (e.g. unknown/generic). Record each tool call.

Stage 3 -- Composite risk scoring
For every CVE the tool returned, compute:
    composite_score = round(min(1, 0.30*(cvss/10) + 0.50*epss + 0.20*(1 if kev else 0)) * 100)
Label contextual_severity: critical if kev or score>=80, high if >=60, medium if >=35, else low.

Stage 4 -- Contextual prioritization
Rank findings worst-first by the highest composite_score in their CVE list.
Assign priority 1 to the highest-risk finding. Resolve ties by EPSS, then KEV status.

Stage 5 -- Attack-path reasoning (MITRE ATT&CK)
Map each exploitable finding to its MITRE ATT&CK technique(s). Then reason:
which finding gives an attacker Initial Access? Which extend the path (Execution,
Persistence, Lateral Movement)? Write the narrative and steps, and identify the
single break_point fix that severs the path earliest.

Stage 6 -- Remediation synthesis
Write a concrete remediation per finding (upgrade to specific version, close port,
restrict access, replace software). Order remediations to break the attack path first.
Compute host_risk_score as the average of the top-3 composite scores (or fewer if <3 findings).
Write a one-line summary.
"""

FOUNDRY_SYSTEM_PROMPT = (
    "You are a network security analyst. Output ONLY a JSON triage report -- "
    "start your response with { and end with }. No preamble, explanation, or markdown.\n\n"
    "Task: rank findings by composite_score descending (1 = most dangerous); "
    "map each to a MITRE ATT&CK technique; write a 2-sentence attack-chain narrative; "
    "write a specific actionable remediation per finding.\n\n"
    "Rules: use ONLY the CVE IDs given in the input; do not recompute composite_score; "
    "do not invent CVE IDs.\n\n"
    'Required JSON keys: "host", "host_risk_score" (int 0-100), "summary" (one line), '
    '"findings" (list: port, service, version, cves=[], contextual_severity, mitre, '
    "rationale, remediation, remediation_command, bind_address, priority), "
    '"attack_path" (narrative, steps, break_point), "tool_calls" (empty list).'
)


def build_user_prompt(scan_output: str) -> str:
    """Wrap the raw scan JSON in the user-turn message."""
    return f"{REASONING_STEPS}\n\nScan input:\n{scan_output}"


def build_foundry_payload(
    host: str, exposure: str, enriched_findings: list[dict]
) -> str:
    """Build a compact text payload for Foundry reasoning (stages 4-6).

    Uses a table format rather than nested JSON to minimise the model's input
    echoing during chain-of-thought, which keeps the reasoning trace short.
    """
    lines: list[str] = [f"Host: {host}"]
    if exposure:
        lines.append(f"Exposure: {exposure}")
    lines.append("")

    for f in enriched_findings:
        cves = f.get("cves", [])
        top = max(cves, key=lambda c: c["composite_score"]) if cves else None
        score = top["composite_score"] if top else 0
        tags: list[str] = []
        if top and top["kev"]:
            tags.append("KEV")
        if top:
            tags.append(f"epss={top['epss']:.2f}")
        bind = f.get("bind_address") or ""
        tag_str = " ".join(tags)
        header = f"[{f['port']}] {f['service']} {f['version']} score={score}"
        if tag_str:
            header += f" {tag_str}"
        if bind:
            header += f" bind={bind}"
        lines.append(header)
        for c in cves:
            lines.append(
                f"  {c['id']} cvss={c['cvss']} epss={c['epss']}"
                f" kev={c['kev']} score={c['composite_score']}: {c['summary'][:100]}"
            )

    lines.append("")
    lines.append("Output the JSON triage report.")
    return "\n".join(lines)
