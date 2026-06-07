"""Output schema for NetGuard Sentinel (spec §8)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field


@dataclass
class MitreTechnique:
    technique: str
    name: str
    tactic: str


@dataclass
class CVE:
    id: str
    cvss: float
    epss: float
    kev: bool
    composite_score: int
    summary: str


@dataclass
class Finding:
    port: int
    service: str
    version: str
    cves: list[CVE] = field(default_factory=list)
    contextual_severity: str = ""
    mitre: list[MitreTechnique] = field(default_factory=list)
    rationale: str = ""
    remediation: str = ""
    remediation_command: str = ""
    bind_address: str = ""
    priority: int = 0


@dataclass
class AttackStep:
    finding_port: int
    technique: str
    tactic: str


@dataclass
class AttackPath:
    narrative: str
    steps: list[AttackStep] = field(default_factory=list)
    break_point: str = ""


@dataclass
class ToolCall:
    tool: str
    input: str
    result_summary: str


@dataclass
class NaiveCvssEntry:
    port: int
    service: str
    cvss: float


@dataclass
class TriageResult:
    host: str
    host_risk_score: int = 0
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    naive_cvss_order: list[NaiveCvssEntry] = field(default_factory=list)
    attack_path: AttackPath | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    threat_backend: str = "cache"


def to_json(result: TriageResult) -> str:
    """Serialize a TriageResult to the §8 JSON contract."""
    return json.dumps(asdict(result), indent=2)


def validate(payload: dict) -> tuple[bool, str]:
    """Check that a raw dict matches the §8 contract. Returns (ok, error_message)."""
    required = {"host", "host_risk_score", "summary", "findings", "tool_calls"}
    missing = required - payload.keys()
    if missing:
        return False, f"missing top-level keys: {missing}"

    for i, f in enumerate(payload.get("findings", [])):
        for key in ("port", "service", "version", "cves", "priority"):
            if key not in f:
                return False, f"finding[{i}] missing '{key}'"
        for j, c in enumerate(f.get("cves", [])):
            for key in ("id", "cvss", "epss", "kev", "composite_score", "summary"):
                if key not in c:
                    return False, f"finding[{i}].cves[{j}] missing '{key}'"

    return True, ""
