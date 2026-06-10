// Mirrors agent/schema.py (TriageResult -> Finding -> CVE). The backend owns
// this contract; the UI only consumes it.

export interface CVE {
  id: string
  cvss: number
  epss: number
  kev: boolean
  composite_score: number
  summary: string
}

export interface MitreTechnique {
  technique: string
  name: string
  tactic: string
}

export interface Finding {
  port: number
  service: string
  version: string
  cves: CVE[]
  contextual_severity: string
  mitre: MitreTechnique[]
  rationale: string
  remediation: string
  remediation_command: string
  bind_address: string
  priority: number
}

export interface AttackStep {
  finding_port: number
  technique: string
  tactic: string
}

export interface AttackPath {
  narrative: string
  steps: AttackStep[]
  break_point: string
}

export interface NaiveCvssEntry {
  port: number
  service: string
  cvss: number
}

export interface TriageResult {
  host: string
  host_risk_score: number
  summary: string
  findings: Finding[]
  naive_cvss_order: NaiveCvssEntry[]
  attack_path: AttackPath | null
  tool_calls: unknown[]
  threat_backend: string
}

export type Severity = "critical" | "high" | "medium" | "low"
