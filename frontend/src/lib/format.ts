import type { Finding, Severity, TriageResult } from "./types"

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"]

export function normalizeSeverity(value: string): Severity {
  const v = (value || "").toLowerCase()
  return (SEVERITIES as string[]).includes(v) ? (v as Severity) : "low"
}

export interface SeverityMeta {
  label: string
  /** Tailwind text-color utility backed by a theme token. */
  text: string
  /** Tailwind background utility backed by a theme token. */
  bg: string
  /** Tailwind border utility. */
  border: string
}

export const SEVERITY_META: Record<Severity, SeverityMeta> = {
  critical: {
    label: "Critical",
    text: "text-critical",
    bg: "bg-critical-bg",
    border: "border-critical/40",
  },
  high: {
    label: "High",
    text: "text-high",
    bg: "bg-high-bg",
    border: "border-high/40",
  },
  medium: {
    label: "Medium",
    text: "text-medium",
    bg: "bg-medium-bg",
    border: "border-medium/40",
  },
  low: {
    label: "Low",
    text: "text-low",
    bg: "bg-low-bg",
    border: "border-low/40",
  },
}

export function severityMeta(value: string): SeverityMeta {
  return SEVERITY_META[normalizeSeverity(value)]
}

export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  }
  for (const f of findings) counts[normalizeSeverity(f.contextual_severity)]++
  return counts
}

export function clamp(n: number, min = 0, max = 100): number {
  const v = Number(n)
  if (!Number.isFinite(v)) return min
  return Math.min(max, Math.max(min, v))
}

export function topScore(finding: Finding): number {
  return finding.cves.reduce(
    (max, c) => Math.max(max, Number(c.composite_score) || 0),
    0
  )
}

/** Risk tier drives the gauge colour and the host headline. */
export function riskTier(score: number): {
  token: Severity
  label: string
} {
  if (score >= 80) return { token: "critical", label: "Critical exposure" }
  if (score >= 60) return { token: "high", label: "High exposure" }
  if (score >= 35) return { token: "medium", label: "Moderate exposure" }
  return { token: "low", label: "Low exposure" }
}

/** Human-readable provenance for the result footer. */
export function backendLabel(result: TriageResult): string {
  const backend = (result.threat_backend || "").toLowerCase()
  const reasoned = backend.startsWith("foundry")
  const store = backend.includes("oracle")
    ? "Oracle 23ai vector search"
    : "local threat cache"
  return reasoned ? `Phi-4 reasoning over ${store}` : store
}

export function epssPct(epss: number): number {
  return Math.round((Number(epss) || 0) * 100)
}

export function cvssLabel(cvss: number): string {
  return (Number(cvss) || 0).toFixed(1)
}
