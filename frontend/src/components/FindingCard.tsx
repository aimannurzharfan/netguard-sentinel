import { ShieldAlert, Terminal } from "lucide-react"
import type { Finding } from "@/lib/types"
import { cvssLabel, epssPct, severityMeta } from "@/lib/format"
import { cn } from "@/lib/utils"
import { CopyButton } from "./CopyButton"

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex items-baseline gap-1 rounded-sm bg-secondary px-1.5 py-0.5 text-[0.7rem] text-secondary-foreground">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-semibold tabular-nums">{value}</span>
    </span>
  )
}

export function FindingCard({ finding }: { finding: Finding }) {
  const sev = severityMeta(finding.contextual_severity)

  return (
    <article
      className="rounded-md border border-border bg-card p-4 transition-colors focus-within:border-primary/50"
      aria-label={`Priority ${finding.priority}: ${finding.service} on port ${finding.port}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex items-center gap-1.5 rounded-sm border border-border bg-secondary px-2 py-0.5 font-display text-[0.72rem] font-semibold text-muted-foreground">
          <span className="text-muted-foreground">PRIORITY</span>
          <span className="text-foreground tabular-nums">{finding.priority}</span>
        </span>
        <span
          className={cn(
            "tactical-label rounded-sm border px-2 py-0.5 text-[0.66rem]",
            sev.text,
            sev.bg,
            sev.border
          )}
        >
          {sev.label}
        </span>
        <span className="font-display text-sm font-semibold text-foreground">
          {finding.service}
          <span className="text-muted-foreground">:{finding.port}</span>
        </span>
        {finding.version ? (
          <span className="text-[0.78rem] text-muted-foreground">
            v{finding.version}
          </span>
        ) : null}
      </div>

      {finding.cves.length > 0 ? (
        <ul className="mt-3 divide-y divide-border" aria-label="Matched CVEs">
          {finding.cves.map((c) => (
            <li
              key={c.id}
              className="flex flex-wrap items-baseline gap-x-2 gap-y-1 py-1.5"
            >
              <span className="font-semibold text-primary">{c.id}</span>
              {c.kev ? (
                <span className="tactical-label rounded-sm bg-kev-bg px-1.5 py-0.5 text-[0.6rem] text-kev">
                  KEV
                </span>
              ) : null}
              <Metric label="score" value={String(c.composite_score)} />
              <Metric label="CVSS" value={cvssLabel(c.cvss)} />
              <Metric label="EPSS" value={`${epssPct(c.epss)}%`} />
              <span className="w-full text-[0.76rem] text-muted-foreground sm:w-auto sm:flex-1">
                {c.summary}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-3 text-[0.8rem] text-muted-foreground">
          No CVEs matched for this service version.
        </p>
      )}

      {finding.mitre.length > 0 ? (
        <ul
          className="mt-3 flex flex-wrap gap-1.5"
          aria-label="MITRE ATT&CK techniques"
        >
          {finding.mitre.map((m) => (
            <li
              key={m.technique}
              title={m.name}
              className="rounded-sm border border-chart-5/30 bg-chart-5/10 px-1.5 py-0.5 text-[0.7rem] text-chart-5"
            >
              <span className="font-semibold">{m.technique}</span>{" "}
              <span className="opacity-80">{m.tactic}</span>
            </li>
          ))}
        </ul>
      ) : null}

      {finding.rationale ? (
        <p className="mt-3 text-[0.82rem] leading-relaxed text-muted-foreground">
          {finding.rationale}
        </p>
      ) : null}

      {finding.remediation ? (
        <div className="mt-3 flex gap-2 rounded-sm border-l-2 border-primary bg-signal-bg/40 px-3 py-2">
          <ShieldAlert
            className="mt-0.5 size-4 shrink-0 text-primary"
            aria-hidden="true"
          />
          <p className="text-[0.84rem] leading-relaxed text-foreground">
            {finding.remediation}
          </p>
        </div>
      ) : null}

      {finding.remediation_command ? (
        <div className="mt-2 flex items-stretch gap-2">
          <div className="flex min-w-0 flex-1 items-center gap-2 rounded-sm border border-border bg-background px-2.5 py-1.5">
            <Terminal
              className="size-4 shrink-0 text-muted-foreground"
              aria-hidden="true"
            />
            <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-[0.8rem] text-primary">
              {finding.remediation_command}
            </code>
          </div>
          <CopyButton
            value={finding.remediation_command}
            label={`Copy remediation command for ${finding.service}`}
          />
        </div>
      ) : null}
    </article>
  )
}
