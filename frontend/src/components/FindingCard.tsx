import { useId, useState } from "react"
import { ChevronDown, ShieldAlert, Terminal } from "lucide-react"
import type { CVE, Finding } from "@/lib/types"
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

/* Summaries shorter than this always fit two clamped lines, even in the
   narrower two-column layout, so the expand control would be a no-op.
   The backend sends the full NVD description, so anything longer gets
   clamped collapsed and shown complete when expanded. */
const CLAMP_THRESHOLD = 100

function CveItem({ cve }: { cve: CVE }) {
  const [expanded, setExpanded] = useState(false)
  const summaryId = useId()
  const clampable = (cve.summary || "").length > CLAMP_THRESHOLD

  return (
    <li className="flex flex-col gap-2 rounded-sm border border-border bg-background/60 p-3">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="font-semibold text-primary">{cve.id}</span>
        {cve.kev ? (
          <span className="tactical-label rounded-sm bg-kev-bg px-1.5 py-0.5 text-[0.6rem] text-kev">
            KEV
          </span>
        ) : null}
      </div>

      {/* Fixed metric order keeps badges aligned across the CVE grid. */}
      <div className="flex flex-wrap items-center gap-1.5">
        <Metric label="score" value={String(cve.composite_score)} />
        <Metric label="CVSS" value={cvssLabel(cve.cvss)} />
        <Metric label="EPSS" value={`${epssPct(cve.epss)}%`} />
      </div>

      {cve.summary ? (
        <p
          id={summaryId}
          className={cn(
            "text-[0.78rem] leading-relaxed text-muted-foreground",
            clampable && !expanded && "line-clamp-2"
          )}
        >
          {cve.summary}
        </p>
      ) : null}

      {clampable ? (
        <button
          type="button"
          aria-expanded={expanded}
          aria-controls={summaryId}
          aria-label={`${expanded ? "Show less of" : "Show more of"} the description for ${cve.id}`}
          onClick={() => setExpanded((v) => !v)}
          className="-mx-1.5 -my-1.5 inline-flex w-fit cursor-pointer items-center gap-1 rounded-sm px-1.5 py-1.5 text-[0.72rem] font-semibold text-primary hover:underline"
        >
          {expanded ? "Show less" : "Show more"}
          <ChevronDown
            aria-hidden="true"
            className={cn(
              "size-3 transition-transform motion-reduce:transition-none",
              expanded && "rotate-180"
            )}
          />
        </button>
      ) : null}
    </li>
  )
}

export function FindingCard({ finding }: { finding: Finding }) {
  const sev = severityMeta(finding.contextual_severity)

  return (
    <article
      className={cn(
        "rounded-md border border-border border-l-2 p-4 transition-colors focus-within:border-primary/50 sm:p-5",
        sev.cardAccent,
        sev.cardTint
      )}
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
        <ul
          className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2"
          aria-label="Matched CVEs"
        >
          {finding.cves.map((c) => (
            <CveItem key={c.id} cve={c} />
          ))}
        </ul>
      ) : (
        <p className="mt-4 text-[0.8rem] leading-relaxed text-muted-foreground">
          No known vulnerabilities match this service version.
        </p>
      )}

      {finding.mitre.length > 0 ? (
        <ul
          className="mt-4 flex flex-wrap gap-1.5"
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
        <p className="mt-4 text-[0.82rem] leading-relaxed text-muted-foreground">
          {finding.rationale}
        </p>
      ) : null}

      {finding.remediation ? (
        <div className="mt-4 flex gap-2 rounded-sm border-l-2 border-primary bg-signal-bg/40 px-3 py-2">
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
