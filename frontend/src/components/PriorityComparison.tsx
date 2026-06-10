import { ArrowLeftRight } from "lucide-react"
import type { Finding, NaiveCvssEntry } from "@/lib/types"
import { cvssLabel, topScore } from "@/lib/format"

function Row({
  rank,
  service,
  port,
  metric,
  emphasis,
}: {
  rank: number
  service: string
  port: number
  metric: string
  emphasis?: boolean
}) {
  return (
    <li className="flex items-center gap-2 py-1 text-[0.8rem]">
      <span className="w-5 shrink-0 text-right text-[0.72rem] text-muted-foreground tabular-nums">
        {rank}
      </span>
      <span className="min-w-0 flex-1 truncate">
        {service}
        <span className="text-muted-foreground">:{port}</span>
      </span>
      <span
        className={
          emphasis
            ? "shrink-0 font-semibold text-primary tabular-nums"
            : "shrink-0 text-muted-foreground tabular-nums"
        }
      >
        {metric}
      </span>
    </li>
  )
}

export function PriorityComparison({
  findings,
  naive,
}: {
  findings: Finding[]
  naive: NaiveCvssEntry[]
}) {
  if (!naive || naive.length < 2) return null

  return (
    <section aria-labelledby="cmp-heading">
      <h3
        id="cmp-heading"
        className="tactical-label mb-2 flex items-center gap-2 text-[0.72rem] text-muted-foreground"
      >
        <ArrowLeftRight className="size-3.5" aria-hidden="true" />
        How prioritization changes
      </h3>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-md border border-border bg-card p-3">
          <p className="tactical-label mb-1.5 text-[0.66rem] text-muted-foreground">
            Sorted by CVSS alone
          </p>
          <ol>
            {naive.map((e, i) => (
              <Row
                key={`${e.port}-${e.service}`}
                rank={i + 1}
                service={e.service}
                port={e.port}
                metric={`CVSS ${cvssLabel(e.cvss)}`}
              />
            ))}
          </ol>
        </div>
        <div className="rounded-md border border-primary/30 bg-signal-bg/30 p-3">
          <p className="tactical-label mb-1.5 text-[0.66rem] text-primary">
            Sentinel composite priority
          </p>
          <ol>
            {findings.map((f, i) => (
              <Row
                key={`${f.port}-${f.service}`}
                rank={i + 1}
                service={f.service}
                port={f.port}
                metric={`score ${topScore(f)}`}
                emphasis
              />
            ))}
          </ol>
        </div>
      </div>
    </section>
  )
}
