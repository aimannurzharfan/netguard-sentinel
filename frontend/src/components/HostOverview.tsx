import { RotateCcw, Server } from "lucide-react"
import type { Severity, TriageResult } from "@/lib/types"
import { Button } from "@/components/ui/button"
import { backendLabel, severityCounts, SEVERITY_META } from "@/lib/format"
import { cn } from "@/lib/utils"
import { RiskGauge } from "./RiskGauge"

const ORDER: Severity[] = ["critical", "high", "medium", "low"]

export function HostOverview({
  result,
  onReset,
}: {
  result: TriageResult
  onReset: () => void
}) {
  const counts = severityCounts(result.findings)

  return (
    <div className="hud-frame rounded-md border border-border bg-card p-4 sm:p-5">
      <div className="flex flex-col gap-5 sm:flex-row sm:items-center">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <Server className="size-4 text-primary" aria-hidden="true" />
            <h2 className="font-display text-lg font-bold tracking-wide text-foreground">
              {result.host}
            </h2>
          </div>
          <p className="mt-1.5 text-[0.85rem] leading-relaxed text-muted-foreground">
            {result.summary}
          </p>

          <ul className="mt-3 flex flex-wrap gap-1.5" aria-label="Severity counts">
            {ORDER.map((sev) => {
              const meta = SEVERITY_META[sev]
              return (
                <li
                  key={sev}
                  className={cn(
                    "inline-flex items-baseline gap-1.5 rounded-sm border px-2 py-0.5 text-[0.74rem]",
                    meta.bg,
                    meta.border,
                    meta.text
                  )}
                >
                  <span className="font-display text-sm font-bold tabular-nums">
                    {counts[sev]}
                  </span>
                  <span className="opacity-90">{meta.label}</span>
                </li>
              )
            })}
          </ul>
        </div>

        <div className="flex shrink-0 flex-col items-center gap-3 sm:border-l sm:border-border sm:pl-5">
          <RiskGauge score={result.host_risk_score} />
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={onReset}
            className="gap-1.5"
          >
            <RotateCcw className="size-3.5" aria-hidden="true" />
            New Scan
          </Button>
        </div>
      </div>

      <p className="mt-4 border-t border-border pt-2.5 text-[0.7rem] text-muted-foreground">
        <span className="tactical-label mr-1.5 text-[0.64rem]">Source</span>
        {backendLabel(result)}
      </p>
    </div>
  )
}
