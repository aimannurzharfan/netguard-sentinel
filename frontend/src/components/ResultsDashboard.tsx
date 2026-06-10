import { ListTree } from "lucide-react"
import type { TriageResult } from "@/lib/types"
import { HostOverview } from "./HostOverview"
import { PriorityComparison } from "./PriorityComparison"
import { FindingCard } from "./FindingCard"
import { AttackPath } from "./AttackPath"
import { EmptyFindings } from "./states"

export function ResultsDashboard({
  result,
  onReset,
}: {
  result: TriageResult
  onReset: () => void
}) {
  const findings = result.findings ?? []

  return (
    <div className="space-y-4">
      <HostOverview result={result} onReset={onReset} />

      <PriorityComparison
        findings={findings}
        naive={result.naive_cvss_order ?? []}
      />

      {findings.length === 0 ? (
        <EmptyFindings host={result.host} />
      ) : (
        <section aria-labelledby="findings-heading">
          <h3
            id="findings-heading"
            className="tactical-label mb-2 flex items-center gap-2 text-[0.72rem] text-muted-foreground"
          >
            <ListTree className="size-3.5" aria-hidden="true" />
            Findings ranked by risk ({findings.length})
          </h3>
          <div className="space-y-3">
            {findings.map((f) => (
              <FindingCard key={`${f.port}-${f.service}`} finding={f} />
            ))}
          </div>
        </section>
      )}

      <AttackPath attackPath={result.attack_path} />
    </div>
  )
}
