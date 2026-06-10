import { ChevronRight, Crosshair, Scissors } from "lucide-react"
import type { AttackPath as AttackPathType } from "@/lib/types"

export function AttackPath({ attackPath }: { attackPath: AttackPathType | null }) {
  if (!attackPath || !attackPath.narrative) return null

  return (
    <section aria-labelledby="attack-heading">
      <h3
        id="attack-heading"
        className="tactical-label mb-2 flex items-center gap-2 text-[0.72rem] text-muted-foreground"
      >
        <Crosshair className="size-3.5" aria-hidden="true" />
        Attack path / MITRE ATT&CK
      </h3>
      <div className="hud-frame rounded-md border border-border bg-card p-4">
        <p className="text-[0.88rem] leading-relaxed text-foreground">
          {attackPath.narrative}
        </p>

        {attackPath.steps.length > 0 ? (
          <ol
            className="mt-4 flex flex-wrap items-stretch gap-1.5"
            aria-label="Attack chain steps"
          >
            {attackPath.steps.map((s, i) => (
              <li key={`${s.finding_port}-${i}`} className="flex items-center gap-1.5">
                <div className="rounded-sm border border-border bg-secondary px-2.5 py-1.5 text-center">
                  <div className="font-display text-[0.78rem] font-semibold text-foreground">
                    {s.technique}
                  </div>
                  <div className="text-[0.66rem] text-muted-foreground">
                    {s.tactic}
                  </div>
                  <div className="text-[0.62rem] text-muted-foreground/80">
                    port {s.finding_port}
                  </div>
                </div>
                {i < attackPath.steps.length - 1 ? (
                  <ChevronRight
                    className="size-4 shrink-0 text-primary"
                    aria-hidden="true"
                  />
                ) : null}
              </li>
            ))}
          </ol>
        ) : null}

        {attackPath.break_point ? (
          <div className="mt-4 flex gap-2 rounded-sm border-l-2 border-low bg-low-bg/60 px-3 py-2">
            <Scissors
              className="mt-0.5 size-4 shrink-0 text-low"
              aria-hidden="true"
            />
            <p className="text-[0.84rem] leading-relaxed text-foreground">
              <span className="tactical-label mr-1.5 text-[0.66rem] text-low">
                Break point
              </span>
              {attackPath.break_point}
            </p>
          </div>
        ) : null}
      </div>
    </section>
  )
}
