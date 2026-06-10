import { Radar } from "lucide-react"
import { HelpDialog } from "./HelpDialog"

export function AppHeader() {
  return (
    <header className="relative z-10 border-b border-border bg-card/60 backdrop-blur-sm">
      <div className="mx-auto flex max-w-5xl items-center gap-3 px-5 py-3">
        <span
          className="flex size-9 shrink-0 items-center justify-center rounded-sm border border-primary/40 bg-signal-bg text-primary"
          aria-hidden="true"
        >
          <Radar className="size-5" strokeWidth={1.75} />
        </span>
        <div className="min-w-0">
          <h1 className="font-display text-[1.05rem] font-bold leading-none tracking-[0.14em] text-foreground">
            NETGUARD <span className="text-primary">SENTINEL</span>
          </h1>
          <p className="mt-1 truncate text-[0.72rem] text-muted-foreground">
            Autonomous vulnerability triage console
          </p>
        </div>
        <div className="ml-auto">
          <HelpDialog />
        </div>
      </div>
    </header>
  )
}
