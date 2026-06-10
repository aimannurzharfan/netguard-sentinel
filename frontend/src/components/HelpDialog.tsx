import { HelpCircle } from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"

const SIGNALS: { term: string; range: string; desc: string }[] = [
  {
    term: "Composite",
    range: "0 - 100",
    desc: "Sentinel's ranking score: severity plus exploit probability plus KEV. Fix the highest first.",
  },
  {
    term: "CVSS",
    range: "0 - 10",
    desc: "Flaw severity. A high CVSS does not mean attackers are targeting it yet.",
  },
  {
    term: "EPSS",
    range: "0 - 100%",
    desc: "Probability the flaw is exploited in the next 30 days (FIRST.org model).",
  },
  {
    term: "KEV",
    range: "flag",
    desc: "On CISA's Known Exploited list: confirmed exploited in the wild right now.",
  },
]

export function HelpDialog() {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="gap-1.5 text-muted-foreground hover:text-foreground"
        >
          <HelpCircle className="size-4" aria-hidden="true" />
          What do these mean?
        </Button>
      </DialogTrigger>
      <DialogContent className="hud-frame border-border bg-card sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="font-display tracking-wide">
            Reading the signals
          </DialogTitle>
          <DialogDescription>
            Sentinel ranks by composite risk, not raw severity, so an actively
            exploited medium can outrank an unexploited critical.
          </DialogDescription>
        </DialogHeader>
        <dl className="divide-y divide-border">
          {SIGNALS.map((s) => (
            <div
              key={s.term}
              className="grid grid-cols-[7rem_1fr] gap-3 py-2.5"
            >
              <dt className="font-display text-sm font-semibold text-foreground">
                {s.term}
                <span className="ml-1.5 block text-[0.68rem] font-normal tracking-wide text-muted-foreground">
                  {s.range}
                </span>
              </dt>
              <dd className="text-[0.82rem] leading-relaxed text-muted-foreground">
                {s.desc}
              </dd>
            </div>
          ))}
        </dl>
      </DialogContent>
    </Dialog>
  )
}
