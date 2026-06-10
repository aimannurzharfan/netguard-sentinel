import { useCallback, useRef, useState } from "react"
import type { TriageResult } from "@/lib/types"
import { scanHost, triageScan } from "@/lib/api"
import { backendLabel } from "@/lib/format"
import { AppHeader } from "@/components/AppHeader"
import { ScanConsole } from "@/components/ScanConsole"
import { ResultsDashboard } from "@/components/ResultsDashboard"
import { ErrorState, LoadingState } from "@/components/states"

type Status = "idle" | "loading" | "result" | "error"

const PHASES: { at: number; text: string }[] = [
  { at: 0, text: "Scanning ports and grabbing service banners…" },
  { at: 3000, text: "Enriching findings with live threat intel…" },
  { at: 7000, text: "Scoring and mapping MITRE ATT&CK…" },
  { at: 12000, text: "Reasoning over the attack path and remediation…" },
]

export default function App() {
  const [status, setStatus] = useState<Status>("idle")
  const [result, setResult] = useState<TriageResult | null>(null)
  const [error, setError] = useState("")
  const [phase, setPhase] = useState("Enter a host and run a scan.")
  const [live, setLive] = useState("")
  const timers = useRef<number[]>([])

  const clearTimers = useCallback(() => {
    timers.current.forEach(window.clearTimeout)
    timers.current = []
  }, [])

  const run = useCallback(
    async (label: string, work: () => Promise<TriageResult>) => {
      clearTimers()
      setStatus("loading")
      setResult(null)
      setError("")
      setLive(`${label} started.`)
      timers.current = PHASES.map((p) =>
        window.setTimeout(() => setPhase(p.text), p.at)
      )
      try {
        const data = await work()
        clearTimers()
        setResult(data)
        setStatus("result")
        const n = data.findings?.length ?? 0
        const done = `Done. ${n} finding${n === 1 ? "" : "s"} analyzed via ${backendLabel(data)}.`
        setPhase(done)
        setLive(
          `${label} complete. ${n} finding${n === 1 ? "" : "s"}. Host risk ${data.host_risk_score} of 100.`
        )
      } catch (err) {
        clearTimers()
        const message = err instanceof Error ? err.message : "Unknown error."
        setError(message)
        setStatus("error")
        setPhase("Scan failed.")
        setLive(`${label} failed: ${message}`)
      }
    },
    [clearTimers]
  )

  const onScan = useCallback(
    (host: string) => {
      if (!host) {
        setPhase("Enter a target host first.")
        document.getElementById("host-input")?.focus()
        return
      }
      void run("Scan", () => scanHost(host))
    },
    [run]
  )

  const onAnalyze = useCallback(
    (scan: string) => {
      if (!scan) {
        setPhase("Paste a scan JSON first.")
        return
      }
      void run("Analysis", () => triageScan(scan))
    },
    [run]
  )

  const onReset = useCallback(() => {
    clearTimers()
    setStatus("idle")
    setResult(null)
    setError("")
    setPhase("Enter a host and run a scan.")
    setLive("Cleared. Ready for a new scan.")
    document.getElementById("host-input")?.focus()
  }, [clearTimers])

  return (
    <div className="relative z-10 flex min-h-dvh flex-col">
      <a
        href="#results"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-sm focus:bg-primary focus:px-3 focus:py-2 focus:font-semibold focus:text-primary-foreground"
      >
        Skip to results
      </a>
      <AppHeader />

      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-6 sm:px-5">
        <ScanConsole
          busy={status === "loading"}
          statusText={phase}
          onScan={onScan}
          onAnalyze={onAnalyze}
        />

        <section
          id="results"
          role="region"
          aria-label="Triage results"
          aria-live="polite"
          aria-atomic="false"
          className="mt-5 scroll-mt-4"
        >
          {/* Concise summary announced first when the live region updates. */}
          <p className="sr-only">{live}</p>
          {status === "loading" ? <LoadingState phase={phase} /> : null}
          {status === "error" ? <ErrorState message={error} /> : null}
          {status === "result" && result ? (
            <ResultsDashboard result={result} onReset={onReset} />
          ) : null}
        </section>
      </main>

      <footer className="relative z-10 border-t border-border px-4 py-4 text-center text-[0.72rem] text-muted-foreground sm:px-5">
        NetGuard Sentinel. Authorized testing only. Scan hosts you own or are
        permitted to assess.
      </footer>
    </div>
  )
}
