import { useState } from "react"
import { Radar, ShieldAlert, TriangleAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion"
import { SAMPLE_SCAN } from "@/lib/sample"

interface ScanConsoleProps {
  busy: boolean
  statusText: string
  onScan: (host: string) => void
  onAnalyze: (scan: string) => void
}

export function ScanConsole({
  busy,
  statusText,
  onScan,
  onAnalyze,
}: ScanConsoleProps) {
  const [host, setHost] = useState("127.0.0.1")
  const [scanJson, setScanJson] = useState("")

  function submitScan(e: React.FormEvent) {
    e.preventDefault()
    onScan(host.trim())
  }

  return (
    <section
      className="hud-frame relative rounded-md border border-border bg-card/80 p-5 sm:p-7"
      aria-labelledby="scan-heading"
    >
      <h2 id="scan-heading" className="tactical-label text-[0.72rem] text-primary">
        Target acquisition
      </h2>
      <p className="mt-1 mb-5 max-w-xl text-sm text-muted-foreground">
        Enter a host and run a scan. Sentinel finds the open services, enriches
        them with live threat intel, and tells you what to fix first.
      </p>

      <form onSubmit={submitScan} noValidate>
        <label
          htmlFor="host-input"
          className="tactical-label mb-2 block text-[0.68rem] text-muted-foreground"
        >
          Target host
        </label>
        <div className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Radar
              className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              id="host-input"
              name="host"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="e.g. 127.0.0.1 or scanme.example.com"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              inputMode="url"
              aria-describedby="host-hint"
              className="h-12 pl-9 font-mono text-base"
            />
          </div>
          <Button
            type="submit"
            size="lg"
            disabled={busy}
            className="h-12 px-7 text-base font-semibold"
          >
            {busy ? (
              <>
                <Radar className="size-4 animate-spin" aria-hidden="true" />
                Scanning…
              </>
            ) : (
              <>
                <ShieldAlert className="size-4" aria-hidden="true" />
                Scan
              </>
            )}
          </Button>
        </div>
        <p id="host-hint" className="mt-2 text-[0.76rem] text-muted-foreground">
          Common ports are scanned automatically. Only scan hosts you own or are
          authorized to test.
        </p>
      </form>

      <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1">
        <button
          type="button"
          disabled={busy}
          onClick={() => onAnalyze(SAMPLE_SCAN)}
          className="rounded-sm text-[0.76rem] text-primary underline-offset-4 hover:underline disabled:opacity-50"
        >
          or run a built-in sample host
        </button>
      </div>

      {/* Live status: announced to assistive tech as phases progress. */}
      <p
        className="mt-4 min-h-5 font-mono text-[0.78rem] text-muted-foreground"
        role="status"
        aria-live="polite"
      >
        {statusText}
      </p>

      {/* Advanced, visually subordinate: paste a raw scan JSON. */}
      <Accordion type="single" collapsible className="mt-4 border-t border-border">
        <AccordionItem value="paste" className="border-b-0">
          <AccordionTrigger className="py-3 text-[0.78rem] text-muted-foreground hover:text-foreground hover:no-underline">
            Advanced: paste scan JSON
          </AccordionTrigger>
          <AccordionContent>
            <label htmlFor="scan-json" className="sr-only">
              Scan JSON
            </label>
            <textarea
              id="scan-json"
              name="scan"
              value={scanJson}
              onChange={(e) => setScanJson(e.target.value)}
              spellCheck={false}
              placeholder='{"host": "10.0.0.5", "ports": [{"port": 80, "service": "Apache httpd", "version": "2.4.49"}]}'
              className="h-36 w-full resize-y rounded-sm border border-input bg-background p-3 font-mono text-[0.82rem] text-foreground placeholder:text-muted-foreground/70 focus-visible:outline-2 focus-visible:outline-ring"
            />
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="secondary"
                size="sm"
                disabled={busy}
                onClick={() => onAnalyze(scanJson.trim())}
              >
                <TriangleAlert className="size-4" aria-hidden="true" />
                Analyze JSON
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={busy}
                onClick={() => setScanJson(SAMPLE_SCAN)}
              >
                Load Sample JSON
              </Button>
            </div>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </section>
  )
}
