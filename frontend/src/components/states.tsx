import { CircleCheck, OctagonAlert } from "lucide-react"
import { Skeleton } from "@/components/ui/skeleton"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"

/** Loading: a skeleton that mirrors the real dashboard so layout does not jump. */
export function LoadingState({ phase }: { phase: string }) {
  return (
    <div className="space-y-4" aria-hidden="true">
      <div className="rounded-md border border-border bg-card p-5">
        <div className="flex flex-col gap-5 sm:flex-row sm:items-center">
          <div className="flex-1 space-y-3">
            <Skeleton className="h-6 w-40" />
            <Skeleton className="h-4 w-full max-w-md" />
            <div className="flex gap-2">
              <Skeleton className="h-6 w-20" />
              <Skeleton className="h-6 w-16" />
              <Skeleton className="h-6 w-20" />
              <Skeleton className="h-6 w-16" />
            </div>
          </div>
          <Skeleton className="size-28 rounded-full" />
        </div>
      </div>
      {[0, 1, 2].map((i) => (
        <div key={i} className="space-y-3 rounded-md border border-border bg-card p-4">
          <div className="flex gap-2">
            <Skeleton className="h-6 w-24" />
            <Skeleton className="h-6 w-20" />
            <Skeleton className="h-6 w-32" />
          </div>
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-4/5" />
          <Skeleton className="h-9 w-full" />
        </div>
      ))}
      <p className="text-center font-mono text-[0.78rem] text-muted-foreground">
        {phase || "Working…"}
      </p>
    </div>
  )
}

/** Error: a clearly marked, assertive alert with the server's message. */
export function ErrorState({ message }: { message: string }) {
  return (
    <Alert
      variant="destructive"
      className="hud-frame border-destructive/50 bg-critical-bg/50 text-foreground"
    >
      <OctagonAlert className="size-4" aria-hidden="true" />
      <AlertTitle className="tactical-label text-critical">
        Scan failed
      </AlertTitle>
      <AlertDescription className="text-muted-foreground">
        {message}
        <span className="mt-1 block text-[0.78rem]">
          Check the host is reachable and the server is running, then try again.
        </span>
      </AlertDescription>
    </Alert>
  )
}

/** Empty: a real result with zero findings is good news, not an error. */
export function EmptyFindings({ host }: { host: string }) {
  return (
    <div className="flex items-start gap-3 rounded-md border border-low/40 bg-low-bg/50 p-4">
      <CircleCheck className="mt-0.5 size-5 shrink-0 text-low" aria-hidden="true" />
      <div>
        <p className="font-display text-sm font-semibold text-low">
          No known vulnerabilities
        </p>
        <p className="mt-1 text-[0.84rem] leading-relaxed text-muted-foreground">
          Sentinel scanned {host} and matched no CVEs against the detected
          service versions. Keep monitoring as new advisories land.
        </p>
      </div>
    </div>
  )
}
