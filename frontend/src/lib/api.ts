import type { TriageResult } from "./types"

// The two backend endpoints are unchanged from the original UI:
//   POST /scan   { host }   -> scans the host, then triages
//   POST /triage { scan }   -> triages a pre-built scan JSON string
async function postJson(url: string, body: unknown): Promise<TriageResult> {
  let resp: Response
  try {
    resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : "network error"
    throw new Error(`Could not reach the server: ${message}`)
  }

  let data: unknown
  try {
    data = await resp.json()
  } catch {
    throw new Error(`Server returned an unreadable response (${resp.status}).`)
  }

  if (!resp.ok) {
    const error =
      data && typeof data === "object" && "error" in data
        ? String((data as { error: unknown }).error)
        : `Server returned ${resp.status}.`
    throw new Error(error)
  }
  return data as TriageResult
}

export function scanHost(host: string): Promise<TriageResult> {
  return postJson("/scan", { host })
}

export function triageScan(scan: string): Promise<TriageResult> {
  return postJson("/triage", { scan })
}
