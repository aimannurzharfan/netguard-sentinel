"""One-shot: capture a single live Phi-4-mini-instruct response for offline testing.

Wraps foundry_client.run_reasoning so the exact raw text the real pipeline
receives is teed to tests/fixtures/foundry_exposed_raw.txt, then runs triage()
once on the exposed-host sample. This is the ONLY live model call we make.

Usage: python scripts/capture_foundry_fixture.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv()

FIXTURE = ROOT / "tests" / "fixtures" / "foundry_exposed_raw.txt"


def main() -> int:
    from agent import foundry_client

    if not foundry_client.is_configured():
        print("Foundry not configured; aborting (no fixture written).")
        return 1

    original = foundry_client.run_reasoning
    captured: list[str] = []

    def tee(system_prompt: str, payload: str) -> str:
        raw = original(system_prompt, payload)
        captured.append(raw)
        return raw

    foundry_client.run_reasoning = tee  # ty: ignore[invalid-assignment]

    from agent.agent import triage

    scan = (ROOT / "samples" / "host_exposed.json").read_text(encoding="utf-8")
    print("Making ONE live Phi-4-mini-instruct call on samples/host_exposed.json ...")
    result = triage(scan)

    if not captured:
        print(
            "No raw response captured (Foundry path did not run). Backend:",
            result.threat_backend,
        )
        return 2

    raw = captured[0]
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(raw, encoding="utf-8")
    print(f"Wrote {len(raw)} chars to {FIXTURE}")
    print("threat_backend:", result.threat_backend)
    top = next((f for f in result.findings if f.priority == 1), None)
    if top:
        print("priority-1 port:", top.port, "CVEs:", [c.id for c in top.cves])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
