# NetGuard Sentinel

Autonomous vulnerability-triage agent built on Microsoft Foundry.

Given the output of a network scan, it does the analysis a security analyst does next: looks up CVEs for each detected service, scores each one using real exploitability signals, ranks the host worst-first, maps findings to MITRE ATT&CK to reason about the attacker path, then writes remediation ordered to break that path. The demo case is Apache 2.4.49 (CVE-2021-41773) -- on CISA's Known Exploited Vulnerabilities list, EPSS ~0.97 -- ranking above higher-CVSS bugs that nobody is actively exploiting.

This is the agentic sequel to [NetGuard](https://github.com/aimannurzharfan), a Python port scanner. NetGuard finds what's running; Sentinel decides what to do about it.

## How it works

The agent reasons through six stages:

1. **Findings intake** -- parses scan output into structured findings (host, port, service, version).
2. **Vulnerability enrichment** -- calls the `threat_intel_lookup` tool, which returns CVEs with three signals: CVSS base severity (NVD), EPSS exploit probability (FIRST), and CISA KEV known-exploited status.
3. **Composite risk scoring** -- combines the three signals into a 0-100 score per CVE (formula below).
4. **Contextual prioritization** -- ranks findings worst-first; a reachable, actively-exploited medium can outrank an unreachable critical.
5. **Attack-path reasoning** -- maps findings to MITRE ATT&CK techniques and chains them into the likely attacker path through the host.
6. **Remediation synthesis** -- writes a per-finding fix ordered to break the attack path first, plus a one-line host risk summary.

Output is strict JSON (see `agent/schema.py`).

## Composite scoring formula

```
composite = round(min(1, 0.30 * (cvss / 10) + 0.50 * epss + 0.20 * kev_flag) * 100)
```

CVSS contributes 30% (severity baseline). EPSS contributes 50% (real-world exploit probability, the most predictive signal). KEV contributes 20% (active exploitation confirmed by CISA). A CVSS 9.8 bug with no known exploits scores ~29; the same bug on KEV with EPSS 0.97 scores ~91.

## Architecture

```
NetGuard scanner
     |
     v scan JSON
  Web UI  ----POST /triage---->  Flask server  ---->  triage pipeline
                                                            |
                                                  threat_intel_lookup()
                                                       |          |
                                              Layer 1: cache   Layer 2: Oracle 23ai
                                              data/cache/      AI Vector Search
                                              (NVD/EPSS/KEV)   (semantic query)
```

Two layers, one tool interface. The agent calls `threat_intel_lookup(service)` and gets the same CVE records back regardless of which backend is active. Switch with `THREAT_BACKEND=oracle` in `.env`.

**Microsoft Foundry** (the agent runtime) wires in on Day 4 (~June 9) via `agent/foundry_client.py`. Until then the triage pipeline runs as local Python.

## Setup

Requires Python 3.11+, Docker Desktop (for Oracle).

```bash
# Python environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt

# Configuration
cp .env.example .env
# Fill in ORACLE_USER, ORACLE_PASSWORD, and optionally NVD_API_KEY

# Start Oracle 23ai container (or use docker-compose up)
docker compose up -d

# Build the threat data cache
python -m data.fetch_cache

# Load CVE knowledge into Oracle (Layer 2)
python -m data.load_oracle

# Run tests
pytest

# Start the web UI
python -m web.server         # then open http://localhost:5000
```

## Repository layout

```
agent/           Triage pipeline, six-step prompt, output schema, Foundry seam
tools/           threat_intel tool, composite scoring, Oracle backend
data/            NVD/EPSS/KEV fetcher, Oracle loader, embedding module
samples/         Three scan files: badly exposed / moderate / clean
web/             Single-page UI (WCAG 2.1 AA) and Flask server
tests/           Unit tests for scoring and schema; integration tests for the pipeline
docs/            Architecture diagram
```

## Switching backends

```bash
# Layer 1 (default): reads from data/cache/cves.json
THREAT_BACKEND=cache python -m web.server

# Layer 2: Oracle 23ai AI Vector Search
THREAT_BACKEND=oracle python -m web.server
```

## Wiring in Foundry (Day 4)

Open `agent/foundry_client.py`. It contains the stub and the exact implementation to paste in once `FOUNDRY_PROJECT_ENDPOINT`, `FOUNDRY_MODEL_DEPLOYMENT`, and `FOUNDRY_API_KEY` are in `.env`.

## License

MIT
