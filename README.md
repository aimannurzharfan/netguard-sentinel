# NetGuard Sentinel

Autonomous vulnerability-triage agent built on Microsoft Foundry.

Enter a host. One click. Get back: every open service fingerprinted, each CVE scored by real-world exploitability, findings ranked worst-first, a MITRE ATT&CK attack path, and per-finding remediation ordered to break that path first.

The demo case is Apache 2.4.49 (CVE-2021-41773, on CISA's Known Exploited Vulnerabilities list, EPSS ~0.97) ranking above higher-CVSS bugs that nobody is actively exploiting. Run it locally in two commands.

This project grew out of [NetGuard](https://github.com/aimannurzharfan/Network-Scanner), a Python port scanner written earlier as a learning project. That scanner found what was running; Sentinel decides what to do about it, with the scan step built in.

**Authorized use only. Only scan hosts you own or are explicitly authorized to test.**

## How it works

Six stages, all automated:

1. **Port scan** -- threaded TCP connect scan, banner grab, service and version fingerprinted from the banner with regex (Apache/2.4.49, SSH-2.0-OpenSSH_7.4, 220 (vsFTPd 2.3.4), etc.).
2. **Vulnerability enrichment** -- calls the `threat_intel_lookup` tool, which returns CVEs with CVSS base score (NVD), EPSS exploit probability (FIRST), and CISA KEV known-exploited status.
3. **Composite risk scoring** -- combines the three signals into a 0-100 score per CVE (formula below).
4. **Contextual prioritization** -- ranks findings worst-first. A reachable, actively-exploited medium outranks an unreachable critical.
5. **Attack-path reasoning** -- maps findings to MITRE ATT&CK techniques and chains them into the likely attacker path through the host.
6. **Remediation synthesis** -- writes a per-finding fix ordered to break the attack path first, plus a one-line host risk summary.

Output is strict JSON (schema in `agent/schema.py`).

## Network exposure override

The triage pipeline applies a context pass after composite scoring. When a scan includes exposure data (present in pre-built samples and added automatically by the scanner for IP addresses), two rules fire:

1. **Elevation**: sensitive data-store services (MySQL 3306, PostgreSQL 5432, Redis 6379, MongoDB 27017) with `bind_address == "0.0.0.0"` or `exposure == "internet"` are moved to the top of the priority list, ahead of CVE-scored services. These ports are dangerous regardless of whether a matching CVE is in the cache. The finding rationale says explicitly why the override fired.

2. **Downgrade**: SMB (port 445) on a confirmed internal host (`exposure == "internal"`) is deprioritised. Lateral-movement risk is lower when the host is not internet-reachable.

The override only fires on data actually present in the scan. A scan with no `exposure` field and no `bind_address` values is not modified. This is enforced in the code and verified by tests.

These behaviors run in Layer 1 (deterministic Python) now. Once wired, the Foundry LLM will reason over the same exposure context with the deterministic pipeline as fallback.

## Executable remediation commands

Each finding includes a `remediation_command` field: a single copy-pasteable shell command for the most urgent remediation step. Examples:

- Exposed Redis on 0.0.0.0: `sudo iptables -A INPUT -p tcp --dport 6379 -j DROP`
- Apache httpd: `sudo apt-get install --only-upgrade apache2`
- vsftpd 2.3.4 (backdoored): `sudo systemctl disable --now vsftpd`

The command is rendered in the UI as a monospace block under each finding. The longer human-readable `remediation` text is kept alongside it.

## Composite scoring formula

```
composite = round(min(1, 0.30 * (cvss / 10) + 0.50 * epss + 0.20 * kev_flag) * 100)
```

CVSS contributes 30% (severity baseline). EPSS contributes 50% (real-world exploit probability, the most predictive signal). KEV contributes 20% (active exploitation confirmed by CISA). A CVSS 9.8 bug with no known exploits scores ~29; the same bug on KEV with EPSS 0.97 scores ~91.

## Architecture

![Architecture](docs/architecture.png)

```
                          python -m netguard_sentinel <host>
                                         |
                          Web UI (Scan button)  ----POST /scan---->  Flask server
                                                                           |
                                                                    scanner/scan.py
                                                                    (TCP connect, banner)
                                                                           |
                                                               agent/agent.py (6-step)
                                                                           |
                                              Stages 1-3 (always run in Python)
                                                 threat_intel_lookup() per service
                                                    |                    |
                                          cache: data/cache/      Oracle 23ai
                                          (NVD/EPSS/KEV JSON)     AI Vector Search
                                                           |
                                              composite scores computed (0-100)
                                                           |
                                        Stages 4-6: prioritize, attack-path, remediation
                                                           |
                                              +------------+------------+
                                              |                         |
                               Phi-4-reasoning on Azure           local deterministic
                               AI Foundry (active brain)          Python pipeline
                               foundry_client.run_reasoning()     (fallback)
```

**Two-phase design.** Stages 1-3 (parse, enrich, score) always run as deterministic Python so CVE data and composite scores are always authoritative. Stages 4-6 (prioritize, attack-path reasoning, remediation narrative) are handled by Phi-4-reasoning on Azure AI Foundry when `FOUNDRY_ENDPOINT`, `FOUNDRY_MODEL_DEPLOYMENT`, and `FOUNDRY_API_KEY` are set in `.env`. The deterministic pipeline is the fallback when Foundry is unconfigured or returns an error, so the demo never breaks.

Phi-4-reasoning reasons over the pre-enriched findings and returns contextual prioritization, MITRE ATT&CK attack-path analysis with a narrative, and per-finding remediation text. The model cannot change CVE scores or invent CVE IDs -- those come only from the deterministic pipeline.

Switch threat enrichment backends with `THREAT_BACKEND=oracle` in `.env`.

## Quick start

Requires Python 3.11+. Docker Desktop is optional (Oracle Layer 2 and demo target only).

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt

cp .env.example .env
# Set ORACLE_PASSWORD if you plan to use Layer 2.

# data/cache/cves.json ships committed for an offline deterministic demo.
# Run the line below only when you want to refresh it from NVD/EPSS/KEV.
# python -m data.fetch_cache
pytest                          # run the test suite
python -m web.server            # start the UI at http://localhost:5000
```

## Demo: scan a deliberately vulnerable local target

The demo container runs Apache 2.4.49 on localhost port 8080. The scanner fingerprints it, triage returns CVE-2021-41773 at priority 1.

```bash
docker compose -f docker-compose.demo.yml up -d
```

Open http://localhost:5000, leave the host as `127.0.0.1`, and click **Scan**. The result appears in a few seconds.

Authorized use: local testing on machines you control only.

## CLI usage

Scan and triage in one command:

```bash
python -m netguard_sentinel 127.0.0.1
python -m netguard_sentinel 127.0.0.1 --ports 80,8080,22,21
```

Scanner only (outputs raw scan JSON):

```bash
python -m scanner.scan 127.0.0.1
python -m scanner.scan 127.0.0.1 --ports 80,8080 --out scan.json
```

Triage only (pipe a pre-built scan JSON):

```bash
python -m web.server            # then POST /triage with {"scan": "<json>"}
```

## Repository layout

```
scanner/         TCP connect scanner, banner fingerprinting
netguard_sentinel/  End-to-end CLI entry point
agent/           Six-step triage pipeline, output schema, Foundry seam
tools/           threat_intel tool, composite scoring, Oracle backend
data/            NVD/EPSS/KEV fetcher, Oracle loader, embedding module
samples/         Three scan files: badly exposed / moderate / clean
web/             Single-page UI (WCAG 2.1 AA) and Flask server
tests/           Unit and integration tests
docs/            Architecture diagram
```

## Switching backends

```bash
# Layer 1 (default): reads from data/cache/cves.json
THREAT_BACKEND=cache python -m web.server

# Layer 2: Oracle 23ai AI Vector Search
# Start Oracle first: docker compose up -d
# Load knowledge: python -m data.load_oracle
THREAT_BACKEND=oracle python -m web.server
```

Oracle defaults: user `system`, DSN `localhost:1521/FREEPDB1`. Only `ORACLE_PASSWORD` must be set in `.env`.

## Enabling Foundry reasoning

Set three variables in `.env`:

```
FOUNDRY_ENDPOINT=https://<resource>.services.ai.azure.com/api/projects/<project>/openai/v1
FOUNDRY_MODEL_DEPLOYMENT=Phi-4-reasoning
FOUNDRY_API_KEY=<your key>
```

`FOUNDRY_PROJECT_ENDPOINT` is also accepted as a fallback -- the client appends `/openai/v1` automatically. With these set, `triage()` sends enriched findings to Phi-4-reasoning for stages 4-6 and falls back to the deterministic pipeline on any error.

## License

MIT
