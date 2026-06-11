# NetGuard Sentinel

Autonomous vulnerability-triage agent built on Microsoft Foundry.

Enter a host. One click. Get back: every open service fingerprinted, each CVE scored by real-world exploitability, findings ranked worst-first, a MITRE ATT&CK attack path, and per-finding remediation ordered to break that path first.

The demo case is Apache 2.4.49 (CVE-2021-41773, on CISA's Known Exploited Vulnerabilities list, EPSS ~0.97) ranking above higher-CVSS bugs that nobody is actively exploiting. Run it locally in two commands.

This project grew out of [NetGuard](https://github.com/aimannurzharfan/Network-Scanner), a Python port scanner written earlier as a learning project. That scanner found what was running; Sentinel decides what to do about it, with the scan step built in.

**Authorized use only. Only scan hosts you own or are explicitly authorized to test.**

## How it works

Six stages, all automated:

1. **Port scan** -- threaded TCP connect scan, banner grab, service and version fingerprinted from the banner with regex (Apache/2.4.49, SSH-2.0-OpenSSH_6.6.1p1, nginx/1.18.0, etc.).
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
                               Phi-4-mini-instruct via            local deterministic
                               Microsoft Foundry (active brain)   Python pipeline
                               foundry_client.run_reasoning()     (fallback)
```

**Two-phase design.** Stages 1-3 (parse, enrich, score) always run as deterministic Python so CVE data and composite scores are always authoritative. Stages 4-6 (prioritize, attack-path reasoning, remediation narrative) are handled by Phi-4-mini-instruct via Microsoft Foundry when `FOUNDRY_ENDPOINT`, `FOUNDRY_MODEL_DEPLOYMENT`, and `FOUNDRY_API_KEY` are set in `.env`. The deterministic pipeline is the fallback when Foundry is unconfigured or returns an error, so the demo never breaks.

Phi-4-mini-instruct reasons over the pre-enriched findings and returns contextual prioritization, an attack-path narrative, and per-finding remediation text. The model cannot change CVE scores, invent CVE IDs, or assign MITRE ATT&CK techniques -- those come only from the deterministic pipeline.

Switch threat enrichment backends with `THREAT_BACKEND=oracle` in `.env`.

## Quick start

Requires Python 3.11 to 3.13. Python 3.14 is not yet supported because numpy and sentence-transformers do not ship 3.14 wheels. Docker Desktop is optional (Oracle Layer 2 and demo target only).

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

`docker-compose.demo.yml` starts three deliberately old services on localhost, each on its own port and each bound to `127.0.0.1` so nothing is reachable off this host. One scan surfaces three CVE-bearing findings across three services, ranked worst-first. The Apache CISA KEV bug stays at priority 1, above the OpenSSH and nginx findings. Every banner reports a real version that its matched CVEs actually affect, so the demo uses only real vulnerability data (live NVD CVSS, FIRST EPSS, CISA KEV).

| Service | Image | Port | Banner reports | CVEs |
| --- | --- | --- | --- | --- |
| Apache httpd | `httpd:2.4.49` | 8080 | `Apache/2.4.49` | CVE-2021-41773, CVE-2021-42013 (CISA KEV) |
| OpenSSH | `rastasheep/ubuntu-sshd:14.04` | 22 | `OpenSSH_6.6.1p1` | CVE-2023-38408, CVE-2016-0777 |
| nginx | `nginx:1.18.0` | 80 | `nginx/1.18.0` | CVE-2021-23017 |

```bash
docker compose -f docker-compose.demo.yml up -d
python -m netguard_sentinel 127.0.0.1 --ports 22,80,8080
```

Or open http://localhost:5000, leave the host as `127.0.0.1`, and click **Scan**. The result appears in a few seconds with all three findings sorted by priority. Each finding only lists CVEs for its own product (the scanner matches on an exact product key, so an Apache query never returns an Apache Struts CVE).

Authorized use: local testing on machines you control only.

## CLI usage

Scan and triage in one command:

```bash
python -m netguard_sentinel 127.0.0.1
python -m netguard_sentinel 127.0.0.1 --ports 22,80,8080   # exactly the demo ports
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
FOUNDRY_MODEL_DEPLOYMENT=Phi-4-mini-instruct
FOUNDRY_API_KEY=<your key>
```

`FOUNDRY_PROJECT_ENDPOINT` is also accepted as a fallback -- the client appends `/openai/v1` automatically. With these set, `triage()` sends enriched findings to Phi-4-mini-instruct for stages 4-6 and falls back to the deterministic pipeline on any error.

## Security and scope

NetGuard Sentinel is a local, authorized-use tool. It is meant to run on your own machine against hosts you own or are explicitly permitted to assess. It is not a hosted service and ships with no authentication layer by design.

- **Default-deny scan targets.** The scanner and the `/scan` endpoint accept only targets that resolve to localhost or RFC1918 private ranges (`10/8`, `172.16/12`, `192.168/16`, loopback). The host is validated, resolved through DNS, and the resolved IP is re-checked against the policy, so a public name cannot slip through by mapping to an internal address. Public targets are refused with a clear message. To scan a public host you are authorized to test, set `ALLOW_PUBLIC_TARGETS=1`; a one-line authorized-use warning is logged whenever the flag is active.
- **Socket-only scanning.** Probing uses plain TCP connect and banner reads. No user input ever reaches a shell, and there is no `subprocess` or `os.system` anywhere in the scan path. Scanning runs with bounded concurrency and per-connection socket timeouts so a scan cannot hang or exhaust resources.
- **Rate limit.** `/scan` is capped at 10 requests per minute per client by default, configurable with `SCAN_RATE_LIMIT`. Exceeding it returns HTTP 429. The limiter is in-process with no external dependency.
- **Server hardening.** Flask debug is off by default, request bodies are capped at 1 MB, error responses are generic with no stack traces, CORS is not enabled, and responses carry `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`.
- **Secrets.** No secrets are committed. `.env`, `.mcp.json`, `_local/`, `.claude/`, and `node_modules/` are gitignored; `.env.example` holds placeholders only.

The localhost demo works one-click out of the box because `127.0.0.1` satisfies the default policy. Scanning `scanme.nmap.org` or any other public host requires the `ALLOW_PUBLIC_TARGETS=1` flag.

## License

MIT
