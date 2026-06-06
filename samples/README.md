# Sample scans

Three hosts in NetGuard scanner format, used by the demo and test suite.

| File | Profile | Purpose |
|---|---|---|
| `host_exposed.json` | Badly exposed | Apache 2.4.49 (CVE-2021-41773, CISA KEV, EPSS ~0.97), vsftpd 2.3.4 backdoor, old OpenSSH. The demo hero case: the KEV CVE ranks first above higher-CVSS bugs. |
| `host_moderate.json` | Mixed | nginx 1.18.0 with a known CVE, OpenSSH 7.4, OpenSSL 1.0.1 (Heartbleed). Tests that scoring separates urgent from non-urgent findings. |
| `host_clean.json` | Current | OpenSSH 8.9 and nginx 1.24.0 -- both current releases with no known actively exploited CVEs. Tests that Sentinel reports low risk and invents no CVE IDs. |

## Format

Each file is a JSON object with `host`, `scan_time`, and `ports` (list of `{port, service, version, banner}`).
This is the output format produced by [NetGuard](https://github.com/aimannurzharfan), the upstream port scanner.
