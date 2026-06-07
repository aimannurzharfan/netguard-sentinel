# Sample scans

Five hosts in NetGuard scanner format, used by the demo and test suite.

| File | Profile | Purpose |
|---|---|---|
| `host_exposed.json` | Internet-exposed, critically vulnerable | Apache 2.4.49 (CVE-2021-41773, CISA KEV, EPSS ~0.97), vsftpd 2.3.4 backdoor, old OpenSSH, OpenSSL 1.0.1 (Heartbleed). The demo hero case: the KEV CVE ranks first above higher-CVSS bugs. All ports bound to 0.0.0.0 on an internet host. |
| `host_noisy.json` | Internet-exposed, many services | 9 services including MySQL:3306 and Redis:6379 bound to 0.0.0.0. ProFTPD has CVSS 10.0 but no KEV; the exposure override elevates the two exposed data-stores above the CVSS-only winners. Shows the CVSS-vs-composite reordering clearly. |
| `host_moderate.json` | Mixed | nginx 1.18.0 with a known CVE, OpenSSH 7.4, OpenSSL 1.0.1 (Heartbleed). Tests that scoring separates urgent from non-urgent findings. |
| `host_clean.json` | Current | OpenSSH 8.9 and nginx 1.24.0 -- both current releases with no known actively exploited CVEs. Tests that Sentinel reports low risk and invents no CVE IDs. |

## Format

Each file is a JSON object with `host`, `scan_time`, optional `exposure` (`"internet"` or `"internal"`), and `ports`.

Each port record has `port`, `service`, `version`, `banner`, and optional `bind_address`. When `bind_address` is `"0.0.0.0"` or `exposure` is `"internet"`, sensitive data-store ports (MySQL 3306, PostgreSQL 5432, Redis 6379, MongoDB 27017) are elevated in priority by the exposure override, regardless of whether they have CVE data.

This is the extended format produced by the built-in scanner in `scanner/scan.py`. The `exposure` field is derived automatically from the host IP (RFC1918 = internal, public = internet). The `bind_address` field can only be populated by the scanner when it has local socket information; it is absent from live TCP connect scans and must be supplied in pre-built sample files.
