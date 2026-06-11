"""Lightweight threaded TCP connect scanner.

Grabs service banners from open ports and fingerprints the service and version
using regex patterns. Returns the scan JSON schema that the triage pipeline
expects: {"host", "scan_time", "ports": [{"port", "service", "version", "banner"}]}.

Usage:
    python -m scanner.scan <host> [--ports 80,443,...] [--out scan.json]

Only scan hosts you own or are explicitly authorized to test.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import ipaddress
import json
import logging
import os
import re
import socket
import sys
from pathlib import Path

logger = logging.getLogger("netguard.scanner")

# RFC1918 and loopback address ranges used for exposure classification.
_INTERNAL_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::1/128"),
)

# Hostname/IP characters only; length bounded to 253 (max DNS name length).
_VALID_HOST = re.compile(r"^[A-Za-z0-9.\-_:]{1,253}$")


class TargetPolicyError(ValueError):
    """Raised when a scan target is rejected by the default-deny policy.

    Carries an HTTP status hint so the web layer can map format errors (400)
    apart from policy refusals (403) without re-parsing the message.
    """

    def __init__(self, message: str, status: int = 403) -> None:
        super().__init__(message)
        self.status = status


def _is_internal_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr in net for net in _INTERNAL_NETWORKS)


def _allow_public_targets() -> bool:
    """Read the opt-in flag at call time so tests and operators can toggle it."""
    return os.getenv("ALLOW_PUBLIC_TARGETS", "0") == "1"


def validate_and_resolve_target(
    host: str, allow_public: bool | None = None
) -> list[str]:
    """Validate a scan target and resolve it to the IPs that will be scanned.

    Enforces the default-deny policy: a target is only allowed when every IP it
    resolves to is loopback or RFC1918 private. Public targets are refused
    unless ``allow_public`` (or the ALLOW_PUBLIC_TARGETS env flag) is set, in
    which case a one-line authorized-use warning is logged.

    Returns the resolved IP strings (deduped). The caller should scan these
    resolved IPs, not the original name, so a name cannot be re-resolved to a
    different address between this check and the scan.

    Raises TargetPolicyError (status 400 for malformed/unresolvable input,
    403 for a policy refusal).
    """
    if not isinstance(host, str) or not host.strip():
        raise TargetPolicyError("host must be a non-empty string.", status=400)
    host = host.strip()
    if not _VALID_HOST.match(host):
        raise TargetPolicyError(
            "Invalid host format (use a hostname or IP address).", status=400
        )

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise TargetPolicyError(
            f"Could not resolve host '{host}'.", status=400
        ) from None
    resolved = sorted({str(info[4][0]) for info in infos})
    if not resolved:
        raise TargetPolicyError(f"Could not resolve host '{host}'.", status=400)

    if allow_public is None:
        allow_public = _allow_public_targets()

    public = [ip for ip in resolved if not _is_internal_ip(ipaddress.ip_address(ip))]
    if public and not allow_public:
        raise TargetPolicyError(
            f"Refusing to scan public target '{host}' "
            f"(resolves to {', '.join(public)}). NetGuard Sentinel only scans "
            "localhost and private networks by default. Set ALLOW_PUBLIC_TARGETS=1 "
            "to scan a host you are explicitly authorized to assess.",
            status=403,
        )
    if public:
        logger.warning(
            "ALLOW_PUBLIC_TARGETS is set: scanning public target %s (%s). "
            "Authorized use only; scan hosts you own or are permitted to assess.",
            host,
            ", ".join(public),
        )
    return resolved


def _classify_exposure(host: str) -> str | None:
    """Return 'internal' for RFC1918/loopback, 'internet' for public IPs.

    Returns None for hostnames (cannot classify without a DNS lookup and
    we never guess).
    """
    try:
        addr = ipaddress.ip_address(host)
        return "internal" if _is_internal_ip(addr) else "internet"
    except ValueError:
        return None


CONNECT_TIMEOUT = 2.0
BANNER_TIMEOUT = 2.0
MAX_BANNER_BYTES = 2048
MAX_WORKERS = 50

DEFAULT_PORTS = [
    21,
    22,
    23,
    25,
    80,
    110,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    27017,
]

# Ports where we probe with an HTTP HEAD request to elicit a Server: header.
_HTTP_PROBE_PORTS: frozenset[int] = frozenset({80, 8080})

# (compiled_pattern, service_name) pairs. Ordered specific-to-general so the
# best match wins. Group 1 captures the version string.
_FINGERPRINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"SSH-[\d.]+-OpenSSH[_/]([\d.p]+)", re.IGNORECASE), "OpenSSH"),
    (re.compile(r"\bApache[/ ]([\d.]+)", re.IGNORECASE), "Apache httpd"),
    (re.compile(r"\bnginx[/ ]([\d.]+)", re.IGNORECASE), "nginx"),
    (re.compile(r"vsFTPd[/ ]?([\d.]+)", re.IGNORECASE), "vsftpd"),
    (re.compile(r"ProFTPD[/ ]?([\d.]+)", re.IGNORECASE), "ProFTPD"),
    (re.compile(r"PostgreSQL[/ ]([\d.]+)", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"MongoDB[/ ]([\d.]+)", re.IGNORECASE), "MongoDB"),
    (re.compile(r"\bRedis[/ ]([\d.]+)", re.IGNORECASE), "Redis"),
    (re.compile(r"OpenSSL[/ ]([\d.]+[a-z]?)", re.IGNORECASE), "OpenSSL"),
    (re.compile(r"\bMySQL[/ ]([\d.]+)", re.IGNORECASE), "MySQL"),
]

# Port-based fallback service name when no banner regex matches.
_PORT_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP",
    8443: "HTTPS",
    27017: "MongoDB",
}


def _grab_banner(host: str, port: int) -> str | None:
    """Connect to host:port and return the opening banner, or None if unreachable."""
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(BANNER_TIMEOUT)
            if port in _HTTP_PROBE_PORTS:
                # Strip any CRLF from host before embedding in the HTTP header.
                safe_host = host.replace("\r", "").replace("\n", "")
                probe = (
                    f"HEAD / HTTP/1.0\r\nHost: {safe_host}\r\nConnection: close\r\n\r\n"
                ).encode("ascii", errors="replace")
                sock.sendall(probe)
            data = bytearray()
            try:
                while len(data) < MAX_BANNER_BYTES:
                    chunk = sock.recv(512)
                    if not chunk:
                        break
                    data.extend(chunk)
            except (socket.timeout, OSError):
                pass
            return data.decode("utf-8", errors="replace").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def _fingerprint(banner: str, port: int) -> tuple[str, str]:
    """Return (service_name, version) from a banner string.

    Returns an empty version when the banner matches by port fallback only.
    """
    for pattern, service in _FINGERPRINTS:
        m = pattern.search(banner)
        if m:
            return service, m.group(1)
    return _PORT_SERVICES.get(port, ""), ""


def _scan_port(host: str, port: int) -> dict | None:
    """Probe a single port. Returns None if closed or filtered."""
    banner = _grab_banner(host, port)
    if banner is None:
        return None
    service, version = _fingerprint(banner, port)
    return {
        "port": port,
        "service": service,
        "version": version,
        "banner": banner[:256],
    }


def scan(host: str, ports: list[int] | None = None) -> dict:
    """TCP connect scan of host on the given port list.

    Returns a dict with keys: host, scan_time, ports (list of open-port records).
    The schema matches what the triage pipeline expects.
    """
    port_list = ports if ports is not None else DEFAULT_PORTS
    open_ports: list[dict] = []
    workers = min(MAX_WORKERS, max(1, len(port_list)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scan_port, host, p): p for p in port_list}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    open_ports.append(result)
            except Exception:
                pass
    open_ports.sort(key=lambda p: p["port"])
    result: dict = {
        "host": host,
        "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ports": open_ports,
    }
    exposure = _classify_exposure(host)
    if exposure is not None:
        result["exposure"] = exposure
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="NetGuard lightweight TCP connect scanner",
    )
    parser.add_argument("host", help="Target host IP or hostname")
    parser.add_argument(
        "--ports",
        help="Comma-separated port list (default: common service ports)",
    )
    parser.add_argument("--out", help="Write scan JSON to this file path")
    args = parser.parse_args()

    print(
        "WARNING: Only scan hosts you own or are explicitly authorized to test.",
        file=sys.stderr,
    )
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    port_list: list[int] | None = None
    if args.ports:
        port_list = [
            int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()
        ]

    try:
        resolved = validate_and_resolve_target(args.host)
    except TargetPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None

    # Scan the resolved address so the name cannot map elsewhere after the check.
    result = scan(resolved[0], port_list)
    output = json.dumps(result, indent=2)
    print(output)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
