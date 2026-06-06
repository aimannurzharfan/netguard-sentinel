"""NetGuard Sentinel end-to-end entry point: scan a host and triage findings.

Usage:
    python -m netguard_sentinel <host> [--ports 80,443,...]

Only scan hosts you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import json
import sys

from agent.agent import triage
from agent.schema import to_json
from scanner.scan import scan


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetGuard Sentinel: scan a host and triage findings",
    )
    parser.add_argument("host", help="Target host IP or hostname")
    parser.add_argument(
        "--ports",
        help="Comma-separated port list (default: common service ports)",
    )
    args = parser.parse_args()

    print(
        "WARNING: Only scan hosts you own or are explicitly authorized to test.",
        file=sys.stderr,
    )

    port_list: list[int] | None = None
    if args.ports:
        port_list = [
            int(p.strip())
            for p in args.ports.split(",")
            if p.strip().isdigit()
        ]

    print(f"Scanning {args.host} ...", file=sys.stderr)
    scan_data = scan(args.host, port_list)
    n = len(scan_data["ports"])
    print(f"Scan complete: {n} open port(s) found.", file=sys.stderr)

    print("Triaging findings ...", file=sys.stderr)
    result = triage(json.dumps(scan_data))
    print(to_json(result))


if __name__ == "__main__":
    main()
