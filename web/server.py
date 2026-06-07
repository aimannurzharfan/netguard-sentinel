"""Flask server for the NetGuard Sentinel web UI.

Run from the repo root:
    python -m web.server

Serves web/index.html at / and exposes two JSON endpoints:
  POST /scan    -- scans a target host then runs the triage pipeline
  POST /triage  -- runs the triage pipeline on a pre-built scan JSON
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_file

from agent.agent import triage
from agent.schema import to_json

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB request limit
_WEB_DIR = Path(__file__).parent

# Hostname/IP characters only; length bounded to 253 (max DNS name length).
_VALID_HOST = re.compile(r"^[a-zA-Z0-9.\-_]{1,253}$")


@app.route("/")
def index() -> Response:
    return send_file(_WEB_DIR / "index.html")


@app.route("/app.js")
def serve_app_js() -> Response:
    return send_file(_WEB_DIR / "app.js", mimetype="application/javascript")


@app.route("/favicon.ico")
def serve_favicon() -> Response:
    return Response(status=204)


@app.post("/scan")
def run_scan() -> Response:
    """Scan a host then triage the findings. Returns a TriageResult JSON."""
    data = request.get_json(silent=True)
    if not data or "host" not in data:
        return jsonify({"error": "JSON body must include a 'host' key."}), 400

    host = data["host"]
    if not isinstance(host, str) or not host.strip():
        return jsonify({"error": "host must be a non-empty string."}), 400
    host = host.strip()

    if not _VALID_HOST.match(host):
        return jsonify(
            {"error": "Invalid host format (use a hostname or IP address)."}
        ), 400

    ports = data.get("ports")
    if ports is not None:
        if not isinstance(ports, list) or not all(
            isinstance(p, int) and 1 <= p <= 65535 for p in ports
        ):
            return jsonify(
                {"error": "ports must be a list of integers in range 1-65535."}
            ), 400

    try:
        from scanner.scan import DEFAULT_PORTS, scan as tcp_scan

        scan_data = tcp_scan(host, ports if ports is not None else DEFAULT_PORTS)
        result = triage(json.dumps(scan_data))
        return Response(to_json(result), mimetype="application/json")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 422
    except Exception as exc:
        return jsonify({"error": f"Scan failed: {exc}"}), 500


@app.post("/triage")
def run_triage() -> Response:
    """Run the triage pipeline on pre-built scan JSON. Returns a TriageResult JSON."""
    data = request.get_json(silent=True)
    if not data or "scan" not in data:
        return jsonify({"error": "Request body must be JSON with a 'scan' key."}), 400

    scan_input = data["scan"]
    if not isinstance(scan_input, str):
        scan_input = json.dumps(scan_input)

    try:
        result = triage(scan_input)
        return Response(to_json(result), mimetype="application/json")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 422
    except Exception as exc:
        return jsonify({"error": f"Triage failed: {exc}"}), 500


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, port=5000)
