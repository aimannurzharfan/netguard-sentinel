"""Flask server for the NetGuard Sentinel web UI.

Run from the repo root:
    python -m web.server

Serves the built React SPA (web/dist, produced by `npm run build` in frontend/)
at / with a static + SPA fallback route, and exposes two JSON endpoints:
  POST /scan    -- scans a target host then runs the triage pipeline
  POST /triage  -- runs the triage pipeline on a pre-built scan JSON
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory
from flask.typing import ResponseReturnValue
from werkzeug.exceptions import NotFound

from agent.agent import triage
from agent.schema import to_json

_WEB_DIR = Path(__file__).parent
# Built single-page app produced by `npm run build` in frontend/ (Vite outDir).
_DIST_DIR = _WEB_DIR / "dist"

# Point Flask's built-in static handler at the bundle so hashed JS/CSS under
# web/dist/static are served at /static/<file>; the SPA fallback below covers
# index.html, the favicon, and client-side routes.
app = Flask(
    __name__,
    static_folder=str(_DIST_DIR / "static"),
    static_url_path="/static",
)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB request limit

# Hostname/IP characters only; length bounded to 253 (max DNS name length).
_VALID_HOST = re.compile(r"^[a-zA-Z0-9.\-_]{1,253}$")


@app.route("/")
def index() -> ResponseReturnValue:
    return send_from_directory(_DIST_DIR, "index.html")


# SPA static + fallback: serve a built asset when the path maps to a real file
# (hashed JS/CSS under static/, the favicon), otherwise return index.html so
# refreshes and deep links resolve to the app. This only handles GET; the POST
# API routes below (/scan, /triage) are matched first and are unaffected.
@app.route("/<path:path>")
def static_or_spa(path: str) -> ResponseReturnValue:
    try:
        return send_from_directory(_DIST_DIR, path)
    except NotFound:
        return send_from_directory(_DIST_DIR, "index.html")


@app.post("/scan")
def run_scan() -> ResponseReturnValue:
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
    except Exception:
        return jsonify({"error": "Scan failed due to an internal error."}), 500


@app.post("/triage")
def run_triage() -> ResponseReturnValue:
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
    except Exception:
        return jsonify({"error": "Triage failed due to an internal error."}), 500


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, port=5000)
