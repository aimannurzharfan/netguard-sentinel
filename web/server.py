"""Flask server for the NetGuard Sentinel web UI.

Run from the repo root:
    python -m web.server

Serves web/index.html at / and accepts POST /triage with JSON scan input.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_file

from agent.agent import triage
from agent.schema import to_json

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB request limit
_WEB_DIR = Path(__file__).parent


@app.route("/")
def index() -> Response:
    return send_file(_WEB_DIR / "index.html")


@app.post("/triage")
def run_triage() -> Response:
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
