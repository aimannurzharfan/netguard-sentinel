"""Endpoint tests for the Flask app: target policy and rate limiting.

These exercise the request-handling guards without performing a real scan: a
public target is refused before any socket work, and the rate limiter counts
every hit, so neither test reaches the network.
"""

import pytest

from web import server


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("ALLOW_PUBLIC_TARGETS", raising=False)
    # Isolate the in-process rate-limit state between tests.
    server._rate_hits.clear()
    server.app.config.update(TESTING=True)
    return server.app.test_client()


def test_public_target_blocked_by_default(client):
    resp = client.post("/scan", json={"host": "8.8.8.8"})
    assert resp.status_code == 403
    assert "public" in resp.get_json()["error"].lower()


def test_rate_limit_returns_429(client, monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT", "2")
    # Public host so each request is refused (403) without scanning, but every
    # hit still counts toward the rolling window.
    assert client.post("/scan", json={"host": "8.8.8.8"}).status_code == 403
    assert client.post("/scan", json={"host": "8.8.8.8"}).status_code == 403
    third = client.post("/scan", json={"host": "8.8.8.8"})
    assert third.status_code == 429
    assert "rate limit" in third.get_json()["error"].lower()


def test_security_headers_present(client):
    resp = client.get("/")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
