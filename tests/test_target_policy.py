"""Tests for the scan-target default-deny policy in scanner.scan.

Numeric IP literals are passed straight through getaddrinfo without a DNS
lookup, so these run offline.
"""

import pytest

from scanner.scan import TargetPolicyError, validate_and_resolve_target


class TestTargetPolicy:
    def test_localhost_allowed(self):
        assert validate_and_resolve_target("127.0.0.1") == ["127.0.0.1"]

    def test_rfc1918_allowed(self):
        for host in ("10.0.0.20", "192.168.1.10", "172.16.5.5"):
            assert validate_and_resolve_target(host) == [host]

    def test_public_target_blocked_by_default(self, monkeypatch):
        monkeypatch.delenv("ALLOW_PUBLIC_TARGETS", raising=False)
        with pytest.raises(TargetPolicyError) as exc:
            validate_and_resolve_target("8.8.8.8")
        assert exc.value.status == 403
        assert "public" in str(exc.value).lower()

    def test_public_target_allowed_with_flag(self, monkeypatch):
        monkeypatch.setenv("ALLOW_PUBLIC_TARGETS", "1")
        assert validate_and_resolve_target("8.8.8.8") == ["8.8.8.8"]

    def test_explicit_allow_public_argument_overrides_env(self, monkeypatch):
        monkeypatch.delenv("ALLOW_PUBLIC_TARGETS", raising=False)
        assert validate_and_resolve_target("1.1.1.1", allow_public=True) == ["1.1.1.1"]

    def test_empty_host_rejected(self):
        with pytest.raises(TargetPolicyError) as exc:
            validate_and_resolve_target("   ")
        assert exc.value.status == 400

    def test_malformed_host_rejected(self):
        with pytest.raises(TargetPolicyError) as exc:
            validate_and_resolve_target("bad host;rm -rf")
        assert exc.value.status == 400

    def test_unresolvable_host_rejected(self):
        with pytest.raises(TargetPolicyError) as exc:
            validate_and_resolve_target("nonexistent.invalid")
        assert exc.value.status == 400
