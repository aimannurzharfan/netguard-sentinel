"""Verify _MITRE technique IDs are correct and no deprecated IDs are used."""

from agent.agent import _MITRE, _map_mitre

_ALLOWED_TECHNIQUE_IDS = {
    "T1190",
    "T1021",
    "T1021.001",
    "T1021.002",
    "T1021.004",
    "T1046",
    "T1078",  # Valid Accounts -- used for FTP anonymous access
}

_DEPRECATED_IDS = {"T1198", "T1500"}


def test_no_deprecated_technique_ids():
    for keyword, entries in _MITRE.items():
        for tid, _name, _tactic in entries:
            assert tid not in _DEPRECATED_IDS, (
                f"Deprecated technique {tid} found under keyword '{keyword}'"
            )


def test_all_technique_ids_in_allowlist():
    for keyword, entries in _MITRE.items():
        for tid, _name, _tactic in entries:
            assert tid in _ALLOWED_TECHNIQUE_IDS, (
                f"Unexpected technique {tid} under keyword '{keyword}'; "
                f"allowed: {_ALLOWED_TECHNIQUE_IDS}"
            )


def test_database_service_maps_to_initial_access_not_persistence():
    techniques = _map_mitre("MySQL 8.0")
    assert techniques, "Expected at least one technique for 'MySQL 8.0'"
    for t in techniques:
        assert t.technique == "T1190", (
            f"MySQL should map to T1190 (Initial Access), got {t.technique}"
        )
        assert t.tactic != "Persistence", (
            f"MySQL should not map to Persistence tactic, got {t.tactic}"
        )
