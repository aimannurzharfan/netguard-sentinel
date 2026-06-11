"""Shared pytest fixtures.

agent.foundry_client loads .env at import, so a developer machine with real
Foundry credentials would silently route every triage() call through the live
model and make the deterministic tests slow and flaky. Scrub the Foundry env
for every test except the ones explicitly marked slow, which exist to exercise
the live endpoint.
"""

from __future__ import annotations

import pytest

_FOUNDRY_VARS = (
    "FOUNDRY_ENDPOINT",
    "FOUNDRY_PROJECT_ENDPOINT",
    "FOUNDRY_MODEL_DEPLOYMENT",
    "FOUNDRY_API_KEY",
)


@pytest.fixture(autouse=True)
def _foundry_unconfigured_by_default(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    if request.node.get_closest_marker("slow"):
        return
    for var in _FOUNDRY_VARS:
        monkeypatch.delenv(var, raising=False)
