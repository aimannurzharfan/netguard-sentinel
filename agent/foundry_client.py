"""Foundry client: Phi-4-reasoning via the OpenAI-compatible endpoint.

Set FOUNDRY_ENDPOINT (the /openai/v1 base URL), FOUNDRY_MODEL_DEPLOYMENT,
and FOUNDRY_API_KEY in .env to activate.

FOUNDRY_PROJECT_ENDPOINT is accepted as a fallback -- /openai/v1 is appended
automatically, so either variable works.
"""

from __future__ import annotations

import os


def _get_endpoint() -> str | None:
    """Return the resolved OpenAI-compatible base URL, or None if unconfigured."""
    if v := os.getenv("FOUNDRY_ENDPOINT"):
        return v.rstrip("/")
    if project := os.getenv("FOUNDRY_PROJECT_ENDPOINT"):
        return project.rstrip("/") + "/openai/v1"
    return None


def is_configured() -> bool:
    """Return True when all required Foundry env vars are present."""
    return (
        bool(_get_endpoint())
        and bool(os.getenv("FOUNDRY_MODEL_DEPLOYMENT"))
        and bool(os.getenv("FOUNDRY_API_KEY"))
    )


def run_reasoning(system_prompt: str, payload: str) -> str:
    """Submit enriched findings to Phi-4-reasoning and return the raw response text.

    Connects via the OpenAI-compatible chat completions API on Azure AI Foundry.
    Raises RuntimeError when called without Foundry configured.
    """
    endpoint = _get_endpoint()
    api_key = os.getenv("FOUNDRY_API_KEY")
    model = os.getenv("FOUNDRY_MODEL_DEPLOYMENT")

    if not (endpoint and api_key and model):
        raise RuntimeError(
            "Foundry not configured -- set FOUNDRY_ENDPOINT (or FOUNDRY_PROJECT_ENDPOINT), "
            "FOUNDRY_MODEL_DEPLOYMENT, and FOUNDRY_API_KEY in .env"
        )

    from openai import OpenAI  # deferred: only required when Foundry is active

    # timeout=300 keeps the connection open long enough for Phi-4-reasoning's
    # chain-of-thought. stream=True avoids a blocking wait for the full response.
    client = OpenAI(base_url=endpoint, api_key=api_key, timeout=300.0)
    parts: list[str] = []
    stream = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": payload},
        ],
        temperature=0.1,
        max_tokens=16384,
        stream=True,
    )
    for chunk in stream:
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta.content
        if delta:
            parts.append(delta)
    return "".join(parts)
