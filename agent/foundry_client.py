"""Foundry client: Phi-4-mini-instruct via the OpenAI-compatible endpoint.

Set FOUNDRY_ENDPOINT (the /openai/v1 base URL), FOUNDRY_MODEL_DEPLOYMENT,
and FOUNDRY_API_KEY in .env to activate.

FOUNDRY_PROJECT_ENDPOINT is accepted as a fallback -- /openai/v1 is appended
automatically, so either variable works.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

# Every entry point (web server, CLI, tests) reaches Foundry through this
# module, so loading .env here guarantees the credentials are present no
# matter which front door was used. Existing process env always wins.
load_dotenv()


def _ensure_openai_path(base: str) -> str:
    """Append the OpenAI-compatible route when the configured endpoint omits it.

    Azure AI Foundry serves the OpenAI-compatible API under /openai/v1; a bare
    resource host (https://<resource>.services.ai.azure.com) returns 404 without it.
    Endpoints that already carry an /openai or /models path are left untouched.
    """
    if "/openai" in base or "/models" in base:
        return base
    return base + "/openai/v1"


def _get_endpoint() -> str | None:
    """Return the resolved OpenAI-compatible base URL, or None if unconfigured."""
    if v := os.getenv("FOUNDRY_ENDPOINT"):
        return _ensure_openai_path(v.rstrip("/"))
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
    """Submit enriched findings to Phi-4-mini-instruct and return the raw response text.

    Connects via the OpenAI-compatible chat completions API on Azure AI Foundry.
    Phi-4-mini-instruct emits a small structured object (no chain-of-thought), so a
    single blocking call with temperature 0 and a modest token budget is enough.

    The instructions (system_prompt: schema + few-shot) are delivered in the USER
    turn, not the system role: this 3.8B model effectively ignores the system role
    and anchors on the user message, so a schema placed there is followed reliably
    while a system-role schema is not.

    Requests JSON mode (response_format={"type": "json_object"}) first; if the
    endpoint rejects it for this model (HTTP 400), retries without it and relies on
    parse_foundry_response's defensive extraction.

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

    # deferred: only required when Foundry is active
    from openai import BadRequestError, OpenAI
    from openai.types.chat import ChatCompletionMessageParam

    client = OpenAI(base_url=endpoint, api_key=api_key, timeout=120.0)
    # Schema + few-shot first, then the data, all in one user turn (see docstring).
    messages: list[ChatCompletionMessageParam] = [
        {"role": "user", "content": f"{system_prompt}\n\n=== Input ===\n{payload}"},
    ]
    # max_tokens=2000 leaves headroom so a full multi-finding object is never
    # truncated mid-JSON (truncation would force the deterministic fallback).
    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0,
            max_tokens=2000,
            response_format={"type": "json_object"},
        )
    except BadRequestError:
        # This model/endpoint does not support JSON mode; fall back to the parser.
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0,
            max_tokens=2000,
        )
    return response.choices[0].message.content or ""
