"""Microsoft Foundry client -- wire this on Day 4 (~June 9) when Azure unlocks.

SEAM: Everything in this module is intentionally left as stubs.
The agent (agent.py) imports run_agent() from here. To wire Foundry:
  1. Set FOUNDRY_PROJECT_ENDPOINT, FOUNDRY_MODEL_DEPLOYMENT, FOUNDRY_API_KEY in .env.
  2. Replace the NotImplementedError body below with the AIProjectClient call.
  3. No other file needs to change.

SDK: azure-ai-projects >= 2.0.0 (unified AIProjectClient, bundles openai + azure-identity).
"""

from __future__ import annotations

import os


def is_configured() -> bool:
    """Return True if all three Foundry env vars are present."""
    return all(
        os.getenv(k)
        for k in ("FOUNDRY_PROJECT_ENDPOINT", "FOUNDRY_MODEL_DEPLOYMENT", "FOUNDRY_API_KEY")
    )


def run_agent(system_prompt: str, user_message: str) -> str:
    """Submit a prompt to the Foundry agent and return the raw response text.

    Day 4 implementation:
        from azure.ai.projects import AIProjectClient
        from azure.identity import DefaultAzureCredential

        client = AIProjectClient(
            endpoint=os.environ["FOUNDRY_PROJECT_ENDPOINT"],
            credential=DefaultAzureCredential(),
        )
        agent = client.agents.create_agent(
            model=os.environ["FOUNDRY_MODEL_DEPLOYMENT"],
            instructions=system_prompt,
        )
        thread = client.agents.create_thread()
        client.agents.create_message(thread_id=thread.id, role="user", content=user_message)
        run = client.agents.create_and_process_run(thread_id=thread.id, agent_id=agent.id)
        messages = client.agents.list_messages(thread_id=thread.id)
        return messages.get_last_text_message_by_role("assistant").text.value
    """
    raise NotImplementedError(
        f"Foundry not wired (prompt {len(system_prompt)}c / message {len(user_message)}c). "
        "Set FOUNDRY_PROJECT_ENDPOINT, FOUNDRY_MODEL_DEPLOYMENT, and FOUNDRY_API_KEY in .env."
    )
