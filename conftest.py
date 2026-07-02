from __future__ import annotations

import os

import pytest


_ENV_KEYS_TO_RESTORE = (
    "AGENTGUARD_ADAPTER_TOKEN",
    "AGENTGUARD_BROWSER_ACTION_TIMEOUT",
    "AGENTGUARD_BROWSER_MODE",
    "AGENTGUARD_CONTROL_TOKEN",
    "AGENTGUARD_DATABASE_URL",
    "AGENTGUARD_ENV",
    "AGENTGUARD_LANGGRAPH_RECURSION_LIMIT",
    "AGENTGUARD_LLM_BASE_URL",
    "AGENTGUARD_LLM_ENABLED",
    "AGENTGUARD_LLM_ENV_FILE",
    "AGENTGUARD_LLM_MAX_RETRIES",
    "AGENTGUARD_LLM_MAX_TOOL_ROUNDS",
    "AGENTGUARD_LLM_MODEL",
    "AGENTGUARD_LLM_PROVIDER",
    "AGENTGUARD_LLM_REQUEST_TIMEOUT",
    "AGENTGUARD_MAX_WALL_CLOCK_SECONDS",
    "AGENTGUARD_STORAGE_BACKEND",
    "DEEPSEEK_API_KEY",
    "DEEPSEEK_BASE_URL",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
)


@pytest.fixture(autouse=True)
def restore_agentguard_env() -> None:
    snapshot = {key: os.environ[key] for key in _ENV_KEYS_TO_RESTORE if key in os.environ}
    missing = set(_ENV_KEYS_TO_RESTORE) - set(snapshot)
    yield
    for key in missing:
        os.environ.pop(key, None)
    for key, value in snapshot.items():
        os.environ[key] = value
