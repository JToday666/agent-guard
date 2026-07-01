"""Configuration model for the AgentGuard LangGraph adapter SDK."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class AgentGuardLangGraphConfig:
    core_base_url: str = "http://localhost:8000"
    token: str = "demo-token"
    timeout: float = 5.0
    fail_closed: bool = True
    defense_enabled: bool = True
    runtime: str = "langgraph"
    agent_id: str = "langgraph"
    api_mode: str = "legacy"

    @property
    def core_api_mode(self) -> str:
        return self.api_mode
