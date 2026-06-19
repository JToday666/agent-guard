"""Guard configuration compatibility model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class GuardConfig:
    core_base_url: str = "http://localhost:8000"
    token: str = "demo-token"
    timeout: float = 5.0
    fail_closed: bool = True
    defense_enabled: bool = True
    runtime: str = "unknown"
    agent_id: str = "unknown_agent"
    schema_version: str = "0.3"
    event_type: str = "tool_call_proposed"
    api_mode: str = "legacy"

    @property
    def core_api_mode(self) -> str:
        return self.api_mode

    @classmethod
    def from_bench_config(cls, config: Any, *, runtime: str, agent_id: str) -> "GuardConfig":
        return cls(
            core_base_url=config.core_base_url,
            token=config.token,
            timeout=config.timeout,
            fail_closed=config.fail_closed,
            defense_enabled=config.defense_enabled,
            runtime=runtime,
            agent_id=agent_id,
            api_mode=getattr(config, "core_api_mode", "legacy"),
        )
