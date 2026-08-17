"""Guard configuration compatibility model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentguard_langgraph_adapter.config import (
    ApiMode,
    DEFAULT_API_MODE,
    validate_api_mode,
    warn_if_legacy_api_mode,
)


@dataclass(slots=True)
class GuardConfig:
    core_base_url: str = "http://127.0.0.1:8088"
    token: str = "demo-token"
    timeout: float = 5.0
    fail_closed: bool = True
    defense_enabled: bool = True
    runtime: str = "unknown"
    agent_id: str = "unknown_agent"
    runtime_binding_id: str | None = None
    schema_version: str = "0.3"
    event_type: str = "tool_call_proposed"
    api_mode: ApiMode = DEFAULT_API_MODE

    def __post_init__(self) -> None:
        self.api_mode = validate_api_mode(self.api_mode)
        warn_if_legacy_api_mode(self.api_mode)

    @property
    def core_api_mode(self) -> ApiMode:
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
            runtime_binding_id=getattr(config, "runtime_binding_id", None),
            api_mode=getattr(config, "core_api_mode", DEFAULT_API_MODE),
        )
