"""Configuration model for the AgentGuard LangGraph adapter SDK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
import warnings

ApiMode = Literal["guard-api-v0.3", "legacy"]
SUPPORTED_API_MODES: tuple[ApiMode, ...] = ("guard-api-v0.3", "legacy")
DEFAULT_API_MODE: ApiMode = "guard-api-v0.3"


def validate_api_mode(value: object) -> ApiMode:
    mode = str(value).strip()
    if mode not in SUPPORTED_API_MODES:
        supported = ", ".join(SUPPORTED_API_MODES)
        raise ValueError(f"api_mode must be one of: {supported}; got {value!r}")
    return mode  # type: ignore[return-value]


def warn_if_legacy_api_mode(mode: ApiMode) -> None:
    if mode == "legacy":
        warnings.warn(
            "api_mode='legacy' is deprecated; use guard-api-v0.3. "
            "Legacy mode requires /v1/evaluate/tool-call and /v1/audit/event.",
            DeprecationWarning,
            stacklevel=3,
        )


@dataclass(slots=True)
class AgentGuardLangGraphConfig:
    core_base_url: str = "http://127.0.0.1:8088"
    token: str = "demo-token"
    timeout: float = 5.0
    fail_closed: bool = True
    defense_enabled: bool = True
    runtime: str = "langgraph"
    agent_id: str = "langgraph"
    api_mode: ApiMode = DEFAULT_API_MODE

    def __post_init__(self) -> None:
        self.api_mode = validate_api_mode(self.api_mode)
        warn_if_legacy_api_mode(self.api_mode)

    @property
    def core_api_mode(self) -> ApiMode:
        return self.api_mode
