"""Configuration model for the AgentGuard LangGraph adapter SDK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
import warnings

from .endpoint_policy import validate_guard_api_base_url

ApiMode = Literal["guard-api-v0.3", "legacy"]
ContextIsolationMode = Literal["off", "required"]
SUPPORTED_API_MODES: tuple[ApiMode, ...] = ("guard-api-v0.3", "legacy")
SUPPORTED_CONTEXT_ISOLATION_MODES: tuple[ContextIsolationMode, ...] = (
    "off",
    "required",
)
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


def validate_context_isolation_mode(value: object) -> ContextIsolationMode:
    mode = str(value).strip().lower()
    if mode not in SUPPORTED_CONTEXT_ISOLATION_MODES:
        supported = ", ".join(SUPPORTED_CONTEXT_ISOLATION_MODES)
        raise ValueError(
            "context_isolation_mode must be one of: "
            f"{supported}; got {value!r}"
        )
    return mode  # type: ignore[return-value]


@dataclass(slots=True)
class AgentGuardLangGraphConfig:
    core_base_url: str = "http://127.0.0.1:8088"
    token: str = "demo-token"
    timeout: float = 5.0
    fail_closed: bool = True
    defense_enabled: bool = True
    runtime: str = "langgraph"
    agent_id: str = "langgraph"
    # Trusted credential-side binding identity.  Strong evaluate responses are
    # unusable (and fail closed) unless this exact value is provisioned.
    runtime_binding_id: str | None = None
    api_mode: ApiMode = DEFAULT_API_MODE
    # ``required`` binds every model input to a Guard API ContextAssemblyPlan.
    # The default remains off for wire-compatible, opt-in rollout.
    context_isolation_mode: ContextIsolationMode = "off"

    def __post_init__(self) -> None:
        self.core_base_url = validate_guard_api_base_url(self.core_base_url)
        self.api_mode = validate_api_mode(self.api_mode)
        self.context_isolation_mode = validate_context_isolation_mode(
            self.context_isolation_mode
        )
        warn_if_legacy_api_mode(self.api_mode)
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than 0")

    @property
    def core_api_mode(self) -> ApiMode:
        return self.api_mode
