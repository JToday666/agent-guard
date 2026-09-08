"""Configuration model for the AgentGuard LangGraph adapter SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
from pathlib import Path
from typing import Any
from typing import Literal
import warnings

from .endpoint_policy import validate_guard_api_base_url

ApiMode = Literal["guard-api-v0.3", "legacy"]
ContextIsolationMode = Literal["off", "required"]
RuntimeReceiptMode = Literal["best_effort", "required"]
SUPPORTED_API_MODES: tuple[ApiMode, ...] = ("guard-api-v0.3", "legacy")
SUPPORTED_CONTEXT_ISOLATION_MODES: tuple[ContextIsolationMode, ...] = (
    "off",
    "required",
)
SUPPORTED_RUNTIME_RECEIPT_MODES: tuple[RuntimeReceiptMode, ...] = (
    "best_effort",
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
            "context_isolation_mode must be one of: " f"{supported}; got {value!r}"
        )
    return mode  # type: ignore[return-value]


def validate_runtime_receipt_mode(value: object) -> RuntimeReceiptMode:
    mode = str(value).strip().lower()
    if mode not in SUPPORTED_RUNTIME_RECEIPT_MODES:
        supported = ", ".join(SUPPORTED_RUNTIME_RECEIPT_MODES)
        raise ValueError(
            "runtime_receipt_mode must be one of: " f"{supported}; got {value!r}"
        )
    return mode  # type: ignore[return-value]


@dataclass(slots=True)
class AgentGuardLangGraphConfig:
    core_base_url: str = "http://127.0.0.1:8088"
    token: str = field(default="demo-token", repr=False)
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
    # Product Active and required-durable decisions always require receipts,
    # independently of this opt-in compatibility default.
    runtime_receipt_mode: RuntimeReceiptMode = "best_effort"
    # Protected local expectations, never learned from an evaluate response.
    # This batch enables transport only; execution remains gated until the
    # complete native/receipt/breaker composition is available.
    product_manifest_path: str | None = None
    product_refresh_interval_seconds: float = 30.0
    activation_ack_max_age_seconds: float = 120.0

    def __post_init__(self) -> None:
        self.core_base_url = validate_guard_api_base_url(self.core_base_url)
        self.api_mode = validate_api_mode(self.api_mode)
        self.context_isolation_mode = validate_context_isolation_mode(
            self.context_isolation_mode
        )
        self.runtime_receipt_mode = validate_runtime_receipt_mode(
            self.runtime_receipt_mode
        )
        warn_if_legacy_api_mode(self.api_mode)
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than 0")
        if self.product_manifest_path is not None:
            validate_product_configuration(self)

    @property
    def core_api_mode(self) -> ApiMode:
        return self.api_mode


def validate_product_configuration(config: Any) -> None:
    """Reject every compatibility downgrade before an official request."""

    path = getattr(config, "product_manifest_path", None)
    if (
        not isinstance(path, str)
        or not path
        or not Path(path).is_absolute()
        or getattr(config, "api_mode", None) != "guard-api-v0.3"
        or getattr(config, "runtime", None) != "langgraph"
        or getattr(config, "defense_enabled", None) is not True
        or getattr(config, "fail_closed", None) is not True
        or getattr(config, "context_isolation_mode", None) != "required"
        or getattr(config, "runtime_receipt_mode", None) != "required"
        or not isinstance(getattr(config, "token", None), str)
        or not config.token
        or not isinstance(getattr(config, "runtime_binding_id", None), str)
        or not config.runtime_binding_id
    ):
        raise ValueError("Product configuration is incomplete or incompatible")
    interval = getattr(config, "product_refresh_interval_seconds", None)
    age = getattr(config, "activation_ack_max_age_seconds", None)
    timeout = getattr(config, "timeout", None)
    for value in (interval, age, timeout):
        if (
            isinstance(value, bool)
            or not isinstance(value, (float, int))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError("Product timing configuration is invalid")
    assert isinstance(age, (int, float)) and isinstance(interval, (int, float))
    if age > 120 or interval > 30 or interval >= age:
        raise ValueError("Product timing configuration is invalid")


def product_configuration_digest(config: Any) -> str:
    """Detect mutable compatibility config changes without retaining secrets."""

    validate_product_configuration(config)
    fields = (
        "core_base_url",
        "token",
        "timeout",
        "fail_closed",
        "defense_enabled",
        "runtime",
        "agent_id",
        "runtime_binding_id",
        "api_mode",
        "context_isolation_mode",
        "runtime_receipt_mode",
        "product_manifest_path",
        "product_refresh_interval_seconds",
        "activation_ack_max_age_seconds",
    )
    projection = {name: getattr(config, name, None) for name in fields}
    return hashlib.sha256(
        json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
