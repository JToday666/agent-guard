"""Runtime settings for the Guard API / Control Plane."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_DATABASE_URL = "postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard"
DEFAULT_CONTROL_TOKEN = "demo-control-token"
DEFAULT_ENVIRONMENT = "development"
DEFAULT_STORAGE_BACKEND = "postgres"
DEFAULT_LLM_APPROVAL_BASE_URL = "https://api.openai.com/v1"
SUPPORTED_STORAGE_BACKENDS = {"postgres", "memory"}


class GuardApiConfigurationError(RuntimeError):
    """Raised when Guard API startup configuration is unsafe."""


@dataclass(slots=True)
class GuardApiSettings:
    database_url: str = field(
        default_factory=lambda: os.getenv(
            "AGENTGUARD_DATABASE_URL", DEFAULT_DATABASE_URL
        )
    )
    storage_backend: str = field(
        default_factory=lambda: (
            os.getenv("AGENTGUARD_STORAGE_BACKEND", DEFAULT_STORAGE_BACKEND)
            .strip()
            .lower()
        )
    )
    control_token: str = field(
        default_factory=lambda: os.getenv(
            "AGENTGUARD_CONTROL_TOKEN", DEFAULT_CONTROL_TOKEN
        )
    )
    host: str = field(default_factory=lambda: os.getenv("AGENTGUARD_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("AGENTGUARD_PORT", "8088")))
    environment: str = field(
        default_factory=lambda: os.getenv("AGENTGUARD_ENV", DEFAULT_ENVIRONMENT)
    )
    browser_session_ttl_seconds: int = 3600
    launch_code_ttl_seconds: int = 300
    approval_ttl_seconds: int = 900
    llm_approval_enabled: bool = field(
        default_factory=lambda: _env_bool(
            "AGENTGUARD_LLM_APPROVAL_ENABLED", default=False
        )
    )
    llm_approval_base_url: str = field(
        default_factory=lambda: os.getenv(
            "AGENTGUARD_LLM_APPROVAL_BASE_URL", DEFAULT_LLM_APPROVAL_BASE_URL
        )
    )
    llm_approval_api_key: str | None = field(
        default_factory=lambda: _optional_env("AGENTGUARD_LLM_APPROVAL_API_KEY")
    )
    llm_approval_model: str | None = field(
        default_factory=lambda: _optional_env("AGENTGUARD_LLM_APPROVAL_MODEL")
    )
    llm_approval_timeout_seconds: float = field(
        default_factory=lambda: _env_float(
            "AGENTGUARD_LLM_APPROVAL_TIMEOUT_SECONDS", default=3.0
        )
    )
    audit_window_enabled: bool = field(
        default_factory=lambda: _default_audit_window_enabled()
    )

    def llm_approval_configured(self) -> bool:
        return bool(self.llm_approval_api_key and self.llm_approval_model)

    def validate_for_startup(self) -> None:
        if self.storage_backend not in SUPPORTED_STORAGE_BACKENDS:
            supported = ", ".join(sorted(SUPPORTED_STORAGE_BACKENDS))
            raise GuardApiConfigurationError(
                f"AGENTGUARD_STORAGE_BACKEND must be one of: {supported}"
            )
        if self.environment.lower() != "production":
            return
        if self.storage_backend == "memory":
            raise GuardApiConfigurationError(
                "Production startup requires persistent storage backend: postgres"
            )
        default_variables = []
        if self.database_url == DEFAULT_DATABASE_URL:
            default_variables.append("AGENTGUARD_DATABASE_URL")
        if self.control_token == DEFAULT_CONTROL_TOKEN:
            default_variables.append("AGENTGUARD_CONTROL_TOKEN")
        if default_variables:
            names = ", ".join(default_variables)
            raise GuardApiConfigurationError(
                f"Production startup requires explicit configuration for: {names}"
            )


def _optional_env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _env_bool(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, *, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _default_audit_window_enabled() -> bool:
    """契约 §14.1：非 production 默认开启，production 默认关闭。"""

    explicit = os.getenv("AGENTGUARD_AUDIT_WINDOW_ENABLED")
    if explicit is not None:
        return explicit.strip().lower() in {"1", "true", "yes", "on"}
    environment = os.getenv("AGENTGUARD_ENV", DEFAULT_ENVIRONMENT)
    return environment.strip().lower() != "production"
