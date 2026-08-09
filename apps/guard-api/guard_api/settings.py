"""Runtime settings for the Guard API / Control Plane."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from ipaddress import ip_address

DEFAULT_DATABASE_URL = "postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard"
DEFAULT_CONTROL_TOKEN = "demo-control-token"
DEFAULT_ENVIRONMENT = "development"
DEFAULT_STORAGE_BACKEND = "postgres"
DEFAULT_LLM_APPROVAL_BASE_URL = "https://api.openai.com/v1"
SUPPORTED_STORAGE_BACKENDS = {"postgres", "memory"}
SUPPORTED_ENVIRONMENTS = {"development", "test", "production"}
DEFAULT_MAX_REQUEST_BODY_BYTES = 1024 * 1024
MAX_CONFIGURABLE_REQUEST_BODY_BYTES = 8 * 1024 * 1024


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
    port: int = field(default_factory=lambda: _env_int("AGENTGUARD_PORT", default=8088))
    environment: str = field(
        default_factory=lambda: (
            os.getenv("AGENTGUARD_ENV", DEFAULT_ENVIRONMENT).strip().lower()
        )
    )
    browser_session_ttl_seconds: int = 3600
    launch_code_ttl_seconds: int = 300
    approval_ttl_seconds: int = 900
    browser_cookie_secure: bool = field(
        default_factory=lambda: _env_bool(
            "AGENTGUARD_BROWSER_COOKIE_SECURE",
            default=(
                os.getenv("AGENTGUARD_ENV", DEFAULT_ENVIRONMENT).strip().lower()
                == "production"
            ),
        )
    )
    max_request_body_bytes: int = field(
        default_factory=lambda: _env_int(
            "AGENTGUARD_MAX_REQUEST_BODY_BYTES",
            default=DEFAULT_MAX_REQUEST_BODY_BYTES,
        )
    )
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

    def llm_approval_configured(self) -> bool:
        return bool(self.llm_approval_api_key and self.llm_approval_model)

    def validate_for_startup(self) -> None:
        environment = self.environment.strip().lower()
        if environment not in SUPPORTED_ENVIRONMENTS:
            supported = ", ".join(sorted(SUPPORTED_ENVIRONMENTS))
            raise GuardApiConfigurationError(
                f"AGENTGUARD_ENV must be one of: {supported}"
            )
        if self.storage_backend not in SUPPORTED_STORAGE_BACKENDS:
            supported = ", ".join(sorted(SUPPORTED_STORAGE_BACKENDS))
            raise GuardApiConfigurationError(
                f"AGENTGUARD_STORAGE_BACKEND must be one of: {supported}"
            )
        if not self.control_token.strip():
            raise GuardApiConfigurationError("AGENTGUARD_CONTROL_TOKEN cannot be empty")
        if self.storage_backend == "postgres" and not self.database_url.strip():
            raise GuardApiConfigurationError("AGENTGUARD_DATABASE_URL cannot be empty")
        if not 1 <= self.port <= 65535:
            raise GuardApiConfigurationError(
                "AGENTGUARD_PORT must be between 1 and 65535"
            )
        if (
            not 1024
            <= self.max_request_body_bytes
            <= MAX_CONFIGURABLE_REQUEST_BODY_BYTES
        ):
            raise GuardApiConfigurationError(
                "AGENTGUARD_MAX_REQUEST_BODY_BYTES must be between 1024 and 8388608"
            )
        if self.llm_approval_timeout_seconds <= 0:
            raise GuardApiConfigurationError(
                "AGENTGUARD_LLM_APPROVAL_TIMEOUT_SECONDS must be greater than zero"
            )

        externally_exposed = environment == "production" or not _is_loopback_host(
            self.host
        )
        if not externally_exposed:
            return
        if self.storage_backend == "memory":
            raise GuardApiConfigurationError(
                "Externally exposed startup requires persistent storage backend: postgres"
            )
        default_variables = []
        if self.database_url.strip() == DEFAULT_DATABASE_URL:
            default_variables.append("AGENTGUARD_DATABASE_URL")
        if self.control_token.strip() == DEFAULT_CONTROL_TOKEN:
            default_variables.append("AGENTGUARD_CONTROL_TOKEN")
        if default_variables:
            names = ", ".join(default_variables)
            raise GuardApiConfigurationError(
                f"Externally exposed startup requires explicit configuration for: {names}"
            )
        if len(self.control_token.strip()) < 32:
            raise GuardApiConfigurationError(
                "Externally exposed startup requires AGENTGUARD_CONTROL_TOKEN "
                "to contain at least 32 characters"
            )
        if not self.browser_cookie_secure:
            raise GuardApiConfigurationError(
                "Externally exposed startup requires AGENTGUARD_BROWSER_COOKIE_SECURE=true"
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
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise GuardApiConfigurationError(f"{name} must be a boolean")


def _env_float(name: str, *, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        raise GuardApiConfigurationError(f"{name} must be a number") from None


def _env_int(name: str, *, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        raise GuardApiConfigurationError(f"{name} must be an integer") from None


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False
