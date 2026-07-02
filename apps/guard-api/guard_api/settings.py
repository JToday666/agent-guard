"""Runtime settings for the Guard API / Control Plane."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


DEFAULT_DATABASE_URL = "postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard"
DEFAULT_ADAPTER_TOKEN = "demo-token"
DEFAULT_CONTROL_TOKEN = "demo-control-token"
DEFAULT_ENVIRONMENT = "development"
DEFAULT_STORAGE_BACKEND = "postgres"
SUPPORTED_STORAGE_BACKENDS = {"postgres", "memory"}


class GuardApiConfigurationError(RuntimeError):
    """Raised when Guard API startup configuration is unsafe."""


@dataclass(slots=True)
class GuardApiSettings:
    database_url: str = field(default_factory=lambda: os.getenv("AGENTGUARD_DATABASE_URL", DEFAULT_DATABASE_URL))
    storage_backend: str = field(
        default_factory=lambda: os.getenv("AGENTGUARD_STORAGE_BACKEND", DEFAULT_STORAGE_BACKEND).strip().lower()
    )
    adapter_token: str = field(default_factory=lambda: os.getenv("AGENTGUARD_ADAPTER_TOKEN", DEFAULT_ADAPTER_TOKEN))
    control_token: str = field(default_factory=lambda: os.getenv("AGENTGUARD_CONTROL_TOKEN", DEFAULT_CONTROL_TOKEN))
    host: str = field(default_factory=lambda: os.getenv("AGENTGUARD_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("AGENTGUARD_PORT", "8088")))
    environment: str = field(default_factory=lambda: os.getenv("AGENTGUARD_ENV", DEFAULT_ENVIRONMENT))
    browser_session_ttl_seconds: int = 3600
    launch_code_ttl_seconds: int = 300
    approval_nonce_ttl_seconds: int = 900

    def validate_for_startup(self) -> None:
        if self.storage_backend not in SUPPORTED_STORAGE_BACKENDS:
            supported = ", ".join(sorted(SUPPORTED_STORAGE_BACKENDS))
            raise GuardApiConfigurationError(
                f"AGENTGUARD_STORAGE_BACKEND must be one of: {supported}"
            )
        if self.environment.lower() != "production":
            return
        if self.storage_backend == "memory":
            raise GuardApiConfigurationError("Production startup requires persistent storage backend: postgres")
        default_variables = []
        if self.database_url == DEFAULT_DATABASE_URL:
            default_variables.append("AGENTGUARD_DATABASE_URL")
        if self.adapter_token == DEFAULT_ADAPTER_TOKEN:
            default_variables.append("AGENTGUARD_ADAPTER_TOKEN")
        if self.control_token == DEFAULT_CONTROL_TOKEN:
            default_variables.append("AGENTGUARD_CONTROL_TOKEN")
        if default_variables:
            names = ", ".join(default_variables)
            raise GuardApiConfigurationError(f"Production startup requires explicit configuration for: {names}")
