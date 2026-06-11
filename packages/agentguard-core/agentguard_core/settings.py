"""Runtime settings for the formal AgentGuard Core."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


DEFAULT_DATABASE_URL = "postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard"
DEFAULT_ADAPTER_TOKEN = "demo-token"
DEFAULT_CONTROL_TOKEN = "demo-control-token"
DEFAULT_ENVIRONMENT = "development"


class CoreConfigurationError(RuntimeError):
    """Raised when Core startup configuration is not safe for the selected environment."""


@dataclass(slots=True)
class CoreSettings:
    database_url: str = field(default_factory=lambda: os.getenv("AGENTGUARD_DATABASE_URL", DEFAULT_DATABASE_URL))
    adapter_token: str = field(default_factory=lambda: os.getenv("AGENTGUARD_ADAPTER_TOKEN", DEFAULT_ADAPTER_TOKEN))
    control_token: str = field(default_factory=lambda: os.getenv("AGENTGUARD_CONTROL_TOKEN", DEFAULT_CONTROL_TOKEN))
    host: str = field(default_factory=lambda: os.getenv("AGENTGUARD_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("AGENTGUARD_PORT", "8088")))
    environment: str = field(default_factory=lambda: os.getenv("AGENTGUARD_ENV", DEFAULT_ENVIRONMENT))
    browser_session_ttl_seconds: int = 3600
    launch_code_ttl_seconds: int = 300
    approval_nonce_ttl_seconds: int = 900

    def validate_for_startup(self) -> None:
        if self.environment.lower() != "production":
            return
        default_variables = []
        if self.database_url == DEFAULT_DATABASE_URL:
            default_variables.append("AGENTGUARD_DATABASE_URL")
        if self.adapter_token == DEFAULT_ADAPTER_TOKEN:
            default_variables.append("AGENTGUARD_ADAPTER_TOKEN")
        if self.control_token == DEFAULT_CONTROL_TOKEN:
            default_variables.append("AGENTGUARD_CONTROL_TOKEN")
        if default_variables:
            names = ", ".join(default_variables)
            raise CoreConfigurationError(f"Production startup requires explicit configuration for: {names}")
