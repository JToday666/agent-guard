"""Runtime settings for the formal AgentGuard Core."""

from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULT_DATABASE_URL = "postgresql://agentguard:agentguard@127.0.0.1:5432/agentguard"


@dataclass(slots=True)
class CoreSettings:
    database_url: str = os.getenv("AGENTGUARD_DATABASE_URL", DEFAULT_DATABASE_URL)
    adapter_token: str = os.getenv("AGENTGUARD_ADAPTER_TOKEN", "demo-token")
    control_token: str = os.getenv("AGENTGUARD_CONTROL_TOKEN", "demo-control-token")
    host: str = os.getenv("AGENTGUARD_HOST", "127.0.0.1")
    port: int = int(os.getenv("AGENTGUARD_PORT", "8088"))
    browser_session_ttl_seconds: int = 3600
    launch_code_ttl_seconds: int = 300
    approval_nonce_ttl_seconds: int = 900

