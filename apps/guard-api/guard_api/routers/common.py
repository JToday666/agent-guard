"""Shared route-level authorization and bounds helpers."""

from __future__ import annotations

from typing import Any

from guard_api.auth import ApiAuthError, CapabilityAuthService


def bounded_limit(limit: int) -> int:
    return max(1, min(limit, 1000))


def verify_browser_or_bearer_read(
    auth: CapabilityAuthService,
    *,
    required_scope: str,
    authorization: str | None,
    agentguard_session: str | None,
) -> None:
    if authorization:
        auth.verify_bearer(authorization, required_scope)
        return
    auth.verify_browser_session(agentguard_session)


def verify_adapter_heartbeat_write(
    auth: CapabilityAuthService, authorization: str | None
) -> None:
    try:
        auth.verify_bearer(authorization, "adapter:status:write")
    except ApiAuthError as error:
        if error.code != "SCOPE_DENIED":
            raise
        auth.verify_bearer(authorization, "event:evaluate")


def legacy_unknown_adapter_status() -> dict[str, Any]:
    return {
        "status": "unknown",
        "loaded": False,
        "hook_count": None,
        "expected_hook_count": 22,
        "last_verified_at": None,
        "error": None,
        "source": None,
    }
