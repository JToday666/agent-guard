"""Shared route-level authorization and bounds helpers."""

from __future__ import annotations

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


def verify_browser_or_bearer_scopes(
    auth: CapabilityAuthService,
    *,
    required_scopes: tuple[str, ...],
    authorization: str | None,
    agentguard_session: str | None,
) -> None:
    """契约 §5.1：bearer 调用方必须同时具备全部 required scope。"""

    if authorization:
        context = auth.verify_bearer(authorization, required_scopes[0])
        for scope in required_scopes[1:]:
            if scope not in context.scopes:
                raise ApiAuthError("SCOPE_DENIED", status_code=403)
        return
    auth.verify_browser_session(agentguard_session)
