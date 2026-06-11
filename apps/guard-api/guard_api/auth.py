"""Minimal P0 capability auth for the Guard API."""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from agentguard_core.models import AuthContext, new_id
from agentguard_core.settings import CoreSettings


class ApiAuthError(Exception):
    def __init__(self, code: str, status_code: int = 401) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(code)


@dataclass(slots=True)
class BrowserSession:
    session_id: str
    csrf_token: str
    expires_at: datetime


@dataclass(slots=True)
class ApprovalNonce:
    nonce: str
    approval_id: str
    session_id: str
    tool_call_id: str
    expires_at: datetime
    used: bool = False


@dataclass(slots=True)
class CapabilityAuthService:
    settings: CoreSettings
    launch_codes: dict[str, datetime] = field(default_factory=dict)
    sessions: dict[str, BrowserSession] = field(default_factory=dict)
    nonces: dict[str, ApprovalNonce] = field(default_factory=dict)

    def verify_bearer(self, authorization: str | None, required_scope: str) -> AuthContext:
        if not authorization:
            raise ApiAuthError("AUTH_MISSING")
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            raise ApiAuthError("TOKEN_INVALID")
        token = authorization.removeprefix(prefix)
        if hmac.compare_digest(token, self.settings.adapter_token):
            context = AuthContext(
                principal_type="component",
                principal_id="cred_adapter_main",
                role="adapter",
                scopes=["event:evaluate", "event:audit:write", "approval:wait"],
                auth_method="bearer",
                runtime="langgraph",
                agent_id="main",
            )
        elif hmac.compare_digest(token, self.settings.control_token):
            context = AuthContext(
                principal_type="cli",
                principal_id="cred_control",
                role="control",
                scopes=["auth:launch"],
                auth_method="bearer",
            )
        else:
            raise ApiAuthError("TOKEN_INVALID")
        if required_scope not in context.scopes:
            raise ApiAuthError("SCOPE_DENIED", status_code=403)
        return context

    def create_launch_code(self) -> str:
        code = new_id("lc")
        self.launch_codes[code] = _now() + timedelta(seconds=self.settings.launch_code_ttl_seconds)
        return code

    def exchange_launch_code(self, code: str) -> BrowserSession:
        expires_at = self.launch_codes.pop(code, None)
        if expires_at is None:
            raise ApiAuthError("LAUNCH_CODE_INVALID")
        if expires_at < _now():
            raise ApiAuthError("LAUNCH_CODE_EXPIRED")
        session = BrowserSession(
            session_id=new_id("sess"),
            csrf_token=new_id("csrf"),
            expires_at=_now() + timedelta(seconds=self.settings.browser_session_ttl_seconds),
        )
        self.sessions[session.session_id] = session
        return session

    def verify_browser_session(self, session_id: str | None) -> BrowserSession:
        if not session_id:
            raise ApiAuthError("SESSION_INVALID")
        session = self.sessions.get(session_id)
        if session is None:
            raise ApiAuthError("SESSION_INVALID")
        if session.expires_at < _now():
            raise ApiAuthError("SESSION_EXPIRED")
        return session

    def verify_csrf(self, session: BrowserSession, csrf_token: str | None) -> None:
        if not csrf_token or not hmac.compare_digest(csrf_token, session.csrf_token):
            raise ApiAuthError("CSRF_INVALID", status_code=403)

    def issue_approval_nonce(self, *, approval_id: str, session_id: str, tool_call_id: str) -> str:
        nonce = new_id("nonce")
        self.nonces[nonce] = ApprovalNonce(
            nonce=nonce,
            approval_id=approval_id,
            session_id=session_id,
            tool_call_id=tool_call_id,
            expires_at=_now() + timedelta(seconds=self.settings.approval_nonce_ttl_seconds),
        )
        return nonce

    def consume_approval_nonce(
        self,
        *,
        nonce: str,
        approval_id: str,
        session_id: str,
        tool_call_id: str,
    ) -> None:
        approval_nonce = self.nonces.get(nonce)
        if approval_nonce is None or approval_nonce.used:
            raise ApiAuthError("APPROVAL_NONCE_INVALID", status_code=403)
        if approval_nonce.expires_at < _now():
            raise ApiAuthError("APPROVAL_NONCE_INVALID", status_code=403)
        if (
            approval_nonce.approval_id != approval_id
            or approval_nonce.session_id != session_id
            or approval_nonce.tool_call_id != tool_call_id
        ):
            raise ApiAuthError("APPROVAL_NONCE_INVALID", status_code=403)
        approval_nonce.used = True


def _now() -> datetime:
    return datetime.now(timezone.utc)

