"""P0 capability auth for the Guard API / Control Plane."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from agentguard_core import new_id

from guard_api.models import CredentialCreateRequest, CredentialRecord
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import ControlPlaneStore


class ApiAuthError(Exception):
    def __init__(self, code: str, status_code: int = 401) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(code)


@dataclass(slots=True)
class AuthContext:
    principal_type: str
    principal_id: str
    role: str
    scopes: list[str]
    auth_method: str
    runtime: str | None = None
    agent_id: str | None = None


@dataclass(slots=True)
class BrowserSession:
    session_id: str
    csrf_token: str
    expires_at: datetime


@dataclass(slots=True)
class CapabilityAuthService:
    settings: GuardApiSettings
    store: ControlPlaneStore

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
                scopes=["event:evaluate", "event:audit:write", "approval:wait", "adapter:status:write"],
                auth_method="bearer",
                runtime="langgraph",
                agent_id="main",
            )
        elif hmac.compare_digest(token, self.settings.control_token):
            context = AuthContext(
                principal_type="cli",
                principal_id="cred_control",
                role="control",
                scopes=[
                    "auth:launch",
                    "audit:read",
                    "metrics:read",
                    "trace:read",
                    "policy:read",
                    "evaluation:read",
                    "evaluation:write",
                    "config-audit:read",
                    "adapter:read",
                    "adapter:status:write",
                    "credential:read",
                    "credential:write",
                    "credential:revoke",
                ],
                auth_method="bearer",
            )
        else:
            credential = self.store.get_credential_by_token_hash(_token_hash(token))
            if credential is None:
                raise ApiAuthError("TOKEN_INVALID")
            if credential.expires_at is not None and _parse_datetime(credential.expires_at) < _now():
                raise ApiAuthError("TOKEN_INVALID")
            context = AuthContext(
                principal_type=credential.principal_type,
                principal_id=credential.principal_id,
                role=credential.role,
                scopes=credential.scopes,
                auth_method="bearer",
                runtime=credential.runtime,
                agent_id=credential.agent_id,
            )
        if required_scope not in context.scopes:
            raise ApiAuthError("SCOPE_DENIED", status_code=403)
        return context

    def create_credential(self, request: CredentialCreateRequest) -> tuple[str, CredentialRecord]:
        token = f"agt_{new_id('tok')}"
        credential = CredentialRecord(
            token_hash=_token_hash(token),
            principal_type=request.principal_type,
            principal_id=request.principal_id,
            role=request.role,
            scopes=request.scopes,
            runtime=request.runtime,
            agent_id=request.agent_id,
            expires_at=request.expires_at,
        )
        return token, self.store.create_credential(credential)

    def list_credentials(self) -> list[CredentialRecord]:
        return self.store.list_credentials()

    def revoke_credential(self, credential_id: str) -> CredentialRecord:
        return self.store.revoke_credential(credential_id, _now().isoformat())

    def create_launch_code(self) -> str:
        code = new_id("lc")
        expires_at = _now() + timedelta(seconds=self.settings.launch_code_ttl_seconds)
        self.store.create_launch_code(_token_hash(code), expires_at.isoformat())
        return code

    def exchange_launch_code(self, code: str) -> BrowserSession:
        launch_code = self.store.consume_launch_code(_token_hash(code), _now().isoformat())
        if launch_code is None:
            raise ApiAuthError("LAUNCH_CODE_INVALID")
        if _parse_datetime(launch_code.expires_at) < _now():
            raise ApiAuthError("LAUNCH_CODE_EXPIRED")
        session_id = new_id("sess")
        csrf_token = new_id("csrf")
        expires_at = _now() + timedelta(seconds=self.settings.browser_session_ttl_seconds)
        session = BrowserSession(session_id=session_id, csrf_token=csrf_token, expires_at=expires_at)
        self.store.create_browser_session(
            _token_hash(session.session_id),
            csrf_token=session.csrf_token,
            expires_at=session.expires_at.isoformat(),
        )
        return session

    def verify_browser_session(self, session_id: str | None) -> BrowserSession:
        if not session_id:
            raise ApiAuthError("SESSION_INVALID")
        stored = self.store.get_browser_session(_token_hash(session_id))
        if stored is None or stored.revoked_at is not None:
            raise ApiAuthError("SESSION_INVALID")
        expires_at = _parse_datetime(stored.expires_at)
        if expires_at < _now():
            raise ApiAuthError("SESSION_EXPIRED")
        return BrowserSession(session_id=session_id, csrf_token=stored.csrf_token, expires_at=expires_at)

    def logout_browser_session(self, session_id: str) -> None:
        self.store.revoke_browser_session(_token_hash(session_id), _now().isoformat())

    def verify_csrf(self, session: BrowserSession, csrf_token: str | None) -> None:
        if not csrf_token or not hmac.compare_digest(csrf_token, session.csrf_token):
            raise ApiAuthError("CSRF_INVALID", status_code=403)

    def issue_approval_nonce(
        self,
        *,
        approval_id: str,
        session_id: str,
        subject_id: str | None = None,
        tool_call_id: str | None = None,
    ) -> str:
        approval_subject_id = _approval_subject_id(subject_id=subject_id, tool_call_id=tool_call_id)
        nonce = new_id("nonce")
        expires_at = _now() + timedelta(seconds=self.settings.approval_nonce_ttl_seconds)
        self.store.create_approval_nonce(
            _token_hash(nonce),
            approval_id=approval_id,
            session_hash=_token_hash(session_id),
            subject_id=approval_subject_id,
            tool_call_id=tool_call_id or approval_subject_id,
            expires_at=expires_at.isoformat(),
        )
        return nonce

    def consume_approval_nonce(
        self,
        *,
        nonce: str,
        approval_id: str,
        session_id: str,
        subject_id: str | None = None,
        tool_call_id: str | None = None,
    ) -> None:
        approval_subject_id = _approval_subject_id(subject_id=subject_id, tool_call_id=tool_call_id)
        approval_nonce = self.store.consume_approval_nonce(
            _token_hash(nonce),
            approval_id=approval_id,
            session_hash=_token_hash(session_id),
            subject_id=approval_subject_id,
            tool_call_id=tool_call_id or approval_subject_id,
            used_at=_now().isoformat(),
        )
        if approval_nonce is None:
            raise ApiAuthError("APPROVAL_NONCE_INVALID", status_code=403)
        if _parse_datetime(approval_nonce.expires_at) < _now():
            raise ApiAuthError("APPROVAL_NONCE_INVALID", status_code=403)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _approval_subject_id(*, subject_id: str | None, tool_call_id: str | None) -> str:
    approval_subject_id = subject_id or tool_call_id
    if approval_subject_id is None:
        raise ApiAuthError("APPROVAL_SUBJECT_MISSING", status_code=403)
    return approval_subject_id
