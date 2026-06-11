"""FastAPI service entrypoint for the formal AgentGuard Core."""

from __future__ import annotations

from typing import Any

from fastapi import Cookie, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agentguard_core.models import AuditEvent, ToolCallEvent
from agentguard_core.service import AgentGuardCore
from agentguard_core.settings import CoreSettings
from agentguard_core.storage.base import CoreStore

from .auth import ApiAuthError, CapabilityAuthService


class LaunchExchangeRequest(BaseModel):
    launch_code: str


class ApprovalResolveRequest(BaseModel):
    decision: str
    approval_nonce: str


def create_app(*, store: CoreStore | None = None, settings: CoreSettings | None = None) -> FastAPI:
    settings = settings or CoreSettings()
    core = AgentGuardCore(store=store, settings=settings)
    auth = CapabilityAuthService(settings=settings)
    app = FastAPI(title="AgentGuard Formal Core API", version="0.1.0")

    @app.exception_handler(ApiAuthError)
    async def auth_exception_handler(_: Request, exc: ApiAuthError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code}})

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/auth/browser/launch")
    def launch(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        auth.verify_bearer(authorization, "auth:launch")
        return {"launch_code": auth.create_launch_code(), "expires_in": settings.launch_code_ttl_seconds}

    @app.post("/v1/auth/browser/exchange")
    def exchange(payload: LaunchExchangeRequest) -> JSONResponse:
        session = auth.exchange_launch_code(payload.launch_code)
        response = JSONResponse(
            {
                "authenticated": True,
                "expires_at": session.expires_at.isoformat(),
                "csrf_token": session.csrf_token,
            }
        )
        response.set_cookie(
            "agentguard_session",
            session.session_id,
            httponly=True,
            samesite="strict",
            path="/",
            max_age=settings.browser_session_ttl_seconds,
        )
        return response

    @app.get("/v1/auth/browser/me")
    def me(agentguard_session: str | None = Cookie(default=None)) -> dict[str, Any]:
        session = auth.verify_browser_session(agentguard_session)
        return {
            "authenticated": True,
            "expires_at": session.expires_at.isoformat(),
            "csrf_token": session.csrf_token,
        }

    @app.post("/v1/auth/browser/logout")
    def logout(agentguard_session: str | None = Cookie(default=None)) -> JSONResponse:
        session = auth.verify_browser_session(agentguard_session)
        auth.logout_browser_session(session.session_id)
        response = JSONResponse({"authenticated": False})
        response.delete_cookie("agentguard_session", path="/")
        return response

    @app.post("/v1/evaluate/tool-call")
    def evaluate_tool_call(payload: ToolCallEvent, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        context = auth.verify_bearer(authorization, "event:evaluate")
        decision = core.evaluate_tool_call(payload, requesting_principal_id=context.principal_id)
        return decision.model_dump(mode="json")

    @app.post("/v1/audit/event")
    def audit_event(payload: AuditEvent, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        auth.verify_bearer(authorization, "event:audit:write")
        return core.submit_audit_event(payload)

    @app.get("/v1/audit/events")
    def audit_events(agentguard_session: str | None = Cookie(default=None)) -> list[dict[str, Any]]:
        auth.verify_browser_session(agentguard_session)
        return [event.model_dump(mode="json") for event in core.list_audit_events()]

    @app.get("/v1/metrics/eval")
    def eval_metrics(agentguard_session: str | None = Cookie(default=None)) -> dict[str, Any]:
        auth.verify_browser_session(agentguard_session)
        return core.eval_metrics()

    @app.get("/v1/approvals/pending")
    def pending_approvals(agentguard_session: str | None = Cookie(default=None)) -> list[dict[str, Any]]:
        session = auth.verify_browser_session(agentguard_session)
        rows: list[dict[str, Any]] = []
        for approval in core.list_pending_approvals():
            payload = approval.model_dump(mode="json")
            payload["approval_nonce"] = auth.issue_approval_nonce(
                approval_id=approval.approval_id,
                session_id=session.session_id,
                tool_call_id=approval.tool_call_id,
            )
            rows.append(payload)
        return rows

    @app.post("/v1/approvals/{approval_id}/resolve")
    def resolve_approval(
        approval_id: str,
        payload: ApprovalResolveRequest,
        x_agentguard_csrf: str | None = Header(default=None, alias="X-AgentGuard-CSRF"),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        session = auth.verify_browser_session(agentguard_session)
        auth.verify_csrf(session, x_agentguard_csrf)
        approval = core.get_approval(approval_id)
        if approval is None:
            raise ApiAuthError("APPROVAL_NOT_FOUND", status_code=404)
        auth.consume_approval_nonce(
            nonce=payload.approval_nonce,
            approval_id=approval_id,
            session_id=session.session_id,
            tool_call_id=approval.tool_call_id,
        )
        if payload.decision not in approval.decision_options:
            raise ApiAuthError("APPROVAL_DECISION_INVALID", status_code=403)
        resolved = core.resolve_approval(approval_id, payload.decision)
        return {
            "approval_id": resolved.approval_id,
            "status": resolved.status,
            "decision": resolved.decision,
        }

    @app.get("/v1/approvals/{approval_id}/wait")
    def wait_approval(approval_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        context = auth.verify_bearer(authorization, "approval:wait")
        approval = core.get_approval(approval_id)
        if approval is None:
            raise ApiAuthError("APPROVAL_NOT_FOUND", status_code=404)
        if approval.requesting_principal_id != context.principal_id:
            raise ApiAuthError("APPROVAL_WAIT_DENIED", status_code=403)
        if approval.status == "resolved":
            return {"status": "resolved", "decision": approval.decision}
        return {"status": approval.status, "decision": "deny" if approval.status != "pending" else None}

    return app


app = create_app()
