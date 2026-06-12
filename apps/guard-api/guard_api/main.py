"""FastAPI entrypoint for the Guard API / Control Plane."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Cookie, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agentguard_core import AuditEvent, GuardEvent

from guard_api.auth import ApiAuthError, CapabilityAuthService
from guard_api.services import (
    ApprovalService,
    AuditService,
    EvaluationService,
    MetricService,
    PolicyService,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import AuditEventFilters, ControlPlaneStore, EvalMetricFilters
from guard_api.storage.postgres import PostgresControlPlaneStore


class LaunchExchangeRequest(BaseModel):
    launch_code: str


class ApprovalResolveRequest(BaseModel):
    decision: str
    approval_nonce: str


def _bounded_limit(limit: int) -> int:
    return max(1, min(limit, 1000))


def create_app(*, store: ControlPlaneStore | None = None, settings: GuardApiSettings | None = None) -> FastAPI:
    settings = settings or GuardApiSettings()
    store = store or PostgresControlPlaneStore(settings.database_url)
    auth = CapabilityAuthService(settings=settings, store=store)
    audit_service = AuditService(store=store)
    approval_service = ApprovalService(store=store, settings=settings)
    metric_service = MetricService(store=store)
    evaluation_service = EvaluationService(
        policy_service=PolicyService(),
        audit_service=audit_service,
        approval_service=approval_service,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        settings.validate_for_startup()
        store.initialize()
        yield

    app = FastAPI(title="AgentGuard Guard API", version="0.1.0", lifespan=lifespan)

    @app.exception_handler(ApiAuthError)
    async def auth_exception_handler(_: Request, exc: ApiAuthError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code}})

    @app.get("/health", response_model=None)
    def health(check_db: bool = False) -> dict[str, str] | JSONResponse:
        if check_db:
            if store.health_check():
                return {"status": "ok", "database": "ok"}
            return JSONResponse(status_code=503, content={"status": "degraded", "database": "error"})
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

    @app.post("/v1/guard/evaluate")
    def evaluate_guard_event(payload: GuardEvent, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        context = auth.verify_bearer(authorization, "event:evaluate")
        response = evaluation_service.evaluate(payload, requesting_principal_id=context.principal_id)
        return response.model_dump(mode="json")

    @app.post("/v1/audit/events")
    def audit_event(payload: AuditEvent, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        auth.verify_bearer(authorization, "event:audit:write")
        return audit_service.submit(payload)

    @app.get("/v1/audit/events")
    def audit_events(
        trace_id: str | None = None,
        case_id: str | None = None,
        runtime: str | None = None,
        decision: str | None = None,
        limit: int = 500,
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        auth.verify_browser_session(agentguard_session)
        filters = AuditEventFilters(
            trace_id=trace_id,
            case_id=case_id,
            runtime=runtime,
            decision=decision,
            limit=_bounded_limit(limit),
        )
        return [event.model_dump(mode="json") for event in audit_service.list_events(filters)]

    @app.get("/v1/metrics/eval")
    def eval_metrics(
        trace_id: str | None = None,
        case_id: str | None = None,
        runtime: str | None = None,
        decision: str | None = None,
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        auth.verify_browser_session(agentguard_session)
        filters = EvalMetricFilters(trace_id=trace_id, case_id=case_id, runtime=runtime, decision=decision)
        return metric_service.eval_metrics(filters)

    @app.get("/v1/approvals/pending")
    def pending_approvals(agentguard_session: str | None = Cookie(default=None)) -> list[dict[str, Any]]:
        session = auth.verify_browser_session(agentguard_session)
        rows: list[dict[str, Any]] = []
        for approval in approval_service.list_pending_approvals():
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
        approval = approval_service.get_approval(approval_id)
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
        resolved = approval_service.resolve_approval(approval_id, payload.decision)
        return {
            "approval_id": resolved.approval_id,
            "status": resolved.status,
            "decision": resolved.decision,
        }

    @app.get("/v1/approvals/{approval_id}/wait")
    def wait_approval(approval_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        context = auth.verify_bearer(authorization, "approval:wait")
        approval = approval_service.get_approval(approval_id)
        if approval is None:
            raise ApiAuthError("APPROVAL_NOT_FOUND", status_code=404)
        if approval.requesting_principal_id != context.principal_id:
            raise ApiAuthError("APPROVAL_WAIT_DENIED", status_code=403)
        if approval.status == "resolved":
            return {"status": "resolved", "decision": approval.decision}
        return {"status": approval.status, "decision": "deny" if approval.status != "pending" else None}

    return app


app = create_app()
