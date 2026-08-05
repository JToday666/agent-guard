"""Human approval routes."""

from __future__ import annotations

from typing import Any

from fastapi import Cookie, FastAPI, Header
from pydantic import BaseModel

from guard_api.auth import ApiAuthError

from .context import ApiContext


class ApprovalResolveRequest(BaseModel):
    decision: str
    approval_nonce: str


def approval_wait_payload(approval: Any) -> dict[str, Any]:
    decision = approval.decision
    if approval.status not in {"pending", "resolved"} and decision is None:
        decision = "deny"
    return {
        "status": approval.status,
        "decision": decision,
        "resolution_source": approval.resolution_source,
        "resolved_by": approval.resolved_by,
        "resolution_reason": approval.resolution_reason,
        "llm_review": (
            approval.llm_review.model_dump()
            if approval.llm_review is not None
            else None
        ),
    }


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    approval_service = context.approval_service

    @app.get("/v1/approvals/pending")
    def pending_approvals(
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        session = auth.verify_browser_session(agentguard_session)
        rows: list[dict[str, Any]] = []
        for approval in approval_service.list_pending_approvals():
            payload = approval.model_dump(mode="json")
            payload["approval_nonce"] = auth.issue_approval_nonce(
                approval_id=approval.approval_id,
                session_id=session.session_id,
                subject_id=approval.subject_id,
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
            subject_id=approval.subject_id,
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
    def wait_approval(
        approval_id: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        context = auth.verify_bearer(authorization, "approval:wait")
        approval = approval_service.get_approval(approval_id)
        if approval is None:
            raise ApiAuthError("APPROVAL_NOT_FOUND", status_code=404)
        if approval.requesting_principal_id != context.principal_id:
            raise ApiAuthError("APPROVAL_WAIT_DENIED", status_code=403)
        return approval_wait_payload(approval)
