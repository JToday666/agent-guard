"""Audit, trace, and provenance routes."""

from __future__ import annotations

from typing import Any

from agentguard_core import AuditEvent
from fastapi import Cookie, FastAPI, Header

from guard_api.storage.base import AuditEventFilters

from .common import bounded_limit, verify_browser_or_bearer_read
from .context import ApiContext


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    audit_service = context.audit_service
    trace_service = context.trace_service

    @app.post("/v1/audit/events")
    def audit_event(
        payload: AuditEvent, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        auth.verify_bearer(authorization, "event:audit:write")
        return audit_service.submit(payload)

    @app.get("/v1/audit/events")
    def audit_events(
        trace_id: str | None = None,
        case_id: str | None = None,
        runtime: str | None = None,
        decision: str | None = None,
        limit: int = 500,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="audit:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        filters = AuditEventFilters(
            trace_id=trace_id,
            case_id=case_id,
            runtime=runtime,
            decision=decision,
            limit=bounded_limit(limit),
        )
        return [
            event.model_dump(mode="json")
            for event in audit_service.list_events(filters)
        ]

    @app.get("/v1/audit/integrity")
    def audit_integrity(
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, object]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="audit:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return audit_service.integrity()

    @app.get("/v1/traces/{trace_id}")
    def trace_detail(
        trace_id: str,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="trace:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return trace_service.get_trace(trace_id)

    @app.get("/v1/traces/{trace_id}/provenance")
    def trace_provenance(
        trace_id: str,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, object]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="trace:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return trace_service.get_provenance(trace_id)
