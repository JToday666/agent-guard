"""Audit, trace, and provenance routes."""

from __future__ import annotations

from typing import Any

from agentguard_core import AuditEvent

from guard_api.auth import ApiAuthError
from guard_api.errors import error_response
from guard_api.services.audit import PolicyEvaluationWriteForbiddenError
from guard_api.services.trace import (
    encode_conditional_document,
    if_none_match_matches,
)
from guard_api.storage.base import AuditIdConflictError
from fastapi import Cookie, FastAPI, Header
from fastapi.responses import JSONResponse, Response

from guard_api.storage.base import AuditEventFilters

from .common import (
    bounded_limit,
    verify_browser_or_bearer_read,
    verify_browser_or_bearer_scopes,
)
from .context import ApiContext

_TRACE_CACHE_HEADERS = {
    "Cache-Control": "private, no-cache",
    "Vary": "Cookie, Authorization",
}


def _conditional_json_response(
    payload: dict[str, object], if_none_match: str | None
) -> Response:
    body, etag = encode_conditional_document(payload)
    headers = {**_TRACE_CACHE_HEADERS, "ETag": etag}
    if if_none_match_matches(if_none_match, etag):
        return Response(status_code=304, headers=headers)
    return Response(content=body, media_type="application/json", headers=headers)


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    audit_service = context.audit_service
    trace_service = context.trace_service
    audit_window_service = context.audit_window_service
    settings = context.settings

    @app.post("/v1/audit/events")
    def audit_event(
        payload: AuditEvent, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        auth_context = auth.verify_bearer(authorization, "event:audit:write")
        metadata_agent_id = payload.metadata.get("agent_id")
        auth.verify_runtime_identity(
            auth_context,
            runtime=payload.runtime,
            agent_id=(
                metadata_agent_id
                if isinstance(metadata_agent_id, str) and metadata_agent_id
                else None
            ),
        )
        try:
            return audit_service.submit(payload)
        except PolicyEvaluationWriteForbiddenError:
            # §12.1：policy_evaluation 只能由 POST /v1/guard/evaluate 写入。
            raise ApiAuthError(
                "POLICY_EVALUATION_WRITE_FORBIDDEN",
                status_code=422,
            ) from None
        except AuditIdConflictError:
            raise ApiAuthError(
                "AUDIT_ID_CONFLICT",
                status_code=409,
            ) from None

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

    @app.get("/v1/audit/window", response_model=None)
    def audit_window(
        limit: int = 500,
        trace_id: str | None = None,
        case_id: str | None = None,
        runtime: str | None = None,
        decision: str | None = None,
        cursor: str | None = None,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any] | JSONResponse:
        # 契约 §14.1：feature flag 关闭时端点不存在。
        if not settings.audit_window_enabled:
            return error_response("NOT_FOUND", status_code=404)
        # 契约 §5.1：bearer 需同时具备 audit:read 与 metrics:read。
        verify_browser_or_bearer_scopes(
            auth,
            required_scopes=("audit:read", "metrics:read"),
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return audit_window_service.get_window(
            limit=bounded_limit(limit),
            trace_id=trace_id,
            case_id=case_id,
            runtime=runtime,
            decision=decision,
            cursor=cursor,
        )

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
        if_none_match: str | None = Header(default=None, alias="If-None-Match"),
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> Response:
        verify_browser_or_bearer_read(
            auth,
            required_scope="trace:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return _conditional_json_response(
            trace_service.get_trace(trace_id), if_none_match
        )

    @app.get("/v1/traces/{trace_id}/provenance")
    def trace_provenance(
        trace_id: str,
        if_none_match: str | None = Header(default=None, alias="If-None-Match"),
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> Response:
        verify_browser_or_bearer_read(
            auth,
            required_scope="trace:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return _conditional_json_response(
            trace_service.get_provenance(trace_id), if_none_match
        )
