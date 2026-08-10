"""Configuration audit routes."""

from __future__ import annotations

from typing import Any

from agentguard_core import ConfigAuditEvent
from fastapi import Cookie, FastAPI, Header

from .common import bounded_limit, verify_browser_or_bearer_read
from .context import ApiContext


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    store = context.store
    config_audit_service = context.config_audit_service

    @app.get("/v1/config-audit/findings")
    def config_audit_findings(
        trace_id: str | None = None,
        target_id: str | None = None,
        target_type: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="config-audit:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return [
            row.model_dump(mode="json")
            for row in store.list_config_audit_findings(
                trace_id=trace_id,
                target_id=target_id,
                target_type=target_type,
                severity=severity,
                limit=bounded_limit(limit),
            )
        ]

    @app.post("/v1/config-audit/evaluate")
    def evaluate_config_audit_event(
        payload: ConfigAuditEvent,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth_context = auth.verify_bearer(authorization, "event:evaluate")
        metadata_agent_id = payload.metadata.get("agent_id")
        auth.verify_runtime_identity(
            auth_context,
            runtime=payload.runtime,
            agent_id=(
                metadata_agent_id
                if isinstance(metadata_agent_id, str) and metadata_agent_id
                else None
            ),
            require_agent_id=True,
        )
        return config_audit_service.evaluate(payload).model_dump(mode="json")
