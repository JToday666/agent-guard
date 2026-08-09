"""Evaluation and runtime metrics routes."""

from __future__ import annotations

from typing import Any

from fastapi import Cookie, FastAPI, Header

from .common import bounded_limit, verify_browser_or_bearer_read
from .context import ApiContext


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    metric_service = context.metric_service
    audit_window_service = context.audit_window_service

    @app.get("/v1/metrics/policy-evaluations", response_model=None)
    def policy_evaluation_cohort(
        evaluated_from: str | None = None,
        evaluated_to: str | None = None,
        outcomes_as_of: str | None = None,
        runtime: str | None = None,
        case_id: str | None = None,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="metrics:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        # 契约 §6.1：evaluated_from/to 必填；时间参数规范化到 UTC。
        return audit_window_service.get_policy_cohort(
            evaluated_from=evaluated_from,
            evaluated_to=evaluated_to,
            outcomes_as_of=outcomes_as_of,
            runtime=runtime,
            case_id=case_id,
        )

    @app.get("/v1/metrics/runtime")
    def runtime_metrics(
        runtime: str | None = None,
        limit: int = 1000,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, object]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="metrics:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return metric_service.runtime_metrics(
            runtime=runtime, limit=bounded_limit(limit)
        )
