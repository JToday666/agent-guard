"""Evaluation and runtime metrics routes."""

from __future__ import annotations

from typing import Any

from fastapi import Cookie, FastAPI, Header

from guard_api.storage.base import EvalMetricFilters

from .common import bounded_limit, verify_browser_or_bearer_read
from .context import ApiContext


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    metric_service = context.metric_service

    @app.get("/v1/metrics/eval")
    def eval_metrics(
        trace_id: str | None = None,
        case_id: str | None = None,
        runtime: str | None = None,
        decision: str | None = None,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="metrics:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        filters = EvalMetricFilters(
            trace_id=trace_id, case_id=case_id, runtime=runtime, decision=decision
        )
        return metric_service.eval_metrics(filters)

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
