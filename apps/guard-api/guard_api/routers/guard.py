"""Guard evaluation route."""

from __future__ import annotations

from typing import Any

from agentguard_core import GuardEvent
from fastapi import FastAPI, Header

from .context import ApiContext


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    evaluation_service = context.evaluation_service

    @app.post("/v1/guard/evaluate")
    def evaluate_guard_event(
        payload: GuardEvent, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        context = auth.verify_bearer(authorization, "event:evaluate")
        response = evaluation_service.evaluate(
            payload, requesting_principal_id=context.principal_id
        )
        return response.model_dump(mode="json")
