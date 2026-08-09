"""Guard evaluation route."""

from __future__ import annotations

from typing import Any

from agentguard_core import GuardEvent
from fastapi import FastAPI, Header

from guard_api.auth import ApiAuthError
from guard_api.services.evaluation import EvaluationConflictError

from .context import ApiContext


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    evaluation_service = context.evaluation_service

    @app.post("/v1/guard/evaluate")
    def evaluate_guard_event(
        payload: GuardEvent, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        context = auth.verify_bearer(authorization, "event:evaluate")
        event_agent_id = (
            payload.security_context.agent_id
            if "agent_id" in payload.security_context.model_fields_set
            else None
        )
        auth.verify_runtime_identity(
            context,
            runtime=payload.runtime,
            agent_id=event_agent_id,
            require_agent_id=True,
        )
        try:
            response = evaluation_service.evaluate(
                payload, requesting_principal_id=context.principal_id
            )
        except EvaluationConflictError:
            raise ApiAuthError("EVALUATION_CONFLICT", status_code=409) from None
        return response.model_dump(mode="json")
