"""Guard evaluation route."""

from __future__ import annotations

import logging
from typing import Any

from agentguard_core import GuardEvent
from fastapi import FastAPI, Header

from guard_api.auth import ApiAuthError
from guard_api.services.evaluation import EvaluationConflictError

from .context import ApiContext

logger = logging.getLogger(__name__)


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
                payload,
                auth_context=context,
            )
        except EvaluationConflictError as exc:
            logger.warning(
                "evaluation conflict for event %s (%s): %s",
                payload.event_id,
                payload.event_type,
                exc,
                exc_info=True,
            )
            raise ApiAuthError("EVALUATION_CONFLICT", status_code=409) from None
        dumped = response.model_dump(mode="json")
        # Keep the frozen C1 wire keyset even on older supported Pydantic
        # releases that do not honor Field(exclude_if=...).
        if response.enforcement_binding is None:
            dumped.pop("enforcement_binding", None)
        if response.context_plan is None:
            dumped.pop("context_plan", None)
        if response.decision_authority is None:
            dumped.pop("decision_authority", None)
        if response.approval_release_directive is None:
            dumped.pop("approval_release_directive", None)
        return dumped
