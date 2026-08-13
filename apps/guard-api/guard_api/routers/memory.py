"""Memory change routes."""

from __future__ import annotations

from typing import Any

from agentguard_core import MemoryGuardChange
from fastapi import FastAPI, Header

from guard_api.auth import ApiAuthError

from .context import ApiContext


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    memory_guard_service = context.memory_guard_service

    @app.post("/v1/memory/changes/propose")
    def propose_memory_change(
        payload: MemoryGuardChange,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth_context = auth.verify_bearer(authorization, "event:evaluate")
        return memory_guard_service.propose(
            payload,
            runtime=auth_context.runtime,
            agent_id=auth_context.agent_id,
            principal_id=auth_context.principal_id,
        ).model_dump(mode="json")

    @app.post("/v1/memory/changes/{change_id}/commit")
    def commit_memory_change(
        change_id: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        auth.verify_bearer(authorization, "event:evaluate")
        try:
            return memory_guard_service.commit(change_id).model_dump(mode="json")
        except KeyError:
            raise ApiAuthError("MEMORY_CHANGE_NOT_FOUND", status_code=404)

    @app.post("/v1/memory/changes/{change_id}/rollback")
    def rollback_memory_change(
        change_id: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        auth.verify_bearer(authorization, "event:evaluate")
        try:
            return memory_guard_service.rollback(change_id).model_dump(mode="json")
        except KeyError:
            raise ApiAuthError("MEMORY_CHANGE_NOT_FOUND", status_code=404)
