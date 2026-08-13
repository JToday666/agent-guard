"""Memory change routes."""

from __future__ import annotations

from typing import Any

from agentguard_core import MemoryGuardChange
from fastapi import FastAPI, Header

from guard_api.auth import ApiAuthError, AuthContext, CapabilityAuthService
from guard_api.storage.base import MemoryChangeTransitionError

from .context import ApiContext


def _verify_change_ownership(
    auth: CapabilityAuthService,
    auth_context: AuthContext,
    change: MemoryGuardChange,
) -> None:
    """生命周期处置仅放给绑定身份一致的调用方。

    历史存量记录无 runtime 绑定，无法证明归属，一律拒绝并返回明确错误。
    runtime 身份一致还不够：同一 runtime/agent_id 下签发给不同 principal
    的凭证不得处置他人提议的变更，必须再比对提议方 principal。
    """

    if change.runtime is None:
        raise ApiAuthError("MEMORY_CHANGE_IDENTITY_UNBOUND", status_code=403)
    auth.verify_runtime_identity(
        auth_context,
        runtime=change.runtime,
        agent_id=change.agent_id,
    )
    if (
        change.principal_id is not None
        and change.principal_id != auth_context.principal_id
    ):
        raise ApiAuthError("MEMORY_CHANGE_PRINCIPAL_MISMATCH", status_code=403)


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
        auth_context = auth.verify_bearer(authorization, "event:evaluate")
        change = memory_guard_service.get(change_id)
        if change is None:
            raise ApiAuthError("MEMORY_CHANGE_NOT_FOUND", status_code=404)
        _verify_change_ownership(auth, auth_context, change)
        try:
            return memory_guard_service.commit(
                change_id, operator_id=auth_context.principal_id
            ).model_dump(mode="json")
        except MemoryChangeTransitionError:
            raise ApiAuthError("MEMORY_CHANGE_TRANSITION_CONFLICT", status_code=409)
        except KeyError:
            raise ApiAuthError("MEMORY_CHANGE_NOT_FOUND", status_code=404)

    @app.post("/v1/memory/changes/{change_id}/rollback")
    def rollback_memory_change(
        change_id: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        auth_context = auth.verify_bearer(authorization, "event:evaluate")
        change = memory_guard_service.get(change_id)
        if change is None:
            raise ApiAuthError("MEMORY_CHANGE_NOT_FOUND", status_code=404)
        _verify_change_ownership(auth, auth_context, change)
        try:
            return memory_guard_service.rollback(
                change_id, operator_id=auth_context.principal_id
            ).model_dump(mode="json")
        except MemoryChangeTransitionError:
            raise ApiAuthError("MEMORY_CHANGE_TRANSITION_CONFLICT", status_code=409)
        except KeyError:
            raise ApiAuthError("MEMORY_CHANGE_NOT_FOUND", status_code=404)
