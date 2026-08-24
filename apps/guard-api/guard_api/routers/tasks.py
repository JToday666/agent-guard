"""V21-03 Task Ingress routes：task:write 专用任务入口（01 §30）。

``POST /v1/tasks`` 创建 authoritative TaskFact；``PUT /v1/tasks/{task_id}``
按 ``expected_revision`` 修订。两者首行均要求已认证 ``task:write`` scope
（adapter 凭据结构上不持有该 scope）；runtime 绑定凭据另经
``verify_runtime_identity`` 校验请求 runtime 一致性。
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header

from guard_api.models import TaskCreateRequest, TaskReviseRequest

from .context import ApiContext


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    task_ingress_service = context.task_ingress_service

    @app.post("/v1/tasks")
    def create_task(
        payload: TaskCreateRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth_context = auth.verify_bearer(authorization, "task:write")
        if auth_context.runtime is not None:
            auth.verify_runtime_identity(auth_context, runtime=payload.runtime)
        return task_ingress_service.create_task(payload, auth_context).model_dump(
            mode="json"
        )

    @app.put("/v1/tasks/{task_id}")
    def revise_task(
        task_id: str,
        payload: TaskReviseRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth_context = auth.verify_bearer(authorization, "task:write")
        if auth_context.runtime is not None:
            auth.verify_runtime_identity(auth_context, runtime=payload.runtime)
        return task_ingress_service.revise_task(
            task_id, payload, auth_context
        ).model_dump(mode="json")
