"""Health and adapter runtime routes."""

from __future__ import annotations

from typing import Any, cast

from agentguard_core import utc_now_iso
from fastapi import Cookie, FastAPI, Header, Query
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from guard_api.auth import ApiAuthError
from guard_api.models import AdapterStatusRecord
from guard_api.runtime_status import (
    ProductRuntime,
    ProductRuntimeHeartbeatV2,
    ProductRuntimeStatusIdentityV1,
    ProductRuntimeStatusV2,
)

from .common import verify_browser_or_bearer_read
from .context import ApiContext


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    store = context.store

    @app.get("/health", response_model=None)
    def health(check_db: bool = False) -> dict[str, str] | JSONResponse:
        if check_db:
            if store.health_check():
                return {"status": "ok", "database": "ok"}
            return JSONResponse(
                status_code=503, content={"status": "degraded", "database": "error"}
            )
        return {"status": "ok"}

    @app.put("/v1/adapters/{runtime}/status")
    def save_adapter_status(
        runtime: str,
        payload: AdapterStatusRecord,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth_context = auth.verify_bearer(authorization, "adapter:status:write")
        if auth_context.role == "adapter":
            auth.verify_runtime_identity(
                auth_context,
                runtime=runtime,
                agent_id=payload.agent_id,
                require_agent_id=True,
            )
        return store.save_adapter_status(
            runtime,
            payload,
            preserve_heartbeat=True,
        )

    @app.post("/v1/adapters/{runtime}/heartbeat")
    def save_adapter_heartbeat(
        runtime: str,
        payload: ProductRuntimeHeartbeatV2 | AdapterStatusRecord,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth_context = auth.verify_bearer(authorization, "adapter:status:write")
        if isinstance(payload, ProductRuntimeHeartbeatV2):
            auth.verify_runtime_identity(
                auth_context,
                runtime=runtime,
                agent_id=payload.agent_id,
                require_agent_id=True,
            )
            try:
                status = ProductRuntimeStatusV2.model_validate(
                    {
                        **payload.model_dump(mode="json"),
                        "runtime": runtime,
                        "principal_id": auth_context.principal_id,
                        "last_heartbeat_at": utc_now_iso(),
                    }
                )
            except ValidationError:
                raise ApiAuthError("VALIDATION_ERROR", status_code=422) from None
            persisted = store.save_product_runtime_status(status)
            return {"runtime_status": persisted.model_dump(mode="json")}

        auth.verify_runtime_identity(
            auth_context,
            runtime=runtime,
            agent_id=payload.agent_id,
            require_agent_id=True,
        )
        heartbeat = payload.model_copy(
            update={
                "last_heartbeat_at": utc_now_iso(),
            }
        )
        return store.save_adapter_status(runtime, heartbeat)

    @app.get("/v1/adapters/{runtime}/status")
    def get_adapter_status(
        runtime: str,
        agent_id: str | None = Query(default=None, min_length=1),
        runtime_binding_id: str | None = Query(default=None, min_length=1),
        profile_id: str | None = Query(default=None, min_length=1),
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="adapter:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        identity_values = (agent_id, runtime_binding_id, profile_id)
        if all(value is None for value in identity_values):
            status = store.get_adapter_status(runtime)
            if status is None:
                return AdapterStatusRecord().model_dump(mode="json")
            return status
        if not all(value is not None for value in identity_values):
            raise ApiAuthError("VALIDATION_ERROR", status_code=422)
        assert agent_id is not None
        assert runtime_binding_id is not None
        assert profile_id is not None
        try:
            identity = ProductRuntimeStatusIdentityV1(
                runtime=cast(ProductRuntime, runtime),
                agent_id=agent_id,
                runtime_binding_id=runtime_binding_id,
                profile_id=profile_id,
            )
        except ValidationError:
            raise ApiAuthError("VALIDATION_ERROR", status_code=422) from None
        product_status = store.get_product_runtime_status(identity)
        if product_status is None:
            raise ApiAuthError("NOT_FOUND", status_code=404)
        return product_status.model_dump(mode="json")

    @app.get("/v1/adapters/{runtime}/statuses")
    def list_product_runtime_statuses(
        runtime: str,
        limit: int = Query(default=100, ge=1, le=500),
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="adapter:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        if runtime not in {"langgraph", "openclaw"}:
            raise ApiAuthError("VALIDATION_ERROR", status_code=422)
        product_runtime = cast(ProductRuntime, runtime)
        return [
            status.model_dump(mode="json")
            for status in store.list_product_runtime_statuses(
                runtime=product_runtime,
                limit=limit,
            )
        ]
