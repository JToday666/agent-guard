"""Health and adapter runtime routes."""

from __future__ import annotations

from typing import Any

from agentguard_core import utc_now_iso
from fastapi import Cookie, FastAPI, Header
from fastapi.responses import JSONResponse

from guard_api.models import AdapterStatusRecord

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
        return store.save_adapter_status(runtime, payload)

    @app.post("/v1/adapters/{runtime}/heartbeat")
    def save_adapter_heartbeat(
        runtime: str,
        payload: AdapterStatusRecord,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth_context = auth.verify_bearer(authorization, "adapter:status:write")
        auth.verify_runtime_identity(
            auth_context,
            runtime=runtime,
            agent_id=payload.agent_id,
            require_agent_id=True,
        )
        heartbeat = payload.model_copy(
            update={
                "last_heartbeat_at": payload.last_heartbeat_at or utc_now_iso(),
            }
        )
        return store.save_adapter_status(runtime, heartbeat)

    @app.get("/v1/adapters/{runtime}/status")
    def get_adapter_status(
        runtime: str,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="adapter:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        status = store.get_adapter_status(runtime)
        if status is None:
            return AdapterStatusRecord().model_dump(mode="json")
        return status
