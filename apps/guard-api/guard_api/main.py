"""FastAPI entrypoint for the Guard API / Control Plane."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from agentguard_core import PolicyBundle
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from guard_api import __version__
from guard_api.auth import ApiAuthError, CapabilityAuthService
from guard_api.errors import error_response, http_error_code, validation_error_details
from guard_api.llm_approval import HttpLlmApprovalReviewer, LlmApprovalReviewer
from guard_api.middleware import RequestBodyLimitMiddleware
from guard_api.routers import ApiContext, register_routes
from guard_api.services import (
    ApprovalService,
    AuditService,
    AuditWindowRequestError,
    AuditWindowService,
    ConfigAuditService,
    EvaluationService,
    MemoryGuardService,
    MetricService,
    PolicyService,
    ProvenanceWriter,
    TraceService,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import (
    AuditTimestampError,
    ControlPlaneStore,
    ProvenanceConflictError,
)
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore


def create_app(
    *,
    store: ControlPlaneStore | None = None,
    settings: GuardApiSettings | None = None,
    policy_bundle: PolicyBundle | None = None,
    policy_provider: Callable[[], PolicyBundle] | None = None,
    llm_approval_reviewer: LlmApprovalReviewer | None = None,
) -> FastAPI:
    settings = settings or GuardApiSettings()
    if store is None:
        if settings.storage_backend == "memory":
            store = MemoryControlPlaneStore()
        else:
            store = PostgresControlPlaneStore(settings.database_url)

    auth = CapabilityAuthService(settings=settings, store=store)
    provenance_writer = ProvenanceWriter(store=store)
    audit_service = AuditService(store=store, provenance_writer=provenance_writer)
    audit_window_service = AuditWindowService(store=store)
    config_audit_service = ConfigAuditService(store=store, audit_service=audit_service)
    memory_guard_service = MemoryGuardService(store=store)
    approval_service = ApprovalService(
        store=store,
        settings=settings,
        llm_reviewer=llm_approval_reviewer
        or HttpLlmApprovalReviewer.from_settings(settings),
        provenance_writer=provenance_writer,
    )
    metric_service = MetricService(store=store)
    trace_service = TraceService(
        store=store,
        audit_window_service=audit_window_service,
    )
    policy_service = PolicyService(
        store=store,
        policy_bundle=policy_bundle,
        policy_provider=policy_provider,
    )
    evaluation_service = EvaluationService(
        policy_service=policy_service,
        audit_service=audit_service,
        approval_service=approval_service,
        memory_guard_service=memory_guard_service,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        settings.validate_for_startup()
        store.initialize()
        yield

    app = FastAPI(title="AgentGuard Guard API", version=__version__, lifespan=lifespan)
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_body_bytes=settings.max_request_body_bytes,
    )

    @app.exception_handler(ApiAuthError)
    async def auth_exception_handler(_: Request, exc: ApiAuthError) -> JSONResponse:
        return error_response(exc.code, status_code=exc.status_code)

    @app.exception_handler(AuditWindowRequestError)
    async def audit_window_error_handler(
        _: Request, exc: AuditWindowRequestError
    ) -> JSONResponse:
        return error_response(exc.code, status_code=exc.status_code)

    @app.exception_handler(ProvenanceConflictError)
    async def provenance_conflict_handler(
        _: Request, __: ProvenanceConflictError
    ) -> JSONResponse:
        return error_response("PROVENANCE_CONFLICT", status_code=409)

    @app.exception_handler(AuditTimestampError)
    async def audit_timestamp_error_handler(
        _: Request, __: AuditTimestampError
    ) -> JSONResponse:
        return error_response("AUDIT_TIMESTAMP_INVALID", status_code=422)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        _: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return error_response(
            "VALIDATION_ERROR",
            status_code=422,
            details=validation_error_details(list(exc.errors())),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        _: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        return error_response(
            http_error_code(exc.status_code),
            status_code=exc.status_code,
            message=str(exc.detail) if exc.detail else None,
            details={"detail": exc.detail} if exc.detail else [],
        )

    register_routes(
        app,
        ApiContext(
            settings=settings,
            store=store,
            auth=auth,
            audit_service=audit_service,
            audit_window_service=audit_window_service,
            config_audit_service=config_audit_service,
            memory_guard_service=memory_guard_service,
            approval_service=approval_service,
            metric_service=metric_service,
            trace_service=trace_service,
            policy_service=policy_service,
            evaluation_service=evaluation_service,
        ),
    )
    return app


app = create_app()
