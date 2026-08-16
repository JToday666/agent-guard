"""FastAPI entrypoint for the Guard API / Control Plane."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from pathlib import Path

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
from guard_api.security_state import SecurityStateService
from guard_api.security_state.lease_service import (
    approval_execution_lease_service_from_settings,
)
from guard_api.services import (
    ApprovalService,
    AuditCheckpointService,
    AuditService,
    AuditWindowRequestError,
    AuditWindowService,
    ConfigAuditService,
    CtProjectionService,
    EvaluationService,
    MemoryGuardService,
    MetricService,
    PolicyService,
    PolicyValidationError,
    ProvenanceWriter,
    TaskIngressService,
    TraceService,
    V21PipelineService,
    V21ShadowService,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import (
    AuditCanonicalizationError,
    AuditTimestampError,
    ControlPlaneStore,
    EvaluationRunConflictError,
    PolicyRevisionConflictError,
    ProvenanceConflictError,
    TaskRevisionConflictError,
)
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore

logger = logging.getLogger(__name__)


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
    audit_checkpoint_service: AuditCheckpointService | None = None
    if settings.audit_checkpoint_configured():
        checkpoint_key = settings.audit_checkpoint_signing_key()
        assert checkpoint_key is not None
        assert settings.audit_checkpoint_path is not None
        assert settings.audit_checkpoint_key_id is not None
        audit_checkpoint_service = AuditCheckpointService(
            store=store,
            path=Path(settings.audit_checkpoint_path),
            signing_key=checkpoint_key,
            key_id=settings.audit_checkpoint_key_id,
        )
    audit_service = AuditService(
        store=store,
        provenance_writer=provenance_writer,
        checkpoint_service=audit_checkpoint_service,
    )
    audit_window_service = AuditWindowService(
        store=store,
        cursor_signing_key=settings.audit_cursor_signing_key(),
    )
    config_audit_service = ConfigAuditService(store=store, audit_service=audit_service)
    # V21-08：安全状态门面（构造无 I/O；flag off 时不产生任何 I/O）。
    # 提前创建以便 ApprovalService 承接 human allow_once → grant 投影（T6），
    # 且与 V21ShadowService 共用同一实例，不重复注册。
    security_state_service = SecurityStateService(store)
    approval_service = ApprovalService(
        store=store,
        settings=settings,
        llm_reviewer=llm_approval_reviewer
        or HttpLlmApprovalReviewer.from_settings(settings),
        provenance_writer=provenance_writer,
        state_service=security_state_service,
    )
    approval_execution_lease_service = approval_execution_lease_service_from_settings(
        store,
        settings,
        approval_service,
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
    # V21-08：shadow 旁路编排器（flag 默认关闭，D3）。
    # 构造无 I/O；flag off 时 build_shadow_evidence 仅一次布尔判断，
    # evaluate 热路径不引入任何额外状态读取。
    v21_shadow_service = V21ShadowService(
        settings=settings,
        store=store,
        state_service=security_state_service,
    )
    # V21-09：四段式编排器（D4，shadow-only）。与 V21ShadowService 同一
    # flag/secret 门控；就绪时 evaluate 编排切换为 pipeline（Phase A
    # 事务外、Phase B 短事务），Phase A 彻底失败回退 V21-08 逐字节路径。
    v21_pipeline_service = V21PipelineService(
        settings=settings,
        store=store,
        state_service=security_state_service,
        policy_service=policy_service,
    )
    # CT-PR-03b：CT 事实投影编排器（D2/D3：独立 flag，默认关闭；
    # 仅 pipeline 材料就绪时生效）。构造无 I/O；flag off 时全部入口
    # 仅一次布尔判断，evaluate 热路径零新增开销。
    ct_projection_service = CtProjectionService(
        settings=settings,
        store=store,
        state_service=security_state_service,
    )
    memory_guard_service = MemoryGuardService(
        store=store,
        audit_service=audit_service,
        projection_service=ct_projection_service,
    )
    evaluation_service = EvaluationService(
        policy_service=policy_service,
        audit_service=audit_service,
        approval_service=approval_service,
        memory_guard_service=memory_guard_service,
        v21_shadow_service=v21_shadow_service,
        v21_pipeline=v21_pipeline_service,
        ct_projection_service=ct_projection_service,
    )
    task_ingress_service = TaskIngressService(store=store, settings=settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        settings.validate_for_startup()
        store.initialize()
        checkpoint_task: asyncio.Task[None] | None = None
        if audit_checkpoint_service is not None:
            audit_checkpoint_service.initialize()
            checkpoint_task = asyncio.create_task(
                _run_audit_checkpoint_loop(
                    audit_checkpoint_service,
                    interval_seconds=settings.audit_checkpoint_interval_seconds,
                ),
                name="agentguard-audit-checkpoint",
            )
        try:
            yield
        finally:
            if checkpoint_task is not None and audit_checkpoint_service is not None:
                checkpoint_task.cancel()
                with suppress(asyncio.CancelledError):
                    await checkpoint_task
                try:
                    await asyncio.to_thread(audit_checkpoint_service.checkpoint)
                except Exception:  # pragma: no cover - shutdown diagnostic path
                    logger.exception("final audit checkpoint failed")

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

    @app.exception_handler(AuditCanonicalizationError)
    async def audit_canonicalization_error_handler(
        _: Request, __: AuditCanonicalizationError
    ) -> JSONResponse:
        return error_response("AUDIT_CANONICALIZATION_INVALID", status_code=422)

    @app.exception_handler(PolicyValidationError)
    async def policy_validation_error_handler(
        _: Request, exc: PolicyValidationError
    ) -> JSONResponse:
        return error_response(
            "POLICY_INVALID",
            status_code=422,
            details=[issue.as_dict() for issue in exc.issues],
        )

    @app.exception_handler(PolicyRevisionConflictError)
    async def policy_revision_conflict_handler(
        _: Request, exc: PolicyRevisionConflictError
    ) -> JSONResponse:
        return error_response(
            "POLICY_REVISION_CONFLICT",
            status_code=412,
            details={
                "expected_revision": exc.expected_revision,
                "current_revision": exc.current_revision,
            },
        )

    @app.exception_handler(EvaluationRunConflictError)
    async def evaluation_run_conflict_handler(
        _: Request, exc: EvaluationRunConflictError
    ) -> JSONResponse:
        return error_response(
            "EVALUATION_RUN_CONFLICT",
            status_code=409,
            details={"run_id": exc.run_id},
        )

    @app.exception_handler(TaskRevisionConflictError)
    async def task_revision_conflict_handler(
        _: Request, exc: TaskRevisionConflictError
    ) -> JSONResponse:
        return error_response(
            "TASK_REVISION_CONFLICT",
            status_code=409,
            details={
                "expected_revision": exc.expected_revision,
                "current_revision": exc.current_revision,
            },
        )

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
            approval_execution_lease_service=approval_execution_lease_service,
            metric_service=metric_service,
            trace_service=trace_service,
            policy_service=policy_service,
            evaluation_service=evaluation_service,
            task_ingress_service=task_ingress_service,
            security_state_service=security_state_service,
            v21_shadow_service=v21_shadow_service,
        ),
    )
    return app


async def _run_audit_checkpoint_loop(
    service: AuditCheckpointService,
    *,
    interval_seconds: int,
) -> None:
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            await asyncio.to_thread(service.checkpoint)
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - logged operational degradation
            logger.exception("scheduled audit checkpoint failed")


app = create_app()
