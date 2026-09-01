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
    CriticalDecisionEvidenceError,
    ContextBuilderService,
    CtProjectionService,
    EvaluationService,
    load_frozen_competition_activation,
    load_frozen_product_activation,
    MemoryGuardService,
    MetricService,
    PolicyService,
    PolicyValidationError,
    ProductActivePreSelectorFuse,
    ProvenanceWriter,
    RuntimeBindingResolver,
    TaskIngressService,
    TraceService,
    V21PipelineService,
    V21OfficialEvaluationUnavailableError,
    V21ShadowService,
)
from guard_api.services.semantic import semantic_provider_from_settings
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

# ④ 最小日志装配：无外部配置时使 guard_api 的 INFO/WARNING 可见
# （如启动 warmup 结果），不覆盖已存在的 root handler。
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def create_app(
    *,
    store: ControlPlaneStore | None = None,
    settings: GuardApiSettings | None = None,
    policy_bundle: PolicyBundle | None = None,
    policy_provider: Callable[[], PolicyBundle] | None = None,
    llm_approval_reviewer: LlmApprovalReviewer | None = None,
) -> FastAPI:
    settings = settings or GuardApiSettings()
    product_activation = load_frozen_product_activation(settings)
    competition_activation = (
        None
        if product_activation is not None
        else load_frozen_competition_activation(settings)
    )
    if store is None:
        if settings.storage_backend == "memory":
            store = MemoryControlPlaneStore()
        else:
            store = PostgresControlPlaneStore(settings.database_url)

    product_active_fuse = (
        ProductActivePreSelectorFuse(
            activation=product_activation,
            store=store,
        )
        if product_activation is not None
        else None
    )
    # One process-frozen authority resolver is shared by TaskFact issuance and
    # V2 evaluation. Product mode accepts only the already verified activation
    # wrapper; all other modes preserve the legacy derivation exactly.
    runtime_binding_resolver = RuntimeBindingResolver(
        product_activation=product_activation
    )

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
        evidence_content_preview_enabled=settings.evidence_content_preview_enabled,
    )
    audit_window_service = AuditWindowService(
        store=store,
        cursor_signing_key=settings.audit_cursor_signing_key(),
    )
    config_audit_service = ConfigAuditService(store=store, audit_service=audit_service)
    # V21-08：安全状态门面（构造无 I/O；V2 mode off 时不产生任何 I/O）。
    # 提前创建以便 ApprovalService 承接 human allow_once → grant 投影（T6），
    # 且与 V21ShadowService 共用同一实例，不重复注册。
    security_state_service = SecurityStateService(store)
    resolved_llm_reviewer = (
        llm_approval_reviewer or HttpLlmApprovalReviewer.from_settings(settings)
    )
    approval_service = ApprovalService(
        store=store,
        settings=settings,
        llm_reviewer=resolved_llm_reviewer,
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
    # V21-08：shadow 旁路编排器（V2 mode 默认 off，D3）。
    # 构造无 I/O；mode off 时 build_shadow_evidence 仅一次布尔判断，
    # evaluate 热路径不引入任何额外状态读取。
    v21_shadow_service = V21ShadowService(
        settings=settings,
        store=store,
        state_service=security_state_service,
    )
    # V21-09：四段式编排器（D4，legacy shadow + Product fail-closed）。
    # 与 V21ShadowService 同一 mode/secret 门控；兼容路径的 Phase A 失败
    # 仍回退 V21-08。Product authority fence 与内部 selector/replay 已
    # 实现，但公开 composition root 仍由外层 fuse 阻断，待 ACK/freshness
    # 批次原子接线后才移除。
    competition_active = (
        competition_activation is not None
        and settings.effective_v21_mode() == "active"
        and competition_activation.manifest.profile_id == "competition-langgraph-v2"
        and competition_activation.manifest.runtime == "langgraph"
        and competition_activation.manifest.selection_basis == "profile_all"
    )
    # V21-13 Stage 1 shadow：semantic provider（flag 关/未 configured/
    # mode off 时恒 None，零开销）；在场时产物只供证据/评测，不改变
    # 官方决策。局部保留引用以便 lifespan shutdown 关闭共享
    # httpx.Client（评审 M2）。
    semantic_provider = semantic_provider_from_settings(settings)
    v21_pipeline_service = V21PipelineService(
        settings=settings,
        store=store,
        state_service=security_state_service,
        policy_service=policy_service,
        # V21-13 Stage 1 shadow：flag 关/未 configured 时恒 None（零
        # 开销）；在场时产物只供证据/评测，不改变官方决策。
        semantic_provider=semantic_provider,
        memory_not_required_actions=(
            frozenset({"model_call"}) if competition_active else frozenset()
        ),
        competition_model_output_observation=competition_active,
        runtime_binding_resolver=runtime_binding_resolver,
    )
    # CT-PR-03b：CT 事实投影编排器（D2/D3：独立 flag，默认关闭；
    # 仅 pipeline 材料就绪时生效）。构造无 I/O；flag off 时全部入口
    # 仅一次布尔判断，evaluate 热路径零新增开销。
    ct_projection_service = CtProjectionService(
        settings=settings,
        store=store,
        state_service=security_state_service,
    )
    context_builder_service = ContextBuilderService(
        settings=settings,
        store=store,
        state_service=security_state_service,
        policy_service=policy_service,
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
        context_builder_service=context_builder_service,
        competition_activation=competition_activation,
        product_active_fuse=product_active_fuse,
    )
    task_ingress_service = TaskIngressService(
        store=store,
        settings=settings,
        runtime_binding_resolver=runtime_binding_resolver,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        settings.validate_for_startup()
        store.initialize()
        warmup_task: asyncio.Task[None] | None = None
        if isinstance(resolved_llm_reviewer, HttpLlmApprovalReviewer):
            # ④ 启动预热：fire-and-forget、best-effort；warmup 内部任何
            # 异常只记日志，不阻塞启动，不影响首条请求路径。
            warmup_task = asyncio.create_task(
                asyncio.to_thread(resolved_llm_reviewer.warmup),
                name="agentguard-llm-approval-warmup",
            )
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
            if warmup_task is not None:
                warmup_task.cancel()
                with suppress(asyncio.CancelledError):
                    await warmup_task
            if checkpoint_task is not None and audit_checkpoint_service is not None:
                checkpoint_task.cancel()
                with suppress(asyncio.CancelledError):
                    await checkpoint_task
                try:
                    await asyncio.to_thread(audit_checkpoint_service.checkpoint)
                except Exception:  # pragma: no cover - shutdown diagnostic path
                    logger.exception("final audit checkpoint failed")
            if semantic_provider is not None:
                # 评审 M2：shutdown 关闭共享 httpx.Client 连接池；
                # close() 内部仅在 owns client（未注入外部 client）时
                # 执行关闭，注入式测试 client 不受影响。
                semantic_provider.close()

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

    @app.exception_handler(V21OfficialEvaluationUnavailableError)
    async def v21_official_unavailable_handler(
        _: Request, exc: V21OfficialEvaluationUnavailableError
    ) -> JSONResponse:
        return error_response(exc.code, status_code=503)

    @app.exception_handler(CriticalDecisionEvidenceError)
    async def critical_decision_evidence_handler(
        _: Request, __: CriticalDecisionEvidenceError
    ) -> JSONResponse:
        return error_response("V21_OFFICIAL_EVIDENCE_COMMIT_FAILED", status_code=503)

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
