"""FastAPI entrypoint for the Guard API / Control Plane."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Cookie, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from agentguard_core import AuditEvent, ConfigAuditEvent, GuardEvent, MemoryGuardChange, PolicyBundle, utc_now_iso

from guard_api.auth import ApiAuthError, CapabilityAuthService
from guard_api.errors import error_response, http_error_code, validation_error_details
from guard_api.llm_approval import HttpLlmApprovalReviewer, LlmApprovalReviewer
from guard_api.models import AdapterStatusRecord, CredentialCreateRequest, EvaluationRun
from guard_api.services import (
    ApprovalService,
    AuditService,
    ConfigAuditService,
    EvaluationService,
    MemoryGuardService,
    MetricService,
    PolicyService,
    TraceService,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import AuditEventFilters, ControlPlaneStore, EvalMetricFilters, PolicySnapshotRecord
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore


class LaunchExchangeRequest(BaseModel):
    launch_code: str


class ApprovalResolveRequest(BaseModel):
    decision: str
    approval_nonce: str


def _bounded_limit(limit: int) -> int:
    return max(1, min(limit, 1000))


def _policy_snapshot_record_payload(record: PolicySnapshotRecord) -> dict[str, Any]:
    return {
        "revision": record.revision,
        "updated_at": record.updated_at,
        "updated_by": record.updated_by,
        "bundle_id": record.policy_bundle.bundle_id,
        "version": record.policy_bundle.version,
    }


def _evaluation_dataset_registry(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    datasets: dict[str, dict[str, Any]] = {}
    version_maps: dict[str, dict[str, dict[str, Any]]] = {}
    for run in runs:
        dataset_id = run.get("dataset_id")
        dataset_version = run.get("dataset_version")
        if not isinstance(dataset_id, str) or not dataset_id:
            continue
        if not isinstance(dataset_version, str) or not dataset_version:
            continue
        dataset = datasets.setdefault(
            dataset_id,
            {
                "dataset_id": dataset_id,
                "run_count": 0,
                "latest_run_id": None,
                "latest_run_at": None,
                "versions": [],
            },
        )
        dataset["run_count"] += 1
        _refresh_latest_run(dataset, run)

        versions = version_maps.setdefault(dataset_id, {})
        version = versions.setdefault(
            dataset_version,
            {
                "dataset_version": dataset_version,
                "dataset_digest": run.get("dataset_digest"),
                "locked": bool(run.get("dataset_locked")),
                "run_count": 0,
                "case_count": 0,
                "case_provenance_count": 0,
                "latest_run_id": None,
                "latest_run_at": None,
                "regression_gate": None,
            },
        )
        version["run_count"] += 1
        version["case_count"] += len(run.get("cases") or [])
        version["case_provenance_count"] += sum(1 for case in run.get("cases") or [] if case.get("provenance"))
        version["locked"] = bool(version["locked"] or run.get("dataset_locked"))
        version["dataset_digest"] = run.get("dataset_digest") or version["dataset_digest"]
        if run.get("regression_gate") is not None:
            version["regression_gate"] = run["regression_gate"]
        _refresh_latest_run(version, run)

    for dataset_id, dataset in datasets.items():
        dataset["versions"] = sorted(
            version_maps[dataset_id].values(),
            key=lambda item: str(item["dataset_version"]),
            reverse=True,
        )
    return sorted(datasets.values(), key=lambda item: str(item["dataset_id"]))


def _refresh_latest_run(target: dict[str, Any], run: dict[str, Any]) -> None:
    run_at = str(run.get("run_at") or "")
    latest_at = str(target.get("latest_run_at") or "")
    if run_at >= latest_at:
        target["latest_run_id"] = run.get("run_id")
        target["latest_run_at"] = run.get("run_at")


def _changed_policy_fields(current: PolicyBundle, candidate: PolicyBundle) -> list[str]:
    current_payload = current.model_dump(mode="json")
    candidate_payload = candidate.model_dump(mode="json")
    return sorted(
        key
        for key in set(current_payload) | set(candidate_payload)
        if current_payload.get(key) != candidate_payload.get(key)
    )


def _verify_browser_or_bearer_read(
    auth: CapabilityAuthService,
    *,
    required_scope: str,
    authorization: str | None,
    agentguard_session: str | None,
) -> None:
    if authorization:
        auth.verify_bearer(authorization, required_scope)
        return
    auth.verify_browser_session(agentguard_session)


def _verify_adapter_heartbeat_write(auth: CapabilityAuthService, authorization: str | None) -> None:
    try:
        auth.verify_bearer(authorization, "adapter:status:write")
    except ApiAuthError as error:
        if error.code != "SCOPE_DENIED":
            raise
        auth.verify_bearer(authorization, "event:evaluate")


def _legacy_unknown_adapter_status() -> dict[str, Any]:
    return {
        "status": "unknown",
        "loaded": False,
        "hook_count": None,
        "expected_hook_count": 22,
        "last_verified_at": None,
        "error": None,
        "source": None,
    }


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
    audit_service = AuditService(store=store)
    config_audit_service = ConfigAuditService(store=store, audit_service=audit_service)
    memory_guard_service = MemoryGuardService(store=store)
    approval_service = ApprovalService(
        store=store,
        settings=settings,
        llm_reviewer=llm_approval_reviewer or HttpLlmApprovalReviewer.from_settings(settings),
    )
    metric_service = MetricService(store=store)
    trace_service = TraceService(store=store)
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

    app = FastAPI(title="AgentGuard Guard API", version="0.1.0", lifespan=lifespan)

    @app.exception_handler(ApiAuthError)
    async def auth_exception_handler(_: Request, exc: ApiAuthError) -> JSONResponse:
        return error_response(exc.code, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        return error_response(
            "VALIDATION_ERROR",
            status_code=422,
            details=validation_error_details(exc.errors()),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return error_response(
            http_error_code(exc.status_code),
            status_code=exc.status_code,
            message=str(exc.detail) if exc.detail else None,
            details={"detail": exc.detail} if exc.detail else [],
        )

    @app.get("/health", response_model=None)
    def health(check_db: bool = False) -> dict[str, str] | JSONResponse:
        if check_db:
            if store.health_check():
                return {"status": "ok", "database": "ok"}
            return JSONResponse(status_code=503, content={"status": "degraded", "database": "error"})
        return {"status": "ok"}

    @app.post("/v1/auth/browser/launch")
    def launch(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        auth.verify_bearer(authorization, "auth:launch")
        return {"launch_code": auth.create_launch_code(), "expires_in": settings.launch_code_ttl_seconds}

    @app.post("/v1/auth/browser/exchange")
    def exchange(payload: LaunchExchangeRequest) -> JSONResponse:
        session = auth.exchange_launch_code(payload.launch_code)
        response = JSONResponse(
            {
                "authenticated": True,
                "expires_at": session.expires_at.isoformat(),
                "csrf_token": session.csrf_token,
            }
        )
        response.set_cookie(
            "agentguard_session",
            session.session_id,
            httponly=True,
            samesite="strict",
            path="/",
            max_age=settings.browser_session_ttl_seconds,
        )
        return response

    @app.get("/v1/auth/browser/me")
    def me(agentguard_session: str | None = Cookie(default=None)) -> dict[str, Any]:
        session = auth.verify_browser_session(agentguard_session)
        return {
            "authenticated": True,
            "expires_at": session.expires_at.isoformat(),
            "csrf_token": session.csrf_token,
        }

    @app.post("/v1/auth/browser/logout")
    def logout(agentguard_session: str | None = Cookie(default=None)) -> JSONResponse:
        session = auth.verify_browser_session(agentguard_session)
        auth.logout_browser_session(session.session_id)
        response = JSONResponse({"authenticated": False})
        response.delete_cookie("agentguard_session", path="/")
        return response

    @app.post("/v1/guard/evaluate")
    def evaluate_guard_event(payload: GuardEvent, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        context = auth.verify_bearer(authorization, "event:evaluate")
        response = evaluation_service.evaluate(payload, requesting_principal_id=context.principal_id)
        return response.model_dump(mode="json")

    @app.get("/v1/policies/current")
    def current_policy(
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="policy:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return policy_service.current_snapshot().model_dump(mode="json")

    @app.put("/v1/policies/current")
    def update_current_policy(
        payload: PolicyBundle,
        x_agentguard_csrf: str | None = Header(default=None, alias="X-AgentGuard-CSRF"),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        session = auth.verify_browser_session(agentguard_session)
        auth.verify_csrf(session, x_agentguard_csrf)
        return policy_service.save_snapshot(payload, updated_by="dashboard").model_dump(mode="json")

    @app.get("/v1/policies/history")
    def policy_history(
        limit: int = 100,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="policy:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return [
            _policy_snapshot_record_payload(record)
            for record in policy_service.list_history(limit=_bounded_limit(limit))
        ]

    @app.post("/v1/policies/validate")
    def validate_policy(
        payload: PolicyBundle,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="policy:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return {"valid": True, "bundle_id": payload.bundle_id, "version": payload.version}

    @app.post("/v1/policies/diff")
    def diff_policy(
        payload: PolicyBundle,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="policy:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        current = policy_service.current_snapshot()
        return {
            "current": current.model_dump(mode="json"),
            "candidate": payload.model_dump(mode="json"),
            "changed_fields": _changed_policy_fields(current, payload),
        }

    @app.post("/v1/policies/rollback/{revision}")
    def rollback_policy(
        revision: int,
        x_agentguard_csrf: str | None = Header(default=None, alias="X-AgentGuard-CSRF"),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        session = auth.verify_browser_session(agentguard_session)
        auth.verify_csrf(session, x_agentguard_csrf)
        for record in policy_service.list_history(limit=1000):
            if record.revision == revision:
                return policy_service.save_snapshot(record.policy_bundle, updated_by="rollback").model_dump(mode="json")
        raise ApiAuthError("POLICY_REVISION_NOT_FOUND", status_code=404)

    @app.post("/v1/audit/events")
    def audit_event(payload: AuditEvent, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        auth.verify_bearer(authorization, "event:audit:write")
        return audit_service.submit(payload)

    @app.get("/v1/audit/events")
    def audit_events(
        trace_id: str | None = None,
        case_id: str | None = None,
        runtime: str | None = None,
        decision: str | None = None,
        limit: int = 500,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="audit:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        filters = AuditEventFilters(
            trace_id=trace_id,
            case_id=case_id,
            runtime=runtime,
            decision=decision,
            limit=_bounded_limit(limit),
        )
        return [event.model_dump(mode="json") for event in audit_service.list_events(filters)]

    @app.get("/v1/audit/integrity")
    def audit_integrity(
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, object]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="audit:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return audit_service.integrity()

    @app.get("/v1/metrics/eval")
    def eval_metrics(
        trace_id: str | None = None,
        case_id: str | None = None,
        runtime: str | None = None,
        decision: str | None = None,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="metrics:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        filters = EvalMetricFilters(trace_id=trace_id, case_id=case_id, runtime=runtime, decision=decision)
        return metric_service.eval_metrics(filters)

    @app.get("/v1/metrics/runtime")
    def runtime_metrics(
        runtime: str | None = None,
        limit: int = 1000,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, object]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="metrics:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return metric_service.runtime_metrics(runtime=runtime, limit=_bounded_limit(limit))

    @app.post("/v1/evaluations")
    def save_evaluation_run(
        payload: EvaluationRun,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth.verify_bearer(authorization, "evaluation:write")
        return store.save_evaluation_run(payload)

    @app.get("/v1/evaluations")
    def list_evaluation_runs(
        dataset_id: str | None = None,
        dataset_version: str | None = None,
        limit: int = 100,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="evaluation:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return store.list_evaluation_runs(
            dataset_id=dataset_id,
            dataset_version=dataset_version,
            limit=_bounded_limit(limit),
        )

    @app.get("/v1/evaluations/datasets")
    def list_evaluation_datasets(
        dataset_id: str | None = None,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="evaluation:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        runs = store.list_evaluation_runs(dataset_id=dataset_id, limit=1000)
        return _evaluation_dataset_registry(runs)

    @app.get("/v1/evaluations/latest")
    def latest_evaluation_run(
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="evaluation:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        run = store.get_latest_evaluation_run()
        if run is None:
            raise ApiAuthError("EVALUATION_NOT_FOUND", status_code=404)
        return run

    @app.get("/v1/evaluations/{run_id}")
    def get_evaluation_run(
        run_id: str,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="evaluation:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        run = store.get_evaluation_run(run_id)
        if run is None:
            raise ApiAuthError("EVALUATION_NOT_FOUND", status_code=404)
        return run

    @app.get("/v1/traces/{trace_id}")
    def trace_detail(
        trace_id: str,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="trace:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return trace_service.get_trace(trace_id)

    @app.get("/v1/traces/{trace_id}/provenance")
    def trace_provenance(
        trace_id: str,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, object]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="trace:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return trace_service.get_provenance(trace_id)

    @app.get("/v1/config-audit/findings")
    def config_audit_findings(
        trace_id: str | None = None,
        target_id: str | None = None,
        target_type: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="config-audit:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return [
            row.model_dump(mode="json")
            for row in store.list_config_audit_findings(
                trace_id=trace_id,
                target_id=target_id,
                target_type=target_type,
                severity=severity,
                limit=_bounded_limit(limit),
            )
        ]

    @app.post("/v1/config-audit/evaluate")
    def evaluate_config_audit_event(
        payload: ConfigAuditEvent,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth.verify_bearer(authorization, "event:evaluate")
        return config_audit_service.evaluate(payload).model_dump(mode="json")

    @app.put("/v1/adapters/{adapter_id}/status")
    def save_openclaw_adapter_status(
        adapter_id: str,
        payload: AdapterStatusRecord,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth.verify_bearer(authorization, "adapter:status:write")
        return store.save_adapter_status(adapter_id, payload)

    @app.post("/v1/adapters/{adapter_id}/heartbeat")
    def save_adapter_heartbeat(
        adapter_id: str,
        payload: AdapterStatusRecord,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _verify_adapter_heartbeat_write(auth, authorization)
        heartbeat = payload.model_copy(
            update={
                "last_heartbeat_at": payload.last_heartbeat_at or utc_now_iso(),
            }
        )
        return store.save_adapter_status(adapter_id, heartbeat)

    @app.get("/v1/adapters/{adapter_id}/status")
    def openclaw_adapter_status(
        adapter_id: str,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        _verify_browser_or_bearer_read(
            auth,
            required_scope="adapter:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        status = store.get_adapter_status(adapter_id)
        if status is None:
            return _legacy_unknown_adapter_status()
        return status

    @app.post("/v1/credentials")
    def create_credential(
        payload: CredentialCreateRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth.verify_bearer(authorization, "credential:write")
        token, credential = auth.create_credential(payload)
        return {"token": token, "credential": credential.public_dump()}

    @app.get("/v1/credentials")
    def list_credentials(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
        auth.verify_bearer(authorization, "credential:read")
        return [credential.public_dump() for credential in auth.list_credentials()]

    @app.post("/v1/credentials/{credential_id}/revoke")
    def revoke_credential(credential_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        auth.verify_bearer(authorization, "credential:revoke")
        try:
            return auth.revoke_credential(credential_id).public_dump()
        except KeyError:
            raise ApiAuthError("CREDENTIAL_NOT_FOUND", status_code=404)

    @app.post("/v1/memory/changes/propose")
    def propose_memory_change(
        payload: MemoryGuardChange,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth.verify_bearer(authorization, "event:evaluate")
        return memory_guard_service.propose(payload).model_dump(mode="json")

    @app.post("/v1/memory/changes/{change_id}/commit")
    def commit_memory_change(change_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        auth.verify_bearer(authorization, "event:evaluate")
        try:
            return memory_guard_service.commit(change_id).model_dump(mode="json")
        except KeyError:
            raise ApiAuthError("MEMORY_CHANGE_NOT_FOUND", status_code=404)

    @app.post("/v1/memory/changes/{change_id}/rollback")
    def rollback_memory_change(change_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        auth.verify_bearer(authorization, "event:evaluate")
        try:
            return memory_guard_service.rollback(change_id).model_dump(mode="json")
        except KeyError:
            raise ApiAuthError("MEMORY_CHANGE_NOT_FOUND", status_code=404)

    @app.get("/v1/approvals/pending")
    def pending_approvals(agentguard_session: str | None = Cookie(default=None)) -> list[dict[str, Any]]:
        session = auth.verify_browser_session(agentguard_session)
        rows: list[dict[str, Any]] = []
        for approval in approval_service.list_pending_approvals():
            payload = approval.model_dump(mode="json")
            payload["approval_nonce"] = auth.issue_approval_nonce(
                approval_id=approval.approval_id,
                session_id=session.session_id,
                subject_id=approval.subject_id,
            )
            rows.append(payload)
        return rows

    @app.post("/v1/approvals/{approval_id}/resolve")
    def resolve_approval(
        approval_id: str,
        payload: ApprovalResolveRequest,
        x_agentguard_csrf: str | None = Header(default=None, alias="X-AgentGuard-CSRF"),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        session = auth.verify_browser_session(agentguard_session)
        auth.verify_csrf(session, x_agentguard_csrf)
        approval = approval_service.get_approval(approval_id)
        if approval is None:
            raise ApiAuthError("APPROVAL_NOT_FOUND", status_code=404)
        auth.consume_approval_nonce(
            nonce=payload.approval_nonce,
            approval_id=approval_id,
            session_id=session.session_id,
            subject_id=approval.subject_id,
        )
        if payload.decision not in approval.decision_options:
            raise ApiAuthError("APPROVAL_DECISION_INVALID", status_code=403)
        resolved = approval_service.resolve_approval(approval_id, payload.decision)
        return {
            "approval_id": resolved.approval_id,
            "status": resolved.status,
            "decision": resolved.decision,
        }

    @app.get("/v1/approvals/{approval_id}/wait")
    def wait_approval(approval_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        context = auth.verify_bearer(authorization, "approval:wait")
        approval = approval_service.get_approval(approval_id)
        if approval is None:
            raise ApiAuthError("APPROVAL_NOT_FOUND", status_code=404)
        if approval.requesting_principal_id != context.principal_id:
            raise ApiAuthError("APPROVAL_WAIT_DENIED", status_code=403)
        return _approval_wait_payload(approval)

    return app


def _approval_wait_payload(approval: Any) -> dict[str, Any]:
    decision = approval.decision
    if approval.status not in {"pending", "resolved"} and decision is None:
        decision = "deny"
    return {
        "status": approval.status,
        "decision": decision,
        "resolution_source": approval.resolution_source,
        "resolved_by": approval.resolved_by,
        "resolution_reason": approval.resolution_reason,
        "llm_review": approval.llm_review.model_dump() if approval.llm_review is not None else None,
    }


app = create_app()
