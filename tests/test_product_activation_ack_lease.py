"""Product Activation ACK fencing at the approval-lease commit boundary."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from typing import Any, Literal

import pytest
from sqlalchemy import func, select, text, update

from agentguard_core import GuardDecision, GuardEngine, GuardEvent, PolicyBundle
from agentguard_core.actions import ActionConstraint
from agentguard_core.actions.canonical_json import canonical_sha256

from guard_api.auth import AuthContext
from guard_api.models import (
    ADAPTER_CREDENTIAL_SCOPES,
    CredentialRecord,
    TaskCreateRequest,
)
from guard_api.security_state import SecurityStateService
from guard_api.security_state.lease_service import (
    ApprovalExecutionLeaseService,
    approval_execution_lease_service_from_settings,
)
from guard_api.services import ApprovalService, AuditService, EvaluationService
from guard_api.services.policy import PolicyService
from guard_api.services.product_activation import (
    ACTIVATION_ACK_NOT_CURRENT,
    ACTIVATION_ACK_REQUIRED,
    RUNTIME_OBSERVATION_MISMATCH,
    ProductActivationAuthorityService,
    load_frozen_product_activation,
)
from guard_api.services.runtime_binding import RuntimeBindingResolver
from guard_api.services.task_ingress import TaskIngressService
from guard_api.services.v21_pipeline import (
    V21OfficialEvaluationUnavailableError,
    V21PipelineService,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import (
    PostgresControlPlaneStore,
    _lock_product_runtime_status,
)
from guard_api.storage.sqlalchemy_models import product_runtime_statuses_v2
from tests.support.postgres import get_test_database_url, reset_control_plane_schema
from tests.support.product_activation import (
    TEST_PRODUCT_ACTIVATION_SECRET_B64,
    ProductActivationFixture,
    build_test_product_activation,
    product_activation_ack_for_status,
    product_runtime_status_for_activation,
    write_test_product_activation,
)

Backend = Literal["memory", "postgres"]

_TASK_SCOPE_KEY_ID = "product-ack-lease-task-key"
_TASK_SCOPE_KEY_B64 = base64.urlsafe_b64encode(
    b"product-ack-lease-task-scope-secret-01"
).decode("ascii")
_SHADOW_SECRET_B64 = base64.urlsafe_b64encode(
    b"product-ack-lease-shadow-secret-01"
).decode("ascii")


@dataclass(slots=True)
class _MutableClock:
    current: datetime

    def __call__(self) -> datetime:
        return self.current


@dataclass(slots=True)
class _LeaseRig:
    backend: Backend
    store: MemoryControlPlaneStore | PostgresControlPlaneStore
    fixture: ProductActivationFixture
    authority: ProductActivationAuthorityService
    approvals: ApprovalService
    leases: ApprovalExecutionLeaseService
    auth_context: AuthContext
    clock: _MutableClock
    activation_ack_token: str
    approval_id: str
    action_id: str
    authorization_fingerprint: str
    scope_digest: str
    release_mode: Literal["strong_binding", "restricted_allow_once"] = "strong_binding"
    race_future: Any | None = None

    def consume(self, ack_token: str | None):
        return self.leases.consume(
            self.approval_id,
            action_id=self.action_id,
            authorization_fingerprint=(
                self.authorization_fingerprint
                if self.release_mode == "strong_binding"
                else None
            ),
            release_mode=self.release_mode,
            auth_context=self.auth_context,
            activation_ack_token=ack_token,
            now=self.clock.current,
        )


@pytest.fixture(
    params=(
        pytest.param("memory", id="memory", marks=pytest.mark.integration),
        pytest.param("postgres", id="postgres", marks=pytest.mark.postgres),
    )
)
def lease_store(request):
    backend = request.param
    if backend == "memory":
        yield backend, MemoryControlPlaneStore()
        return

    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    store = PostgresControlPlaneStore(database_url)
    store.initialize()
    try:
        yield backend, store
    finally:
        reset_control_plane_schema(database_url)


def _settings(
    activation_path: Path,
    fixture: ProductActivationFixture,
    *,
    backend: Backend,
    database_url: str | None,
) -> GuardApiSettings:
    return GuardApiSettings(
        storage_backend=backend,
        database_url=database_url or "",
        control_token="product-ack-lease-control-secret",
        v21_mode="active",
        v21_product_activation_path=str(activation_path),
        v21_product_activation_server_secret=TEST_PRODUCT_ACTIVATION_SECRET_B64,
        v21_product_activation_signer_key_id=fixture.signer_key_id,
        v21_shadow_server_secret=_SHADOW_SECRET_B64,
        task_scope_active_key_id=_TASK_SCOPE_KEY_ID,
        task_scope_keys=json.dumps({_TASK_SCOPE_KEY_ID: _TASK_SCOPE_KEY_B64}),
        rte05_strong_binding_enabled=True,
        approval_ttl_seconds=900,
    )


def _force_current_ask(monkeypatch: pytest.MonkeyPatch) -> None:
    original = GuardEngine.evaluate_with_results

    def force(
        self: GuardEngine,
        event: GuardEvent,
        policies: PolicyBundle | None = None,
    ) -> tuple[GuardDecision, list[Any]]:
        decision, detections = original(self, event, policies)
        return (
            decision.model_copy(
                update={
                    "decision_id": "dec:forced-current:product-ack-lease-ask",
                    "decision": "ask",
                    "risk_score": 50,
                    "severity": "medium",
                    "categories": ["forced-current:ask"],
                    "rule_hits": [],
                    "reason": "exercise the Product approval release boundary",
                    "approval_intent": None,
                }
            ),
            detections,
        )

    monkeypatch.setattr(GuardEngine, "evaluate_with_results", force)


def _prepare_rig(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: Backend,
    store: MemoryControlPlaneStore | PostgresControlPlaneStore,
    *,
    suffix: str,
    runtime: Literal["langgraph", "openclaw"] = "langgraph",
    strong_enabled: bool = True,
) -> _LeaseRig:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    clock = _MutableClock(now)
    if isinstance(store, MemoryControlPlaneStore):
        store.audit_clock = clock

    policy = PolicyBundle()
    fixture = build_test_product_activation(
        now=now,
        policy_digest=canonical_sha256(policy.model_dump(mode="json")),
    )
    activation_path = write_test_product_activation(
        tmp_path / f"product-ack-lease-{backend}-{suffix}.json",
        fixture,
    )
    settings = _settings(
        activation_path,
        fixture,
        backend=backend,
        database_url=(
            store.database_url if isinstance(store, PostgresControlPlaneStore) else None
        ),
    )
    settings.rte05_strong_binding_enabled = strong_enabled
    store.save_policy_snapshot(
        policy,
        expected_revision=0,
        updated_by="product-ack-lease-test",
    )
    activation_ack_tokens: dict[str, str] = {}
    for status_runtime in ("langgraph", "openclaw"):
        status = product_runtime_status_for_activation(
            fixture,
            status_runtime,
            last_heartbeat_at=now,
        )
        ack = product_activation_ack_for_status(fixture, status)
        store.save_product_runtime_status(status, activation_ack=ack)
        activation_ack_tokens[status_runtime] = ack.ack_token

    entry = fixture.bundle.runtime_entry(runtime)
    raw_token = f"product-ack-lease-adapter-secret:{suffix}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    credential_id = f"cred_product_ack_lease_{suffix}"
    store.create_credential(
        CredentialRecord(
            credential_id=credential_id,
            token_hash=token_hash,
            principal_type="component",
            principal_id=entry.principal_id,
            role="adapter",
            scopes=list(ADAPTER_CREDENTIAL_SCOPES),
            runtime=entry.runtime,
            agent_id=entry.agent_id,
        )
    )

    activation = load_frozen_product_activation(settings)
    assert activation is not None
    resolver = RuntimeBindingResolver(product_activation=activation)
    authority = ProductActivationAuthorityService(
        activation=activation,
        store=store,
        server_secret=fixture.server_secret,
        clock=clock,
    )
    task = TaskIngressService(
        store=store,
        settings=settings,
        runtime_binding_resolver=resolver,
    ).create_task(
        TaskCreateRequest(
            task_text="exercise Product ACK-fenced approval release",
            runtime=runtime,
            trace_id=f"trace:product-ack-lease-task:{suffix}",
            session_id=f"session:product-ack-lease:{suffix}",
            runtime_binding_id=entry.runtime_binding_id,
            action_constraints=[ActionConstraint(action_types=["tool_call"])],
            resource_constraints=[],
            destination_constraints=[],
        ),
        AuthContext(
            principal_type="cli",
            principal_id="cred_control",
            role="control",
            scopes=["task:write"],
            auth_method="bearer",
        ),
    )
    state_service = SecurityStateService(store)
    state_service.ensure_ready(task.scope_digest)
    approvals = ApprovalService(
        store=store,
        settings=settings,
        state_service=state_service,
    )
    policy_service = PolicyService(store=store)
    pipeline = V21PipelineService(
        settings=settings,
        store=store,
        state_service=state_service,
        policy_service=policy_service,
        runtime_binding_resolver=resolver,
        product_activation_authority=authority,
    )
    evaluation = EvaluationService(
        policy_service=policy_service,
        audit_service=AuditService(store=store),
        approval_service=approvals,
        v21_pipeline=pipeline,
        product_activation_authority=authority,
    )
    auth_context = AuthContext(
        principal_type="component",
        principal_id=entry.principal_id,
        role="adapter",
        scopes=list(ADAPTER_CREDENTIAL_SCOPES),
        auth_method="bearer",
        credential_id=credential_id,
        credential_token_hash=token_hash,
        runtime=entry.runtime,
        agent_id=entry.agent_id,
    )
    _force_current_ask(monkeypatch)
    event = GuardEvent.model_validate(
        {
            "schema_version": "0.3",
            "event_id": f"evt:product-ack-lease:{suffix}",
            "event_type": "tool_call_proposed",
            "runtime": runtime,
            "trace_id": f"trace:product-ack-lease:{suffix}",
            "timestamp": now.isoformat(),
            "pre_execution": True,
            "security_context": {
                "agent_id": "main",
                "session_id": f"session:product-ack-lease:{suffix}",
                "user_task": "Read the approved local report",
                "source_type": "user",
                "source_trust": "trusted",
            },
            "payload": {
                "tool": {
                    "name": "read_file",
                    "call_id": f"call:product-ack-lease:{suffix}",
                },
                "arguments": {"path": "/docs/approved-report.txt"},
                "derived_resources": [],
            },
            "metadata": {"task_id": task.task_id},
        }
    )
    response = evaluation.evaluate(
        event,
        auth_context=auth_context,
        activation_ack_token=activation_ack_tokens[runtime],
    )
    assert response.decision.decision == "ask"
    assert response.approval is not None
    assert (response.enforcement_binding is not None) == (runtime == "langgraph")
    resolved = approvals.resolve_approval(
        response.approval.approval_id,
        "allow_once",
        resolution_source="human",
    )
    assert resolved.status == "resolved"
    binding = store.get_enforcement_binding(response.approval.approval_id)
    assert binding is not None and binding.grant_id is not None
    grant = store.get_capability_grant_runtime(binding.grant_id)
    assert grant is not None and grant["remaining_uses"] == 1

    return _LeaseRig(
        backend=backend,
        store=store,
        fixture=fixture,
        authority=authority,
        approvals=approvals,
        leases=approval_execution_lease_service_from_settings(
            store,
            settings,
            approvals,
            product_activation_authority=authority,
        ),
        auth_context=auth_context,
        clock=clock,
        activation_ack_token=activation_ack_tokens[runtime],
        approval_id=response.approval.approval_id,
        action_id=binding.action_id,
        authorization_fingerprint=binding.authorization_fingerprint,
        release_mode=binding.release_mode,
        scope_digest=task.scope_digest,
    )


def _backend_now(rig: _LeaseRig) -> datetime:
    if isinstance(rig.store, MemoryControlPlaneStore):
        return rig.clock.current
    with rig.store._session_factory() as session:  # noqa: SLF001
        return session.execute(select(func.clock_timestamp())).scalar_one()


def _save_fresh_observations(
    rig: _LeaseRig,
    at: datetime,
) -> dict[str, str]:
    tokens: dict[str, str] = {}
    for runtime in ("langgraph", "openclaw"):
        status = product_runtime_status_for_activation(
            rig.fixture,
            runtime,
            last_heartbeat_at=at,
        )
        ack = product_activation_ack_for_status(rig.fixture, status)
        rig.store.save_product_runtime_status(status, activation_ack=ack)
        tokens[runtime] = ack.ack_token
    rig.clock.current = at
    return tokens


def _expired_caller_ack(rig: _LeaseRig) -> str:
    current = _backend_now(rig)
    old_status = product_runtime_status_for_activation(
        rig.fixture,
        rig.auth_context.runtime,
        last_heartbeat_at=current - timedelta(seconds=2),
    )
    old_ack = product_activation_ack_for_status(
        rig.fixture,
        old_status,
        expires_at=current - timedelta(seconds=1),
    )
    rig.store.save_product_runtime_status(old_status, activation_ack=old_ack)
    _save_fresh_observations(rig, current)
    return old_ack.ack_token


def _short_lived_caller_ack(rig: _LeaseRig) -> tuple[str, datetime]:
    current = _backend_now(rig)
    old_status = product_runtime_status_for_activation(
        rig.fixture,
        rig.auth_context.runtime,
        last_heartbeat_at=current - timedelta(seconds=1),
    )
    expires_at = current + timedelta(seconds=2)
    old_ack = product_activation_ack_for_status(
        rig.fixture,
        old_status,
        expires_at=expires_at,
    )
    rig.store.save_product_runtime_status(old_status, activation_ack=old_ack)
    _save_fresh_observations(rig, current)
    return old_ack.ack_token, expires_at


def _assert_not_consumed(rig: _LeaseRig) -> None:
    assert rig.store.approval_execution_was_consumed(rig.approval_id) is False
    binding = rig.store.get_enforcement_binding(rig.approval_id)
    assert binding is not None and binding.grant_id is not None
    grant = rig.store.get_capability_grant_runtime(binding.grant_id)
    assert grant is not None
    assert grant["remaining_uses"] == 1


@pytest.mark.parametrize(
    ("ack_case", "expected_code"),
    (
        ("missing", ACTIVATION_ACK_REQUIRED),
        ("tampered", ACTIVATION_ACK_NOT_CURRENT),
        ("stale", ACTIVATION_ACK_NOT_CURRENT),
    ),
)
def test_lease_release_rejects_bad_ack_without_consumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lease_store,
    ack_case: str,
    expected_code: str,
) -> None:
    backend, store = lease_store
    rig = _prepare_rig(tmp_path, monkeypatch, backend, store, suffix=ack_case)
    if ack_case == "missing":
        token = None
    elif ack_case == "tampered":
        token = rig.activation_ack_token[:-1] + (
            "A" if rig.activation_ack_token[-1] != "A" else "B"
        )
    else:
        token = _expired_caller_ack(rig)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        rig.consume(token)

    assert raised.value.code == expected_code
    _assert_not_consumed(rig)


def test_release_precheck_storage_failure_preserves_retryable_product_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lease_store,
) -> None:
    backend, store = lease_store
    rig = _prepare_rig(
        tmp_path,
        monkeypatch,
        backend,
        store,
        suffix="precheck-store-failure",
    )
    private_driver_detail = "private-driver-detail-must-not-escape"

    def fail_exact_ack(*_args: Any, **_kwargs: Any):
        raise RuntimeError(private_driver_detail)

    monkeypatch.setattr(
        type(store),
        "get_product_activation_ack",
        fail_exact_ack,
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        rig.consume(rig.activation_ack_token)

    assert raised.value.code == "V21_PRODUCT_ACTIVATION_ACK_VERIFIER_UNAVAILABLE"
    assert private_driver_detail not in str(raised.value)
    _assert_not_consumed(rig)


def test_exact_replay_accepts_a_new_equivalent_fresh_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lease_store,
) -> None:
    backend, store = lease_store
    rig = _prepare_rig(tmp_path, monkeypatch, backend, store, suffix="exact-replay")
    first = rig.consume(rig.activation_ack_token)
    refreshed_at = _backend_now(rig) + timedelta(microseconds=1)
    refreshed = _save_fresh_observations(rig, refreshed_at)

    replay = rig.consume(refreshed["langgraph"])

    assert replay.replayed is True
    assert replay.lease == first.lease
    assert replay.consumption == first.consumption
    assert replay.lease_token == first.lease_token
    assert rig.store.approval_execution_was_consumed(rig.approval_id) is True


def test_execution_lease_expiry_is_capped_by_activation_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lease_store,
) -> None:
    backend, store = lease_store
    rig = _prepare_rig(tmp_path, monkeypatch, backend, store, suffix="expiry-cap")
    ack_record = rig.store.get_latest_product_activation_ack(
        rig.fixture.bundle.runtime_entry("langgraph").model_dump(
            include={"runtime", "agent_id", "runtime_binding_id", "profile_id"}
        )
    )
    assert ack_record is not None

    result = rig.consume(rig.activation_ack_token)

    assert datetime.fromisoformat(result.lease.expires_at) == datetime.fromisoformat(
        ack_record.unsigned_ack().expires_at
    )
    assert (
        datetime.fromisoformat(result.lease.expires_at) - rig.clock.current
    ) <= timedelta(seconds=120)


@pytest.mark.parametrize(
    ("race", "expected_code"),
    (
        ("expiry", ACTIVATION_ACK_NOT_CURRENT),
        ("drift", RUNTIME_OBSERVATION_MISMATCH),
    ),
)
def test_lock_wait_revalidates_ack_before_first_lease_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lease_store,
    race: str,
    expected_code: str,
) -> None:
    backend, store = lease_store
    rig = _prepare_rig(tmp_path, monkeypatch, backend, store, suffix=f"race-{race}")
    caller_token, expires_at = _short_lived_caller_ack(rig)

    if isinstance(store, MemoryControlPlaneStore):
        _run_memory_lock_race(rig, monkeypatch, caller_token, expires_at, race)
    else:
        _run_postgres_lock_race(rig, caller_token, expires_at, race)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        assert rig.race_future is not None
        rig.race_future.result(timeout=5)
    assert raised.value.code == expected_code
    _assert_not_consumed(rig)


def _run_memory_lock_race(
    rig: _LeaseRig,
    monkeypatch: pytest.MonkeyPatch,
    caller_token: str,
    expires_at: datetime,
    race: str,
) -> None:
    store = rig.store
    assert isinstance(store, MemoryControlPlaneStore)
    entered_store = Event()
    enter_transaction = Event()
    original = MemoryControlPlaneStore.consume_approval_execution_lease

    def delayed(self, command, *, release_check=None):
        entered_store.set()
        assert enter_transaction.wait(timeout=5)
        return original(self, command, release_check=release_check)

    monkeypatch.setattr(
        MemoryControlPlaneStore,
        "consume_approval_execution_lease",
        delayed,
    )
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(rig.consume, caller_token)
    assert entered_store.wait(timeout=5)
    with store.product_runtime_status_lock:
        if race == "expiry":
            rig.clock.current = expires_at
        else:
            _write_runtime_drift(rig, "openclaw")
        enter_transaction.set()
        assert not future.done()
    pool.shutdown(wait=False)
    rig.race_future = future


def _run_postgres_lock_race(
    rig: _LeaseRig,
    caller_token: str,
    expires_at: datetime,
    race: str,
) -> None:
    store = rig.store
    assert isinstance(store, PostgresControlPlaneStore)
    pool = ThreadPoolExecutor(max_workers=1)
    with store._session_factory() as blocker:  # noqa: SLF001
        with blocker.begin():
            _lock_product_runtime_status(blocker, "langgraph")
            future = pool.submit(rig.consume, caller_token)
            _wait_for_advisory_lock(store)
            if race == "expiry":
                deadline = time.monotonic() + 5
                while (
                    blocker.execute(select(func.clock_timestamp())).scalar_one()
                    < expires_at
                ):
                    if time.monotonic() >= deadline:
                        raise AssertionError("short-lived ACK did not expire")
                    time.sleep(0.02)
            else:
                status = rig.store.get_product_runtime_status(
                    rig.fixture.bundle.runtime_entry("openclaw").model_dump(
                        include={
                            "runtime",
                            "agent_id",
                            "runtime_binding_id",
                            "profile_id",
                        }
                    )
                )
                assert status is not None
                drifted = status.model_copy(
                    update={"tool_inventory_digest": "sha256:" + "f" * 64}
                )
                blocker.execute(
                    update(product_runtime_statuses_v2)
                    .where(product_runtime_statuses_v2.c.runtime == "openclaw")
                    .values(payload_json=drifted.model_dump(mode="json"))
                )
    pool.shutdown(wait=False)
    rig.race_future = future


def _wait_for_advisory_lock(store: PostgresControlPlaneStore) -> None:
    deadline = time.monotonic() + 5
    query = text(
        "SELECT count(*) FROM pg_stat_activity "
        "WHERE datname = current_database() "
        "AND pid <> pg_backend_pid() "
        "AND wait_event_type = 'Lock' AND wait_event = 'advisory'"
    )
    with store._session_factory() as monitor:  # noqa: SLF001
        while int(monitor.execute(query).scalar_one()) < 1:
            if time.monotonic() >= deadline:
                raise AssertionError("lease consume did not wait on the runtime lock")
            time.sleep(0.02)


def _write_runtime_drift(rig: _LeaseRig, runtime: str) -> None:
    entry = rig.fixture.bundle.runtime_entry(runtime)  # type: ignore[arg-type]
    status = rig.store.get_product_runtime_status(
        entry.model_dump(
            include={"runtime", "agent_id", "runtime_binding_id", "profile_id"}
        )
    )
    assert status is not None
    rig.store.save_product_runtime_status(
        status.model_copy(update={"tool_inventory_digest": "sha256:" + "f" * 64})
    )
