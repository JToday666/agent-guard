"""PostgreSQL concurrency parity for the Product authority fence."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, get_ident

import pytest
from agentguard_core import PolicyBundle
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.security_context import CommittedRecord
from sqlalchemy import select

from guard_api.auth import AuthContext
from guard_api.models import (
    ADAPTER_CREDENTIAL_SCOPES,
    CredentialRecord,
    TaskCreateRequest,
)
from guard_api.security_state import SecurityStateProjectError, SecurityStateService
from guard_api.services import ApprovalService, AuditService, EvaluationService
from guard_api.services.policy import PolicyService
from guard_api.services.product_activation import load_frozen_product_activation
from guard_api.services.runtime_binding import (
    PRODUCT_ACTIVATION_NOT_CURRENT,
    RuntimeBindingResolver,
)
from guard_api.services.task_ingress import TaskIngressService
from guard_api.services.v21_pipeline import (
    PRODUCT_CREDENTIAL_NOT_CURRENT,
    PRODUCT_POLICY_NOT_CURRENT,
    PRODUCT_SECURITY_STATE_NOT_READY,
    V21OfficialEvaluationUnavailableError,
    V21PipelineService,
    build_evaluation_delta,
)
from guard_api.storage.postgres import PostgresControlPlaneStore
from guard_api.storage.base import ProjectionIdentityRecord, TaskFactRecord
from guard_api.storage import postgres as postgres_storage
from tests.support.postgres import get_test_database_url, reset_control_plane_schema
from tests.support.product_activation import (
    build_test_product_activation,
    product_runtime_status_for_activation,
    write_test_product_activation,
)
from tests.test_product_runtime_binding_wiring import (
    _RUNTIME_CREDENTIAL_HASH,
    _RUNTIME_CREDENTIAL_ID,
    _auth,
    _event,
    _settings,
    _task_payload,
)

pytestmark = pytest.mark.postgres


_PRODUCT_TRANSACTION_TABLES = (
    postgres_storage.audit_events,
    postgres_storage.audit_integrity_heads,
    postgres_storage.provenance_nodes,
    postgres_storage.provenance_edges,
    postgres_storage.approval_requests,
    postgres_storage.enforcement_bindings,
    postgres_storage.memory_guard_changes,
    postgres_storage.action_critic_reviews,
    postgres_storage.policy_snapshots,
    postgres_storage.policy_snapshot_history,
    postgres_storage.task_facts,
    postgres_storage.security_states,
    postgres_storage.projection_records,
    postgres_storage.product_runtime_statuses_v2,
    postgres_storage.adapter_statuses,
    postgres_storage.credentials,
)


def _postgres_store_image(store: PostgresControlPlaneStore) -> dict[str, list[dict]]:
    """Read every table covered by the Product transaction rollback contract."""

    image: dict[str, list[dict]] = {}
    with store._session_factory() as session:
        for table in _PRODUCT_TRANSACTION_TABLES:
            statement = select(table)
            primary_key = list(table.primary_key.columns)
            if primary_key:
                statement = statement.order_by(*primary_key)
            image[table.name] = [
                dict(row) for row in session.execute(statement).mappings().all()
            ]
    return image


def _advance_unrelated_projection(
    store: PostgresControlPlaneStore,
    scope_digest: str,
) -> None:
    delta = build_evaluation_delta(
        scope_digest=scope_digest,
        audit_id="audit:pg-interleaved-other-projector",
        base_state_version=0,
    )
    SecurityStateService(store).project_committed(
        CommittedRecord(
            record_id="record:pg-interleaved-other-projector",
            committed=True,
            source_record_type=delta.source.source_record_type,
            source_record_id=delta.source.source_record_id,
            source_revision=delta.source.source_revision,
            scope_digest=scope_digest,
            projector_version=delta.projector_version,
            delta=delta,
        ),
        scope_digest=scope_digest,
    )


def _record_unapplied_unrelated_projection(
    store: PostgresControlPlaneStore,
    scope_digest: str,
) -> None:
    delta = build_evaluation_delta(
        scope_digest=scope_digest,
        audit_id="audit:pg-crashed-other-projector",
        base_state_version=0,
    )
    store.record_projection(
        ProjectionIdentityRecord(
            scope_digest=scope_digest,
            source_record_type=delta.source.source_record_type,
            source_record_id=delta.source.source_record_id,
            source_revision=delta.source.source_revision,
            projector_version=delta.projector_version,
            delta_digest=delta.delta_digest,
            delta_payload=delta.model_dump(mode="json"),
            applied_state_version=delta.new_state_version,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )


def _seed_projection_history(
    store: PostgresControlPlaneStore,
    scope_digest: str,
    *,
    count: int,
) -> None:
    service = SecurityStateService(store)
    access = service.store_access
    with access.scope_lock(scope_digest), access.transaction(scope_digest):
        for index in range(count):
            delta = build_evaluation_delta(
                scope_digest=scope_digest,
                audit_id=f"audit:pg-capacity-seed:{index}",
                base_state_version=index,
            )
            access.record_projection(
                ProjectionIdentityRecord(
                    scope_digest=scope_digest,
                    source_record_type=delta.source.source_record_type,
                    source_record_id=delta.source.source_record_id,
                    source_revision=delta.source.source_revision,
                    projector_version=delta.projector_version,
                    delta_digest=delta.delta_digest,
                    delta_payload=delta.model_dump(mode="json"),
                    applied_state_version=delta.new_state_version,
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
            )
        service.reconcile_projection_history(scope_digest)


def _invalid_projection(
    scope_digest: str, *, audit_id: str
) -> ProjectionIdentityRecord:
    delta = build_evaluation_delta(
        scope_digest=scope_digest,
        audit_id=audit_id,
        base_state_version=0,
    )
    return ProjectionIdentityRecord(
        scope_digest=scope_digest,
        source_record_type=delta.source.source_record_type,
        source_record_id=f"{delta.source.source_record_id}:row-conflict",
        source_revision=delta.source.source_revision,
        projector_version=delta.projector_version,
        delta_digest=delta.delta_digest,
        delta_payload=delta.model_dump(mode="json"),
        applied_state_version=delta.new_state_version,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


@pytest.fixture
def product_stack(tmp_path: Path):
    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    store = PostgresControlPlaneStore(database_url)
    writer = PostgresControlPlaneStore(database_url)
    store.initialize()
    policy = PolicyBundle()
    fixture = build_test_product_activation(
        now=datetime.now(timezone.utc),
        policy_digest=canonical_sha256(policy.model_dump(mode="json")),
    )
    activation_path = tmp_path / "product-activation-postgres.json"
    write_test_product_activation(activation_path, fixture)
    settings = _settings(activation_path, fixture)
    store.save_policy_snapshot(policy, expected_revision=0, updated_by="p0-pg-test")
    for runtime in ("langgraph", "openclaw"):
        store.save_product_runtime_status(
            product_runtime_status_for_activation(fixture, runtime)
        )
    entry = fixture.bundle.runtime_entry("langgraph")
    store.create_credential(
        CredentialRecord(
            credential_id=_RUNTIME_CREDENTIAL_ID,
            token_hash=_RUNTIME_CREDENTIAL_HASH,
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
    control = AuthContext(
        principal_type="cli",
        principal_id="cred_control",
        role="control",
        scopes=["task:write"],
        auth_method="bearer",
    )
    created = TaskIngressService(
        store=store,
        settings=settings,
        runtime_binding_resolver=resolver,
    ).create_task(
        TaskCreateRequest(**_task_payload(runtime_binding_id=entry.runtime_binding_id)),
        control,
    )
    SecurityStateService(store).ensure_ready(created.scope_digest)
    state_service = SecurityStateService(store)
    policy_service = PolicyService(store=store)
    pipeline = V21PipelineService(
        settings=settings,
        store=store,
        state_service=state_service,
        policy_service=policy_service,
        runtime_binding_resolver=resolver,
    )
    evaluation = EvaluationService(
        policy_service=policy_service,
        audit_service=AuditService(store=store),
        approval_service=ApprovalService(store=store, settings=settings),
        v21_pipeline=pipeline,
    )
    try:
        yield (
            fixture,
            store,
            writer,
            pipeline,
            evaluation,
            created.task_id,
            created.scope_digest,
        )
    finally:
        reset_control_plane_schema(database_url)


def test_postgres_product_evaluation_commits_and_projects(product_stack) -> None:
    fixture, store, _writer, _pipeline, evaluation, task_id, scope_digest = (
        product_stack
    )
    event = _event(task_id)

    response = evaluation.evaluate(event, auth_context=_auth(fixture))

    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    state = store.get_security_state(scope_digest)
    projections = store.list_rebuild_inputs(scope_digest, limit=10)
    assert audit is not None and response.policy_audit_id == audit.audit_id
    assert audit.metadata["product_authority_digest"].startswith("sha256:")
    assert len(projections) == 1
    assert state is not None and state.state_version == 1


def test_postgres_state_transaction_rolls_back_failed_reconcile(
    product_stack,
) -> None:
    _fixture, store, _writer, _pipeline, _evaluation, _task_id, scope_digest = (
        product_stack
    )
    before = _postgres_store_image(store)
    service = SecurityStateService(store)
    access = service.store_access

    with pytest.raises(SecurityStateProjectError):
        with access.scope_lock(scope_digest), access.transaction(scope_digest):
            access.record_projection(
                _invalid_projection(
                    scope_digest,
                    audit_id="audit:postgres-failed-reconcile",
                )
            )
            service.reconcile_projection_history(scope_digest)

    assert _postgres_store_image(store) == before


@pytest.mark.parametrize(
    ("existing_count", "accepted"),
    [(998, True), (999, False)],
)
def test_postgres_reservation_proves_bounded_rebuild_headroom_before_commit(
    product_stack,
    existing_count: int,
    accepted: bool,
) -> None:
    fixture, store, _writer, _pipeline, evaluation, task_id, scope_digest = (
        product_stack
    )
    _seed_projection_history(store, scope_digest, count=existing_count)
    event = _event(
        task_id,
        event_id=f"evt_product_pg_capacity_{existing_count}",
        call_id=f"call:product-pg-capacity-{existing_count}",
    )
    before = _postgres_store_image(store)

    if accepted:
        evaluation.evaluate(event, auth_context=_auth(fixture))
        state = store.get_security_state(scope_digest)
        assert state is not None and state.state_version == 999
        assert len(store.list_rebuild_inputs(scope_digest, limit=1000)) == 999
    else:
        with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
            evaluation.evaluate(event, auth_context=_auth(fixture))
        assert raised.value.code == PRODUCT_SECURITY_STATE_NOT_READY
        assert store.get_policy_evaluation_by_event_id(event.event_id) is None
        assert _postgres_store_image(store) == before
        state = store.get_security_state(scope_digest)
        assert state is not None and state.state_version == 999
        assert len(store.list_rebuild_inputs(scope_digest, limit=1000)) == 999


def test_postgres_missing_exact_credential_is_a_zero_write_503(product_stack) -> None:
    fixture, store, writer, _pipeline, evaluation, task_id, scope_digest = product_stack
    event = _event(task_id)
    writer.revoke_credential(
        _RUNTIME_CREDENTIAL_ID,
        datetime.now(timezone.utc).isoformat(),
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        evaluation.evaluate(event, auth_context=_auth(fixture))

    assert raised.value.code == PRODUCT_CREDENTIAL_NOT_CURRENT
    assert store.get_policy_evaluation_by_event_id(event.event_id) is None
    assert store.list_rebuild_inputs(scope_digest, limit=10) == []


def test_postgres_backfill_applies_existing_unapplied_reservation(
    product_stack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, _writer, pipeline, evaluation, task_id, scope_digest = product_stack
    event = _event(task_id)
    monkeypatch.setattr(pipeline, "run_phase_c", lambda _plan: None)

    evaluation.evaluate(event, auth_context=_auth(fixture))

    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    pending = store.get_security_state(scope_digest)
    assert audit is not None
    assert pending is not None and pending.state_version == 0
    assert len(store.list_rebuild_inputs(scope_digest, limit=10)) == 1

    pipeline.backfill_projection(audit)

    recovered = store.get_security_state(scope_digest)
    assert recovered is not None and recovered.state_version == 1


def test_postgres_phase_c_rebuilds_after_other_projector_advances(
    product_stack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, _writer, pipeline, evaluation, task_id, scope_digest = product_stack
    event = _event(task_id)
    original_phase_c = pipeline.run_phase_c

    def interleave_other_projector(plan):
        _advance_unrelated_projection(store, scope_digest)
        original_phase_c(plan)

    monkeypatch.setattr(pipeline, "run_phase_c", interleave_other_projector)

    evaluation.evaluate(event, auth_context=_auth(fixture))

    state = store.get_security_state(scope_digest)
    assert state is not None and state.state_version == 2
    assert len(store.list_rebuild_inputs(scope_digest, limit=10)) == 2


def test_postgres_phase_c_rebuilds_foreign_unapplied_envelope(
    product_stack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, writer, pipeline, evaluation, task_id, scope_digest = product_stack
    event = _event(task_id)
    original_phase_c = pipeline.run_phase_c

    def interleave_crashed_projector(plan):
        _record_unapplied_unrelated_projection(writer, scope_digest)
        original_phase_c(plan)

    monkeypatch.setattr(pipeline, "run_phase_c", interleave_crashed_projector)

    evaluation.evaluate(event, auth_context=_auth(fixture))

    state = store.get_security_state(scope_digest)
    assert state is not None and state.state_version == 2
    assert len(store.list_rebuild_inputs(scope_digest, limit=10)) == 2


def test_postgres_writer_wins_after_phase_a_and_fence_rejects_it(
    product_stack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, writer, pipeline, evaluation, task_id, scope_digest = product_stack
    event = _event(task_id)
    phase_a_done = Event()
    release_phase_a = Event()
    original_phase_a = pipeline.run_phase_a

    def hold_after_phase_a(*args, **kwargs):
        materials = original_phase_a(*args, **kwargs)
        phase_a_done.set()
        assert release_phase_a.wait(timeout=10)
        return materials

    monkeypatch.setattr(pipeline, "run_phase_a", hold_after_phase_a)
    with ThreadPoolExecutor(max_workers=1) as executor:
        evaluation_future = executor.submit(
            evaluation.evaluate,
            event,
            auth_context=_auth(fixture),
        )
        assert phase_a_done.wait(timeout=10)
        writer.mark_security_state_dirty(scope_digest, ["behavior"])
        release_phase_a.set()
        with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
            evaluation_future.result(timeout=10)

    assert raised.value.code == PRODUCT_SECURITY_STATE_NOT_READY
    assert store.get_policy_evaluation_by_event_id(event.event_id) is None
    assert store.list_rebuild_inputs(scope_digest, limit=10) == []


def test_postgres_fence_blocks_scope_writer_until_physical_commit(
    product_stack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, writer, pipeline, evaluation, task_id, scope_digest = product_stack
    event = _event(task_id)
    phase_b_done = Event()
    release_phase_b = Event()
    writer_entered_advisory = Event()
    writer_acquired_advisory = Event()
    original_phase_b = pipeline.build_phase_b
    original_advisory = postgres_storage._acquire_advisory_xact_lock
    writer_thread_id: int | None = None

    def hold_after_phase_b(*args, **kwargs):
        outcome = original_phase_b(*args, **kwargs)
        phase_b_done.set()
        assert release_phase_b.wait(timeout=10)
        return outcome

    def observed_advisory(session, lock_id, *, shared=False):
        is_writer = get_ident() == writer_thread_id
        if is_writer:
            writer_entered_advisory.set()
        result = original_advisory(session, lock_id, shared=shared)
        if is_writer:
            writer_acquired_advisory.set()
        return result

    def mark_dirty():
        nonlocal writer_thread_id
        writer_thread_id = get_ident()
        writer.mark_security_state_dirty(scope_digest, ["behavior"])

    monkeypatch.setattr(pipeline, "build_phase_b", hold_after_phase_b)
    # Keep the assertion focused on the transaction lock.  The Product audit
    # and reservation still commit; Phase-C behavior is covered separately.
    monkeypatch.setattr(pipeline, "run_phase_c", lambda _plan: None)
    monkeypatch.setattr(
        postgres_storage,
        "_acquire_advisory_xact_lock",
        observed_advisory,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        evaluation_future = executor.submit(
            evaluation.evaluate,
            event,
            auth_context=_auth(fixture),
        )
        assert phase_b_done.wait(timeout=10)
        writer_future = executor.submit(mark_dirty)
        assert writer_entered_advisory.wait(timeout=10)
        assert not writer_acquired_advisory.is_set()
        with pytest.raises(FutureTimeout):
            writer_future.result(timeout=0.25)
        assert not writer_acquired_advisory.is_set()
        release_phase_b.set()
        response = evaluation_future.result(timeout=10)
        writer_future.result(timeout=10)
        assert writer_acquired_advisory.is_set()

    assert store.get_policy_evaluation_by_event_id(event.event_id) is not None
    assert response.policy_audit_id is not None
    assert len(store.list_rebuild_inputs(scope_digest, limit=10)) == 1


@pytest.mark.parametrize("authority", ["policy", "task", "runtime", "credential"])
def test_postgres_fence_blocks_each_authority_writer_until_physical_commit(
    product_stack,
    monkeypatch: pytest.MonkeyPatch,
    authority: str,
) -> None:
    fixture, store, writer, pipeline, evaluation, task_id, scope_digest = product_stack
    event = _event(task_id)
    phase_b_done = Event()
    release_phase_b = Event()
    writer_entered_advisory = Event()
    writer_acquired_advisory = Event()
    original_phase_b = pipeline.build_phase_b
    original_advisory = postgres_storage._acquire_advisory_xact_lock
    writer_thread_id: int | None = None

    task_head = store.get_task_fact(task_id)
    assert task_head is not None
    advanced_task = task_head.task_fact.model_copy(update={"revision": 2})
    runtime_status = product_runtime_status_for_activation(fixture, "langgraph")
    changed_runtime_status = runtime_status.model_copy(
        update={"runtime_version": "1.2.7-authority-writer"}
    )

    def hold_after_phase_b(*args, **kwargs):
        outcome = original_phase_b(*args, **kwargs)
        phase_b_done.set()
        assert release_phase_b.wait(timeout=10)
        return outcome

    def observed_advisory(session, lock_id, *, shared=False):
        is_writer = get_ident() == writer_thread_id
        if is_writer:
            writer_entered_advisory.set()
        result = original_advisory(session, lock_id, shared=shared)
        if is_writer:
            writer_acquired_advisory.set()
        return result

    def mutate_authority() -> None:
        nonlocal writer_thread_id
        writer_thread_id = get_ident()
        if authority == "policy":
            writer.save_policy_snapshot(
                PolicyBundle(), expected_revision=1, updated_by="blocked-writer"
            )
        elif authority == "task":
            writer.create_task_fact(
                TaskFactRecord(
                    task_fact=advanced_task,
                    canonical_payload=advanced_task.model_dump(mode="json"),
                    request_digest="sha256:" + "c" * 64,
                    expected_revision=1,
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
            )
        elif authority == "runtime":
            writer.save_product_runtime_status(changed_runtime_status)
        else:
            writer.revoke_credential(
                _RUNTIME_CREDENTIAL_ID,
                datetime.now(timezone.utc).isoformat(),
            )

    monkeypatch.setattr(pipeline, "build_phase_b", hold_after_phase_b)
    monkeypatch.setattr(pipeline, "run_phase_c", lambda _plan: None)
    monkeypatch.setattr(
        postgres_storage,
        "_acquire_advisory_xact_lock",
        observed_advisory,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        evaluation_future = executor.submit(
            evaluation.evaluate,
            event,
            auth_context=_auth(fixture),
        )
        assert phase_b_done.wait(timeout=10)
        writer_future = executor.submit(mutate_authority)
        # The paired events surround the exact advisory call: before release
        # the writer has entered but cannot return; after commit it returns and
        # proves acquisition rather than a slow connection/query false pass.
        assert writer_entered_advisory.wait(timeout=10)
        assert not writer_acquired_advisory.is_set()
        with pytest.raises(FutureTimeout):
            writer_future.result(timeout=0.25)
        assert not writer_acquired_advisory.is_set()
        release_phase_b.set()
        response = evaluation_future.result(timeout=10)
        writer_future.result(timeout=10)
        assert writer_acquired_advisory.is_set()

    assert response.policy_audit_id is not None
    assert store.get_policy_evaluation_by_event_id(event.event_id) is not None
    assert len(store.list_rebuild_inputs(scope_digest, limit=10)) == 1
    if authority == "policy":
        current_policy = store.get_policy_snapshot_record()
        assert current_policy is not None and current_policy.revision == 2
    elif authority == "task":
        current_task = store.get_task_fact(task_id)
        assert current_task is not None and current_task.task_fact.revision == 2
    elif authority == "runtime":
        current_runtime = store.get_product_runtime_status(runtime_status.identity())
        assert current_runtime is not None
        assert current_runtime.runtime_version == "1.2.7-authority-writer"
    else:
        credential = next(
            item
            for item in store.list_credentials()
            if item.credential_id == _RUNTIME_CREDENTIAL_ID
        )
        assert credential.revoked_at is not None


def test_postgres_projection_reservation_linearizes_same_scope_events(
    product_stack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, _writer, pipeline, evaluation, task_id, scope_digest = product_stack
    first = _event(task_id)
    second = _event(
        task_id,
        event_id="evt_product_binding_pg_second",
        call_id="call:product-binding-pg-second",
    )
    entered_phase_c = Event()
    release_phase_c = Event()
    original_phase_c = pipeline.run_phase_c

    def hold_first_phase_c(plan):
        entered_phase_c.set()
        assert release_phase_c.wait(timeout=10)
        original_phase_c(plan)

    monkeypatch.setattr(pipeline, "run_phase_c", hold_first_phase_c)

    with ThreadPoolExecutor(max_workers=1) as executor:
        first_future = executor.submit(
            evaluation.evaluate,
            first,
            auth_context=_auth(fixture),
        )
        assert entered_phase_c.wait(timeout=10)
        with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
            evaluation.evaluate(second, auth_context=_auth(fixture))
        assert raised.value.code == PRODUCT_SECURITY_STATE_NOT_READY
        release_phase_c.set()
        first_response = first_future.result(timeout=10)

    evaluations = [
        item
        for item in store.list_audit_events()
        if item.record_type == "policy_evaluation"
    ]
    state = store.get_security_state(scope_digest)
    assert len(evaluations) == 1
    assert evaluations[0].audit_id == first_response.policy_audit_id
    assert len(store.list_rebuild_inputs(scope_digest, limit=10)) == 1
    assert state is not None and state.state_version == 1


def test_postgres_same_digest_policy_revision_drift_is_503(
    product_stack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, writer, pipeline, evaluation, task_id, scope_digest = product_stack
    event = _event(task_id)
    phase_a_done = Event()
    release_phase_a = Event()
    original_phase_a = pipeline.run_phase_a

    def hold_after_phase_a(*args, **kwargs):
        materials = original_phase_a(*args, **kwargs)
        phase_a_done.set()
        assert release_phase_a.wait(timeout=10)
        return materials

    monkeypatch.setattr(pipeline, "run_phase_a", hold_after_phase_a)
    with ThreadPoolExecutor(max_workers=1) as executor:
        evaluation_future = executor.submit(
            evaluation.evaluate,
            event,
            auth_context=_auth(fixture),
        )
        assert phase_a_done.wait(timeout=10)
        writer.save_policy_snapshot(
            PolicyBundle(),
            expected_revision=1,
            updated_by="p0-pg-race",
        )
        release_phase_a.set()
        with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
            evaluation_future.result(timeout=10)

    assert raised.value.code == PRODUCT_POLICY_NOT_CURRENT
    assert store.get_policy_evaluation_by_event_id(event.event_id) is None
    assert store.list_rebuild_inputs(scope_digest, limit=10) == []


def test_postgres_final_activation_drift_rolls_back_audit_and_reservation(
    product_stack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, _writer, pipeline, evaluation, task_id, scope_digest = product_stack
    event = _event(task_id)
    initial_store_image = _postgres_store_image(store)
    original_phase_b = pipeline.build_phase_b

    def build_then_mutate_activation(*args, **kwargs):
        outcome = original_phase_b(*args, **kwargs)
        activation = pipeline._runtime_binding_resolver.product_activation
        assert activation is not None
        entry = activation.bundle.runtimes[0]
        activation.bundle.runtimes[0] = entry.model_copy(
            update={"runtime_binding_id": "binding:pg-final-drift"}
        )
        return outcome

    monkeypatch.setattr(pipeline, "build_phase_b", build_then_mutate_activation)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        evaluation.evaluate(event, auth_context=_auth(fixture))

    assert raised.value.code == PRODUCT_ACTIVATION_NOT_CURRENT
    assert store.get_policy_evaluation_by_event_id(event.event_id) is None
    assert store.list_rebuild_inputs(scope_digest, limit=10) == []
    assert _postgres_store_image(store) == initial_store_image
