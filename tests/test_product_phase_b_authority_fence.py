"""Product authority fence, final validation, and reservation tests.

The public Product endpoint remains behind ``SELECTOR_NOT_WIRED`` in this
batch.  These tests deliberately construct the internal evaluation service
without that terminal fuse so the next selector PR cannot expose an untested
Phase-A/commit race.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from threading import Event

import pytest
from agentguard_core import PolicyBundle
from agentguard_core.security_context import CommittedRecord

from guard_api.security_state import SecurityStateProjectError, SecurityStateService
from guard_api.services import ApprovalService, AuditService, EvaluationService
from guard_api.services.policy import PolicyService
from guard_api.services.product_activation import RUNTIME_OBSERVATION_MISMATCH
from guard_api.services.runtime_binding import (
    PRODUCT_ACTIVATION_NOT_CURRENT,
    PRODUCT_TASK_IDENTITY_MISMATCH,
)
from guard_api.services.v21_pipeline import (
    PRODUCT_CREDENTIAL_NOT_CURRENT,
    PRODUCT_POLICY_NOT_CURRENT,
    PRODUCT_SECURITY_STATE_NOT_READY,
    V21OfficialEvaluationUnavailableError,
    build_evaluation_delta,
)
from guard_api.storage.base import ProjectionIdentityRecord, TaskFactRecord
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.test_product_runtime_binding_wiring import (
    _auth,
    _create_product_task,
    _event,
    _pipeline,
)
from tests.support.product_activation import product_runtime_status_for_activation

pytestmark = pytest.mark.integration


def _stack(tmp_path):
    fixture, settings, store, created = _create_product_task(tmp_path)
    task_id = str(created["task_id"])
    scope_digest = str(created["scope_digest"])
    SecurityStateService(store).ensure_ready(scope_digest)
    pipeline = _pipeline(store, settings)
    evaluation = EvaluationService(
        policy_service=PolicyService(store=store),
        audit_service=AuditService(store=store),
        approval_service=ApprovalService(store=store, settings=settings),
        v21_pipeline=pipeline,
    )
    return (
        fixture,
        store,
        pipeline,
        evaluation,
        task_id,
        scope_digest,
    )


def _assert_no_evaluation_effects(
    store: MemoryControlPlaneStore,
    *,
    event_id: str,
    expected_store_image: dict | None = None,
) -> None:
    assert store.get_policy_evaluation_by_event_id(event_id) is None
    assert store.approvals == {}
    assert store.action_critic_reviews == {}
    assert store.memory_changes == {}
    assert store.enforcement_bindings == {}
    if expected_store_image is None:
        assert store.projection_records == {}
    else:
        assert _memory_store_image(store) == expected_store_image


def _memory_store_image(store: MemoryControlPlaneStore) -> dict:
    """Capture every Product transaction container for rollback assertions."""

    return deepcopy(
        {
            "audit_events": store.audit_events,
            "audit_events_by_id": store.audit_events_by_id,
            "audit_ingested_at_by_id": store.audit_ingested_at_by_id,
            "provenance_nodes": store.provenance_nodes,
            "provenance_edges": store.provenance_edges,
            "approvals": store.approvals,
            "enforcement_bindings": store.enforcement_bindings,
            "memory_changes": store.memory_changes,
            "action_critic_reviews": store.action_critic_reviews,
            "policy_snapshot": store.policy_snapshot,
            "policy_snapshot_history": store.policy_snapshot_history,
            "task_facts": store.task_facts,
            "security_states": store.security_states,
            "projection_records": store.projection_records,
            "product_runtime_statuses_v2": store.product_runtime_statuses_v2,
            "product_runtime_status_write_sequence": (
                store.product_runtime_status_write_sequence
            ),
            "adapter_statuses": store.adapter_statuses,
            "credentials": store.credentials,
        }
    )


def _seed_projection_history(
    store: MemoryControlPlaneStore,
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
                audit_id=f"audit:capacity-seed:{index}",
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


def _advance_unrelated_projection(
    store: MemoryControlPlaneStore,
    scope_digest: str,
) -> None:
    delta = build_evaluation_delta(
        scope_digest=scope_digest,
        audit_id="audit:interleaved-other-projector",
        base_state_version=0,
    )
    SecurityStateService(store).project_committed(
        CommittedRecord(
            record_id="record:interleaved-other-projector",
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
    store: MemoryControlPlaneStore,
    scope_digest: str,
) -> None:
    delta = build_evaluation_delta(
        scope_digest=scope_digest,
        audit_id="audit:crashed-other-projector",
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


def test_product_fence_commits_audit_and_projection_reservation_atomically(
    tmp_path,
) -> None:
    fixture, store, _pipeline_service, evaluation, task_id, scope_digest = _stack(
        tmp_path
    )
    event = _event(task_id)

    response = evaluation.evaluate(
        event,
        auth_context=_auth(fixture),
    )

    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    state = store.get_security_state(scope_digest)
    assert audit is not None
    assert response.policy_audit_id == audit.audit_id
    assert audit.metadata["product_authority_digest"].startswith("sha256:")
    assert (
        datetime.fromisoformat(
            audit.metadata["product_authority_initial_checked_at"]
        ).tzinfo
        is not None
    )
    assert len(store.projection_records) == 1
    assert state is not None
    assert state.state_version == 1


def test_product_phase_c_never_reads_audit_under_state_transaction(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, _pipeline_service, evaluation, task_id, scope_digest = _stack(
        tmp_path
    )
    event = _event(task_id)
    original_transaction = MemoryControlPlaneStore.security_state_transaction
    original_get_audit = MemoryControlPlaneStore.get_audit_event
    inside_state_transaction = False

    @contextmanager
    def observed_transaction(self, requested_scope_digest):
        nonlocal inside_state_transaction
        with original_transaction(self, requested_scope_digest):
            inside_state_transaction = True
            try:
                yield
            finally:
                inside_state_transaction = False

    def guarded_get_audit(self, audit_id):
        assert not inside_state_transaction, "state -> audit lock inversion"
        return original_get_audit(self, audit_id)

    monkeypatch.setattr(
        MemoryControlPlaneStore,
        "security_state_transaction",
        observed_transaction,
    )
    monkeypatch.setattr(
        MemoryControlPlaneStore,
        "get_audit_event",
        guarded_get_audit,
    )

    evaluation.evaluate(event, auth_context=_auth(fixture))

    state = store.get_security_state(scope_digest)
    assert state is not None and state.state_version == 1


def test_memory_state_transaction_rolls_back_failed_reconcile(tmp_path) -> None:
    _fixture, store, _pipeline_service, _evaluation, _task_id, scope_digest = _stack(
        tmp_path
    )
    before = _memory_store_image(store)
    service = SecurityStateService(store)
    access = service.store_access

    with pytest.raises(SecurityStateProjectError):
        with access.scope_lock(scope_digest), access.transaction(scope_digest):
            access.record_projection(
                _invalid_projection(
                    scope_digest,
                    audit_id="audit:memory-failed-reconcile",
                )
            )
            service.reconcile_projection_history(scope_digest)

    assert _memory_store_image(store) == before


@pytest.mark.parametrize(
    ("existing_count", "accepted"),
    [(998, True), (999, False)],
)
def test_product_reservation_proves_bounded_rebuild_headroom_before_commit(
    tmp_path,
    existing_count: int,
    accepted: bool,
) -> None:
    fixture, store, _pipeline_service, evaluation, task_id, scope_digest = _stack(
        tmp_path
    )
    _seed_projection_history(store, scope_digest, count=existing_count)
    event = _event(
        task_id,
        event_id=f"evt_product_capacity_{existing_count}",
        call_id=f"call:product-capacity-{existing_count}",
    )
    before = _memory_store_image(store)

    if accepted:
        evaluation.evaluate(event, auth_context=_auth(fixture))
        state = store.get_security_state(scope_digest)
        assert state is not None and state.state_version == 999
        assert len(store.projection_records) == 999
    else:
        with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
            evaluation.evaluate(event, auth_context=_auth(fixture))
        assert raised.value.code == PRODUCT_SECURITY_STATE_NOT_READY
        _assert_no_evaluation_effects(
            store,
            event_id=event.event_id,
            expected_store_image=before,
        )


def test_product_missing_exact_credential_fails_before_any_side_effect(
    tmp_path,
) -> None:
    fixture, store, _pipeline_service, evaluation, task_id, _scope_digest = _stack(
        tmp_path
    )
    event = _event(task_id)
    store.credentials.clear()

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        evaluation.evaluate(event, auth_context=_auth(fixture))

    assert raised.value.code == PRODUCT_CREDENTIAL_NOT_CURRENT
    _assert_no_evaluation_effects(store, event_id=event.event_id)


@pytest.mark.parametrize("mutation", ["missing", "digest_mismatch"])
def test_product_phase_a_requires_exact_persisted_policy(
    tmp_path,
    mutation: str,
) -> None:
    fixture, store, _pipeline_service, evaluation, task_id, _scope_digest = _stack(
        tmp_path
    )
    event = _event(
        task_id,
        event_id=f"evt_product_policy_{mutation}",
        call_id=f"call:product-policy-{mutation}",
    )
    original = store.policy_snapshot
    assert original is not None
    if mutation == "missing":
        store.policy_snapshot = None
    else:
        changed_bundle = original.policy_bundle.model_copy(
            update={"version": "product-policy-digest-mismatch"}
        )
        store.policy_snapshot = original.__class__(
            revision=original.revision,
            policy_bundle=changed_bundle,
            updated_at=original.updated_at,
            updated_by=original.updated_by,
        )
    initial_store_image = _memory_store_image(store)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        evaluation.evaluate(event, auth_context=_auth(fixture))

    assert raised.value.code == PRODUCT_POLICY_NOT_CURRENT
    _assert_no_evaluation_effects(
        store,
        event_id=event.event_id,
        expected_store_image=initial_store_image,
    )


def test_product_backfill_applies_an_existing_unapplied_reservation(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, pipeline, evaluation, task_id, scope_digest = _stack(tmp_path)
    event = _event(task_id)
    monkeypatch.setattr(pipeline, "run_phase_c", lambda _plan: None)

    evaluation.evaluate(event, auth_context=_auth(fixture))

    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    pending = store.get_security_state(scope_digest)
    assert audit is not None
    assert pending is not None and pending.state_version == 0
    assert len(store.projection_records) == 1

    pipeline.backfill_projection(audit)

    recovered = store.get_security_state(scope_digest)
    assert recovered is not None and recovered.state_version == 1


def test_product_phase_c_rebuilds_when_another_projector_advances_first(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, pipeline, evaluation, task_id, scope_digest = _stack(tmp_path)
    event = _event(task_id)
    original_phase_c = pipeline.run_phase_c

    def interleave_other_projector(plan):
        _advance_unrelated_projection(store, scope_digest)
        original_phase_c(plan)

    monkeypatch.setattr(pipeline, "run_phase_c", interleave_other_projector)

    evaluation.evaluate(event, auth_context=_auth(fixture))

    state = store.get_security_state(scope_digest)
    assert state is not None and state.state_version == 2
    assert len(store.projection_records) == 2
    second = _event(
        task_id,
        event_id="evt_product_binding_after_rebuild",
        call_id="call:product-binding-after-rebuild",
    )
    assert pipeline.run_phase_a(second, auth_context=_auth(fixture)) is not None


def test_product_phase_c_rebuilds_foreign_unapplied_envelope(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, pipeline, evaluation, task_id, scope_digest = _stack(tmp_path)
    event = _event(task_id)
    original_phase_c = pipeline.run_phase_c

    def interleave_crashed_projector(plan):
        _record_unapplied_unrelated_projection(store, scope_digest)
        original_phase_c(plan)

    monkeypatch.setattr(pipeline, "run_phase_c", interleave_crashed_projector)

    evaluation.evaluate(event, auth_context=_auth(fixture))

    state = store.get_security_state(scope_digest)
    assert state is not None and state.state_version == 2
    assert len(store.projection_records) == 2
    second = _event(
        task_id,
        event_id="evt_product_binding_after_foreign_crash",
        call_id="call:product-binding-after-foreign-crash",
    )
    assert pipeline.run_phase_a(second, auth_context=_auth(fixture)) is not None


@pytest.mark.parametrize("mutation", ["dirty", "payload", "unapplied_projection"])
def test_phase_b_rejects_same_version_state_authority_drift(
    tmp_path,
    mutation: str,
) -> None:
    fixture, store, pipeline, _evaluation, task_id, scope_digest = _stack(tmp_path)
    event = _event(task_id)
    materials = pipeline.run_phase_a(event, auth_context=_auth(fixture))
    assert materials is not None
    original = store.get_security_state(scope_digest)
    assert original is not None

    if mutation == "dirty":
        store.mark_security_state_dirty(scope_digest, ["behavior"])
    elif mutation == "payload":
        payload = deepcopy(original.canonical_payload)
        payload["revoked_grant_ids"] = ["grant:phase-b-drift"]
        store.security_states[scope_digest] = original.__class__(
            scope_digest=original.scope_digest,
            state_version=original.state_version,
            canonical_payload=payload,
            dirty=original.dirty,
            dirty_domains=list(original.dirty_domains),
            projector_version=original.projector_version,
            updated_at=original.updated_at,
        )
    else:
        delta = build_evaluation_delta(
            scope_digest=scope_digest,
            audit_id="audit:unapplied-product-reservation",
            base_state_version=original.state_version,
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

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        pipeline.build_phase_b(event, materials)

    assert raised.value.code == PRODUCT_SECURITY_STATE_NOT_READY


def test_policy_same_content_new_revision_is_a_product_503(tmp_path) -> None:
    fixture, store, pipeline, _evaluation, task_id, _scope_digest = _stack(tmp_path)
    event = _event(task_id)
    materials = pipeline.run_phase_a(event, auth_context=_auth(fixture))
    assert materials is not None
    store.save_policy_snapshot(PolicyBundle(), expected_revision=1, updated_by="race")

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        pipeline.build_phase_b(event, materials)

    assert raised.value.code == PRODUCT_POLICY_NOT_CURRENT


def test_full_task_fact_revision_drift_is_a_product_503(tmp_path) -> None:
    fixture, store, pipeline, _evaluation, task_id, _scope_digest = _stack(tmp_path)
    event = _event(task_id)
    materials = pipeline.run_phase_a(event, auth_context=_auth(fixture))
    assert materials is not None
    original = store.get_task_fact(task_id)
    assert original is not None
    advanced = original.task_fact.model_copy(
        update={"revision": 2, "status": "cancelled"}
    )
    store.create_task_fact(
        TaskFactRecord(
            task_fact=advanced,
            canonical_payload=advanced.model_dump(mode="json"),
            request_digest="sha256:" + "a" * 64,
            expected_revision=1,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        pipeline.build_phase_b(event, materials)

    assert raised.value.code == PRODUCT_TASK_IDENTITY_MISMATCH


def test_final_authority_drift_rolls_back_every_staged_side_effect(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, pipeline, evaluation, task_id, scope_digest = _stack(tmp_path)
    event = _event(task_id)
    initial_store_image = _memory_store_image(store)
    original_build = pipeline.build_phase_b

    def build_then_drift(*args, **kwargs):
        outcome = original_build(*args, **kwargs)
        store.mark_security_state_dirty(scope_digest, ["behavior"])
        return outcome

    monkeypatch.setattr(pipeline, "build_phase_b", build_then_drift)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        evaluation.evaluate(event, auth_context=_auth(fixture))

    assert raised.value.code == PRODUCT_SECURITY_STATE_NOT_READY
    _assert_no_evaluation_effects(
        store,
        event_id=event.event_id,
        expected_store_image=initial_store_image,
    )

    # The failed transaction leaves no poisoned reservation or authority
    # mutation: the exact same event can commit after the interleaving is gone.
    monkeypatch.setattr(pipeline, "build_phase_b", original_build)
    response = evaluation.evaluate(event, auth_context=_auth(fixture))
    assert store.get_policy_evaluation_by_event_id(event.event_id) is not None
    assert response.policy_audit_id is not None


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("policy", PRODUCT_POLICY_NOT_CURRENT),
        ("task", PRODUCT_TASK_IDENTITY_MISMATCH),
        ("runtime", RUNTIME_OBSERVATION_MISMATCH),
        ("credential", PRODUCT_CREDENTIAL_NOT_CURRENT),
        ("activation", PRODUCT_ACTIVATION_NOT_CURRENT),
    ],
)
def test_final_non_state_authority_drift_rolls_back_staged_evaluation(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_code: str,
) -> None:
    fixture, store, pipeline, evaluation, task_id, _scope_digest = _stack(tmp_path)
    event = _event(task_id)
    initial_store_image = _memory_store_image(store)
    original_build = pipeline.build_phase_b

    def build_then_drift(*args, **kwargs):
        outcome = original_build(*args, **kwargs)
        if mutation == "policy":
            store.save_policy_snapshot(
                PolicyBundle(), expected_revision=1, updated_by="final-race"
            )
        elif mutation == "task":
            current = store.get_task_fact(task_id)
            assert current is not None
            advanced = current.task_fact.model_copy(update={"revision": 2})
            store.create_task_fact(
                TaskFactRecord(
                    task_fact=advanced,
                    canonical_payload=advanced.model_dump(mode="json"),
                    request_digest="sha256:" + "b" * 64,
                    expected_revision=1,
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
            )
        elif mutation == "runtime":
            current = product_runtime_status_for_activation(fixture, "openclaw")
            store.save_product_runtime_status(
                current.model_copy(update={"runtime_version": "drifted-host"})
            )
        elif mutation == "credential":
            assert args[1].auth_context is not None
            credential_id = args[1].auth_context.credential_id
            assert credential_id is not None
            store.revoke_credential(
                credential_id,
                datetime.now(timezone.utc).isoformat(),
            )
        else:
            activation = pipeline._runtime_binding_resolver.product_activation
            assert activation is not None
            entry = activation.bundle.runtimes[0]
            activation.bundle.runtimes[0] = entry.model_copy(
                update={"runtime_binding_id": "binding:mutated-before-commit"}
            )
        return outcome

    monkeypatch.setattr(pipeline, "build_phase_b", build_then_drift)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        evaluation.evaluate(event, auth_context=_auth(fixture))

    assert raised.value.code == expected_code
    _assert_no_evaluation_effects(
        store,
        event_id=event.event_id,
        expected_store_image=initial_store_image,
    )


def test_activation_expiry_between_phase_b_and_final_commit_is_zero_write_503(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, pipeline, evaluation, task_id, _scope_digest = _stack(tmp_path)
    event = _event(
        task_id,
        event_id="evt_product_activation_expires_before_commit",
        call_id="call:product-activation-expires-before-commit",
    )
    expiry = datetime.fromisoformat(fixture.bundle.expires_at.replace("Z", "+00:00"))
    sampled_at = [expiry - timedelta(seconds=1)]
    resolver = pipeline._runtime_binding_resolver
    object.__setattr__(resolver, "clock", lambda: sampled_at[0])
    initial_store_image = _memory_store_image(store)
    original_build = pipeline.build_phase_b

    def build_then_expire(*args, **kwargs):
        outcome = original_build(*args, **kwargs)
        sampled_at[0] = expiry + timedelta(seconds=1)
        return outcome

    monkeypatch.setattr(pipeline, "build_phase_b", build_then_expire)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        evaluation.evaluate(event, auth_context=_auth(fixture))

    assert raised.value.code == PRODUCT_ACTIVATION_NOT_CURRENT
    _assert_no_evaluation_effects(
        store,
        event_id=event.event_id,
        expected_store_image=initial_store_image,
    )


def test_projection_reservation_linearizes_same_scope_different_events(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, store, pipeline, evaluation, task_id, scope_digest = _stack(tmp_path)
    first = _event(task_id)
    second = _event(
        task_id,
        event_id="evt_product_binding_pipeline_second",
        call_id="call:product-binding-second",
    )
    entered_phase_c = Event()
    release_phase_c = Event()
    original_phase_c = pipeline.run_phase_c

    def hold_first_phase_c(plan):
        entered_phase_c.set()
        assert release_phase_c.wait(timeout=5)
        original_phase_c(plan)

    monkeypatch.setattr(pipeline, "run_phase_c", hold_first_phase_c)

    with ThreadPoolExecutor(max_workers=1) as executor:
        first_future = executor.submit(
            evaluation.evaluate,
            first,
            auth_context=_auth(fixture),
        )
        assert entered_phase_c.wait(timeout=5)
        with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
            evaluation.evaluate(second, auth_context=_auth(fixture))
        assert raised.value.code == PRODUCT_SECURITY_STATE_NOT_READY
        release_phase_c.set()
        first_response = first_future.result(timeout=5)

    audits = [
        audit
        for audit in store.audit_events
        if audit.record_type == "policy_evaluation"
    ]
    state = store.get_security_state(scope_digest)
    assert len(audits) == 1
    assert audits[0].audit_id == first_response.policy_audit_id
    assert len(store.projection_records) == 1
    assert state is not None and state.state_version == 1
