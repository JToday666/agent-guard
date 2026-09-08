"""Deterministic Product CT recovery, without Host or activation claims.

CT deltas themselves do not append RecentAction facts. These storage-level
fixtures commit real unsequenced policy deltas in Z -> A arrival order before
the CT post-commit boundary, reproducing the non-commutative state mismatch.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    FlowFact,
    OnlineSecurityState,
    SecurityStateDeltaV21,
    delta_digest_projection,
    rebuild_state,
    state_digest,
)
from guard_api.security_state import SecurityStateNotReadyError, SecurityStateService
from guard_api.security_state.delta_builder import build_ct_facts_delta
from guard_api.security_state.transient import (
    FACT_BUILDER_VERSION,
    LEGACY_FACT_BUILDER_VERSION,
    PRODUCT_FACT_BUILDER_VERSION,
    PRODUCT_FACT_PRODUCER,
    TransientSecurityFacts,
    compute_bundle_digest,
    compute_overlay_digest,
)
from guard_api.services.ct_projection import CtCommitPlan, CtProjectionService
from guard_api.storage.base import TaskFactRecord
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.test_ct_state_wiring import _ct_backfill_audit, _settings
from tests.test_product_security_state_readiness import _read
from tests.test_v21_security_state_models import (
    SCOPE,
    make_delta,
    make_recent_action,
    make_source_fact,
)
from tests.test_v21_state_projector import make_record
from tests.test_v21_state_replay import make_task_fact

pytestmark = pytest.mark.integration


def _stack():
    store = MemoryControlPlaneStore()
    task = make_task_fact().model_copy(update={"revision": 1})
    store.create_task_fact(
        TaskFactRecord(
            task_fact=task,
            canonical_payload=task.model_dump(mode="json"),
            request_digest="sha256:" + "1" * 64,
            expected_revision=0,
            created_at="2026-09-01T00:00:00Z",
        )
    )
    state = SecurityStateService(store)
    state.ensure_ready(SCOPE)
    ct = CtProjectionService(settings=_settings(), store=store, state_service=state)
    assert ct.enabled
    return store, state, ct


def _online(store):
    record = store.get_security_state(SCOPE)
    assert record is not None
    return OnlineSecurityState.model_validate(record.canonical_payload)


def _append_action(store, state, label):
    delta = make_delta(
        source_record_id=f"policy-{label}",
        base_state_version=_online(store).state_version,
    ).model_copy(
        update={
            "action_additions": [
                make_recent_action(
                    0,
                    action_id=f"action-{label}",
                    event_id=f"event-{label}",
                    resource_ids=[f"file:{label}.txt"],
                )
            ]
        }
    )
    delta = delta.model_copy(
        update={"delta_digest": canonical_sha256(delta_digest_projection(delta))}
    )
    assert (
        state.project_committed(make_record(delta), scope_digest=SCOPE).outcome
        == "applied"
    )


def _persist_plan(store, ct, version, tag):
    source = make_source_fact(source_id=f"source:{tag}")
    flow = FlowFact(
        flow_id=f"flow:{tag}",
        scope_digest=SCOPE,
        source_ref=source.source_id,
        target_ref=f"action:{tag}",
        relation="influenced_by",
        taints=["UNTRUSTED"],
        strength="possible",
        origin="semantic_inferred",
        sequence=None,
        producer=(
            PRODUCT_FACT_PRODUCER
            if version == PRODUCT_FACT_BUILDER_VERSION
            else "ct-fact-builder"
        ),
        evidence_refs=[],
    )
    bundle = TransientSecurityFacts(
        event_id=f"ct-{tag}",
        scope_digest=SCOPE,
        source_facts=(source,),
        flow_facts=(flow,),
    )
    bundle = bundle.model_copy(
        update={
            "bundle_digest": compute_bundle_digest(
                bundle, fact_builder_version=version
            ),
            "overlay_digest": compute_overlay_digest(bundle),
        }
    )
    base = _online(store).state_version
    source_id = f"ct-facts:{bundle.event_id}"
    delta = build_ct_facts_delta(
        scope_digest=SCOPE,
        source_record_id=source_id,
        base_state_version=base,
        bundle=bundle,
    )
    assert delta is not None and delta.action_additions == []
    payload = ct.commit_envelope(
        bundle,
        source_record_id=source_id,
        projection_id=delta.projection_id,
        base_state_version=base,
        projection_eligible=True,
    )
    payload["fact_builder_version"] = version
    envelope_version = "1.0" if version == LEGACY_FACT_BUILDER_VERSION else "1.1"
    audit = _ct_backfill_audit(
        payload=payload,
        task_id="task_1",
        event_id=bundle.event_id,
        envelope_schema_version=envelope_version,
    )
    with store.evaluation_transaction(bundle.event_id):
        assert store.add_audit_event(audit)
    persisted = store.get_policy_evaluation_by_event_id(bundle.event_id)
    assert persisted is not None
    return (
        CtCommitPlan(
            scope_digest=SCOPE,
            source_record_id=source_id,
            bundle=bundle,
            base_state_version=base,
            envelope=persisted.evidence["ct_transient_facts"],
            projectable=True,
        ),
        persisted,
    )


def _assert_canonical_and_ready(store, state):
    rows = store.list_rebuild_inputs(SCOPE, limit=100)
    expected = rebuild_state(
        [
            make_record(SecurityStateDeltaV21.model_validate(row.delta_payload))
            for row in rows
        ],
        PROJECTOR_VERSION,
    )
    actual = _online(store)
    assert actual.model_dump(mode="json") == expected.model_dump(mode="json")
    assert state_digest(actual) == state_digest(expected)
    before = deepcopy(store.get_security_state(SCOPE))
    assert _read(state)[0].state_version == actual.state_version
    assert store.get_security_state(SCOPE) == before


def _assert_order_mismatch(store, state):
    assert [action.action_id for action in _online(store).recent_actions] == [
        "action-z",
        "action-a",
    ]
    with pytest.raises(SecurityStateNotReadyError) as caught:
        _read(state)
    assert caught.value.condition == "projection_state_digest_mismatch"


def test_product_ct_postcommit_canonicalizes_each_noncommutative_prefix():
    store, state, ct = _stack()
    for label in ("z", "a"):
        _append_action(store, state, label)
        if label == "a":
            _assert_order_mismatch(store, state)
        plan, _audit = _persist_plan(store, ct, PRODUCT_FACT_BUILDER_VERSION, label)
        ct.project_after_commit(plan)
        _assert_canonical_and_ready(store, state)
    assert [action.action_id for action in _online(store).recent_actions] == [
        "action-a",
        "action-z",
    ]


@pytest.mark.parametrize("version", [LEGACY_FACT_BUILDER_VERSION, FACT_BUILDER_VERSION])
def test_nonproduct_backfill_does_not_automatically_reconcile(version, monkeypatch):
    store, state, ct = _stack()
    _append_action(store, state, "z")
    _append_action(store, state, "a")
    _plan, audit = _persist_plan(store, ct, version, "legacy")
    calls = []

    def forbidden(*_args, **_kwargs):
        calls.append("unexpected_reconcile")
        raise AssertionError("legacy CT must not initiate Product reconciliation")

    monkeypatch.setattr(state, "reconcile_projection_history", forbidden)
    ct.backfill(audit)
    assert calls == []
    assert _online(store).state_version == 3
    _assert_order_mismatch(store, state)


@pytest.mark.parametrize("failure", ["storage_error", "bounded_history"])
def test_reconcile_failure_stays_unready_and_public_backfill_recovers(
    failure, monkeypatch
):
    store, state, ct = _stack()
    _append_action(store, state, "z")
    _append_action(store, state, "a")
    plan, audit = _persist_plan(store, ct, PRODUCT_FACT_BUILDER_VERSION, "recovery")
    original_reconcile = state.reconcile_projection_history

    def fail(scope_digest, **kwargs):
        if failure == "storage_error":
            raise OSError("synthetic_storage_failure")
        return original_reconcile(scope_digest, rebuild_limit=1)

    with monkeypatch.context() as broken:
        broken.setattr(state, "reconcile_projection_history", fail)
        ct.project_after_commit(plan)
    # The committed CT projection survives; a failed recovery cannot attest
    # readiness, delete a committed event, or duplicate a runtime action.
    assert _online(store).state_version == 3
    _assert_order_mismatch(store, state)
    rows_before = deepcopy(store.projection_records)
    audit_before = audit.model_dump(mode="json")
    ct.backfill(audit)
    _assert_canonical_and_ready(store, state)
    assert _online(store).state_version == 3
    assert store.projection_records == rows_before
    assert store.get_audit_event(audit.audit_id).model_dump(mode="json") == audit_before


@pytest.mark.parametrize("mutation", ["source_taints", "flow_target", "extra_action"])
def test_existing_ct_delta_must_match_committed_bundle_before_recovery(
    mutation, monkeypatch
):
    store, state, ct = _stack()
    _append_action(store, state, "z")
    plan, audit = _persist_plan(store, ct, PRODUCT_FACT_BUILDER_VERSION, "parity")
    ct.project_after_commit(plan)
    _assert_canonical_and_ready(store, state)
    before = deepcopy(store.get_security_state(SCOPE))
    row_key, row = next(
        (key, row)
        for key, row in store.projection_records.items()
        if row.source_record_id == plan.source_record_id
    )
    delta = SecurityStateDeltaV21.model_validate(row.delta_payload)
    if mutation == "source_taints":
        delta = delta.model_copy(
            update={
                "source_upserts": [
                    source.model_copy(update={"taints": []})
                    for source in delta.source_upserts
                ]
            }
        )
    elif mutation == "flow_target":
        delta = delta.model_copy(
            update={
                "flow_upserts": [
                    flow.model_copy(update={"target_ref": "action:uncommitted"})
                    for flow in delta.flow_upserts
                ]
            }
        )
    else:
        # This container can never originate from the current CT delta builder.
        delta = delta.model_copy(update={"action_additions": [make_recent_action(9)]})
    delta = delta.model_copy(
        update={"delta_digest": canonical_sha256(delta_digest_projection(delta))}
    )
    store.projection_records[row_key] = replace(
        row,
        delta_payload=delta.model_dump(mode="json"),
        delta_digest=delta.delta_digest,
    )
    with pytest.raises(SecurityStateNotReadyError):
        _read(state)
    calls = []
    original = state.reconcile_projection_history

    def observe(*args, **kwargs):
        calls.append("reconcile")
        return original(*args, **kwargs)

    monkeypatch.setattr(state, "reconcile_projection_history", observe)
    ct.backfill(audit)
    assert calls == []
    assert store.get_security_state(SCOPE) == before
    with pytest.raises(SecurityStateNotReadyError):
        _read(state)
