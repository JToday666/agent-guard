"""PostgreSQL transaction parity for Product authority-aware exact replay."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pytest
from agentguard_core import GuardEngine, PolicyBundle
from agentguard_core.provenance import ProvenanceNode

from guard_api.services.v21_pipeline import (
    PRODUCT_POLICY_NOT_CURRENT,
    V21OfficialEvaluationUnavailableError,
)
from tests.support.product_evaluation_postgres import (
    PRODUCT_REPLAY_TRACE_ID,
    ProductPostgresEvaluationHarness,
    create_product_postgres_evaluation_harness,
)

pytestmark = pytest.mark.postgres


@pytest.fixture
def replay_harness(tmp_path: Path):
    with create_product_postgres_evaluation_harness(tmp_path) as harness:
        yield harness


def _commit_pending_reservation(
    harness: ProductPostgresEvaluationHarness,
    monkeypatch: pytest.MonkeyPatch,
    *,
    event_id: str,
):
    event = harness.event(event_id=event_id)
    original_phase_c = harness.pipeline.run_phase_c
    monkeypatch.setattr(harness.pipeline, "run_phase_c", lambda _plan: None)
    response = harness.evaluation.evaluate(
        event,
        auth_context=harness.auth_context,
    )
    monkeypatch.setattr(harness.pipeline, "run_phase_c", original_phase_c)

    state = harness.store.get_security_state(harness.scope_digest)
    audit = harness.store.get_policy_evaluation_by_event_id(event.event_id)
    projections = harness.store.list_rebuild_inputs(harness.scope_digest, limit=10)
    assert response.decision_authority is not None
    assert response.decision_authority.source == "v21"
    assert response.decision_authority.mode == "active"
    assert response.decision_authority.selection_basis == "profile_all"
    assert state is not None and state.state_version == 0
    assert audit is not None
    assert len(projections) == 1
    return event, response, audit


def _persistent_replay_image(harness: ProductPostgresEvaluationHarness) -> dict:
    state = harness.store.get_security_state(harness.scope_digest)
    projections = harness.store.list_rebuild_inputs(harness.scope_digest, limit=10)
    nodes, edges = harness.store.list_provenance(PRODUCT_REPLAY_TRACE_ID)
    return {
        "state": asdict(state) if state is not None else None,
        "projections": [asdict(item) for item in projections],
        "provenance_nodes": [item.model_dump(mode="json") for item in nodes],
        "provenance_edges": [item.model_dump(mode="json") for item in edges],
    }


def test_postgres_replay_recovers_pending_reservation_in_product_transaction(
    replay_harness: ProductPostgresEvaluationHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment_calls = 0
    original_assess = GuardEngine.evaluate_with_results

    def count_assessment(self, event, bundle=None):
        nonlocal assessment_calls
        assessment_calls += 1
        return original_assess(self, event, bundle)

    monkeypatch.setattr(GuardEngine, "evaluate_with_results", count_assessment)
    event, first, audit = _commit_pending_reservation(
        replay_harness,
        monkeypatch,
        event_id="evt:product-replay-postgres-pending",
    )
    assert assessment_calls == 1

    replay = replay_harness.evaluation.evaluate(
        event,
        auth_context=replay_harness.auth_context,
    )

    recovered = replay_harness.store.get_security_state(replay_harness.scope_digest)
    persisted = replay_harness.store.get_policy_evaluation_by_event_id(event.event_id)
    projections = replay_harness.store.list_rebuild_inputs(
        replay_harness.scope_digest,
        limit=10,
    )
    assert assessment_calls == 1
    assert recovered is not None and recovered.state_version == 1
    assert len(projections) == 1
    assert replay.model_dump_json() == first.model_dump_json()
    assert (
        persisted is not None and persisted.model_dump_json() == audit.model_dump_json()
    )


def test_postgres_replay_authority_drift_performs_zero_repair(
    replay_harness: ProductPostgresEvaluationHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event, _first, _audit = _commit_pending_reservation(
        replay_harness,
        monkeypatch,
        event_id="evt:product-replay-postgres-policy-drift",
    )
    replay_harness.writer.save_policy_snapshot(
        PolicyBundle(),
        expected_revision=1,
        updated_by="product-replay-postgres-drift",
    )
    before = _persistent_replay_image(replay_harness)
    repair_calls = 0
    original_repair = replay_harness.audit_service.repair_provenance

    def count_repair(audit):
        nonlocal repair_calls
        repair_calls += 1
        return original_repair(audit)

    monkeypatch.setattr(
        replay_harness.audit_service,
        "repair_provenance",
        count_repair,
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        replay_harness.evaluation.evaluate(
            event,
            auth_context=replay_harness.auth_context,
        )

    assert raised.value.code == PRODUCT_POLICY_NOT_CURRENT
    assert repair_calls == 0
    assert _persistent_replay_image(replay_harness) == before


def test_postgres_provenance_failure_rolls_back_replay_state_repair(
    replay_harness: ProductPostgresEvaluationHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event, _first, _audit = _commit_pending_reservation(
        replay_harness,
        monkeypatch,
        event_id="evt:product-replay-postgres-provenance-rollback",
    )
    before = _persistent_replay_image(replay_harness)
    original_repair = replay_harness.audit_service.repair_provenance
    marker = ProvenanceNode(
        node_id="node:product-replay-postgres-rollback-marker",
        trace_id=PRODUCT_REPLAY_TRACE_ID,
        kind="test_marker",
        ref_id=event.event_id,
        label="must roll back with replay state repair",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    observed_repaired_state = False

    def fail_after_provenance_repair(audit):
        nonlocal observed_repaired_state
        original_repair(audit)
        state = replay_harness.store.get_security_state(replay_harness.scope_digest)
        observed_repaired_state = state is not None and state.state_version == 1
        replay_harness.store.add_provenance_node(marker)
        raise RuntimeError("injected Product replay provenance failure")

    monkeypatch.setattr(
        replay_harness.audit_service,
        "repair_provenance",
        fail_after_provenance_repair,
    )

    with pytest.raises(
        RuntimeError,
        match="injected Product replay provenance failure",
    ):
        replay_harness.evaluation.evaluate(
            event,
            auth_context=replay_harness.auth_context,
        )

    assert observed_repaired_state is True
    assert replay_harness.store.get_provenance_node(marker.node_id) is None
    assert _persistent_replay_image(replay_harness) == before
