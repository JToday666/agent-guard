"""PostgreSQL parity for Product strict SecurityState reads."""

from __future__ import annotations

from dataclasses import replace

import pytest

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.authority.models import EvaluationClock
from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    OnlineSecurityState,
    StateWatermarks,
    delta_digest_projection,
)
from guard_api.security_state import SecurityStateNotReadyError, SecurityStateService
from guard_api.security_state.rebuild import PREVIOUS_PROJECTOR_VERSION
from guard_api.storage.base import ProjectionIdentityRecord, SecurityStateRecord
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import get_test_database_url, reset_control_plane_schema
from tests.test_v21_security_state_models import (
    SCOPE,
    make_delta,
    make_scope,
    make_watermarks,
)
from tests.test_v21_state_projector import make_record

pytestmark = pytest.mark.postgres


@pytest.fixture
def store() -> PostgresControlPlaneStore:
    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    result = PostgresControlPlaneStore(database_url)
    result.initialize()
    return result


def _state() -> OnlineSecurityState:
    return OnlineSecurityState(
        watermarks=StateWatermarks(
            committed_sequence=None,
            projected_sequence=None,
            runtime_receipt_sequence=None,
            memory_sequence=None,
            gaps=[],
        )
    )


def _record(state: OnlineSecurityState | None = None) -> SecurityStateRecord:
    value = state or _state()
    return SecurityStateRecord(
        scope_digest=SCOPE,
        state_version=value.state_version,
        canonical_payload=value.model_dump(mode="json"),
        dirty=False,
        dirty_domains=[],
        projector_version=PROJECTOR_VERSION,
        updated_at="2026-09-01T00:00:00+00:00",
    )


def _read(store: PostgresControlPlaneStore):
    return SecurityStateService(store).read_ready_snapshot_with_revoked(
        SCOPE,
        scope=make_scope(),
        task_fact_head=None,
        evaluation_clock=EvaluationClock(
            evaluated_at="2026-09-01T00:00:00Z",
            clock_version="product-read-ready-postgres",
        ),
        policy_revision="8",
        policy_digest="sha256:" + "b" * 64,
        plan=RequiredCheckPlan(
            plan_id="product-read-ready:postgres",
            impact="high",
            required_domains=["task", "behavior"],
            optional_domains=[
                "source",
                "capability",
                "dataflow",
                "memory",
                "runtime_outcome",
            ],
            required_capabilities=[],
            semantic_resolvable_dimensions=[],
            reason_codes=["product-read-ready:postgres"],
        ),
    )


def test_postgres_ready_read_is_zero_write(
    store: PostgresControlPlaneStore,
) -> None:
    assert store.cas_security_state(SCOPE, 0, _record())
    before = store.get_security_state(SCOPE)

    snapshot, revoked, authority_digest = _read(store)

    assert snapshot.state_version == 0
    assert revoked == []
    assert authority_digest.startswith("sha256:")
    assert store.get_security_state(SCOPE) == before


def test_postgres_missing_read_does_not_initialize(
    store: PostgresControlPlaneStore,
) -> None:
    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(store)

    assert raised.value.condition == "missing"
    assert store.get_security_state(SCOPE) is None


def test_postgres_dirty_read_does_not_rebuild(
    store: PostgresControlPlaneStore,
) -> None:
    assert store.cas_security_state(SCOPE, 0, _record())
    store.mark_security_state_dirty(SCOPE, ["behavior"])
    before = store.get_security_state(SCOPE)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(store)

    assert raised.value.condition == "dirty"
    assert store.get_security_state(SCOPE) == before


def test_postgres_row_payload_mismatch_does_not_repair(
    store: PostgresControlPlaneStore,
) -> None:
    inconsistent = replace(_record(), state_version=1)
    assert store.cas_security_state(SCOPE, 0, inconsistent)
    before = store.get_security_state(SCOPE)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(store)

    assert raised.value.condition == "state_version_mismatch"
    assert store.get_security_state(SCOPE) == before


def test_postgres_clean_state_with_unapplied_projection_is_not_ready(
    store: PostgresControlPlaneStore,
) -> None:
    assert store.cas_security_state(SCOPE, 0, _record())
    projection = ProjectionIdentityRecord(
        scope_digest=SCOPE,
        source_record_type="policy_evaluation",
        source_record_id="audit:postgres-unapplied",
        source_revision=1,
        projector_version=PROJECTOR_VERSION,
        delta_digest="sha256:" + "d" * 64,
        delta_payload={"unapplied": True},
        applied_state_version=1,
        created_at="2026-09-01T00:00:00Z",
    )
    store.record_projection(projection)
    state_before = store.get_security_state(SCOPE)
    projections_before = store.list_rebuild_inputs(SCOPE, limit=10)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(store)

    assert raised.value.condition == "projection_unapplied"
    assert store.get_security_state(SCOPE) == state_before
    assert store.list_rebuild_inputs(SCOPE, limit=10) == projections_before


def test_postgres_conflicting_previous_projector_alias_is_not_ready(
    store: PostgresControlPlaneStore,
) -> None:
    service = SecurityStateService(store)
    current = make_delta(source_record_id="audit:postgres-alias-conflict")
    service.project_committed(make_record(current), scope_digest=SCOPE)

    previous = make_delta(
        source_record_id="audit:postgres-alias-conflict",
        projected_value=999,
    ).model_copy(update={"projector_version": PREVIOUS_PROJECTOR_VERSION})
    previous = previous.model_copy(
        update={"delta_digest": canonical_sha256(delta_digest_projection(previous))}
    )
    store.record_projection(
        ProjectionIdentityRecord(
            scope_digest=SCOPE,
            source_record_type=previous.source.source_record_type,
            source_record_id=previous.source.source_record_id,
            source_revision=previous.source.source_revision,
            projector_version=PREVIOUS_PROJECTOR_VERSION,
            delta_digest=previous.delta_digest,
            delta_payload=previous.model_dump(mode="json"),
            applied_state_version=previous.new_state_version,
            created_at="2026-09-01T00:00:00Z",
        )
    )
    state_before = store.get_security_state(SCOPE)
    projections_before = store.list_rebuild_inputs(SCOPE, limit=10)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(store)

    assert raised.value.condition == "projection_history_invalid"
    assert store.get_security_state(SCOPE) == state_before
    assert store.list_rebuild_inputs(SCOPE, limit=10) == projections_before


def test_postgres_projection_semantic_state_drift_is_not_ready(
    store: PostgresControlPlaneStore,
) -> None:
    service = SecurityStateService(store)
    service.project_committed(
        make_record(make_delta(projected_value=7)),
        scope_digest=SCOPE,
    )
    original = store.get_security_state(SCOPE)
    assert original is not None
    state = OnlineSecurityState.model_validate(original.canonical_payload).model_copy(
        update={"watermarks": make_watermarks()}
    )
    mutated = replace(
        original,
        canonical_payload=state.model_dump(mode="json"),
    )
    assert store.cas_security_state(SCOPE, original.state_version, mutated)
    state_before = store.get_security_state(SCOPE)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(store)

    assert raised.value.condition == "projection_state_digest_mismatch"
    assert store.get_security_state(SCOPE) == state_before
