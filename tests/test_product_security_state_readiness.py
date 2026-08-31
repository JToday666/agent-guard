"""Product strict SecurityState readiness and zero-write contracts."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.authority.models import EvaluationClock
from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    OnlineSecurityState,
    delta_digest_projection,
)
from guard_api.security_state import SecurityStateNotReadyError, SecurityStateService
from guard_api.security_state.rebuild import PREVIOUS_PROJECTOR_VERSION
from guard_api.security_state.snapshot_builder import security_state_authority_digest
from guard_api.storage.base import ProjectionIdentityRecord, SecurityStateRecord
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.test_v21_security_state_models import SCOPE, make_delta, make_scope
from tests.test_v21_security_state_models import make_watermarks
from tests.test_v21_state_projector import make_record

pytestmark = pytest.mark.integration


def _clock() -> EvaluationClock:
    return EvaluationClock(
        evaluated_at="2026-09-01T00:00:00Z",
        clock_version="product-read-ready-test",
    )


def _plan() -> RequiredCheckPlan:
    return RequiredCheckPlan(
        plan_id="product-read-ready:plan",
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
        reason_codes=["product-read-ready:test"],
    )


def _read(service: SecurityStateService):
    return service.read_ready_snapshot_with_revoked(
        SCOPE,
        scope=make_scope(),
        task_fact_head=None,
        evaluation_clock=_clock(),
        policy_revision="7",
        policy_digest="sha256:" + "a" * 64,
        plan=_plan(),
    )


def _seed_ready(store: MemoryControlPlaneStore) -> SecurityStateRecord:
    SecurityStateService(store).ensure_ready(SCOPE)
    record = store.get_security_state(SCOPE)
    assert record is not None
    return record


def _unapplied_projection() -> ProjectionIdentityRecord:
    return ProjectionIdentityRecord(
        scope_digest=SCOPE,
        source_record_type="policy_evaluation",
        source_record_id="audit:unapplied",
        source_revision=1,
        projector_version=PROJECTOR_VERSION,
        delta_digest="sha256:" + "c" * 64,
        delta_payload={"unapplied": True},
        applied_state_version=1,
        created_at="2026-09-01T00:00:00Z",
    )


def _forbid_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("strict ready read attempted a state write")

    monkeypatch.setattr(MemoryControlPlaneStore, "cas_security_state", forbidden)
    monkeypatch.setattr(MemoryControlPlaneStore, "mark_security_state_dirty", forbidden)
    monkeypatch.setattr(MemoryControlPlaneStore, "record_projection", forbidden)


def test_ready_snapshot_is_read_only_and_returns_full_authority_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryControlPlaneStore()
    before = deepcopy(_seed_ready(store))
    service = SecurityStateService(store)
    _forbid_writes(monkeypatch)

    snapshot, revoked, authority_digest = _read(service)

    assert snapshot.state_version == before.state_version == 0
    assert revoked == []
    assert authority_digest.startswith("sha256:")
    assert store.get_security_state(SCOPE) == before


def _authority_digest(record: SecurityStateRecord) -> str:
    return security_state_authority_digest(
        scope_digest=record.scope_digest,
        state_version=record.state_version,
        canonical_payload=record.canonical_payload,
        dirty=record.dirty,
        dirty_domains=record.dirty_domains,
        projector_version=record.projector_version,
    )


def test_same_version_payload_drift_changes_digest_and_is_not_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryControlPlaneStore()
    original = _seed_ready(store)
    first_digest = _read(SecurityStateService(store))[2]
    state = OnlineSecurityState.model_validate(original.canonical_payload).model_copy(
        update={"revoked_grant_ids": ["grant:same-version-drift"]}
    )
    mutated = replace(
        original,
        canonical_payload=state.model_dump(mode="json"),
    )
    store.security_states[SCOPE] = mutated
    state_before = deepcopy(store.get_security_state(SCOPE))
    _forbid_writes(monkeypatch)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(SecurityStateService(store))

    assert _authority_digest(mutated) != first_digest
    assert raised.value.condition == "projection_state_digest_mismatch"
    assert store.get_security_state(SCOPE).state_version == original.state_version  # type: ignore[union-attr]
    assert store.get_security_state(SCOPE) == state_before


def test_current_projection_and_state_are_accepted_together() -> None:
    store = MemoryControlPlaneStore()
    service = SecurityStateService(store)
    result = service.project_committed(make_record(make_delta()), scope_digest=SCOPE)

    snapshot, _revoked, authority_digest = _read(service)

    assert result.state_version == snapshot.state_version == 1
    assert authority_digest.startswith("sha256:")


def test_projection_row_revision_bool_alias_is_not_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryControlPlaneStore()
    service = SecurityStateService(store)
    service.project_committed(make_record(make_delta()), scope_digest=SCOPE)
    projection_key, projection = next(iter(store.projection_records.items()))
    store.projection_records[projection_key] = replace(
        projection,
        source_revision=True,
    )
    state_before = deepcopy(store.get_security_state(SCOPE))
    projections_before = deepcopy(store.projection_records)
    _forbid_writes(monkeypatch)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(service)

    assert raised.value.condition == "projection_envelope_invalid"
    assert store.get_security_state(SCOPE) == state_before
    assert store.projection_records == projections_before


def test_projection_semantic_state_drift_is_not_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryControlPlaneStore()
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
    store.security_states[SCOPE] = replace(
        original,
        canonical_payload=state.model_dump(mode="json"),
    )
    state_before = deepcopy(store.get_security_state(SCOPE))
    _forbid_writes(monkeypatch)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(service)

    assert raised.value.condition == "projection_state_digest_mismatch"
    assert store.get_security_state(SCOPE) == state_before


def test_projection_state_version_inflation_is_not_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryControlPlaneStore()
    service = SecurityStateService(store)
    service.project_committed(make_record(make_delta()), scope_digest=SCOPE)
    original = store.get_security_state(SCOPE)
    assert original is not None
    state = OnlineSecurityState.model_validate(original.canonical_payload).model_copy(
        update={"state_version": original.state_version + 1}
    )
    store.security_states[SCOPE] = replace(
        original,
        state_version=state.state_version,
        canonical_payload=state.model_dump(mode="json"),
    )
    state_before = deepcopy(store.get_security_state(SCOPE))
    _forbid_writes(monkeypatch)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(service)

    assert raised.value.condition == "projection_state_version_mismatch"
    assert store.get_security_state(SCOPE) == state_before


def test_unverifiable_evicted_projection_state_is_not_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryControlPlaneStore()
    service = SecurityStateService(store)
    service.project_committed(make_record(make_delta()), scope_digest=SCOPE)
    original = store.get_security_state(SCOPE)
    assert original is not None
    state = OnlineSecurityState.model_validate(original.canonical_payload).model_copy(
        update={"evicted": True}
    )
    store.security_states[SCOPE] = replace(
        original,
        canonical_payload=state.model_dump(mode="json"),
    )
    _forbid_writes(monkeypatch)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(service)

    assert raised.value.condition == "projection_eviction_unverifiable"


def test_missing_state_fails_without_initialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryControlPlaneStore()
    service = SecurityStateService(store)
    _forbid_writes(monkeypatch)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(service)

    assert raised.value.condition == "missing"
    assert store.get_security_state(SCOPE) is None


def test_missing_state_with_rebuild_input_fails_without_rebuild(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryControlPlaneStore()
    projection = _unapplied_projection()
    store.record_projection(projection)
    before = deepcopy(store.projection_records)
    _forbid_writes(monkeypatch)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(SecurityStateService(store))

    assert raised.value.condition == "missing"
    assert store.get_security_state(SCOPE) is None
    assert store.projection_records == before


def test_clean_state_with_unapplied_projection_is_not_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryControlPlaneStore()
    _seed_ready(store)
    store.record_projection(_unapplied_projection())
    state_before = deepcopy(store.get_security_state(SCOPE))
    projections_before = deepcopy(store.projection_records)
    _forbid_writes(monkeypatch)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(SecurityStateService(store))

    assert raised.value.condition == "projection_unapplied"
    assert store.get_security_state(SCOPE) == state_before
    assert store.projection_records == projections_before


def test_conflicting_previous_projector_alias_is_not_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryControlPlaneStore()
    service = SecurityStateService(store)
    current = make_delta(source_record_id="audit:alias-conflict")
    service.project_committed(make_record(current), scope_digest=SCOPE)

    previous = make_delta(
        source_record_id="audit:alias-conflict",
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
    state_before = deepcopy(store.get_security_state(SCOPE))
    projections_before = deepcopy(store.projection_records)
    _forbid_writes(monkeypatch)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(service)

    assert raised.value.condition == "projection_history_invalid"
    assert store.get_security_state(SCOPE) == state_before
    assert store.projection_records == projections_before


def test_supported_previous_projector_rebuild_is_read_ready() -> None:
    store = MemoryControlPlaneStore()
    previous = make_delta(
        source_record_id="audit:previous-rebuild",
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
    service = SecurityStateService(store)
    rebuilt = service.ensure_ready(SCOPE)

    snapshot, _revoked, authority_digest = _read(service)

    assert snapshot.state_version == rebuilt.state_version == 1
    assert authority_digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("mutate", "condition"),
    [
        (lambda row: replace(row, dirty=True), "dirty"),
        (lambda row: replace(row, dirty_domains=["behavior"]), "dirty"),
        (
            lambda row: replace(row, projector_version="v21-04.projector.stale"),
            "projector_mismatch",
        ),
        (
            lambda row: replace(row, state_version=row.state_version + 1),
            "state_version_mismatch",
        ),
        (lambda row: replace(row, state_version=False), "state_version_invalid"),
        (
            lambda row: replace(
                row,
                canonical_payload={**row.canonical_payload, "unexpected": True},
            ),
            "payload_invalid",
        ),
        (
            lambda row: replace(
                row,
                canonical_payload={
                    key: value
                    for key, value in row.canonical_payload.items()
                    if key != "schema_version"
                },
            ),
            "payload_not_canonical",
        ),
        (
            lambda row: replace(
                row,
                canonical_payload={
                    **row.canonical_payload,
                    "state_version": False,
                },
            ),
            "payload_not_canonical",
        ),
        (lambda row: replace(row, scope_digest="scope:wrong"), "scope_mismatch"),
    ],
)
def test_inconsistent_rows_fail_without_repair(
    monkeypatch: pytest.MonkeyPatch,
    mutate,
    condition: str,
) -> None:
    store = MemoryControlPlaneStore()
    original = _seed_ready(store)
    inconsistent = mutate(original)
    store.security_states[SCOPE] = inconsistent
    before = deepcopy(store.security_states)
    _forbid_writes(monkeypatch)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(SecurityStateService(store))

    assert raised.value.condition == condition
    assert store.security_states == before


def test_payload_dirty_domains_fail_even_when_columns_are_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryControlPlaneStore()
    original = _seed_ready(store)
    state = OnlineSecurityState.model_validate(original.canonical_payload).model_copy(
        update={"dirty_domains": ["behavior"]}
    )
    store.security_states[SCOPE] = replace(
        original,
        dirty=False,
        dirty_domains=[],
        canonical_payload=state.model_dump(mode="json"),
    )
    before = deepcopy(store.security_states)
    _forbid_writes(monkeypatch)

    with pytest.raises(SecurityStateNotReadyError) as raised:
        _read(SecurityStateService(store))

    assert raised.value.condition == "payload_dirty"
    assert store.security_states == before


def test_cross_scope_rejected_before_state_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryControlPlaneStore()
    service = SecurityStateService(store)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("cross-scope input reached storage")

    monkeypatch.setattr(MemoryControlPlaneStore, "get_security_state", forbidden)
    with pytest.raises(ValueError, match="cross-scope snapshot"):
        service.read_ready_snapshot_with_revoked(
            SCOPE,
            scope=make_scope(scope_digest="scope:wrong"),
            task_fact_head=None,
            evaluation_clock=_clock(),
            policy_revision="7",
            policy_digest="sha256:" + "a" * 64,
            plan=_plan(),
        )
