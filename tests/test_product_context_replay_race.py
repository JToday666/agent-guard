"""Product context replay must ignore a concurrent loser's fresh Phase-A plan."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from agentguard_core import (
    ContextBuildPayload,
    ContextSource,
    GuardEvent,
    SecurityContext,
)
from agentguard_core.actions.canonical_json import canonical_sha256

from guard_api.security_state import SecurityStateService
from guard_api.services.context_builder import ContextBuilderService
from guard_api.services.context_manifest import (
    ContextManifestEnvelope,
    context_manifest_anchor_from_policy,
    validate_context_manifest_audit_event,
)
from guard_api.services.ct_projection import CtProjectionService
from guard_api.services.evaluation import EvaluationConflictError
from guard_api.services.v21_pipeline import (
    V21OfficialEvaluationUnavailableError,
)
from tests.support.product_evaluation import (
    PRODUCT_REPLAY_SESSION_ID,
    create_product_evaluation_harness,
)

pytestmark = pytest.mark.integration


def _source(index: int) -> ContextSource:
    content = f"bounded Product context evidence {index}"
    return ContextSource(
        source_id=f"product-context-source-{index:02d}",
        source_type="web",
        source_trust="trusted",
        summary=content,
        contains_instruction_like_text=False,
        contains_sensitive_data=False,
        content_digest=canonical_sha256(content),
        role="user",
        sequence_index=index,
    )


def test_product_context_replay_reconstructs_complete_manifest_without_rebuild(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    context_settings = replace(
        harness.settings,
        context_builder_enabled=True,
        ct_fact_projection_enabled=False,
    )
    state_service = SecurityStateService(harness.store)
    harness.evaluation.ct_projection_service = CtProjectionService(
        settings=context_settings,
        store=harness.store,
        state_service=state_service,
    )
    context_builder = ContextBuilderService(settings=context_settings)
    harness.evaluation.context_builder_service = context_builder
    event = GuardEvent(
        event_id="evt:product-context-replay-complete",
        event_type="context_assembled",
        runtime="langgraph",
        trace_id="trace:product-replay",
        timestamp=datetime.now(timezone.utc).isoformat(),
        pre_execution=True,
        security_context=SecurityContext(
            agent_id="main",
            session_id=PRODUCT_REPLAY_SESSION_ID,
            user_task="verify authority-aware exact Product replay",
        ),
        payload=ContextBuildPayload(sources=[_source(0)]),
        metadata={"task_id": harness.task_id},
    )

    first = harness.evaluation.evaluate(event, auth_context=harness.auth_context)
    assert first.context_plan is not None
    policy_audit = harness.store.get_policy_evaluation_by_event_id(event.event_id)
    assert policy_audit is not None
    anchor = context_manifest_anchor_from_policy(policy_audit)
    assert anchor is not None
    manifest_audit = harness.store.get_audit_event(anchor.audit_id)
    assert manifest_audit is not None
    manifest = validate_context_manifest_audit_event(
        manifest_audit
    ).evidence.context_manifest
    assert isinstance(manifest, ContextManifestEnvelope)
    assert manifest.completeness.status == "complete"
    assert manifest.completeness.truncated is False
    audit_count = len(harness.store.audit_events)

    def fail_if_rebuilt(*_args, **_kwargs):
        raise AssertionError("Product context replay must not rerun Context Builder")

    monkeypatch.setattr(context_builder, "build", fail_if_rebuilt)
    replay = harness.evaluation.evaluate(event, auth_context=harness.auth_context)

    assert replay.context_plan == first.context_plan
    assert replay.model_dump_json() == first.model_dump_json()
    assert len(harness.store.audit_events) == audit_count


def test_concurrent_product_replay_rejects_winner_truncated_manifest(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second-lookup winner must use the Product stored-manifest gate.

    The first lookup is forced to miss an already committed winner, reproducing
    the race where the loser runs Phase A before entering the Product authority
    transaction.  Its freshly rebuilt plan must be discarded: the winner's
    partial manifest cannot prove an exact Product replay.
    """

    harness = create_product_evaluation_harness(tmp_path)
    context_settings = replace(
        harness.settings,
        context_builder_enabled=True,
        # Fact building remains available for the Context Builder, while
        # avoiding a second CT projection that could change the fixture's
        # context facts between winner and loser.
        ct_fact_projection_enabled=False,
    )
    state_service = SecurityStateService(harness.store)
    harness.evaluation.ct_projection_service = CtProjectionService(
        settings=context_settings,
        store=harness.store,
        state_service=state_service,
    )
    harness.evaluation.context_builder_service = ContextBuilderService(
        settings=context_settings
    )

    event = GuardEvent(
        event_id="evt:product-context-replay-race",
        event_type="context_assembled",
        runtime="langgraph",
        trace_id="trace:product-replay",
        timestamp=datetime.now(timezone.utc).isoformat(),
        pre_execution=True,
        security_context=SecurityContext(
            agent_id="main",
            session_id=PRODUCT_REPLAY_SESSION_ID,
            user_task="verify authority-aware exact Product replay",
        ),
        payload=ContextBuildPayload(sources=[_source(index) for index in range(21)]),
        metadata={"task_id": harness.task_id},
    )

    winner = harness.evaluation.evaluate(event, auth_context=harness.auth_context)
    assert winner.context_plan is not None
    policy_audit = harness.store.get_policy_evaluation_by_event_id(event.event_id)
    assert policy_audit is not None
    anchor = context_manifest_anchor_from_policy(policy_audit)
    assert anchor is not None
    manifest_audit = harness.store.get_audit_event(anchor.audit_id)
    assert manifest_audit is not None
    manifest = validate_context_manifest_audit_event(
        manifest_audit
    ).evidence.context_manifest
    assert isinstance(manifest, ContextManifestEnvelope)
    assert manifest.completeness.status == "partial"
    assert manifest.completeness.truncated is True

    persisted_before = deepcopy(
        {
            "audit_events": harness.store.audit_events,
            "provenance_nodes": harness.store.provenance_nodes,
            "provenance_edges": harness.store.provenance_edges,
            "projections": harness.store.projection_records,
            "security_states": harness.store.security_states,
        }
    )
    store_type = type(harness.store)
    original_lookup = store_type.get_policy_evaluation_by_event_id
    lookup_count = 0

    def miss_only_the_initial_lookup(store, event_id: str):
        nonlocal lookup_count
        if store is harness.store:
            lookup_count += 1
            if lookup_count == 1:
                return None
        return original_lookup(store, event_id)

    monkeypatch.setattr(
        store_type,
        "get_policy_evaluation_by_event_id",
        miss_only_the_initial_lookup,
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        harness.evaluation.evaluate(event, auth_context=harness.auth_context)

    assert raised.value.code == "V21_PRODUCT_CONTEXT_REPLAY_UNAVAILABLE"
    assert lookup_count >= 2
    assert {
        "audit_events": harness.store.audit_events,
        "provenance_nodes": harness.store.provenance_nodes,
        "provenance_edges": harness.store.provenance_edges,
        "projections": harness.store.projection_records,
        "security_states": harness.store.security_states,
    } == persisted_before


@pytest.mark.parametrize("manifest_state", ["partial", "missing"])
def test_conflicting_product_replay_precedes_partial_or_missing_manifest_repair(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    manifest_state: str,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    context_settings = replace(
        harness.settings,
        context_builder_enabled=True,
        ct_fact_projection_enabled=False,
    )
    state_service = SecurityStateService(harness.store)
    harness.evaluation.ct_projection_service = CtProjectionService(
        settings=context_settings,
        store=harness.store,
        state_service=state_service,
    )
    harness.evaluation.context_builder_service = ContextBuilderService(
        settings=context_settings
    )
    event = GuardEvent(
        event_id=f"evt:product-context-conflict-{manifest_state}",
        event_type="context_assembled",
        runtime="langgraph",
        trace_id="trace:product-replay",
        timestamp=datetime.now(timezone.utc).isoformat(),
        pre_execution=True,
        security_context=SecurityContext(
            agent_id="main",
            session_id=PRODUCT_REPLAY_SESSION_ID,
            user_task="verify authority-aware exact Product replay",
        ),
        payload=ContextBuildPayload(sources=[_source(index) for index in range(21)]),
        metadata={"task_id": harness.task_id},
    )
    harness.evaluation.evaluate(event, auth_context=harness.auth_context)
    policy_audit = harness.store.get_policy_evaluation_by_event_id(event.event_id)
    assert policy_audit is not None
    anchor = context_manifest_anchor_from_policy(policy_audit)
    assert anchor is not None
    manifest_audit = harness.store.get_audit_event(anchor.audit_id)
    assert manifest_audit is not None
    manifest = validate_context_manifest_audit_event(
        manifest_audit
    ).evidence.context_manifest
    assert isinstance(manifest, ContextManifestEnvelope)
    assert manifest.completeness.status == "partial"
    if manifest_state == "missing":
        harness.store.audit_events_by_id.pop(anchor.audit_id)

    persisted_before = deepcopy(
        {
            "audit_events": harness.store.audit_events,
            "audit_events_by_id": harness.store.audit_events_by_id,
            "provenance_nodes": harness.store.provenance_nodes,
            "provenance_edges": harness.store.provenance_edges,
            "projections": harness.store.projection_records,
            "security_states": harness.store.security_states,
        }
    )
    state_repair_calls = 0
    provenance_repair_calls = 0

    def count_state_repair(*_args, **_kwargs):
        nonlocal state_repair_calls
        state_repair_calls += 1
        raise AssertionError("request conflict must precede Product state repair")

    def count_provenance_repair(_audit):
        nonlocal provenance_repair_calls
        provenance_repair_calls += 1
        raise AssertionError("request conflict must precede provenance repair")

    monkeypatch.setattr(
        harness.pipeline,
        "_repair_product_replay_projection_locked",
        count_state_repair,
    )
    monkeypatch.setattr(
        harness.audit_service,
        "repair_provenance",
        count_provenance_repair,
    )
    conflicting = event.model_copy(
        update={"payload": ContextBuildPayload(sources=[_source(999)])}
    )

    with pytest.raises(EvaluationConflictError):
        harness.evaluation.evaluate(conflicting, auth_context=harness.auth_context)

    assert state_repair_calls == 0
    assert provenance_repair_calls == 0
    assert {
        "audit_events": harness.store.audit_events,
        "audit_events_by_id": harness.store.audit_events_by_id,
        "provenance_nodes": harness.store.provenance_nodes,
        "provenance_edges": harness.store.provenance_edges,
        "projections": harness.store.projection_records,
        "security_states": harness.store.security_states,
    } == persisted_before
