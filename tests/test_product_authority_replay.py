"""Authority-aware exact replay acceptance tests for Product Active mode."""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from agentguard_core import (
    DecisionAuthority,
    DecisionAuthorityEvidenceV1,
    GuardDecision,
    GuardEngine,
    PolicyBundle,
    ProductDecisionAuthorityEvidenceV1,
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
    decision_authority_envelope,
)
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions.evidence import (
    CoverageMap,
    DecisionEvidenceV21,
    DomainCoverage,
    decision_v21_envelope,
)

from guard_api.security_state import SecurityStateService
from guard_api.services import ApprovalService, EvaluationService
from guard_api.services import product_activation as product_activation_service
from guard_api.services.competition import parse_decision_authority_evidence_payload
from guard_api.services.evaluation import canonical_request_dump
from guard_api.services.policy import PolicyService
from guard_api.services.product_activation import RUNTIME_OBSERVATION_MISMATCH
from guard_api.services.runtime_binding import (
    PRODUCT_RUNTIME_IDENTITY_MISMATCH,
    PRODUCT_TASK_IDENTITY_MISMATCH,
    RuntimeBindingResolver,
)
from guard_api.services.v21_pipeline import (
    PRODUCT_AUTHORITY_NOT_CURRENT,
    PRODUCT_CREDENTIAL_NOT_CURRENT,
    PRODUCT_POLICY_NOT_CURRENT,
    V21OfficialEvaluationUnavailableError,
    V21PipelineService,
)
from guard_api.storage.base import TaskFactRecord
from tests.support.product_evaluation import (
    PRODUCT_REPLAY_SESSION_ID,
    ProductEvaluationHarness,
    ProductReplayRuntime,
    create_product_evaluation_harness,
)

pytestmark = pytest.mark.integration


def _persistent_image(harness: ProductEvaluationHarness) -> dict[str, Any]:
    store = harness.store
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
            "security_states": store.security_states,
            "projection_records": store.projection_records,
        }
    )


def _committed_product_evaluation(
    harness: ProductEvaluationHarness,
    *,
    event_id: str = "evt:product-replay",
):
    event = harness.event(event_id=event_id)
    response = harness.evaluation.evaluate(
        event,
        auth_context=harness.auth_context,
    )
    assert response.decision_authority is not None
    assert response.decision_authority.source == "v21"
    assert response.decision_authority.mode == "active"
    assert response.decision_authority.selection_basis == "profile_all"
    audit = harness.store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None and audit.evidence is not None
    raw_authority = audit.evidence.get("decision_authority")
    parsed = parse_decision_authority_evidence_payload(
        {"decision_authority": raw_authority}
    )
    assert isinstance(parsed, ProductDecisionAuthorityEvidenceV1)
    assert parsed.event_id == event.event_id
    assert parsed.decision_authority == response.decision_authority
    assert response.approval_release_directive == (parsed.approval_release_directive)
    return event, response, audit


@pytest.mark.parametrize(
    "runtime_state",
    ["pipeline_none", "activation_missing", "pipeline_nonactive"],
)
def test_historical_product_replay_never_downgrades_to_legacy_without_active_authority(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    runtime_state: str,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    event, _first, _audit = _committed_product_evaluation(
        harness,
        event_id=f"evt:product-replay-{runtime_state}",
    )
    policy_service = PolicyService(store=harness.store)
    pipeline: V21PipelineService | None
    settings = harness.settings
    if runtime_state == "pipeline_none":
        pipeline = None
    else:
        activation = harness.pipeline.product_activation
        assert activation is not None
        if runtime_state == "activation_missing":
            resolver = RuntimeBindingResolver()
        else:
            settings = replace(settings, v21_mode="shadow")
            resolver = RuntimeBindingResolver(product_activation=activation)
        pipeline = V21PipelineService(
            settings=settings,
            store=harness.store,
            state_service=SecurityStateService(harness.store),
            policy_service=policy_service,
            runtime_binding_resolver=resolver,
        )
    evaluation = EvaluationService(
        policy_service=policy_service,
        audit_service=harness.audit_service,
        approval_service=ApprovalService(store=harness.store, settings=settings),
        v21_pipeline=pipeline,
    )
    before = _persistent_image(harness)
    monkeypatch.setattr(
        harness.audit_service,
        "repair_provenance",
        lambda _audit: pytest.fail("legacy provenance repair must not run"),
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        evaluation.evaluate(event, auth_context=harness.auth_context)

    assert raised.value.code == "V21_PRODUCT_REPLAY_UNAVAILABLE"
    assert _persistent_image(harness) == before


def test_product_replay_recaptures_authority_before_provenance_repair_without_reassess(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    assessment_calls = 0
    original_assess = GuardEngine.evaluate_with_results
    original_phase_c = harness.pipeline.run_phase_c

    def count_assessment(self, event, bundle=None):
        nonlocal assessment_calls
        assessment_calls += 1
        return original_assess(self, event, bundle)

    monkeypatch.setattr(GuardEngine, "evaluate_with_results", count_assessment)
    monkeypatch.setattr(harness.pipeline, "run_phase_c", lambda _plan: None)
    event, first, _audit = _committed_product_evaluation(harness)
    assert assessment_calls == 1
    pending = harness.store.get_security_state(harness.scope_digest)
    assert pending is not None and pending.state_version == 0
    monkeypatch.setattr(harness.pipeline, "run_phase_c", original_phase_c)

    order: list[str] = []
    original_reconcile = (
        product_activation_service.reconcile_product_runtime_observations
    )
    original_state_repair = harness.pipeline._repair_product_replay_projection_locked
    original_repair = harness.audit_service.repair_provenance

    def observed_reconcile(*args, **kwargs):
        order.append("authority")
        return original_reconcile(*args, **kwargs)

    def observed_state_repair(audit, *, evidence, scope_digest):
        order.append("state_repair")
        return original_state_repair(
            audit,
            evidence=evidence,
            scope_digest=scope_digest,
        )

    def observed_repair(audit):
        order.append("provenance")
        return original_repair(audit)

    monkeypatch.setattr(
        product_activation_service,
        "reconcile_product_runtime_observations",
        observed_reconcile,
    )
    monkeypatch.setattr(
        harness.pipeline,
        "_repair_product_replay_projection_locked",
        observed_state_repair,
    )
    monkeypatch.setattr(harness.audit_service, "repair_provenance", observed_repair)

    replay = harness.evaluation.evaluate(
        event,
        auth_context=harness.auth_context,
    )

    assert assessment_calls == 1
    assert order == ["authority", "state_repair", "authority", "provenance"]
    assert replay.model_dump(mode="json") == first.model_dump(mode="json")


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_product_replay_is_byte_exact_and_storage_idempotent(
    tmp_path,
    runtime: ProductReplayRuntime,
) -> None:
    harness = create_product_evaluation_harness(tmp_path, runtime=runtime)
    event, first, audit = _committed_product_evaluation(
        harness,
        event_id=f"evt:product-replay-byte-exact:{runtime}",
    )
    response_bytes = first.model_dump_json()
    audit_bytes = audit.model_dump_json()
    persistent_image = deepcopy(
        {
            "approvals": harness.store.approvals,
            "bindings": harness.store.enforcement_bindings,
            "memory_changes": harness.store.memory_changes,
            "critic_reviews": harness.store.action_critic_reviews,
            "projections": harness.store.projection_records,
            "security_states": harness.store.security_states,
            "provenance_nodes": harness.store.provenance_nodes,
            "provenance_edges": harness.store.provenance_edges,
        }
    )
    audit_count = len(harness.store.audit_events)

    for _ in range(2):
        replay = harness.evaluation.evaluate(
            event,
            auth_context=harness.auth_context,
        )
        persisted = harness.store.get_policy_evaluation_by_event_id(event.event_id)
        assert persisted is not None
        assert replay.model_dump_json() == response_bytes
        assert persisted.model_dump_json() == audit_bytes

    assert len(harness.store.audit_events) == audit_count
    assert {
        "approvals": harness.store.approvals,
        "bindings": harness.store.enforcement_bindings,
        "memory_changes": harness.store.memory_changes,
        "critic_reviews": harness.store.action_critic_reviews,
        "projections": harness.store.projection_records,
        "security_states": harness.store.security_states,
        "provenance_nodes": harness.store.provenance_nodes,
        "provenance_edges": harness.store.provenance_edges,
    } == persistent_image


def test_openclaw_replay_preserves_restricted_ask_carrier_without_reassessment(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = create_product_evaluation_harness(tmp_path, runtime="openclaw")
    event = harness.event(
        event_id="evt:product-replay-openclaw-restricted-ask",
        call_id="call:product-replay-openclaw-restricted-ask",
    ).model_copy(
        update={
            "security_context": SecurityContext(
                agent_id="main",
                user_task=(
                    "Summarize the quarterly results already present in the "
                    "conversation."
                ),
                session_id=PRODUCT_REPLAY_SESSION_ID,
            ),
            "payload": ToolCallPayload(
                tool=ToolDescriptor(
                    name="read_file",
                    call_id="call:product-replay-openclaw-restricted-ask",
                ),
                arguments={"path": "/docs/quarterly-results.txt"},
                derived_resources=[],
            ),
        }
    )
    original_assess = GuardEngine.evaluate_with_results

    def force_current_ask(self, candidate, bundle=None):
        decision, detections = original_assess(self, candidate, bundle)
        return (
            decision.model_copy(
                update={
                    "decision_id": "dec:forced-current:openclaw-replay-ask",
                    "decision": "ask",
                    "risk_score": 50,
                    "severity": "medium",
                    "categories": ["forced-current:ask"],
                    "rule_hits": [],
                    "reason": "force a restricted ASK carrier for exact replay",
                    "approval_intent": None,
                }
            ),
            detections,
        )

    monkeypatch.setattr(GuardEngine, "evaluate_with_results", force_current_ask)
    first = harness.evaluation.evaluate(event, auth_context=harness.auth_context)
    audit = harness.store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None and audit.evidence is not None
    evidence = parse_decision_authority_evidence_payload(
        {"decision_authority": audit.evidence["decision_authority"]}
    )
    assert isinstance(evidence, ProductDecisionAuthorityEvidenceV1)
    assert evidence.raw_v21_decision.decision == "allow"
    assert first.decision.decision == "ask"
    assert first.approval is not None
    assert first.approval_release_directive is not None
    assert first.approval_release_directive.mode == "restricted_allow_once"
    assert first.enforcement_binding is None
    approval_before = harness.store.get_approval(first.approval.approval_id)
    assert approval_before is not None

    def fail_if_reassessed(*_args, **_kwargs):
        raise AssertionError("Product replay must not reassess")

    monkeypatch.setattr(GuardEngine, "evaluate_with_results", fail_if_reassessed)
    replay = harness.evaluation.evaluate(event, auth_context=harness.auth_context)

    assert replay.model_dump_json() == first.model_dump_json()
    assert harness.store.get_approval(first.approval.approval_id) == approval_before
    assert harness.store.enforcement_bindings == {}


def test_product_replay_recovers_pending_reservation_without_reassessment(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    original_phase_c = harness.pipeline.run_phase_c
    assessment_calls = 0
    original_assess = GuardEngine.evaluate_with_results

    def count_assessment(self, event, bundle=None):
        nonlocal assessment_calls
        assessment_calls += 1
        return original_assess(self, event, bundle)

    monkeypatch.setattr(GuardEngine, "evaluate_with_results", count_assessment)
    monkeypatch.setattr(harness.pipeline, "run_phase_c", lambda _plan: None)
    event, first, audit = _committed_product_evaluation(
        harness,
        event_id="evt:product-replay-pending-reservation",
    )
    pending = harness.store.get_security_state(harness.scope_digest)
    assert pending is not None and pending.state_version == 0
    assert len(harness.store.projection_records) == 1
    assert assessment_calls == 1

    monkeypatch.setattr(harness.pipeline, "run_phase_c", original_phase_c)
    replay = harness.evaluation.evaluate(
        event,
        auth_context=harness.auth_context,
    )

    recovered = harness.store.get_security_state(harness.scope_digest)
    persisted = harness.store.get_policy_evaluation_by_event_id(event.event_id)
    assert assessment_calls == 1
    assert recovered is not None and recovered.state_version == 1
    assert len(harness.store.projection_records) == 1
    assert replay.model_dump_json() == first.model_dump_json()
    assert (
        persisted is not None and persisted.model_dump_json() == audit.model_dump_json()
    )


@pytest.mark.parametrize(
    ("authority_drift", "expected_code"),
    [
        ("policy", PRODUCT_POLICY_NOT_CURRENT),
        ("credential", PRODUCT_CREDENTIAL_NOT_CURRENT),
    ],
)
def test_product_replay_authority_drift_performs_zero_repair_or_d9_backfill(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    authority_drift: str,
    expected_code: str,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    monkeypatch.setattr(harness.pipeline, "run_phase_c", lambda _plan: None)
    event, _first, _audit = _committed_product_evaluation(
        harness,
        event_id="evt:product-replay-authority-drift",
    )
    pending = harness.store.get_security_state(harness.scope_digest)
    assert pending is not None and pending.state_version == 0

    if authority_drift == "policy":
        harness.store.save_policy_snapshot(
            PolicyBundle(),
            expected_revision=1,
            updated_by="replay-authority-drift",
        )
    else:
        assert harness.auth_context.credential_id is not None
        harness.store.revoke_credential(
            harness.auth_context.credential_id,
            datetime.now(timezone.utc).isoformat(),
        )
    repair_calls = 0
    state_repair_calls = 0
    backfill_calls = 0
    original_repair = harness.audit_service.repair_provenance
    original_backfill = harness.pipeline.backfill_projection

    def count_repair(audit):
        nonlocal repair_calls
        repair_calls += 1
        return original_repair(audit)

    def count_state_repair(*args, **kwargs):
        nonlocal state_repair_calls
        state_repair_calls += 1
        raise AssertionError("authority drift must precede Product state repair")

    def count_backfill(audit):
        nonlocal backfill_calls
        backfill_calls += 1
        return original_backfill(audit)

    monkeypatch.setattr(harness.audit_service, "repair_provenance", count_repair)
    monkeypatch.setattr(
        harness.pipeline,
        "_repair_product_replay_projection_locked",
        count_state_repair,
    )
    monkeypatch.setattr(harness.pipeline, "backfill_projection", count_backfill)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        harness.evaluation.evaluate(event, auth_context=harness.auth_context)

    assert raised.value.code == expected_code
    assert state_repair_calls == 0
    assert repair_calls == 0
    assert backfill_calls == 0
    still_pending = harness.store.get_security_state(harness.scope_digest)
    assert still_pending is not None and still_pending.state_version == 0


def test_product_replay_accepts_heartbeat_refresh_but_rejects_inventory_drift(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    event, first, _audit = _committed_product_evaluation(
        harness,
        event_id="evt:product-replay-runtime-observation",
    )
    entry = harness.fixture.bundle.runtime_entry("langgraph")
    current = harness.store.get_product_runtime_status(
        harness.store.list_product_runtime_statuses(runtime="langgraph")[0].identity()
    )
    assert current is not None
    heartbeat = datetime.fromisoformat(current.last_heartbeat_at.replace("Z", "+00:00"))
    refreshed = current.model_copy(
        update={"last_heartbeat_at": (heartbeat + timedelta(seconds=30)).isoformat()}
    )
    harness.store.save_product_runtime_status(refreshed)

    replay = harness.evaluation.evaluate(
        event,
        auth_context=harness.auth_context,
    )
    assert replay.model_dump_json() == first.model_dump_json()

    repair_calls = 0
    original_repair = harness.audit_service.repair_provenance

    def count_repair(audit):
        nonlocal repair_calls
        repair_calls += 1
        return original_repair(audit)

    monkeypatch.setattr(harness.audit_service, "repair_provenance", count_repair)
    drifted = refreshed.model_copy(
        update={"tool_inventory_digest": "sha256:" + "9" * 64}
    )
    assert drifted.tool_inventory_digest != entry.tool_inventory_digest
    harness.store.save_product_runtime_status(drifted)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        harness.evaluation.evaluate(event, auth_context=harness.auth_context)

    assert raised.value.code == RUNTIME_OBSERVATION_MISMATCH
    assert repair_calls == 0


@pytest.mark.parametrize(
    ("drift", "expected_code"),
    [
        ("task_fact", PRODUCT_TASK_IDENTITY_MISMATCH),
        ("runtime_binding", PRODUCT_RUNTIME_IDENTITY_MISMATCH),
    ],
)
def test_late_product_replay_authority_drift_precedes_all_repair(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
    expected_code: str,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    event, _first, _audit = _committed_product_evaluation(
        harness,
        event_id=f"evt:product-replay-late-{drift}",
    )
    persistent_before = deepcopy(
        {
            "security_states": harness.store.security_states,
            "projections": harness.store.projection_records,
            "provenance_nodes": harness.store.provenance_nodes,
            "provenance_edges": harness.store.provenance_edges,
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
    original_transaction = harness.pipeline.authority_transaction
    drift_injected = False

    @contextmanager
    def inject_drift_before_authority_transaction(candidate, materials):
        nonlocal drift_injected
        assert drift_injected is False
        drift_injected = True
        if drift == "task_fact":
            current = harness.store.get_task_fact(harness.task_id)
            assert current is not None
            advanced = current.task_fact.model_copy(
                update={
                    "revision": current.task_fact.revision + 1,
                    "status": "cancelled",
                }
            )
            harness.store.create_task_fact(
                TaskFactRecord(
                    task_fact=advanced,
                    canonical_payload=advanced.model_dump(mode="json"),
                    request_digest="sha256:" + "e" * 64,
                    expected_revision=current.task_fact.revision,
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
            )
        else:
            assert materials.auth_context is not None
            materials.auth_context.agent_id = "drifted-after-phase-a"
        with original_transaction(candidate, materials):
            yield

    monkeypatch.setattr(
        harness.pipeline,
        "authority_transaction",
        inject_drift_before_authority_transaction,
    )
    state_repair_calls = 0
    provenance_repair_calls = 0

    def count_state_repair(*_args, **_kwargs):
        nonlocal state_repair_calls
        state_repair_calls += 1
        raise AssertionError("late authority drift must precede state repair")

    def count_provenance_repair(_audit):
        nonlocal provenance_repair_calls
        provenance_repair_calls += 1
        raise AssertionError("late authority drift must precede provenance repair")

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

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        harness.evaluation.evaluate(event, auth_context=harness.auth_context)

    assert raised.value.code == expected_code
    assert drift_injected is True
    assert lookup_count >= 2
    assert state_repair_calls == 0
    assert provenance_repair_calls == 0
    assert {
        "security_states": harness.store.security_states,
        "projections": harness.store.projection_records,
        "provenance_nodes": harness.store.provenance_nodes,
        "provenance_edges": harness.store.provenance_edges,
    } == persistent_before


@pytest.mark.parametrize("historical_authority", ["current", "competition"])
def test_product_replay_rejects_non_product_historical_audit_before_repair(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    historical_authority: str,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    event = harness.event(event_id=f"evt:product-replay-old-{historical_authority}")
    bundle = PolicyBundle()
    decision = GuardEngine().evaluate(event, bundle)
    request_digest = canonical_sha256(canonical_request_dump(event))
    keyword_args: dict[str, Any] = {}
    if historical_authority == "competition":
        authority = DecisionAuthority(
            source="v21",
            mode="active",
            selection_basis="profile_all",
            matched_path_ids=[],
            legacy_floor_applied=False,
            activation_ref_digest="sha256:" + "a" * 64,
            approval_release="not_applicable",
        )
        authority_evidence = DecisionAuthorityEvidenceV1(
            event_id=event.event_id,
            assessment_id="asm:old-competition",
            assessment_digest="sha256:" + "1" * 64,
            snapshot_id="snapshot:old-competition",
            snapshot_digest="sha256:" + "2" * 64,
            state_version=0,
            policy_digest=canonical_sha256(bundle.model_dump(mode="json")),
            dataset_digest="sha256:" + "3" * 64,
            profile_digest="sha256:" + "4" * 64,
            current_decision=decision,
            current_decision_digest=canonical_sha256(decision.model_dump(mode="json")),
            raw_v21_decision=decision,
            raw_v21_decision_digest=canonical_sha256(decision.model_dump(mode="json")),
            selected_decision=decision,
            selected_decision_digest=canonical_sha256(decision.model_dump(mode="json")),
            decision_authority=authority,
        )
        decision_evidence = _old_competition_decision_evidence(decision)
        keyword_args = {
            "v21_evidence": decision_v21_envelope(
                decision_evidence.model_dump(mode="json")
            ),
            "decision_authority_evidence": decision_authority_envelope(
                authority_evidence
            ),
            "decision_authority": authority,
        }
    harness.audit_service.record_evaluation(
        event,
        decision,
        policy_bundle=bundle,
        policy_revision=1,
        extra_metadata={
            "request_digest": request_digest,
            "policy_digest": canonical_sha256(bundle.model_dump(mode="json")),
        },
        **keyword_args,
    )
    repair_calls = 0
    original_repair = harness.audit_service.repair_provenance

    def count_repair(audit):
        nonlocal repair_calls
        repair_calls += 1
        return original_repair(audit)

    monkeypatch.setattr(harness.audit_service, "repair_provenance", count_repair)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        harness.evaluation.evaluate(event, auth_context=harness.auth_context)

    assert raised.value.code == PRODUCT_AUTHORITY_NOT_CURRENT
    assert repair_calls == 0


def _old_competition_decision_evidence(
    decision: GuardDecision,
) -> DecisionEvidenceV21:
    domains: dict[str, DomainCoverage] = {}
    for domain in (
        "task",
        "source",
        "capability",
        "behavior",
        "dataflow",
        "memory",
        "runtime_outcome",
    ):
        domains[domain] = DomainCoverage(
            domain=domain,  # type: ignore[arg-type]
            status="complete",
            as_of_sequence=None,
            projector_version="old-competition-replay-test",
            reason_codes=[],
        )
    return DecisionEvidenceV21(
        assessment_id="asm:old-competition",
        assessment_digest="sha256:" + "1" * 64,
        snapshot_id="snapshot:old-competition",
        snapshot_digest="sha256:" + "2" * 64,
        state_version=0,
        required_domains=[],
        coverage=CoverageMap.model_validate(domains),
        authority_status="authorized",
        matched_grant_ids=[],
        flow_status="safe",
        flow_path_refs=[],
        policy_violation_ids=[],
        signal_ids=[],
        degradation_ids=[],
        semantic_judgment_id=None,
        semantic_digest=None,
        legacy_decision=decision.decision,
        v21_fast_disposition={
            "allow": "CLEAR_ALLOW",
            "ask": "DEFER",
            "deny": "CLEAR_DENY",
        }[
            decision.decision
        ],  # type: ignore[arg-type]
        final_decision=decision.decision,
        mode="active",
        divergence_category=None,
        evidence_refs=[],
    )
