"""Gate A Core current-event overlay contract tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentguard_core.actions.models import ActionEffect
from agentguard_core.decisions.shadow import shadow_assess_with_coverage
from agentguard_core.events.contracts import GuardEvent
from agentguard_core.events.payloads import (
    ModelCallPayload,
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
)
from agentguard_core.policies.models import PolicyBundle
from agentguard_core.security_context import (
    AssessmentOverlayError,
    AssessmentTransientFacts,
    build_assessment_overlay,
    compute_overlay_digest,
)
from agentguard_core.security_context import assessment_overlay as overlay_module
from agentguard_core.security_context.facts import (
    FlowFact,
    RecentActionFact,
    SourceFact,
)
from agentguard_core.signals.models import EvaluationDegradation
from guard_api.security_state.transient import (
    TransientSecurityFacts,
    compute_overlay_digest as compute_api_overlay_digest,
)
from tests.test_v21_08_shadow_assessment import _snapshot

SERVER_SECRET = b"gate-a-core-overlay-test-secret"
SCOPE = "sha256:" + "0" * 64


def _event() -> GuardEvent:
    return GuardEvent(
        event_id="evt-gate-a-current",
        event_type="tool_call_proposed",
        runtime="langgraph",
        trace_id="trace-1",
        timestamp="2026-08-16T00:00:00+00:00",
        security_context=SecurityContext(agent_id="agent-1"),
        payload=ToolCallPayload(
            tool=ToolDescriptor(name="bash", call_id="call-current"),
            arguments={"command": "true"},
        ),
        metadata={},
    )


def _model_input_event(source_id: str) -> GuardEvent:
    return GuardEvent(
        event_id="evt-gate-a-model-input",
        event_type="model_input_prepared",
        runtime="langgraph",
        trace_id="trace-1",
        timestamp="2026-08-16T00:00:00+00:00",
        security_context=SecurityContext(
            agent_id="agent-1",
            visible_source_refs=(source_id,),
        ),
        payload=ModelCallPayload(
            phase="input",
            content_preview="trusted model input",
            provider="competition-provider",
            model="competition-model",
            context_plan_id="plan-1",
            context_plan_digest="sha256:" + "3" * 64,
            context_ref="context:evt-gate-a-context",
            visible_source_refs=(source_id,),
        ),
        metadata={},
    )


def _source() -> SourceFact:
    return SourceFact(
        source_id="tool_result:binding-1:call-prior",
        scope_digest=SCOPE,
        source_type="tool_result",
        trust="untrusted",
        verification_state="verified",
        origin="observed",
        authority="authoritative",
        producer="guard_api.ct_fact_builder",
        taints=["UNTRUSTED"],
        first_sequence=None,
        last_sequence=None,
        evidence_refs=[],
    )


def _flow(
    flow_id: str,
    *,
    source_ref: str,
    target_ref: str,
    relation: str,
    taints: list[str],
    strength: str = "possible",
) -> FlowFact:
    return FlowFact(
        flow_id=flow_id,
        scope_digest=SCOPE,
        source_ref=source_ref,
        target_ref=target_ref,
        relation=relation,  # type: ignore[arg-type]
        taints=taints,  # type: ignore[arg-type]
        strength=strength,  # type: ignore[arg-type]
        origin="semantic_inferred" if strength == "possible" else "deterministic",
        sequence=None,
        producer="guard_api.ct_fact_builder",
        evidence_refs=[],
    )


def _current_action(*, data_refs: list[str]) -> RecentActionFact:
    return RecentActionFact(
        action_id="call-current",
        event_id="evt-gate-a-current",
        agent_id="agent-1",
        branch_id=None,
        parent_event_ids=[],
        runtime_sequence=None,
        action_type="tool_call",
        impact="high",
        effects=ActionEffect(
            code_execution=True,
            mutates_state=True,
            privilege_use=True,
            reversible=False,
        ),
        resource_ids=[],
        destination_ids=[],
        data_refs=data_refs,
        authority_status="unknown",
        final_decision=None,
        evidence_refs=[],
    )


def test_api_and_core_overlay_digest_are_identical_and_tamper_evident() -> None:
    api = TransientSecurityFacts(event_id="evt", scope_digest=SCOPE)
    api = api.model_copy(update={"overlay_digest": compute_api_overlay_digest(api)})

    core = AssessmentTransientFacts.model_validate(api.model_dump(mode="json"))
    assert core.overlay_digest == api.overlay_digest
    assert compute_overlay_digest(core) == api.overlay_digest

    tampered = api.model_dump(mode="json")
    tampered["event_id"] = "evt-tampered"
    with pytest.raises(ValidationError, match="overlay_digest mismatch"):
        AssessmentTransientFacts.model_validate(tampered)


def test_shadow_rechecks_digest_after_nested_overlay_mutation() -> None:
    transient = AssessmentTransientFacts.from_primitives(
        event_id=_event().event_id,
        scope_digest=SCOPE,
        current_action=_current_action(data_refs=[]),
    )
    assert transient.current_action is not None
    transient.current_action.data_refs.append("forged-after-validation")

    outcome = shadow_assess_with_coverage(
        _event(),
        PolicyBundle(),
        _snapshot(),
        server_secret=SERVER_SECRET,
        transient_facts=transient,
    )

    assert outcome.assessment.disposition == "DEFER"
    assert any(
        degradation.component_id == "v21-08-shadow"
        for degradation in outcome.assessment.degradations
    )
    assert outcome.consumed_overlay_digest is None


def test_any_fact_builder_degradation_is_promoted_to_required_defer() -> None:
    producer_gap = EvaluationDegradation(
        degradation_id="degradation:evt-gate-a-current:ct-fact:handler_failed",
        component_id="guard_api.ct_fact_builder",
        domain="dataflow",
        required_for_action=False,
        failure_kind="invalid_output",
        reason_codes=["ct-fact:handler_failed"],
        evidence_refs=[],
    )
    transient = AssessmentTransientFacts.from_primitives(
        event_id=_event().event_id,
        scope_digest=SCOPE,
        current_action=_current_action(data_refs=[]),
        degradations=[producer_gap],
    )

    outcome = shadow_assess_with_coverage(
        _event(),
        PolicyBundle(),
        _snapshot(),
        server_secret=SERVER_SECRET,
        transient_facts=transient,
    )

    assert outcome.consumed_overlay_digest == transient.overlay_digest
    assert outcome.coverage.dataflow.status == "unknown"
    assert outcome.assessment.disposition == "DEFER"
    assert any(
        degradation.required_for_action
        and "ct-fact:handler_failed" in degradation.reason_codes
        for degradation in outcome.assessment.degradations
    )


def test_shadow_overlay_generates_b2_medium_signal_without_persisting_action() -> None:
    source = _source()
    snapshot = _snapshot().model_copy(
        update={
            "sources": [source],
            "flows": [
                _flow(
                    "flow-prior",
                    source_ref="action:call-prior",
                    target_ref=source.source_id,
                    relation="returned_by",
                    taints=[],
                    strength="exact",
                )
            ],
        }
    )
    transient = AssessmentTransientFacts.from_primitives(
        event_id=_event().event_id,
        scope_digest=SCOPE,
        flow_facts=[
            _flow(
                "flow-current-influence",
                source_ref=source.source_id,
                target_ref="action:call-current",
                relation="influenced_by",
                taints=["UNTRUSTED"],
            )
        ],
        current_action=_current_action(data_refs=[source.source_id]),
    )

    outcome = shadow_assess_with_coverage(
        _event(),
        PolicyBundle(),
        snapshot,
        server_secret=SERVER_SECRET,
        transient_facts=transient,
    )

    b2 = [
        signal
        for signal in outcome.assessment.signals
        if signal.category == "behavior:B2"
    ]
    assert len(b2) == 1
    assert outcome.consumed_overlay_digest == transient.overlay_digest
    assert b2[0].confidence == "medium"
    assert "v21-07:signal-only-no-standalone-deny" in b2[0].tags
    assert outcome.assessment.disposition == "DEFER"
    assert (
        "v21-08:behavior_rule:BEHAVIOR-ANOMALY-DEFAULT"
        in outcome.assessment.reason_codes
    )
    assert snapshot.recent_actions == []
    assert snapshot.flows == [snapshot.flows[0]]

    # The pure overlay exposes current_action only in the returned view.
    base_state = __import__(
        "agentguard_core.decisions.shadow", fromlist=["_state_from_snapshot"]
    )._state_from_snapshot(snapshot, revoked_grant_ids=())
    overlay = build_assessment_overlay(
        base_state,
        transient,
        target_refs=("action:call-current",),
    )
    assert [action.action_id for action in overlay.state.recent_actions] == [
        "call-current"
    ]
    assert base_state.recent_actions == []


def test_missing_visible_set_forces_required_defer_and_dataflow_unknown() -> None:
    app_degradation = EvaluationDegradation(
        degradation_id="degradation:evt-gate-a-current:visible",
        component_id="guard_api.ct_fact_builder",
        domain="dataflow",
        required_for_action=False,
        failure_kind="unavailable",
        reason_codes=["ct-fact:visible_set_unavailable"],
        evidence_refs=[],
    )
    transient = AssessmentTransientFacts.from_primitives(
        event_id=_event().event_id,
        scope_digest=SCOPE,
        flow_facts=[
            _flow(
                "flow-action-resource",
                source_ref="action:call-current",
                target_ref="process:true",
                relation="written_to",
                taints=[],
                strength="exact",
            )
        ],
        current_action=_current_action(data_refs=[]),
        degradations=[app_degradation],
    )

    outcome = shadow_assess_with_coverage(
        _event(),
        PolicyBundle(),
        _snapshot(),
        server_secret=SERVER_SECRET,
        transient_facts=transient,
    )

    assert outcome.coverage.dataflow.status == "unknown"
    promoted = [
        degradation
        for degradation in outcome.assessment.degradations
        if degradation.degradation_id == "gate-a:overlay-incomplete:evt-gate-a-current"
    ]
    assert len(promoted) == 1
    assert promoted[0].required_for_action is True
    assert outcome.assessment.disposition == "DEFER"


def test_explicit_none_transient_is_strict_assessment_parity() -> None:
    kwargs = {
        "server_secret": SERVER_SECRET,
        "detection_results": (),
        "revoked_grant_ids": (),
    }
    old_shape = shadow_assess_with_coverage(
        _event(), PolicyBundle(), _snapshot(), **kwargs
    )
    explicit_none = shadow_assess_with_coverage(
        _event(),
        PolicyBundle(),
        _snapshot(),
        **kwargs,
        transient_facts=None,
    )
    assert explicit_none == old_shape


def test_overlay_rejects_merged_container_overflow_before_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source()
    base_state = __import__(
        "agentguard_core.decisions.shadow", fromlist=["_state_from_snapshot"]
    )._state_from_snapshot(_snapshot(), revoked_grant_ids=())
    base_state = base_state.model_copy(
        update={
            "source_index": [
                source,
                source.model_copy(update={"source_id": "source:second"}),
            ]
        }
    )
    transient = AssessmentTransientFacts.from_primitives(
        event_id=_event().event_id,
        scope_digest=SCOPE,
    )
    monkeypatch.setattr(overlay_module, "ASSESSMENT_OVERLAY_MAX_CONTAINER_ITEMS", 1)

    with pytest.raises(AssessmentOverlayError, match="sources exceeds 1 item limit"):
        build_assessment_overlay(
            base_state,
            transient,
            target_refs=("action:call-current",),
        )


def test_same_trace_unrelated_flow_is_not_current_action_evidence() -> None:
    unrelated = _flow(
        "flow-unrelated-same-trace",
        source_ref="trace:trace-1",
        target_ref="https://unrelated.example/egress",
        relation="sent_to",
        taints=["SENSITIVE"],
        strength="exact",
    )
    snapshot = _snapshot().model_copy(update={"flows": [unrelated]})
    transient = AssessmentTransientFacts.from_primitives(
        event_id=_event().event_id,
        scope_digest=SCOPE,
        current_action=_current_action(data_refs=[]),
    )

    outcome = shadow_assess_with_coverage(
        _event(),
        PolicyBundle(),
        snapshot,
        server_secret=SERVER_SECRET,
        transient_facts=transient,
    )

    assert unrelated.flow_id not in outcome.assessment.flow.path_refs
    assert not any(
        signal.category == "behavior:B1" for signal in outcome.assessment.signals
    )


def test_model_input_canonical_refs_and_typed_sink_reach_coverage() -> None:
    source = _source().model_copy(
        update={"source_id": "source:user:evt-gate-a-context:0"}
    )
    event = _model_input_event(source.source_id)
    transient = AssessmentTransientFacts.from_primitives(
        event_id=event.event_id,
        scope_digest=SCOPE,
        flow_facts=[
            _flow(
                "flow-model-input",
                source_ref=source.source_id,
                target_ref=f"model_input:{event.event_id}",
                relation="assembled_into",
                taints=[],
                strength="exact",
            )
        ],
    )
    snapshot = _snapshot().model_copy(update={"sources": [source]})

    outcome = shadow_assess_with_coverage(
        event,
        PolicyBundle(),
        snapshot,
        server_secret=SERVER_SECRET,
        transient_facts=transient,
        memory_not_required_actions=frozenset({"model_call"}),
    )

    assert outcome.coverage.source.status == "complete"
    assert outcome.coverage.dataflow.status == "complete"
    assert "v21-05:source_complete" in outcome.coverage.source.reason_codes
    assert "v21-05:dataflow_complete" in outcome.coverage.dataflow.reason_codes
