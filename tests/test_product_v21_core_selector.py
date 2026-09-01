"""Product Active V2 authority selector contract tests.

These tests exercise only the runtime-neutral Core selector.  They deliberately
construct their own assessment and coverage inputs so the Product contract is
not coupled to private helpers from another test module or to Guard API wiring.
"""

from __future__ import annotations

from datetime import datetime, timezone
from itertools import product
from typing import Literal

import pytest

from agentguard_core import (
    ApprovalIntent,
    OPENCLAW_RESIDUAL_BOUNDARIES,
    V21SelectionEligibility,
    legacy_approval_release_projection,
    select_product_v21_authority,
)
from agentguard_core.decisions.competition import V21AuthoritySelectionError
from agentguard_core.decisions.evidence import (
    CoverageMap,
    DomainCoverage,
    FastAssessment,
    RequiredCheckPlan,
    SemanticRoutingAssessment,
)
from agentguard_core.decisions.models import GuardDecision
from agentguard_core.events import GuardEventType
from agentguard_core.signals.models import AuthorityVerdict, FlowVerdict
from tests.support.product_activation import build_test_product_activation

pytestmark = pytest.mark.contract

Runtime = Literal["langgraph", "openclaw"]
Decision = Literal["allow", "ask", "deny"]

POLICY_DIGEST = "sha256:" + "1" * 64
SNAPSHOT_DIGEST = "sha256:" + "2" * 64
ASSESSMENT_DIGEST = "sha256:" + "3" * 64
TASK_DIGEST = "sha256:" + "4" * 64
AUTHORIZATION_FINGERPRINT = "hmac-sha256:" + "5" * 64
AUDIT_FINGERPRINT = "sha256:" + "6" * 64
SCOPE_DIGEST = "sha256:" + "7" * 64

RANK: dict[Decision, int] = {"allow": 0, "ask": 1, "deny": 2}
DISPOSITION = {
    "allow": "CLEAR_ALLOW",
    "ask": "DEFER",
    "deny": "CLEAR_DENY",
}


def _coverage() -> CoverageMap:
    values: dict[str, DomainCoverage] = {}
    for domain in (
        "task",
        "source",
        "capability",
        "behavior",
        "dataflow",
        "memory",
        "runtime_outcome",
    ):
        values[domain] = DomainCoverage(
            domain=domain,  # type: ignore[arg-type]
            status="complete",
            as_of_sequence=None,
            projector_version="product-selector-contract",
            reason_codes=[],
        )
    return CoverageMap(**values)  # type: ignore[arg-type]


def _assessment(decision: Decision) -> FastAssessment:
    return FastAssessment(
        assessment_id="asm:product-selector-contract",
        event_id="evt:product-selector-contract",
        action_id="action:product-selector-contract",
        disposition=DISPOSITION[decision],  # type: ignore[arg-type]
        impact="moderate",
        required_check_plan=RequiredCheckPlan(
            plan_id="plan:product-selector-contract",
            impact="moderate",
            required_domains=["task", "capability"],
            optional_domains=[
                "source",
                "behavior",
                "dataflow",
                "memory",
                "runtime_outcome",
            ],
            required_capabilities=["tool.call"],
            semantic_resolvable_dimensions=[],
            reason_codes=[],
        ),
        policy_violations=[],
        signals=[],
        degradations=[],
        authority=AuthorityVerdict(
            status="authorized",
            matched_grant_ids=["grant:product-selector-contract"],
            missing_capabilities=[],
            explicit_scope_mismatches=[],
            evidence_refs=[],
        ),
        flow=FlowVerdict(
            status="safe",
            strongest_strength=None,
            taints=[],
            external_sink=False,
            path_refs=[],
            evidence_refs=[],
        ),
        semantic_routing=SemanticRoutingAssessment(
            eligible=False,
            hard_deny_present=False,
            semantic_resolvable=False,
            required_facts_available=True,
            reason_codes=[],
        ),
        reason_codes=[],
        evidence_refs=[],
        authorization_fingerprint=AUTHORIZATION_FINGERPRINT,
        audit_fingerprint=AUDIT_FINGERPRINT,
        task_digest=TASK_DIGEST,
        policy_digest=POLICY_DIGEST,
        snapshot_digest=SNAPSHOT_DIGEST,
        assessment_digest=ASSESSMENT_DIGEST,
    )


def _decision(
    value: Decision,
    *,
    decision_id: str | None = None,
    latency_ms: int = 7,
) -> GuardDecision:
    return GuardDecision(
        decision_id=decision_id or f"dec:{value}:product-selector-contract",
        decision=value,
        risk_score={"allow": 5, "ask": 50, "deny": 95}[value],
        severity={"allow": "low", "ask": "medium", "deny": "critical"}[value],
        categories=[f"category:{value}"],
        rule_hits=[],
        reason=f"reason:{value}",
        latency_ms=latency_ms,
    )


def _eligibility(**overrides: bool) -> V21SelectionEligibility:
    values = {
        "activation_valid": True,
        "trusted_identity_valid": True,
        "profile_valid": True,
        "revalidation_valid": True,
        "pipeline_complete": True,
        "ownership_valid": True,
        "action_ir_complete": True,
        "task_fact_present": True,
        "approval_binding_eligible": True,
    }
    values.update(overrides)
    return V21SelectionEligibility(**values)


def _select(
    *,
    runtime: Runtime = "langgraph",
    current: Decision = "allow",
    raw: Decision | None = "allow",
    eligibility: V21SelectionEligibility | None = None,
    event_type: GuardEventType = "tool_call_proposed",
    current_decision: GuardDecision | None = None,
    raw_decision: GuardDecision | None = None,
):
    assessment_decision = raw or "ask"
    fixture = build_test_product_activation(
        now=datetime(2026, 9, 1, tzinfo=timezone.utc),
        policy_digest=POLICY_DIGEST,
    )
    entry = fixture.bundle.runtime_entry(runtime)
    residual_boundaries = (
        list(OPENCLAW_RESIDUAL_BOUNDARIES) if runtime == "openclaw" else []
    )
    return select_product_v21_authority(
        event_id="evt:product-selector-contract",
        current_decision=current_decision or _decision(current),
        raw_v21_decision=(
            raw_decision
            if raw_decision is not None
            else (_decision(raw) if raw is not None else None)
        ),
        assessment=_assessment(assessment_decision),
        coverage=_coverage(),
        activation=fixture.bundle,
        runtime_entry=entry,
        eligibility=eligibility or _eligibility(),
        snapshot_id="snapshot:product-selector-contract",
        state_version=11,
        scope_digest=SCOPE_DIGEST,
        event_type=event_type,
        residual_boundaries=residual_boundaries,
    )


@pytest.mark.parametrize(("current", "raw"), product(RANK, RANK))
def test_product_active_three_by_three_safety_floor(
    current: Decision,
    raw: Decision,
) -> None:
    result, directive = _select(current=current, raw=raw)
    expected = max((current, raw), key=RANK.__getitem__)

    assert result.selected_decision.decision == expected
    assert result.authority.source == "v21"
    assert result.authority.mode == "active"
    assert result.authority.selection_basis == "profile_all"
    assert result.authority.matched_path_ids == []
    assert result.authority.legacy_floor_applied is (RANK[current] > RANK[raw])
    assert result.selected_decision.decision_id.startswith("dec:v21-product:")
    assert result.selected_decision.latency_ms is None
    assert directive.mode == (
        "strong_binding" if expected == "ask" else "not_applicable"
    )
    assert result.authority.approval_release == legacy_approval_release_projection(
        directive
    )


@pytest.mark.parametrize(
    (
        "runtime",
        "expected_mode",
        "expected_profile",
        "expected_binding",
        "expected_legacy_projection",
    ),
    [
        (
            "langgraph",
            "strong_binding",
            "C3",
            "exact",
            "strong_binding_required",
        ),
        (
            "openclaw",
            "restricted_allow_once",
            "C1",
            "best_effort_host",
            "forbidden",
        ),
    ],
)
def test_product_ask_directive_is_runtime_specific_and_legacy_safe(
    runtime: Runtime,
    expected_mode: str,
    expected_profile: str,
    expected_binding: str,
    expected_legacy_projection: str,
) -> None:
    result, directive = _select(runtime=runtime, current="allow", raw="ask")

    assert result.authority.source == "v21"
    assert result.selected_decision.decision == "ask"
    assert result.selected_decision.approval_intent is not None
    assert directive.mode == expected_mode
    assert directive.required_runtime_profile == expected_profile
    assert directive.action_binding == expected_binding
    assert directive.human_only is True
    assert directive.single_use is True
    assert directive.receipt_requirement == "required_durable"
    assert directive.activation_ref_digest == result.authority.activation_ref_digest
    assert legacy_approval_release_projection(directive) == expected_legacy_projection
    assert result.authority.approval_release == expected_legacy_projection
    assert directive.residual_boundaries == (
        list(OPENCLAW_RESIDUAL_BOUNDARIES) if runtime == "openclaw" else []
    )


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_product_unreviewable_ask_is_forbidden_without_approval_intent(
    runtime: Runtime,
) -> None:
    result, directive = _select(
        runtime=runtime,
        current="allow",
        raw="ask",
        eligibility=_eligibility(action_ir_complete=False),
    )

    assert result.authority.source == "v21"
    assert directive.mode == "forbidden"
    assert result.authority.approval_release == "forbidden"
    assert result.selected_decision.approval_intent is None


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_equal_ask_current_deny_only_intent_prevents_release_synthesis(
    runtime: Runtime,
) -> None:
    current = _decision("ask").model_copy(
        update={
            "approval_intent": ApprovalIntent(
                options=["deny"],
                resource="action:deny-only-product-selector-contract",
            )
        }
    )

    result, directive = _select(
        runtime=runtime,
        current="ask",
        raw="ask",
        current_decision=current,
        raw_decision=_decision("ask"),
    )

    assert result.selected_decision.decision == "ask"
    assert result.selected_decision.approval_intent is None
    assert directive.mode == "forbidden"
    assert result.authority.approval_release == "forbidden"


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_product_non_release_event_ask_is_not_applicable(
    runtime: Runtime,
) -> None:
    result, directive = _select(
        runtime=runtime,
        current="allow",
        raw="ask",
        event_type="model_input_prepared",
    )

    assert result.authority.source == "v21"
    assert directive.mode == "not_applicable"
    assert result.authority.approval_release == "not_applicable"
    assert result.selected_decision.approval_intent is None


@pytest.mark.parametrize(
    "failed_gate",
    [
        "activation_valid",
        "trusted_identity_valid",
        "profile_valid",
        "revalidation_valid",
        "pipeline_complete",
    ],
)
@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_product_active_precondition_failure_never_falls_back_current(
    runtime: Runtime,
    failed_gate: str,
) -> None:
    with pytest.raises(V21AuthoritySelectionError) as raised:
        _select(
            runtime=runtime,
            current="deny",
            raw="allow",
            eligibility=_eligibility(**{failed_gate: False}),
        )

    assert raised.value.args == ("v21-product:active_authority_precondition_failed",)


def test_product_missing_raw_candidate_never_returns_current() -> None:
    with pytest.raises(V21AuthoritySelectionError) as raised:
        _select(current="deny", raw=None)

    assert raised.value.args == ("v21-product:raw_v21_unavailable",)


def test_product_legacy_floor_remains_v2_authority_not_current_fallback() -> None:
    current = _decision("deny", decision_id="dec:current:must-not-be-returned")
    result, directive = _select(
        current="deny",
        raw="allow",
        current_decision=current,
    )

    assert result.selected_decision.decision == current.decision
    assert result.selected_decision.decision_id != current.decision_id
    assert result.authority.source == "v21"
    assert result.authority.mode == "active"
    assert result.authority.selection_basis == "profile_all"
    assert result.authority.legacy_floor_applied is True
    assert directive.mode == "not_applicable"


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_product_official_id_ignores_nondeterministic_decision_fields(
    runtime: Runtime,
) -> None:
    first, first_directive = _select(
        runtime=runtime,
        current="allow",
        raw="ask",
        current_decision=_decision(
            "allow",
            decision_id="dec:current:random-1",
            latency_ms=1,
        ),
        raw_decision=_decision(
            "ask",
            decision_id="dec:raw:random-1",
            latency_ms=2,
        ),
    )
    second, second_directive = _select(
        runtime=runtime,
        current="allow",
        raw="ask",
        current_decision=_decision(
            "allow",
            decision_id="dec:current:random-2",
            latency_ms=999,
        ),
        raw_decision=_decision(
            "ask",
            decision_id="dec:raw:random-2",
            latency_ms=998,
        ),
    )

    assert first.selected_decision == second.selected_decision
    assert first.selected_decision_digest == second.selected_decision_digest
    assert first.authority == second.authority
    assert first_directive == second_directive
