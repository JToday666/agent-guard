"""Competition LangGraph V2 official Core contract tests."""

from __future__ import annotations

from itertools import product

import pytest
from pydantic import ValidationError

from agentguard_core.decisions.competition import (
    FROZEN_ENABLED_PATH_IDS,
    CompetitionActivationManifestV1,
    DecisionAuthorityEvidenceV1,
    V21AuthoritySelectionError,
    V21SelectionEligibility,
    build_competition_activation_manifest,
    build_decision_authority_evidence,
    decision_authority_envelope,
    match_limited_paths,
    select_v21_authority,
    verify_competition_activation_manifest,
)
from agentguard_core.decisions.evidence import (
    CoverageMap,
    DomainCoverage,
    FastAssessment,
    RequiredCheckPlan,
    SemanticRoutingAssessment,
)
from agentguard_core.decisions.evidence_builder import build_decision_evidence_v21
from agentguard_core.decisions.models import GuardDecision
from agentguard_core.signals.models import (
    AuthorityVerdict,
    EvaluationDegradation,
    FlowVerdict,
)

SECRET = b"competition-v2-selector-test-secret"
POLICY_DIGEST = "sha256:" + "1" * 64
DATASET_DIGEST = "sha256:" + "2" * 64
PROFILE_DIGEST = "sha256:" + "3" * 64
SNAPSHOT_DIGEST = "sha256:" + "4" * 64
ASSESSMENT_DIGEST = "sha256:" + "5" * 64
TASK_DIGEST = "sha256:" + "6" * 64
AUTH_FINGERPRINT = "hmac-sha256:" + "7" * 64
AUDIT_FINGERPRINT = "sha256:" + "8" * 64

RANK = {"allow": 0, "ask": 1, "deny": 2}
DISPOSITION = {"allow": "CLEAR_ALLOW", "ask": "DEFER", "deny": "CLEAR_DENY"}


def _coverage(**overrides: str) -> CoverageMap:
    values = {}
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
            domain=domain,
            status=overrides.get(domain, "complete"),
            as_of_sequence=None,
            projector_version="competition-test",
            reason_codes=[],
        )
    return CoverageMap(**values)


def _authority(
    *, status: str = "authorized", mismatches: list[str] | None = None
) -> AuthorityVerdict:
    return AuthorityVerdict(
        status=status,
        matched_grant_ids=[] if status != "authorized" else ["grant:test"],
        missing_capabilities=[] if status == "authorized" else ["tool.call"],
        explicit_scope_mismatches=mismatches or [],
        evidence_refs=[],
    )


def _flow(
    *,
    status: str = "safe",
    strength: str | None = None,
    taints: list[str] | None = None,
    external_sink: bool = False,
) -> FlowVerdict:
    return FlowVerdict(
        status=status,
        strongest_strength=strength,
        taints=taints or [],
        external_sink=external_sink,
        path_refs=[],
        evidence_refs=[],
    )


def _degradation(
    *,
    reason: str = "v21-competition:required_state",
    required: bool = True,
) -> EvaluationDegradation:
    return EvaluationDegradation(
        degradation_id=f"degradation:{reason}",
        component_id="competition-test",
        domain="task",
        required_for_action=required,
        failure_kind="unavailable",
        reason_codes=[reason],
        evidence_refs=[],
    )


def _assessment(
    *,
    decision: str = "ask",
    impact: str = "moderate",
    authority: AuthorityVerdict | None = None,
    flow: FlowVerdict | None = None,
    degradations: list[EvaluationDegradation] | None = None,
    reason_codes: list[str] | None = None,
    task_digest: str | None = TASK_DIGEST,
    authorization_fingerprint: str = AUTH_FINGERPRINT,
    audit_fingerprint: str = AUDIT_FINGERPRINT,
) -> FastAssessment:
    return FastAssessment(
        assessment_id="asm:competition-test",
        event_id="evt:competition-test",
        action_id="action:competition-test",
        disposition=DISPOSITION[decision],
        impact=impact,
        required_check_plan=RequiredCheckPlan(
            plan_id="plan:competition-test",
            impact=impact,
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
        degradations=degradations or [],
        authority=authority or _authority(),
        flow=flow or _flow(),
        semantic_routing=SemanticRoutingAssessment(
            eligible=False,
            hard_deny_present=False,
            semantic_resolvable=False,
            required_facts_available=True,
            reason_codes=[],
        ),
        reason_codes=reason_codes or [],
        evidence_refs=[],
        authorization_fingerprint=authorization_fingerprint,
        audit_fingerprint=audit_fingerprint,
        task_digest=task_digest,
        policy_digest=POLICY_DIGEST,
        snapshot_digest=SNAPSHOT_DIGEST,
        assessment_digest=ASSESSMENT_DIGEST,
    )


def _decision(value: str, *, decision_id: str | None = None, latency: int = 7):
    risk = {"allow": 5, "ask": 50, "deny": 95}[value]
    return GuardDecision(
        decision_id=decision_id or f"dec:{value}",
        decision=value,
        risk_score=risk,
        severity={"allow": "low", "ask": "medium", "deny": "critical"}[value],
        categories=[f"category:{value}"],
        rule_hits=[],
        reason=f"reason:{value}",
        latency_ms=latency,
    )


def _activation(*, basis: str = "profile_all", profile_digest=PROFILE_DIGEST):
    return build_competition_activation_manifest(
        server_secret=SECRET,
        principal_id="principal:competition",
        agent_id="agent:competition",
        runtime_binding_id="binding:competition",
        policy_digest=POLICY_DIGEST,
        dataset_digest=DATASET_DIGEST,
        profile_digest=profile_digest,
        selection_basis=basis,
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
    mode: str,
    current: str,
    raw: str | None,
    assessment: FastAssessment | None = None,
    coverage: CoverageMap | None = None,
    activation=None,
    eligibility=None,
):
    actual_assessment = assessment or _assessment(decision=raw or "ask")
    return select_v21_authority(
        event_id=actual_assessment.event_id,
        current_decision=_decision(current),
        raw_v21_decision=_decision(raw) if raw is not None else None,
        assessment=actual_assessment,
        coverage=coverage or _coverage(),
        mode=mode,
        activation=activation or _activation(),
        eligibility=eligibility or _eligibility(),
        snapshot_id="snapshot:competition-test",
        state_version=11,
    )


def test_activation_manifest_is_strict_canonical_and_server_signed() -> None:
    manifest = _activation()
    assert manifest.enabled_path_ids == list(FROZEN_ENABLED_PATH_IDS)
    assert verify_competition_activation_manifest(manifest, server_secret=SECRET)
    assert not verify_competition_activation_manifest(
        manifest, server_secret=b"another-valid-server-secret"
    )

    # Pydantic's frozen model prevents field reassignment but a nested list can
    # still be mutated by trusted process code.  Verification must recompute
    # the manifest digest rather than trusting the stored digest alone.
    mutable = manifest.model_copy(deep=True)
    mutable.enabled_path_ids.pop()
    assert not verify_competition_activation_manifest(mutable, server_secret=SECRET)

    tampered = manifest.model_dump(mode="json")
    tampered["profile_digest"] = "sha256:" + "9" * 64
    with pytest.raises(ValidationError, match="activation_ref_digest"):
        CompetitionActivationManifestV1.model_validate(tampered)

    unordered = manifest.model_dump(mode="json")
    unordered["enabled_path_ids"] = list(reversed(unordered["enabled_path_ids"]))
    with pytest.raises(ValidationError, match="canonical order"):
        CompetitionActivationManifestV1.model_validate(unordered)

    extra = manifest.model_dump(mode="json")
    extra["attacker_override"] = True
    with pytest.raises(ValidationError):
        CompetitionActivationManifestV1.model_validate(extra)


def test_activation_manifest_rejects_weak_server_secret() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        build_competition_activation_manifest(
            server_secret=b"weak",
            principal_id="principal:competition",
            agent_id="agent:competition",
            runtime_binding_id="binding:competition",
            policy_digest=POLICY_DIGEST,
            dataset_digest=DATASET_DIGEST,
            profile_digest=PROFILE_DIGEST,
            selection_basis="profile_all",
        )
    assert not verify_competition_activation_manifest(
        _activation(), server_secret=b"weak"
    )


def test_path_matcher_matches_all_four_frozen_paths() -> None:
    assessment = _assessment(
        decision="deny",
        impact="high",
        authority=_authority(
            status="unauthorized",
            mismatches=["grant:one:fingerprint_mismatch"],
        ),
        flow=_flow(
            status="violation",
            strength="exact",
            taints=["CREDENTIAL"],
            external_sink=True,
        ),
        degradations=[_degradation()],
    )
    assert match_limited_paths(assessment, _coverage()) == FROZEN_ENABLED_PATH_IDS


@pytest.mark.parametrize(
    ("assessment", "coverage"),
    [
        (
            _assessment(
                decision="deny",
                authority=_authority(status="unauthorized"),
                flow=_flow(
                    status="violation",
                    strength="possible",
                    taints=["CREDENTIAL"],
                    external_sink=True,
                ),
            ),
            _coverage(),
        ),
        (
            _assessment(
                decision="ask",
                impact="moderate",
                authority=_authority(
                    status="unauthorized",
                    mismatches=["grant:one:verdict_scope_mismatch"],
                ),
            ),
            _coverage(),
        ),
        (
            _assessment(
                decision="ask", degradations=[_degradation(required=False)]
            ),
            _coverage(),
        ),
    ],
)
def test_path_matcher_rejects_near_misses(
    assessment: FastAssessment, coverage: CoverageMap
) -> None:
    assert match_limited_paths(assessment, coverage) == ()


def test_required_coverage_and_forged_issuer_have_explicit_paths() -> None:
    assert match_limited_paths(
        _assessment(decision="ask"), _coverage(task="partial")
    ) == ("required_state_degradation",)
    assert match_limited_paths(
        _assessment(
            decision="ask",
            degradations=[_degradation(reason="v21-06:forged_issuer")],
        ),
        _coverage(),
    ) == (
        "forged_authority_or_allow_once_mismatch",
        "required_state_degradation",
    )


@pytest.mark.parametrize(("current", "raw"), product(RANK, RANK))
def test_active_three_by_three_safety_floor(current: str, raw: str) -> None:
    result = _select(mode="active", current=current, raw=raw)
    expected = max((current, raw), key=RANK.__getitem__)
    assert result.selected_decision.decision == expected
    assert result.authority.source == "v21"
    assert result.authority.selection_basis == "profile_all"
    assert result.authority.legacy_floor_applied is (RANK[current] > RANK[raw])
    assert result.selected_decision.decision_id.startswith("dec:v21-official:")
    assert result.selected_decision.latency_ms is None


def test_active_is_v2_official_even_without_a_limited_path() -> None:
    result = _select(mode="active", current="allow", raw="allow")
    assert result.authority.source == "v21"
    assert result.authority.matched_path_ids == []
    assert result.selected_decision.decision_id != result.raw_v21_decision.decision_id


def test_shadow_and_limited_truth_table() -> None:
    shadow = _select(mode="shadow", current="allow", raw="deny")
    assert shadow.authority.source == "current"
    assert shadow.selected_decision is shadow.current_decision

    no_path = _select(
        mode="limited_enable",
        current="allow",
        raw="ask",
        activation=_activation(basis="path_allowlist"),
    )
    assert no_path.authority.source == "current"

    required = _assessment(decision="ask", degradations=[_degradation()])
    transferred = _select(
        mode="limited_enable",
        current="allow",
        raw="ask",
        assessment=required,
        activation=_activation(basis="path_allowlist"),
    )
    assert transferred.authority.source == "v21"
    assert transferred.authority.selection_basis == "path_allowlist"

    weaker = _select(
        mode="limited_enable",
        current="deny",
        raw="ask",
        assessment=required,
        activation=_activation(basis="path_allowlist"),
    )
    assert weaker.authority.source == "current"

    ownership_failed = _select(
        mode="limited_enable",
        current="allow",
        raw="ask",
        assessment=required,
        activation=_activation(basis="path_allowlist"),
        eligibility=_eligibility(ownership_valid=False),
    )
    assert ownership_failed.authority.source == "current"


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
def test_active_authority_failure_never_falls_back_current(failed_gate: str) -> None:
    with pytest.raises(
        V21AuthoritySelectionError,
        match="active_authority_precondition_failed",
    ):
        _select(
            mode="active",
            current="allow",
            raw="allow",
            eligibility=_eligibility(**{failed_gate: False}),
        )


def test_active_requires_raw_candidate_and_profile_all_manifest() -> None:
    with pytest.raises(V21AuthoritySelectionError, match="raw_v21_unavailable"):
        _select(mode="active", current="allow", raw=None)
    with pytest.raises(
        V21AuthoritySelectionError,
        match="activation_selection_basis_mismatch",
    ):
        _select(
            mode="active",
            current="allow",
            raw="allow",
            activation=_activation(basis="path_allowlist"),
        )


def test_official_identity_ignores_nondeterministic_current_id_and_latency() -> None:
    assessment = _assessment(decision="allow")
    activation = _activation()
    kwargs = {
        "event_id": assessment.event_id,
        "raw_v21_decision": _decision("allow", decision_id="raw:stable"),
        "assessment": assessment,
        "coverage": _coverage(),
        "mode": "active",
        "activation": activation,
        "eligibility": _eligibility(),
        "snapshot_id": "snapshot:competition-test",
        "state_version": 11,
    }
    first = select_v21_authority(
        current_decision=_decision("allow", decision_id="current:uuid-1", latency=1),
        **kwargs,
    )
    second = select_v21_authority(
        current_decision=_decision(
            "allow", decision_id="current:uuid-2", latency=999
        ),
        **kwargs,
    )
    assert first.selected_decision == second.selected_decision
    assert first.selected_decision_digest == second.selected_decision_digest


def test_official_identity_changes_with_security_semantics_and_activation() -> None:
    first = _select(mode="active", current="allow", raw="allow")
    changed_current = _select(mode="active", current="ask", raw="allow")
    changed_activation = _select(
        mode="active",
        current="allow",
        raw="allow",
        activation=_activation(profile_digest="sha256:" + "a" * 64),
    )
    assert first.selected_decision.decision_id != changed_current.selected_decision.decision_id
    assert first.selected_decision.decision_id != changed_activation.selected_decision.decision_id


def test_reviewable_and_unreleasable_ask_are_distinct() -> None:
    reviewable = _select(mode="active", current="allow", raw="ask")
    assert reviewable.authority.approval_release == "strong_binding_required"
    assert reviewable.selected_decision.approval_intent is not None

    degraded_assessment = _assessment(
        decision="ask", degradations=[_degradation()]
    )
    forbidden = _select(
        mode="active",
        current="allow",
        raw="ask",
        assessment=degraded_assessment,
    )
    assert forbidden.authority.approval_release == "forbidden"
    assert forbidden.selected_decision.approval_intent is None

    missing_task = _select(
        mode="active",
        current="allow",
        raw="ask",
        eligibility=_eligibility(task_fact_present=False),
    )
    assert missing_task.authority.approval_release == "forbidden"


@pytest.mark.parametrize(
    ("approval_binding_eligible", "action_ir_complete", "task_fact_present"),
    product((False, True), repeat=3),
)
def test_ask_approval_binding_eligibility_truth_table(
    approval_binding_eligible: bool,
    action_ir_complete: bool,
    task_fact_present: bool,
) -> None:
    result = _select(
        mode="active",
        current="allow",
        raw="ask",
        eligibility=_eligibility(
            approval_binding_eligible=approval_binding_eligible,
            action_ir_complete=action_ir_complete,
            task_fact_present=task_fact_present,
        ),
    )
    reviewable = all(
        (approval_binding_eligible, action_ir_complete, task_fact_present)
    )

    assert result.authority.approval_release == (
        "strong_binding_required" if reviewable else "forbidden"
    )
    assert (result.selected_decision.approval_intent is not None) is reviewable


def test_decision_authority_evidence_is_strict_complete_and_critical() -> None:
    assessment = _assessment(decision="ask")
    activation = _activation()
    result = _select(
        mode="active",
        current="allow",
        raw="ask",
        assessment=assessment,
        activation=activation,
    )
    evidence = build_decision_authority_evidence(
        result=result,
        assessment=assessment,
        activation=activation,
        snapshot_id="snapshot:competition-test",
        state_version=11,
    )
    assert evidence.persistence_requirement == "critical_no_drop"
    assert evidence.current_decision == result.current_decision
    assert evidence.raw_v21_decision == result.raw_v21_decision
    assert evidence.selected_decision == result.selected_decision
    assert evidence.decision_authority == result.authority
    restored = DecisionAuthorityEvidenceV1.model_validate(
        evidence.model_dump(mode="json")
    )
    assert restored == evidence
    assert decision_authority_envelope(evidence) == {
        "decision_authority": {
            "schema_version": "1.0",
            "payload": evidence.model_dump(mode="json"),
        }
    }

    tampered = evidence.model_dump(mode="json")
    tampered["selected_decision"]["decision"] = "deny"
    with pytest.raises(ValidationError, match="selected_decision_digest"):
        DecisionAuthorityEvidenceV1.model_validate(tampered)


def test_frozen_decision_evidence_supports_explicit_selected_result() -> None:
    assessment = _assessment(decision="deny")
    evidence = build_decision_evidence_v21(
        assessment,
        legacy_decision="allow",
        snapshot_id="snapshot:competition-test",
        state_version=11,
        coverage=_coverage(),
        mode="active",
        selected_decision="deny",
    )
    assert evidence.legacy_decision == "allow"
    assert evidence.v21_fast_disposition == "CLEAR_DENY"
    assert evidence.final_decision == "deny"
    assert evidence.mode == "active"


def test_default_decision_evidence_shape_and_semantics_remain_shadow() -> None:
    assessment = _assessment(decision="ask")
    evidence = build_decision_evidence_v21(
        assessment,
        legacy_decision="allow",
        snapshot_id="snapshot:competition-test",
        state_version=11,
        coverage=_coverage(),
    )
    assert evidence.final_decision == "allow"
    assert evidence.mode == "shadow"
