"""Version-dispatched critical authority evidence persistence tests."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, cast

import pytest

from agentguard_core import (
    ApprovalIntent,
    DecisionAuthority,
    DecisionAuthorityEvidenceV1,
    GuardDecision,
    GuardEvent,
    PolicyBundle,
    ProductDecisionAuthorityEvidenceV1,
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
    build_approval_release_directive,
    decision_authority_envelope,
    product_decision_authority_envelope,
)
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions.evidence import (
    CoverageMap,
    DecisionEvidenceV21,
    DomainCoverage,
    decision_v21_envelope,
)

from guard_api.services.audit import AuditService
from guard_api.services.approval import ApprovalService
from guard_api.services.competition import (
    CriticalDecisionEvidenceError,
    parse_decision_authority_evidence_payload,
    strict_decision_authority_envelope,
)
from guard_api.services.evaluation import EvaluationService
from guard_api.services.policy import PolicyService
from guard_api.services.v21_pipeline import V21OfficialEvaluationUnavailableError
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.product_activation import build_test_product_activation


def _decision(*, decision_id: str = "dec:v21-product:evidence") -> GuardDecision:
    return GuardDecision(
        decision_id=decision_id,
        decision="allow",
        risk_score=5,
        severity="low",
        categories=["product-authority-evidence"],
        rule_hits=[],
        reason="product V2 authority selected allow",
        latency_ms=None,
    )


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
            projector_version="product-authority-evidence-test",
            reason_codes=[],
        )
    return CoverageMap.model_validate(values)


def _product_authority_fixture() -> tuple[
    ProductDecisionAuthorityEvidenceV1,
    DecisionEvidenceV21,
]:
    activation = build_test_product_activation(
        now=datetime.now(timezone.utc),
        policy_digest="sha256:" + "5" * 64,
    )
    entry = activation.bundle.runtime_entry("langgraph")
    selected = _decision()
    current = _decision(decision_id="dec:current:evidence")
    raw = _decision(decision_id="dec:raw-v21:evidence")
    directive = build_approval_release_directive(
        runtime="langgraph",
        decision=selected.decision,
        reviewable=False,
        activation_ref_digest=activation.bundle.activation_ref_digest,
        scope_digest="sha256:" + "a" * 64,
        capability_digest=activation.langgraph_capability.report_digest,
    )
    authority = DecisionAuthority(
        source="v21",
        mode="active",
        selection_basis="profile_all",
        matched_path_ids=[],
        legacy_floor_applied=False,
        activation_ref_digest=activation.bundle.activation_ref_digest,
        approval_release="not_applicable",
    )
    evidence = ProductDecisionAuthorityEvidenceV1(
        runtime="langgraph",
        profile_id=entry.profile_id,
        event_type="tool_call_proposed",
        event_id="evt:product-authority-evidence",
        assessment_id="asm:product-authority-evidence",
        assessment_digest="sha256:" + "1" * 64,
        snapshot_id="snapshot:product-authority-evidence",
        snapshot_digest="sha256:" + "2" * 64,
        state_version=7,
        policy_digest="sha256:" + "5" * 64,
        dataset_digest=activation.bundle.dataset_digest,
        profile_digest=entry.profile_digest,
        current_decision=current,
        current_decision_digest=canonical_sha256(current.model_dump(mode="json")),
        raw_v21_decision=raw,
        raw_v21_decision_digest=canonical_sha256(raw.model_dump(mode="json")),
        selected_decision=selected,
        selected_decision_digest=canonical_sha256(selected.model_dump(mode="json")),
        decision_authority=authority,
        approval_release_directive=directive,
    )
    decision_evidence = DecisionEvidenceV21(
        assessment_id=evidence.assessment_id,
        assessment_digest=evidence.assessment_digest,
        snapshot_id=evidence.snapshot_id,
        snapshot_digest=evidence.snapshot_digest,
        state_version=evidence.state_version,
        required_domains=[],
        coverage=_coverage(),
        authority_status="authorized",
        matched_grant_ids=[],
        flow_status="safe",
        flow_path_refs=[],
        policy_violation_ids=[],
        signal_ids=[],
        degradation_ids=[],
        semantic_judgment_id=None,
        semantic_digest=None,
        legacy_decision=current.decision,
        v21_fast_disposition="CLEAR_ALLOW",
        final_decision=selected.decision,
        mode="active",
        divergence_category=None,
        evidence_refs=[],
    )
    return evidence, decision_evidence


def _restricted_authority_fixture() -> tuple[
    ProductDecisionAuthorityEvidenceV1,
    DecisionEvidenceV21,
]:
    activation = build_test_product_activation(
        now=datetime.now(timezone.utc),
        policy_digest="sha256:" + "5" * 64,
    )
    entry = activation.bundle.runtime_entry("openclaw")
    current = _decision(decision_id="dec:current:restricted")
    raw = _decision(decision_id="dec:raw-v21:restricted").model_copy(
        update={"decision": "ask"}
    )
    selected = raw.model_copy(
        update={
            "decision_id": "dec:v21-product:restricted",
            "approval_intent": ApprovalIntent(resource="action:restricted-tool"),
        }
    )
    directive = build_approval_release_directive(
        runtime="openclaw",
        decision="ask",
        reviewable=True,
        activation_ref_digest=activation.bundle.activation_ref_digest,
        scope_digest="sha256:" + "a" * 64,
        capability_digest=entry.capability_report_digest,
        residual_boundaries=entry.residual_boundaries,
    )
    authority = DecisionAuthority(
        source="v21",
        mode="active",
        selection_basis="profile_all",
        matched_path_ids=[],
        legacy_floor_applied=False,
        activation_ref_digest=activation.bundle.activation_ref_digest,
        # Old readers must continue to treat restricted release as forbidden.
        approval_release="forbidden",
    )
    evidence = ProductDecisionAuthorityEvidenceV1(
        runtime="openclaw",
        profile_id=entry.profile_id,
        event_type="tool_call_proposed",
        event_id="evt:product-authority-evidence",
        assessment_id="asm:product-authority-restricted",
        assessment_digest="sha256:" + "6" * 64,
        snapshot_id="snapshot:product-authority-restricted",
        snapshot_digest="sha256:" + "7" * 64,
        state_version=9,
        policy_digest="sha256:" + "5" * 64,
        dataset_digest=activation.bundle.dataset_digest,
        profile_digest=entry.profile_digest,
        current_decision=current,
        current_decision_digest=canonical_sha256(current.model_dump(mode="json")),
        raw_v21_decision=raw,
        raw_v21_decision_digest=canonical_sha256(raw.model_dump(mode="json")),
        selected_decision=selected,
        selected_decision_digest=canonical_sha256(selected.model_dump(mode="json")),
        decision_authority=authority,
        approval_release_directive=directive,
    )
    decision_evidence = DecisionEvidenceV21(
        assessment_id=evidence.assessment_id,
        assessment_digest=evidence.assessment_digest,
        snapshot_id=evidence.snapshot_id,
        snapshot_digest=evidence.snapshot_digest,
        state_version=evidence.state_version,
        required_domains=[],
        coverage=_coverage(),
        authority_status="authorized",
        matched_grant_ids=[],
        flow_status="safe",
        flow_path_refs=[],
        policy_violation_ids=[],
        signal_ids=[],
        degradation_ids=[],
        semantic_judgment_id=None,
        semantic_digest=None,
        legacy_decision=current.decision,
        v21_fast_disposition="DEFER",
        final_decision="ask",
        mode="active",
        divergence_category=None,
        evidence_refs=[],
    )
    return evidence, decision_evidence


def _event() -> GuardEvent:
    return GuardEvent(
        event_id="evt:product-authority-evidence",
        event_type="tool_call_proposed",
        runtime="langgraph",
        trace_id="trace:product-authority-evidence",
        timestamp=datetime.now(timezone.utc).isoformat(),
        pre_execution=True,
        security_context=SecurityContext(
            agent_id="main",
            user_task="persist Product V2 authority evidence",
        ),
        payload=ToolCallPayload(
            tool=ToolDescriptor(
                name="product_authority_evidence_tool",
                call_id="call:product-authority-evidence",
            ),
            arguments={},
            derived_resources=[],
        ),
    )


def _restricted_event() -> GuardEvent:
    return _event().model_copy(update={"runtime": "openclaw"})


def test_product_v2_authority_survives_sanitize_commit_and_readback_exactly() -> None:
    authority_evidence, decision_evidence = _product_authority_fixture()
    envelope = product_decision_authority_envelope(authority_evidence)
    v21_envelope = decision_v21_envelope(decision_evidence.model_dump(mode="json"))
    store = MemoryControlPlaneStore()

    persisted = AuditService(store=store).record_evaluation(
        _event(),
        authority_evidence.selected_decision,
        policy_bundle=PolicyBundle(),
        policy_revision=None,
        extra_metadata={"policy_digest": authority_evidence.policy_digest},
        v21_evidence=v21_envelope,
        decision_authority_evidence=envelope,
        decision_authority=authority_evidence.decision_authority,
    )

    assert persisted.evidence is not None
    assert persisted.evidence["decision_authority"] == envelope["decision_authority"]
    assert (persisted.model_extra or {})["decision_authority"] == (
        authority_evidence.decision_authority.model_dump(mode="json")
    )
    parsed = parse_decision_authority_evidence_payload(envelope)
    assert isinstance(parsed, ProductDecisionAuthorityEvidenceV1)
    assert parsed == authority_evidence


def test_product_v2_commit_rejects_common_selected_decision_parity_drift() -> None:
    authority_evidence, decision_evidence = _product_authority_fixture()
    envelope = product_decision_authority_envelope(authority_evidence)
    v21_envelope = decision_v21_envelope(decision_evidence.model_dump(mode="json"))
    store = MemoryControlPlaneStore()
    service = AuditService(store=store)
    persisted = service.record_evaluation(
        _event(),
        authority_evidence.selected_decision,
        policy_bundle=PolicyBundle(),
        policy_revision=None,
        extra_metadata={"policy_digest": authority_evidence.policy_digest},
        v21_evidence=v21_envelope,
        decision_authority_evidence=envelope,
        decision_authority=authority_evidence.decision_authority,
    )
    evidence = deepcopy(persisted.evidence)
    assert evidence is not None
    evidence["guard_decision"] = _decision(
        decision_id="dec:attacker-replaced"
    ).model_dump(mode="json")
    tampered = persisted.model_copy(update={"evidence": evidence})

    with pytest.raises(
        CriticalDecisionEvidenceError,
        match="lack exact parity",
    ):
        service._validate_decision_authority_commit(  # noqa: SLF001
            tampered,
            expected_envelope=envelope,
            expected_decision=authority_evidence.selected_decision,
            expected_authority=authority_evidence.decision_authority,
            expected_v21_evidence=v21_envelope,
        )


@pytest.mark.parametrize(
    "drift",
    ["runtime", "event_type", "event_id", "policy_digest"],
)
def test_product_v2_commit_binds_evidence_to_audit_identity(drift: str) -> None:
    authority_evidence, decision_evidence = _product_authority_fixture()
    envelope = product_decision_authority_envelope(authority_evidence)
    v21_envelope = decision_v21_envelope(decision_evidence.model_dump(mode="json"))
    store = MemoryControlPlaneStore()
    service = AuditService(store=store)
    persisted = service.record_evaluation(
        _event(),
        authority_evidence.selected_decision,
        policy_bundle=PolicyBundle(),
        policy_revision=None,
        extra_metadata={"policy_digest": authority_evidence.policy_digest},
        v21_evidence=v21_envelope,
        decision_authority_evidence=envelope,
        decision_authority=authority_evidence.decision_authority,
    )
    if drift == "runtime":
        tampered = persisted.model_copy(update={"runtime": "openclaw"})
    elif drift == "event_type":
        tampered = persisted.model_copy(update={"event_type": "model_input_prepared"})
    elif drift == "event_id":
        tampered = persisted.model_copy(
            update={"links": {**persisted.links, "event_id": "evt:replaced"}}
        )
    else:
        tampered = persisted.model_copy(
            update={
                "metadata": {
                    **persisted.metadata,
                    "policy_digest": "sha256:" + "9" * 64,
                }
            }
        )

    with pytest.raises(
        CriticalDecisionEvidenceError,
        match="not bound to the persisted audit",
    ):
        service._validate_decision_authority_commit(  # noqa: SLF001
            tampered,
            expected_envelope=envelope,
            expected_decision=authority_evidence.selected_decision,
            expected_authority=authority_evidence.decision_authority,
            expected_v21_evidence=v21_envelope,
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["decision_authority"].update({"schema_version": "3.0"}),
        lambda value: value["decision_authority"].update(
            {"unexpected_envelope_field": True}
        ),
        lambda value: value["decision_authority"]["payload"].update(
            {"schema_version": "1.0"}
        ),
        lambda value: value["decision_authority"]["payload"].update(
            {"unexpected_payload_field": True}
        ),
        lambda value: value["decision_authority"]["payload"].update(
            {"profile_id": "agentguard-openclaw-v2-restricted"}
        ),
    ],
    ids=[
        "unknown-envelope-version",
        "extra-envelope-field",
        "forged-inner-version",
        "extra-payload-field",
        "runtime-profile-mismatch",
    ],
)
def test_product_v2_authority_rejects_unknown_or_spoofed_shapes(mutate) -> None:
    authority_evidence, _ = _product_authority_fixture()
    envelope = product_decision_authority_envelope(authority_evidence)
    mutate(envelope)

    with pytest.raises(CriticalDecisionEvidenceError):
        strict_decision_authority_envelope(envelope)


@pytest.mark.parametrize("deny_only_source", ["current", "raw_v21"])
def test_releasable_product_evidence_rejects_deny_only_authority_input(
    deny_only_source: str,
) -> None:
    authority_evidence, _ = _restricted_authority_fixture()
    payload = authority_evidence.model_dump(mode="json")
    decision_key = f"{deny_only_source}_decision"
    digest_key = f"{deny_only_source}_decision_digest"
    deny_only = GuardDecision.model_validate(payload[decision_key]).model_copy(
        update={
            "decision": "ask",
            "approval_intent": ApprovalIntent(
                options=["deny"],
                resource="action:deny-only-authority-input",
            ),
        }
    )
    payload[decision_key] = deny_only.model_dump(mode="json")
    payload[digest_key] = canonical_sha256(deny_only.model_dump(mode="json"))

    with pytest.raises(
        ValueError,
        match="cannot override an explicit deny-only intent",
    ):
        ProductDecisionAuthorityEvidenceV1.model_validate(payload)

    envelope = {
        "decision_authority": {
            "schema_version": "2.0",
            "payload": payload,
        }
    }
    with pytest.raises(CriticalDecisionEvidenceError):
        strict_decision_authority_envelope(envelope)


def test_authority_version_dispatch_rejects_cross_version_payload_spoofing() -> None:
    authority_evidence, _ = _product_authority_fixture()
    product = product_decision_authority_envelope(authority_evidence)
    product["decision_authority"]["schema_version"] = "1.0"

    with pytest.raises(CriticalDecisionEvidenceError):
        strict_decision_authority_envelope(product)

    competition = DecisionAuthorityEvidenceV1(
        event_id=authority_evidence.event_id,
        assessment_id=authority_evidence.assessment_id,
        assessment_digest=authority_evidence.assessment_digest,
        snapshot_id=authority_evidence.snapshot_id,
        snapshot_digest=authority_evidence.snapshot_digest,
        state_version=authority_evidence.state_version,
        policy_digest=authority_evidence.policy_digest,
        dataset_digest=authority_evidence.dataset_digest,
        profile_digest=authority_evidence.profile_digest,
        current_decision=authority_evidence.current_decision,
        current_decision_digest=authority_evidence.current_decision_digest,
        raw_v21_decision=authority_evidence.raw_v21_decision,
        raw_v21_decision_digest=authority_evidence.raw_v21_decision_digest,
        selected_decision=authority_evidence.selected_decision,
        selected_decision_digest=authority_evidence.selected_decision_digest,
        decision_authority=authority_evidence.decision_authority,
    )
    competition_envelope = decision_authority_envelope(competition)
    competition_envelope["decision_authority"]["schema_version"] = "2.0"

    with pytest.raises(CriticalDecisionEvidenceError):
        strict_decision_authority_envelope(competition_envelope)


@pytest.mark.parametrize("schema_version", [[], {}], ids=["list", "mapping"])
def test_authority_version_dispatch_rejects_non_scalar_version(
    schema_version: object,
) -> None:
    authority_evidence, _ = _product_authority_fixture()
    envelope = product_decision_authority_envelope(authority_evidence)
    envelope["decision_authority"]["schema_version"] = schema_version

    with pytest.raises(
        CriticalDecisionEvidenceError,
        match="schema version is unsupported",
    ):
        strict_decision_authority_envelope(envelope)


def test_unreleasable_product_directives_create_no_approval() -> None:
    store = MemoryControlPlaneStore()
    approvals = ApprovalService(
        store=store,
        settings=GuardApiSettings(storage_backend="memory"),
    )
    non_ask, _ = _product_authority_fixture()

    assert (
        approvals.create_for_decision(
            _event(),
            non_ask.selected_decision,
            requesting_principal_id="principal:langgraph",
            decision_authority=non_ask.decision_authority,
            approval_release_directive=non_ask.approval_release_directive,
        )
        is None
    )

    restricted, _ = _restricted_authority_fixture()
    forbidden_directive = type(restricted.approval_release_directive).model_validate(
        {
            **restricted.approval_release_directive.model_dump(mode="json"),
            "mode": "forbidden",
            "required_runtime_profile": None,
            "action_binding": "none",
            "receipt_requirement": "not_applicable",
            "residual_boundaries": [],
        }
    )
    forbidden_decision = restricted.selected_decision.model_copy(
        update={"approval_intent": None}
    )
    assert (
        approvals.create_for_decision(
            _restricted_event(),
            forbidden_decision,
            requesting_principal_id="principal:openclaw",
            decision_authority=restricted.decision_authority,
            approval_release_directive=forbidden_directive,
        )
        is None
    )
    assert store.approvals == {}


def test_approval_service_rejects_releasable_deny_only_product_intent() -> None:
    restricted, _ = _restricted_authority_fixture()
    store = MemoryControlPlaneStore()
    approvals = ApprovalService(
        store=store,
        settings=GuardApiSettings(storage_backend="memory"),
    )
    deny_only = restricted.selected_decision.model_copy(
        update={
            "approval_intent": ApprovalIntent(
                options=["deny"],
                resource="action:deny-only-direct-call",
            )
        }
    )

    with pytest.raises(ValueError, match="must include allow_once"):
        approvals.create_for_decision(
            _restricted_event(),
            deny_only,
            requesting_principal_id="principal:openclaw",
            decision_authority=restricted.decision_authority,
            approval_release_directive=restricted.approval_release_directive,
        )

    assert store.approvals == {}


def test_restricted_directive_survives_approval_audit_and_response_rebuild() -> None:
    authority_evidence, decision_evidence = _restricted_authority_fixture()
    store = MemoryControlPlaneStore()
    settings = GuardApiSettings(storage_backend="memory")
    approvals = ApprovalService(store=store, settings=settings)
    event = _restricted_event()
    approval = approvals.create_for_decision(
        event,
        authority_evidence.selected_decision,
        requesting_principal_id="principal:openclaw",
        decision_authority=authority_evidence.decision_authority,
        approval_release_directive=(authority_evidence.approval_release_directive),
    )
    assert approval is not None
    assert approval.evidence["approval_release_directive"] == (
        authority_evidence.approval_release_directive.model_dump(mode="json")
    )

    audit_service = AuditService(store=store)
    persisted = audit_service.record_evaluation(
        event,
        authority_evidence.selected_decision,
        policy_bundle=PolicyBundle(),
        policy_revision=None,
        extra_metadata={"policy_digest": authority_evidence.policy_digest},
        approval_id=approval.approval_id,
        v21_evidence=decision_v21_envelope(decision_evidence.model_dump(mode="json")),
        decision_authority_evidence=product_decision_authority_envelope(
            authority_evidence
        ),
        decision_authority=authority_evidence.decision_authority,
        decision_dump=authority_evidence.selected_decision.model_dump(mode="json"),
    )
    service = EvaluationService(
        policy_service=PolicyService(store=store),
        audit_service=audit_service,
        approval_service=approvals,
    )

    response = service._rebuild_response(persisted)  # noqa: SLF001

    assert response.approval is not None
    assert response.enforcement_binding is None
    assert response.decision_authority == authority_evidence.decision_authority
    assert response.approval_release_directive == (
        authority_evidence.approval_release_directive
    )
    assert response.model_dump(mode="json")["approval_release_directive"] == (
        authority_evidence.approval_release_directive.model_dump(mode="json")
    )


def test_restricted_directive_fails_closed_without_verified_materials_or_c3() -> None:
    authority_evidence, decision_evidence = _restricted_authority_fixture()
    store = MemoryControlPlaneStore()
    settings = GuardApiSettings(
        storage_backend="memory",
        rte05_strong_binding_enabled=True,
    )
    approvals = ApprovalService(store=store, settings=settings)
    event = _restricted_event()
    approval = approvals.create_for_decision(
        event,
        authority_evidence.selected_decision,
        requesting_principal_id="principal:openclaw",
        decision_authority=authority_evidence.decision_authority,
        approval_release_directive=(authority_evidence.approval_release_directive),
    )
    assert approval is not None
    audit_service = AuditService(store=store)
    persisted = audit_service.record_evaluation(
        event,
        authority_evidence.selected_decision,
        policy_bundle=PolicyBundle(),
        policy_revision=None,
        extra_metadata={"policy_digest": authority_evidence.policy_digest},
        approval_id=approval.approval_id,
        v21_evidence=decision_v21_envelope(decision_evidence.model_dump(mode="json")),
        decision_authority_evidence=product_decision_authority_envelope(
            authority_evidence
        ),
        decision_authority=authority_evidence.decision_authority,
        decision_dump=authority_evidence.selected_decision.model_dump(mode="json"),
    )
    service = EvaluationService(
        policy_service=PolicyService(store=store),
        audit_service=audit_service,
        approval_service=approvals,
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        service._save_enforcement_binding(  # noqa: SLF001
            event,
            approval=approval,
            audit=persisted,
            materials=cast(Any, object()),
            phase_b_outcome=None,
            requesting_principal_id="principal:openclaw",
            selected_decision=authority_evidence.selected_decision,
            decision_authority=authority_evidence.decision_authority,
            approval_release_directive=(authority_evidence.approval_release_directive),
        )

    assert raised.value.code == "V21_PRODUCT_RESTRICTED_ASK_MATERIALS_INVALID"
    assert store.enforcement_bindings == {}


@pytest.mark.parametrize("carrier", ["directive", "authority"])
def test_product_commit_rejects_approval_release_carrier_drift(carrier: str) -> None:
    authority_evidence, decision_evidence = _restricted_authority_fixture()
    store = MemoryControlPlaneStore()
    approvals = ApprovalService(
        store=store,
        settings=GuardApiSettings(storage_backend="memory"),
    )
    event = _restricted_event()
    approval = approvals.create_for_decision(
        event,
        authority_evidence.selected_decision,
        requesting_principal_id="principal:openclaw",
        decision_authority=authority_evidence.decision_authority,
        approval_release_directive=authority_evidence.approval_release_directive,
    )
    assert approval is not None
    tampered_evidence = deepcopy(approval.evidence)
    if carrier == "directive":
        tampered_evidence["approval_release_directive"]["scope_digest"] = (
            "sha256:" + "b" * 64
        )
    else:
        tampered_evidence["decision_authority"]["legacy_floor_applied"] = True
    store.create_approval(approval.model_copy(update={"evidence": tampered_evidence}))

    with pytest.raises(
        CriticalDecisionEvidenceError,
        match="approval release is not bound",
    ):
        AuditService(store=store).record_evaluation(
            event,
            authority_evidence.selected_decision,
            policy_bundle=PolicyBundle(),
            policy_revision=None,
            extra_metadata={"policy_digest": authority_evidence.policy_digest},
            approval_id=approval.approval_id,
            v21_evidence=decision_v21_envelope(
                decision_evidence.model_dump(mode="json")
            ),
            decision_authority_evidence=product_decision_authority_envelope(
                authority_evidence
            ),
            decision_authority=authority_evidence.decision_authority,
            decision_dump=authority_evidence.selected_decision.model_dump(mode="json"),
        )


def test_product_rebuild_rejects_approval_directive_drift() -> None:
    authority_evidence, decision_evidence = _restricted_authority_fixture()
    store = MemoryControlPlaneStore()
    approvals = ApprovalService(
        store=store,
        settings=GuardApiSettings(storage_backend="memory"),
    )
    event = _restricted_event()
    approval = approvals.create_for_decision(
        event,
        authority_evidence.selected_decision,
        requesting_principal_id="principal:openclaw",
        decision_authority=authority_evidence.decision_authority,
        approval_release_directive=authority_evidence.approval_release_directive,
    )
    assert approval is not None
    audit_service = AuditService(store=store)
    persisted = audit_service.record_evaluation(
        event,
        authority_evidence.selected_decision,
        policy_bundle=PolicyBundle(),
        policy_revision=None,
        extra_metadata={"policy_digest": authority_evidence.policy_digest},
        approval_id=approval.approval_id,
        v21_evidence=decision_v21_envelope(decision_evidence.model_dump(mode="json")),
        decision_authority_evidence=product_decision_authority_envelope(
            authority_evidence
        ),
        decision_authority=authority_evidence.decision_authority,
        decision_dump=authority_evidence.selected_decision.model_dump(mode="json"),
    )
    tampered_evidence = deepcopy(approval.evidence)
    tampered_evidence["approval_release_directive"]["capability_digest"] = (
        "sha256:" + "c" * 64
    )
    store.create_approval(approval.model_copy(update={"evidence": tampered_evidence}))
    service = EvaluationService(
        policy_service=PolicyService(store=store),
        audit_service=audit_service,
        approval_service=approvals,
    )

    with pytest.raises(
        CriticalDecisionEvidenceError,
        match="approval release is not bound",
    ):
        service._rebuild_response(persisted)  # noqa: SLF001


def test_restricted_binding_rejects_approval_directive_drift() -> None:
    authority_evidence, decision_evidence = _restricted_authority_fixture()
    store = MemoryControlPlaneStore()
    settings = GuardApiSettings(
        storage_backend="memory",
        rte05_strong_binding_enabled=True,
    )
    approvals = ApprovalService(store=store, settings=settings)
    event = _restricted_event()
    approval = approvals.create_for_decision(
        event,
        authority_evidence.selected_decision,
        requesting_principal_id="principal:openclaw",
        decision_authority=authority_evidence.decision_authority,
        approval_release_directive=authority_evidence.approval_release_directive,
    )
    assert approval is not None
    audit_service = AuditService(store=store)
    persisted = audit_service.record_evaluation(
        event,
        authority_evidence.selected_decision,
        policy_bundle=PolicyBundle(),
        policy_revision=None,
        extra_metadata={"policy_digest": authority_evidence.policy_digest},
        approval_id=approval.approval_id,
        v21_evidence=decision_v21_envelope(decision_evidence.model_dump(mode="json")),
        decision_authority_evidence=product_decision_authority_envelope(
            authority_evidence
        ),
        decision_authority=authority_evidence.decision_authority,
        decision_dump=authority_evidence.selected_decision.model_dump(mode="json"),
    )
    tampered_evidence = deepcopy(approval.evidence)
    tampered_evidence["approval_release_directive"]["scope_digest"] = (
        "sha256:" + "d" * 64
    )
    tampered = approval.model_copy(update={"evidence": tampered_evidence})
    service = EvaluationService(
        policy_service=PolicyService(store=store),
        audit_service=audit_service,
        approval_service=approvals,
    )

    with pytest.raises(
        RuntimeError,
        match="V21_PRODUCT_APPROVAL_RELEASE_IDENTITY_MISMATCH",
    ):
        service._save_enforcement_binding(  # noqa: SLF001
            event,
            approval=tampered,
            audit=persisted,
            materials=cast(Any, object()),
            phase_b_outcome=None,
            requesting_principal_id="principal:openclaw",
            selected_decision=authority_evidence.selected_decision,
            decision_authority=authority_evidence.decision_authority,
            approval_release_directive=authority_evidence.approval_release_directive,
        )

    assert store.enforcement_bindings == {}


def test_approval_rejects_directive_authority_projection_mismatch() -> None:
    authority_evidence, _ = _restricted_authority_fixture()
    store = MemoryControlPlaneStore()
    approvals = ApprovalService(
        store=store,
        settings=GuardApiSettings(storage_backend="memory"),
    )
    incompatible = authority_evidence.decision_authority.model_copy(
        update={"approval_release": "strong_binding_required"}
    )

    with pytest.raises(
        ValueError,
        match="directive and decision authority are inconsistent",
    ):
        approvals.create_for_decision(
            _event().model_copy(update={"runtime": "openclaw"}),
            authority_evidence.selected_decision,
            requesting_principal_id="principal:openclaw",
            decision_authority=incompatible,
            approval_release_directive=(authority_evidence.approval_release_directive),
        )

    assert store.approvals == {}
