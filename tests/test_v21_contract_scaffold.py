"""V21-01 contract scaffold tests: frozen fields, enums, and round-trips."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, get_args

import pytest
from pydantic import BaseModel, ValidationError

from agentguard_core.decisions import evidence as evidence_mod
from agentguard_core.signals import models as signal_models

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_FREEZE = (
    ROOT
    / "docs"
    / "AgentGuard_Core_V2.1_Final_Contract_Freeze"
    / "contract_freeze.yaml"
)

# ---------------------------------------------------------------------------
# Frozen field sets (01_F1字段与契约冻结.md)
# ---------------------------------------------------------------------------

FROZEN_FIELDS: dict[type[BaseModel], set[str]] = {
    signal_models.SequenceRef: {
        "domain",
        "producer_binding_id",
        "value",
    },
    signal_models.EvidenceRef: {
        "ref_id",
        "kind",
        "record_type",
        "record_id",
        "json_pointer",
        "digest",
        "redaction_state",
    },
    signal_models.FactRef: {
        "fact_id",
        "fact_type",
        "origin",
        "authority",
        "evidence_refs",
    },
    signal_models.SecuritySignal: {
        "signal_id",
        "detector_id",
        "category",
        "scope",
        "impact",
        "confidence",
        "evidence_group",
        "reason_codes",
        "evidence_refs",
        "facts",
        "tags",
    },
    signal_models.PolicyViolation: {
        "violation_id",
        "rule_id",
        "policy_tier",
        "effect",
        "reason_codes",
        "evidence_refs",
    },
    signal_models.EvaluationDegradation: {
        "degradation_id",
        "component_id",
        "domain",
        "required_for_action",
        "failure_kind",
        "reason_codes",
        "evidence_refs",
    },
    signal_models.AuthorityVerdict: {
        "status",
        "matched_grant_ids",
        "missing_capabilities",
        "explicit_scope_mismatches",
        "evidence_refs",
    },
    signal_models.FlowVerdict: {
        "status",
        "strongest_strength",
        "taints",
        "external_sink",
        "path_refs",
        "evidence_refs",
    },
    evidence_mod.RequiredCheckPlan: {
        "plan_id",
        "impact",
        "required_domains",
        "optional_domains",
        "required_capabilities",
        "semantic_resolvable_dimensions",
        "reason_codes",
    },
    evidence_mod.SemanticRoutingAssessment: {
        "eligible",
        "hard_deny_present",
        "semantic_resolvable",
        "required_facts_available",
        "reason_codes",
    },
    evidence_mod.DomainCoverage: {
        "domain",
        "status",
        "as_of_sequence",
        "projector_version",
        "reason_codes",
    },
    evidence_mod.CoverageMap: {
        "task",
        "source",
        "capability",
        "behavior",
        "dataflow",
        "memory",
        "runtime_outcome",
    },
    evidence_mod.FastAssessment: {
        "schema_version",
        "assessment_id",
        "event_id",
        "action_id",
        "disposition",
        "impact",
        "required_check_plan",
        "policy_violations",
        "signals",
        "degradations",
        "authority",
        "flow",
        "semantic_routing",
        "reason_codes",
        "evidence_refs",
        "authorization_fingerprint",
        "audit_fingerprint",
        "task_digest",
        "policy_digest",
        "snapshot_digest",
        "assessment_digest",
    },
    evidence_mod.DecisionEvidenceV21: {
        "schema_version",
        "assessment_id",
        "assessment_digest",
        "snapshot_id",
        "snapshot_digest",
        "state_version",
        "required_domains",
        "coverage",
        "authority_status",
        "matched_grant_ids",
        "flow_status",
        "flow_path_refs",
        "policy_violation_ids",
        "signal_ids",
        "degradation_ids",
        "semantic_judgment_id",
        "semantic_digest",
        "legacy_decision",
        "v21_fast_disposition",
        "final_decision",
        "mode",
        "divergence_category",
        "evidence_refs",
    },
}

FORBIDDEN_DIGEST_TOKENS = (
    "latency",
    "uuid",
    "request_id",
    "debug",
    "wall_clock",
)


def _literal_values(annotation: Any) -> set[str]:
    return {value for value in get_args(annotation) if isinstance(value, str)}


def _load_contract_freeze() -> dict[str, Any]:
    return json.loads(CONTRACT_FREEZE.read_text(encoding="utf-8"))


def _sample_evidence_ref() -> dict[str, Any]:
    return {
        "ref_id": "ev_1",
        "kind": "policy_rule",
        "record_type": "guard_decision",
        "record_id": "evt_1",
        "json_pointer": None,
        "digest": "sha256:00",
        "redaction_state": "none",
    }


def _sample_sequence_ref() -> dict[str, Any]:
    return {"domain": "audit", "producer_binding_id": "binding_1", "value": 1}


def _sample_domain_coverage(domain: str) -> dict[str, Any]:
    return {
        "domain": domain,
        "status": "complete",
        "as_of_sequence": None,
        "projector_version": "projector_v1",
        "reason_codes": [],
    }


def _sample_coverage_map() -> dict[str, Any]:
    return {
        domain: _sample_domain_coverage(domain)
        for domain in (
            "task",
            "source",
            "capability",
            "behavior",
            "dataflow",
            "memory",
            "runtime_outcome",
        )
    }


def _sample_authority() -> dict[str, Any]:
    return {
        "status": "authorized",
        "matched_grant_ids": [],
        "missing_capabilities": [],
        "explicit_scope_mismatches": [],
        "evidence_refs": [],
    }


def _sample_flow() -> dict[str, Any]:
    return {
        "status": "safe",
        "strongest_strength": None,
        "taints": [],
        "external_sink": False,
        "path_refs": [],
        "evidence_refs": [],
    }


def _sample_fast_assessment() -> dict[str, Any]:
    return {
        "assessment_id": "asm_1",
        "event_id": "evt_1",
        "action_id": "act_1",
        "disposition": "DEFER",
        "impact": "moderate",
        "required_check_plan": {
            "plan_id": "plan_1",
            "impact": "moderate",
            "required_domains": ["task"],
            "optional_domains": [],
            "required_capabilities": [],
            "semantic_resolvable_dimensions": ["task_alignment"],
            "reason_codes": [],
        },
        "policy_violations": [],
        "signals": [],
        "degradations": [],
        "authority": _sample_authority(),
        "flow": _sample_flow(),
        "semantic_routing": {
            "eligible": False,
            "hard_deny_present": False,
            "semantic_resolvable": False,
            "required_facts_available": True,
            "reason_codes": [],
        },
        "reason_codes": [],
        "evidence_refs": [],
        "authorization_fingerprint": "fp_auth",
        "audit_fingerprint": "fp_audit",
        "task_digest": None,
        "policy_digest": "sha256:policy",
        "snapshot_digest": "sha256:snapshot",
        "assessment_digest": "sha256:assessment",
    }


def _sample_decision_evidence() -> dict[str, Any]:
    return {
        "assessment_id": "asm_1",
        "assessment_digest": "sha256:assessment",
        "snapshot_id": "snap_1",
        "snapshot_digest": "sha256:snapshot",
        "state_version": 1,
        "required_domains": ["task"],
        "coverage": _sample_coverage_map(),
        "authority_status": "authorized",
        "matched_grant_ids": [],
        "flow_status": "safe",
        "flow_path_refs": [],
        "policy_violation_ids": [],
        "signal_ids": [],
        "degradation_ids": [],
        "semantic_judgment_id": None,
        "semantic_digest": None,
        "legacy_decision": "ask",
        "v21_fast_disposition": "DEFER",
        "final_decision": "ask",
        "mode": "shadow",
        "divergence_category": None,
        "evidence_refs": [],
    }


SAMPLES: dict[type[BaseModel], dict[str, Any]] = {
    signal_models.SequenceRef: _sample_sequence_ref(),
    signal_models.EvidenceRef: _sample_evidence_ref(),
    signal_models.FactRef: {
        "fact_id": "fact_1",
        "fact_type": "task",
        "origin": "observed",
        "authority": "authoritative",
        "evidence_refs": [_sample_evidence_ref()],
    },
    signal_models.SecuritySignal: {
        "signal_id": "sig_1",
        "detector_id": "P001_sensitive_file_access",
        "category": "sensitive_resource",
        "scope": "event",
        "impact": "moderate",
        "confidence": "high",
        "evidence_group": "P001_sensitive_file_access",
        "reason_codes": ["P001_sensitive_file_access"],
        "evidence_refs": [_sample_evidence_ref()],
        "facts": [],
        "tags": ["legacy"],
    },
    signal_models.PolicyViolation: {
        "violation_id": "vio_1",
        "rule_id": "P001_sensitive_file_access",
        "policy_tier": "system_hard_policy",
        "effect": "deny",
        "reason_codes": [],
        "evidence_refs": [],
    },
    signal_models.EvaluationDegradation: {
        "degradation_id": "deg_1",
        "component_id": "PromptInjectionDetector",
        "domain": None,
        "required_for_action": True,
        "failure_kind": "unavailable",
        "reason_codes": [],
        "evidence_refs": [],
    },
    signal_models.AuthorityVerdict: _sample_authority(),
    signal_models.FlowVerdict: _sample_flow(),
    evidence_mod.RequiredCheckPlan: _sample_fast_assessment()["required_check_plan"],
    evidence_mod.SemanticRoutingAssessment: _sample_fast_assessment()[
        "semantic_routing"
    ],
    evidence_mod.DomainCoverage: _sample_domain_coverage("task"),
    evidence_mod.CoverageMap: _sample_coverage_map(),
    evidence_mod.FastAssessment: _sample_fast_assessment(),
    evidence_mod.DecisionEvidenceV21: _sample_decision_evidence(),
}

# ---------------------------------------------------------------------------
# Frozen field sets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model_cls", "expected_fields"),
    sorted(FROZEN_FIELDS.items(), key=lambda item: item[0].__name__),
    ids=lambda value: getattr(value, "__name__", str(value)),
)
def test_frozen_field_sets_match_contract(
    model_cls: type[BaseModel], expected_fields: set[str]
) -> None:
    assert set(model_cls.model_fields) == expected_fields


# ---------------------------------------------------------------------------
# Enum values match contract_freeze.yaml
# ---------------------------------------------------------------------------


def test_enum_literals_match_contract_freeze_yaml() -> None:
    contract = _load_contract_freeze()

    assert _literal_values(signal_models.FastDisposition) == set(
        contract["fast_dispositions"]
    )
    assert _literal_values(signal_models.CoverageDomain) == set(
        contract["coverage_domains"]
    )
    assert _literal_values(signal_models.CoverageStatus) == set(
        contract["coverage_statuses"]
    )
    assert _literal_values(signal_models.TaintLabel) == set(contract["taint_labels"])
    assert _literal_values(signal_models.FlowStrength) == set(
        contract["flow_strengths"]
    )
    assert _literal_values(signal_models.PolicyTier) == set(contract["policy_tiers"])


def test_public_decision_literal_matches_contract() -> None:
    contract = _load_contract_freeze()
    assert _literal_values(signal_models.Decision) == set(contract["public_decisions"])


def test_evaluation_degradation_failure_kind_is_frozen_8_values() -> None:
    failure_kind = evidence_mod.EvaluationDegradation.model_fields[
        "failure_kind"
    ].annotation
    assert _literal_values(failure_kind) == {
        "unavailable",
        "timeout",
        "invalid_output",
        "stale",
        "sequence_gap",
        "overflow",
        "dirty_projection",
        "unsupported",
    }


def test_evidence_ref_kind_is_frozen_13_values() -> None:
    kind = signal_models.EvidenceRef.model_fields["kind"].annotation
    assert _literal_values(kind) == {
        "guard_event",
        "audit_event",
        "task_fact",
        "source_fact",
        "flow_fact",
        "memory_fact",
        "capability_grant",
        "recent_action",
        "policy_rule",
        "runtime_receipt",
        "semantic_judgment",
        "declassification",
        "degradation",
    }


def test_frozen_literal_value_sets_match_01_doc() -> None:
    # 顶层 Literal 别名（01 §1，L11-65）。
    assert _literal_values(signal_models.ImpactClass) == {
        "low",
        "moderate",
        "high",
        "critical",
    }
    assert _literal_values(signal_models.EvidenceOrigin) == {
        "observed",
        "derived",
        "model_judgment",
    }
    assert _literal_values(signal_models.FactAuthority) == {
        "authoritative",
        "trusted_claim",
        "untrusted_claim",
        "model_judgment",
    }
    assert _literal_values(signal_models.AuthorityStatus) == {
        "authorized",
        "unauthorized",
        "unknown",
        "not_required",
    }
    assert _literal_values(signal_models.FlowStatus) == {
        "safe",
        "violation",
        "uncertain",
        "not_applicable",
    }
    assert _literal_values(signal_models.SequenceDomain) == {
        "audit",
        "runtime",
        "memory",
        "receipt",
        "policy",
    }

    # 模型字段注解（取值集按 01 文档逐字冻结）。
    assert _literal_values(
        signal_models.EvidenceRef.model_fields["redaction_state"].annotation
    ) == {"none", "redacted", "summary_only"}
    assert _literal_values(
        signal_models.FactRef.model_fields["fact_type"].annotation
    ) == {
        "task",
        "source",
        "flow",
        "memory",
        "capability",
        "action",
        "runtime_outcome",
        "declassification",
    }
    assert _literal_values(
        signal_models.PolicyViolation.model_fields["effect"].annotation
    ) == {"ask", "deny"}
    assert _literal_values(
        signal_models.SecuritySignal.model_fields["confidence"].annotation
    ) == {"low", "medium", "high"}
    assert _literal_values(
        evidence_mod.DecisionEvidenceV21.model_fields["mode"].annotation
    ) == {"shadow", "limited_enable", "active"}
    semantic_dimensions = evidence_mod.RequiredCheckPlan.model_fields[
        "semantic_resolvable_dimensions"
    ].annotation
    assert _literal_values(get_args(semantic_dimensions)[0]) == {
        "task_alignment",
        "instruction_semantics",
        "intent_ambiguity",
    }


# ---------------------------------------------------------------------------
# extra="forbid" and round-trip behavior
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model_cls",
    sorted(FROZEN_FIELDS, key=lambda cls: cls.__name__),
    ids=lambda cls: cls.__name__,
)
def test_extra_fields_are_forbidden(model_cls: type[BaseModel]) -> None:
    payload = dict(SAMPLES[model_cls])
    payload["__unknown_frozen_field__"] = True
    with pytest.raises(ValidationError):
        model_cls.model_validate(payload)


@pytest.mark.parametrize(
    "model_cls",
    sorted(FROZEN_FIELDS, key=lambda cls: cls.__name__),
    ids=lambda cls: cls.__name__,
)
def test_json_round_trip_is_stable(model_cls: type[BaseModel]) -> None:
    instance = model_cls.model_validate(SAMPLES[model_cls])
    dumped = instance.model_dump(mode="json")
    restored = model_cls.model_validate(dumped)
    assert restored == instance
    assert restored.model_dump(mode="json") == dumped


def test_fast_assessment_defaults_schema_version() -> None:
    payload = _sample_fast_assessment()
    assert "schema_version" not in payload
    assessment = evidence_mod.FastAssessment.model_validate(payload)
    assert assessment.schema_version == "2.1"

    decision_evidence = evidence_mod.DecisionEvidenceV21.model_validate(
        _sample_decision_evidence()
    )
    assert decision_evidence.schema_version == "2.1"


# ---------------------------------------------------------------------------
# Envelope / signal frozen semantics / digest whitelists
# ---------------------------------------------------------------------------


def test_decision_v21_envelope_shape() -> None:
    payload = {"assessment_id": "asm_1"}
    envelope = evidence_mod.decision_v21_envelope(payload)
    assert envelope == {
        "decision_v21": {
            "schema_version": "2.1",
            "payload": {"assessment_id": "asm_1"},
        }
    }
    assert set(envelope) == {"decision_v21"}
    assert set(envelope["decision_v21"]) == {"schema_version", "payload"}


def test_security_signal_has_no_decision_field() -> None:
    assert "decision" not in signal_models.SecuritySignal.model_fields


def test_digest_field_whitelists_are_valid_and_clean() -> None:
    whitelist_models = (
        signal_models.EvidenceRef,
        evidence_mod.FastAssessment,
        evidence_mod.DecisionEvidenceV21,
    )
    for model_cls in whitelist_models:
        whitelist = model_cls.digest_fields()
        assert isinstance(whitelist, frozenset)
        assert whitelist, f"{model_cls.__name__} digest whitelist is empty"
        declared = set(model_cls.model_fields)
        unknown = whitelist - declared
        assert not unknown, f"{model_cls.__name__} whitelists unknown: {unknown}"
        for field in whitelist:
            lowered = field.lower()
            assert not any(
                token in lowered for token in FORBIDDEN_DIGEST_TOKENS
            ), f"{model_cls.__name__}.{field} violates 01 §29 digest bans"


def test_digest_whitelists_exclude_self_digest_and_latency_shape() -> None:
    fast = evidence_mod.FastAssessment.digest_fields()
    assert "assessment_digest" not in fast

    scope_annotation = signal_models.SecuritySignal.model_fields["scope"].annotation
    assert isinstance(get_args(scope_annotation), tuple)
    assert _literal_values(
        Literal["event", "sequence", "flow", "authority"]
    ) == _literal_values(scope_annotation)
