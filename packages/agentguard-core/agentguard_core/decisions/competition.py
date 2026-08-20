"""LangGraph competition V2 official selection primitives.

This module is deliberately pure: it reads no environment variables, files,
clocks or stores.  Guard API owns activation loading and authenticated identity
checks; Core validates their typed result and deterministically selects the one
official :class:`GuardDecision`.

The competition contract is narrower than the formal V21-11 rollout contract.
It is fixed to ``competition-langgraph-v2`` / LangGraph and does not imply C11,
Gate B or cross-runtime completion.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from typing import Any, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..actions.canonical_json import canonical_hmac_sha256, canonical_sha256
from .evidence import CoverageMap, FastAssessment
from .models import ApprovalIntent, Decision, GuardDecision

__all__ = [
    "ACTIVATION_SIGNATURE_DOMAIN",
    "COMPETITION_PROFILE_ID",
    "FROZEN_ENABLED_PATH_IDS",
    "ApprovalRelease",
    "CompetitionActivationManifestV1",
    "DecisionAuthority",
    "DecisionAuthorityEvidenceV1",
    "DecisionSource",
    "EnabledV21PathId",
    "SelectionBasis",
    "V21AuthoritySelectionError",
    "V21Mode",
    "V21SelectionEligibility",
    "V21SelectionResult",
    "build_competition_activation_manifest",
    "build_decision_authority_evidence",
    "build_v21_official_decision",
    "decision_authority_envelope",
    "decision_semantic_projection",
    "match_limited_paths",
    "select_v21_authority",
    "verify_competition_activation_manifest",
]

COMPETITION_PROFILE_ID = "competition-langgraph-v2"
ACTIVATION_SIGNATURE_DOMAIN = "agentguard/competition-langgraph-v2/activation/v1"

V21Mode = Literal["off", "shadow", "limited_enable", "active"]
DecisionSource = Literal["current", "v21"]
SelectionBasis = Literal["current", "path_allowlist", "profile_all"]
ApprovalRelease = Literal[
    "not_applicable", "strong_binding_required", "forbidden"
]
EnabledV21PathId = Literal[
    "credential_unauthorized_external_egress",
    "capability_scope_mismatch_high_impact",
    "required_state_degradation",
    "forged_authority_or_allow_once_mismatch",
]

FROZEN_ENABLED_PATH_IDS: tuple[EnabledV21PathId, ...] = tuple(
    sorted(
        (
            "credential_unauthorized_external_egress",
            "capability_scope_mismatch_high_impact",
            "required_state_degradation",
            "forged_authority_or_allow_once_mismatch",
        )
    )
)  # type: ignore[assignment]

_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_HMAC_SHA256_PATTERN = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_DECISION_RANK: dict[Decision, int] = {"allow": 0, "ask": 1, "deny": 2}
_RAW_DECISION_BY_DISPOSITION: dict[str, Decision] = {
    "CLEAR_ALLOW": "allow",
    "DEFER": "ask",
    "CLEAR_DENY": "deny",
}


class V21AuthoritySelectionError(RuntimeError):
    """An active-profile authority precondition failed.

    ``code`` is safe for API error mapping.  The exception never contains a
    secret or activation payload.
    """

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CompetitionActivationManifestV1(BaseModel):
    """Strict startup-frozen activation for the competition profile."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    profile_id: Literal["competition-langgraph-v2"] = COMPETITION_PROFILE_ID
    runtime: Literal["langgraph"] = "langgraph"
    principal_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    runtime_binding_id: str = Field(min_length=1, max_length=256)
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    dataset_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    profile_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    selection_basis: Literal["path_allowlist", "profile_all"]
    enabled_path_ids: list[EnabledV21PathId]
    activation_ref_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    server_signature: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_canonical_identity(self) -> "CompetitionActivationManifestV1":
        if self.enabled_path_ids != list(FROZEN_ENABLED_PATH_IDS):
            raise ValueError(
                "enabled_path_ids must contain the four frozen paths in "
                "canonical order"
            )
        expected = canonical_sha256(self.digest_projection())
        if not hmac.compare_digest(expected, self.activation_ref_digest):
            raise ValueError("activation_ref_digest does not match manifest")
        return self

    def digest_projection(self) -> dict[str, Any]:
        """Return the exact signature-independent canonical projection."""

        dumped = self.model_dump(
            mode="json", exclude={"activation_ref_digest", "server_signature"}
        )
        return {key: dumped[key] for key in sorted(dumped)}


class DecisionAuthority(BaseModel):
    """Public authority projection returned with a committed evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: DecisionSource
    mode: Literal["shadow", "limited_enable", "active"]
    selection_basis: SelectionBasis
    matched_path_ids: list[EnabledV21PathId]
    legacy_floor_applied: bool
    activation_ref_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    approval_release: ApprovalRelease

    @model_validator(mode="after")
    def validate_authority_semantics(self) -> "DecisionAuthority":
        if self.matched_path_ids != sorted(set(self.matched_path_ids)):
            raise ValueError("matched_path_ids must be unique and canonically sorted")
        if self.source == "current":
            if self.selection_basis != "current":
                raise ValueError("current authority requires selection_basis=current")
            if self.legacy_floor_applied:
                raise ValueError("current authority cannot apply a V2 legacy floor")
            if self.approval_release != "not_applicable":
                raise ValueError("current authority has no V2 approval release")
        else:
            if self.mode == "shadow":
                raise ValueError("shadow cannot select V2 official authority")
            expected_basis = (
                "profile_all" if self.mode == "active" else "path_allowlist"
            )
            if self.selection_basis != expected_basis:
                raise ValueError(
                    f"{self.mode} V2 authority requires {expected_basis}"
                )
        return self


class DecisionAuthorityEvidenceV1(BaseModel):
    """Critical/no-drop evidence for one competition authority selection.

    The frozen ``DecisionEvidenceV21`` schema remains unchanged.  This sibling
    record retains the complete current/raw/selected objects and floor state,
    allowing the response to be rebuilt from committed audit data.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    persistence_requirement: Literal["critical_no_drop"] = "critical_no_drop"
    profile_id: Literal["competition-langgraph-v2"] = COMPETITION_PROFILE_ID
    event_id: str = Field(min_length=1)
    assessment_id: str = Field(min_length=1)
    assessment_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    snapshot_id: str = Field(min_length=1)
    snapshot_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    state_version: int = Field(ge=0)
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    dataset_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    profile_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    current_decision: GuardDecision
    current_decision_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    raw_v21_decision: GuardDecision | None
    raw_v21_decision_digest: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    selected_decision: GuardDecision
    selected_decision_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    decision_authority: DecisionAuthority

    @model_validator(mode="after")
    def validate_decision_parity(self) -> "DecisionAuthorityEvidenceV1":
        expected_current = _guard_decision_digest(self.current_decision)
        if not hmac.compare_digest(expected_current, self.current_decision_digest):
            raise ValueError("current_decision_digest does not match decision")
        expected_selected = _guard_decision_digest(self.selected_decision)
        if not hmac.compare_digest(expected_selected, self.selected_decision_digest):
            raise ValueError("selected_decision_digest does not match decision")
        if self.raw_v21_decision is None:
            if self.raw_v21_decision_digest is not None:
                raise ValueError("raw_v21_decision_digest requires a raw decision")
        else:
            expected_raw = _guard_decision_digest(self.raw_v21_decision)
            if self.raw_v21_decision_digest is None or not hmac.compare_digest(
                expected_raw, self.raw_v21_decision_digest
            ):
                raise ValueError("raw_v21_decision_digest does not match decision")
        if self.decision_authority.source == "current":
            if self.selected_decision != self.current_decision:
                raise ValueError("current authority must select current_decision exactly")
        elif self.raw_v21_decision is None:
            raise ValueError("V2 authority requires raw_v21_decision")
        if self.selected_decision.decision == "ask":
            if self.decision_authority.source == "v21":
                expected_release = (
                    "strong_binding_required"
                    if self.selected_decision.approval_intent is not None
                    else "forbidden"
                )
                if self.decision_authority.approval_release != expected_release:
                    raise ValueError("ASK approval release does not match decision")
        elif self.decision_authority.approval_release != "not_applicable":
            raise ValueError("non-ASK decision requires not_applicable release")
        return self


class V21SelectionEligibility(BaseModel):
    """Server-derived gates consumed by the pure selector.

    Authority validity is intentionally separate from ActionIR/TaskFact
    completeness: the former is an active-mode service failure, while expected
    required-state absence is a valid but unreleasable V2 ASK.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    activation_valid: bool
    trusted_identity_valid: bool
    profile_valid: bool
    revalidation_valid: bool
    pipeline_complete: bool
    ownership_valid: bool
    action_ir_complete: bool
    task_fact_present: bool
    approval_binding_eligible: bool

    @property
    def active_authority_valid(self) -> bool:
        return all(
            (
                self.activation_valid,
                self.trusted_identity_valid,
                self.profile_valid,
                self.revalidation_valid,
                self.pipeline_complete,
            )
        )

    @property
    def limited_authority_valid(self) -> bool:
        return self.active_authority_valid and self.ownership_valid


@dataclass(frozen=True)
class V21SelectionResult:
    """The sole decision object and evidence inputs selected by Core."""

    selected_decision: GuardDecision
    selected_decision_digest: str
    current_decision: GuardDecision
    raw_v21_decision: GuardDecision | None
    authority: DecisionAuthority


def build_competition_activation_manifest(
    *,
    server_secret: bytes,
    principal_id: str,
    agent_id: str,
    runtime_binding_id: str,
    policy_digest: str,
    dataset_digest: str,
    profile_digest: str,
    selection_basis: Literal["path_allowlist", "profile_all"],
) -> CompetitionActivationManifestV1:
    """Build a canonical, server-signed activation manifest."""

    _require_strong_server_secret(server_secret)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "profile_id": COMPETITION_PROFILE_ID,
        "runtime": "langgraph",
        "principal_id": principal_id,
        "agent_id": agent_id,
        "runtime_binding_id": runtime_binding_id,
        "policy_digest": policy_digest,
        "dataset_digest": dataset_digest,
        "profile_digest": profile_digest,
        "selection_basis": selection_basis,
        "enabled_path_ids": list(FROZEN_ENABLED_PATH_IDS),
    }
    activation_ref_digest = canonical_sha256(payload)
    server_signature = _activation_signature(server_secret, activation_ref_digest)
    return CompetitionActivationManifestV1.model_validate(
        {
            **payload,
            "activation_ref_digest": activation_ref_digest,
            "server_signature": server_signature,
        }
    )


def verify_competition_activation_manifest(
    manifest: CompetitionActivationManifestV1, *, server_secret: bytes
) -> bool:
    """Verify the server signature in constant-time comparison semantics."""

    if not isinstance(server_secret, bytes) or len(server_secret) < 32:
        return False
    recomputed_digest = canonical_sha256(manifest.digest_projection())
    if not hmac.compare_digest(recomputed_digest, manifest.activation_ref_digest):
        return False
    expected = _activation_signature(server_secret, manifest.activation_ref_digest)
    return hmac.compare_digest(expected, manifest.server_signature)


def _activation_signature(server_secret: bytes, activation_ref_digest: str) -> str:
    return canonical_hmac_sha256(
        server_secret,
        {
            "activation_ref_digest": activation_ref_digest,
            "domain": ACTIVATION_SIGNATURE_DOMAIN,
        },
    )


def _require_strong_server_secret(server_secret: bytes) -> None:
    if not isinstance(server_secret, bytes) or len(server_secret) < 32:
        raise ValueError("competition activation server_secret must be at least 32 bytes")


def match_limited_paths(
    assessment: FastAssessment, coverage: CoverageMap
) -> tuple[EnabledV21PathId, ...]:
    """Match only the four frozen high-confidence limited-enable paths."""

    matched: set[EnabledV21PathId] = set()
    flow = assessment.flow
    authority = assessment.authority

    if (
        flow.status == "violation"
        and flow.strongest_strength in {"exact", "strong"}
        and "CREDENTIAL" in flow.taints
        and flow.external_sink
        and authority.status == "unauthorized"
    ):
        matched.add("credential_unauthorized_external_egress")

    if (
        authority.status == "unauthorized"
        and bool(authority.explicit_scope_mismatches)
        and assessment.impact in {"high", "critical"}
    ):
        matched.add("capability_scope_mismatch_high_impact")

    if _has_required_state_degradation(assessment, coverage):
        matched.add("required_state_degradation")

    reason_codes = _all_reason_codes(assessment)
    forged_issuer = any(
        code == "v21-06:forged_issuer"
        or code.startswith("v21-06:forged_issuer:")
        for code in reason_codes
    )
    allow_once_mismatch = any(
        mismatch.endswith(":invalid_approval_grant")
        or mismatch.endswith(":fingerprint_mismatch")
        for mismatch in authority.explicit_scope_mismatches
    )
    if forged_issuer or allow_once_mismatch:
        matched.add("forged_authority_or_allow_once_mismatch")

    return tuple(sorted(matched))


def select_v21_authority(
    *,
    event_id: str,
    current_decision: GuardDecision,
    raw_v21_decision: GuardDecision | None,
    assessment: FastAssessment,
    coverage: CoverageMap,
    mode: Literal["shadow", "limited_enable", "active"],
    activation: CompetitionActivationManifestV1,
    eligibility: V21SelectionEligibility,
    snapshot_id: str,
    state_version: int,
) -> V21SelectionResult:
    """Select current or a newly built deterministic V2 official decision."""

    if event_id != assessment.event_id:
        raise V21AuthoritySelectionError("v21-competition:event_mismatch")

    matched_paths = match_limited_paths(assessment, coverage)
    policy_matches = hmac.compare_digest(
        assessment.policy_digest, activation.policy_digest
    )
    raw_matches = _raw_matches_assessment(raw_v21_decision, assessment)

    if mode == "shadow":
        return _current_result(
            current_decision=current_decision,
            raw_v21_decision=raw_v21_decision,
            mode=mode,
            activation=activation,
            matched_paths=matched_paths,
        )

    if mode == "limited_enable":
        transferable = all(
            (
                activation.selection_basis == "path_allowlist",
                eligibility.limited_authority_valid,
                policy_matches,
                raw_matches,
                raw_v21_decision is not None,
                bool(matched_paths),
                _not_weaker(raw_v21_decision, current_decision),
            )
        )
        if not transferable:
            return _current_result(
                current_decision=current_decision,
                raw_v21_decision=raw_v21_decision,
                mode=mode,
                activation=activation,
                matched_paths=matched_paths,
            )
        assert raw_v21_decision is not None
        return build_v21_official_decision(
            event_id=event_id,
            current_decision=current_decision,
            raw_v21_decision=raw_v21_decision,
            assessment=assessment,
            coverage=coverage,
            mode=mode,
            activation=activation,
            eligibility=eligibility,
            snapshot_id=snapshot_id,
            state_version=state_version,
            matched_path_ids=matched_paths,
        )

    if activation.selection_basis != "profile_all":
        raise V21AuthoritySelectionError(
            "v21-competition:activation_selection_basis_mismatch"
        )
    if not eligibility.active_authority_valid:
        raise V21AuthoritySelectionError(
            "v21-competition:active_authority_precondition_failed"
        )
    if not policy_matches:
        raise V21AuthoritySelectionError("v21-competition:policy_digest_mismatch")
    if not raw_matches or raw_v21_decision is None:
        raise V21AuthoritySelectionError("v21-competition:raw_v21_unavailable")
    return build_v21_official_decision(
        event_id=event_id,
        current_decision=current_decision,
        raw_v21_decision=raw_v21_decision,
        assessment=assessment,
        coverage=coverage,
        mode=mode,
        activation=activation,
        eligibility=eligibility,
        snapshot_id=snapshot_id,
        state_version=state_version,
        matched_path_ids=matched_paths,
    )


def build_v21_official_decision(
    *,
    event_id: str,
    current_decision: GuardDecision,
    raw_v21_decision: GuardDecision,
    assessment: FastAssessment,
    coverage: CoverageMap,
    mode: Literal["limited_enable", "active"],
    activation: CompetitionActivationManifestV1,
    eligibility: V21SelectionEligibility,
    snapshot_id: str,
    state_version: int,
    matched_path_ids: Sequence[EnabledV21PathId],
) -> V21SelectionResult:
    """Apply the safety floor and build a new deterministic V2 decision."""

    legacy_floor_applied = (
        _DECISION_RANK[current_decision.decision]
        > _DECISION_RANK[raw_v21_decision.decision]
    )
    base = current_decision if legacy_floor_applied else raw_v21_decision
    approval_release = _approval_release(
        base.decision,
        assessment=assessment,
        coverage=coverage,
        eligibility=eligibility,
    )
    approval_intent: ApprovalIntent | None = None
    if approval_release == "strong_binding_required":
        approval_intent = base.approval_intent or ApprovalIntent(
            resource=f"action:{assessment.action_id}"
        )

    canonical_paths = tuple(sorted(set(matched_path_ids)))
    selection_basis: Literal["path_allowlist", "profile_all"] = (
        "profile_all" if mode == "active" else "path_allowlist"
    )
    authority = DecisionAuthority(
        source="v21",
        mode=mode,
        selection_basis=selection_basis,
        matched_path_ids=list(canonical_paths),
        legacy_floor_applied=legacy_floor_applied,
        activation_ref_digest=activation.activation_ref_digest,
        approval_release=approval_release,
    )
    identity = {
        "schema_version": "1.0",
        "event_id": event_id,
        "assessment_id": assessment.assessment_id,
        "assessment_digest": assessment.assessment_digest,
        "raw_v21_decision": decision_semantic_projection(raw_v21_decision),
        "current_decision": decision_semantic_projection(current_decision),
        "mode": mode,
        "activation_ref_digest": activation.activation_ref_digest,
        "selection_basis": selection_basis,
        "matched_path_ids": list(canonical_paths),
        "legacy_floor_applied": legacy_floor_applied,
        "approval_release": approval_release,
        "snapshot_id": snapshot_id,
        "snapshot_digest": assessment.snapshot_digest,
        "state_version": state_version,
        "policy_digest": assessment.policy_digest,
        "profile_digest": activation.profile_digest,
        "selected_decision": base.decision,
    }
    decision_id = "dec:v21-official:" + canonical_sha256(identity).removeprefix(
        "sha256:"
    )
    selected = base.model_copy(
        update={
            "decision_id": decision_id,
            "approval_intent": approval_intent,
            "latency_ms": None,
        }
    )
    return V21SelectionResult(
        selected_decision=selected,
        selected_decision_digest=_guard_decision_digest(selected),
        current_decision=current_decision,
        raw_v21_decision=raw_v21_decision,
        authority=authority,
    )


def build_decision_authority_evidence(
    *,
    result: V21SelectionResult,
    assessment: FastAssessment,
    activation: CompetitionActivationManifestV1,
    snapshot_id: str,
    state_version: int,
) -> DecisionAuthorityEvidenceV1:
    """Build the strict sibling evidence that must be persisted atomically."""

    raw_digest = (
        _guard_decision_digest(result.raw_v21_decision)
        if result.raw_v21_decision is not None
        else None
    )
    return DecisionAuthorityEvidenceV1(
        event_id=assessment.event_id,
        assessment_id=assessment.assessment_id,
        assessment_digest=assessment.assessment_digest,
        snapshot_id=snapshot_id,
        snapshot_digest=assessment.snapshot_digest,
        state_version=state_version,
        policy_digest=assessment.policy_digest,
        dataset_digest=activation.dataset_digest,
        profile_digest=activation.profile_digest,
        current_decision=result.current_decision,
        current_decision_digest=_guard_decision_digest(result.current_decision),
        raw_v21_decision=result.raw_v21_decision,
        raw_v21_decision_digest=raw_digest,
        selected_decision=result.selected_decision,
        selected_decision_digest=result.selected_decision_digest,
        decision_authority=result.authority,
    )


def decision_authority_envelope(
    evidence: DecisionAuthorityEvidenceV1,
) -> dict[str, Any]:
    """Return the audit sibling envelope; callers must treat it as critical."""

    return {
        "decision_authority": {
            "schema_version": "1.0",
            "payload": evidence.model_dump(mode="json"),
        }
    }


def decision_semantic_projection(decision: GuardDecision) -> dict[str, Any]:
    """Project stable decision semantics for deterministic official identity.

    Current Core decision IDs are UUID-backed and latency is wall-clock derived;
    neither may make an otherwise identical competition request non-replayable.
    Their complete original values remain in ``DecisionAuthorityEvidenceV1``.
    """

    dumped = decision.model_dump(mode="json")
    return {
        key: dumped[key]
        for key in sorted(dumped)
        if key not in {"decision_id", "latency_ms"}
    }


def _current_result(
    *,
    current_decision: GuardDecision,
    raw_v21_decision: GuardDecision | None,
    mode: Literal["shadow", "limited_enable"],
    activation: CompetitionActivationManifestV1,
    matched_paths: Sequence[EnabledV21PathId],
) -> V21SelectionResult:
    authority = DecisionAuthority(
        source="current",
        mode=mode,
        selection_basis="current",
        matched_path_ids=list(matched_paths),
        legacy_floor_applied=False,
        activation_ref_digest=activation.activation_ref_digest,
        approval_release="not_applicable",
    )
    return V21SelectionResult(
        selected_decision=current_decision,
        selected_decision_digest=_guard_decision_digest(current_decision),
        current_decision=current_decision,
        raw_v21_decision=raw_v21_decision,
        authority=authority,
    )


def _not_weaker(
    raw_v21_decision: GuardDecision | None, current_decision: GuardDecision
) -> bool:
    return raw_v21_decision is not None and (
        _DECISION_RANK[raw_v21_decision.decision]
        >= _DECISION_RANK[current_decision.decision]
    )


def _raw_matches_assessment(
    raw_v21_decision: GuardDecision | None, assessment: FastAssessment
) -> bool:
    return raw_v21_decision is not None and (
        raw_v21_decision.decision
        == _RAW_DECISION_BY_DISPOSITION[assessment.disposition]
    )


def _approval_release(
    decision: Decision,
    *,
    assessment: FastAssessment,
    coverage: CoverageMap,
    eligibility: V21SelectionEligibility,
) -> ApprovalRelease:
    if decision != "ask":
        return "not_applicable"
    fingerprints_complete = bool(
        _HMAC_SHA256_PATTERN.fullmatch(assessment.authorization_fingerprint)
        and _SHA256_PATTERN.fullmatch(assessment.audit_fingerprint)
    )
    task_digest_complete = bool(
        assessment.task_digest is not None
        and _SHA256_PATTERN.fullmatch(assessment.task_digest)
    )
    reviewable = all(
        (
            eligibility.approval_binding_eligible,
            eligibility.action_ir_complete,
            eligibility.task_fact_present,
            fingerprints_complete,
            task_digest_complete,
            not _has_required_state_degradation(assessment, coverage),
        )
    )
    return "strong_binding_required" if reviewable else "forbidden"


def _has_required_state_degradation(
    assessment: FastAssessment, coverage: CoverageMap
) -> bool:
    if any(item.required_for_action for item in assessment.degradations):
        return True
    return any(
        getattr(coverage, domain).status not in {"complete", "not_applicable"}
        for domain in assessment.required_check_plan.required_domains
    )


def _all_reason_codes(assessment: FastAssessment) -> set[str]:
    codes = set(assessment.reason_codes)
    for degradation in assessment.degradations:
        codes.update(degradation.reason_codes)
    for signal in assessment.signals:
        codes.update(signal.reason_codes)
    for violation in assessment.policy_violations:
        codes.update(violation.reason_codes)
    return codes


def _guard_decision_digest(decision: GuardDecision) -> str:
    return canonical_sha256(decision.model_dump(mode="json"))
