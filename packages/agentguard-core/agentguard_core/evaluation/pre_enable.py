"""C10 operational pre-enable report contracts and aggregation.

The report is deliberately observational.  It makes evidence completeness and
effect metrics queryable before any decision-changing enable, but it neither
applies a numerical threshold nor asserts that formal Gate B passed.

Each rate carries its numerator and denominator.  Receipt, decision, attack,
and latency observations are separate inputs so one population cannot silently
stand in for another.
"""

from __future__ import annotations

import re
from math import ceil, isclose
from typing import Any, Literal, Mapping, Sequence

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from ..actions.canonical_json import canonical_sha256
from ..decisions.divergence import (
    DEGRADED_COMPONENT_FAILURE,
    DEGRADED_NO_SNAPSHOT,
    DEGRADED_STALE_JUDGMENT,
    DIVERGENCE_VOCABULARY,
)

__all__ = [
    "AttackOutcomeObservation",
    "DecisionComparisonObservation",
    "DivergenceCategoryCount",
    "EvidenceCheck",
    "EvaluationRunPreEnableExtension",
    "LatencyObservation",
    "LatencySummary",
    "PreEnableReport",
    "PreEnableReportInput",
    "RatioMetric",
    "ReceiptEligibilityDescriptor",
    "ReceiptEligibilityExpectation",
    "ReceiptObservation",
    "build_receipt_eligibility_descriptor",
    "build_pre_enable_report",
    "compute_receipt_eligibility_digest",
    "evaluation_run_extension",
    "receipt_eligibility_digest_projection",
    "validate_receipt_eligibility_descriptor",
    "validate_evaluation_run_extension",
    "validate_pre_enable_report",
]


Decision = Literal["allow", "deny", "ask"]
EvidenceCheckKind = Literal["failure_injection", "flag_rollback"]
EvidenceCheckStatus = Literal["passed", "failed"]
ReceiptState = Literal["authoritative_terminal", "missing", "link_conflict"]
AttackOutcome = Literal["harmful_execution", "prevented", "unknown"]
MetricAvailability = Literal["available", "partial", "unavailable"]
EVALUATION_RUN_PRE_ENABLE_REPORT_KEY = "pre_enable_report"
_DISPLAY_SAFE_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}")
_SHA256_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_CREDENTIAL_LIKE_RE = re.compile(
    r"(?:"
    r"sk-[A-Za-z0-9][A-Za-z0-9._-]{8,}"
    r"|gh[pousr]_[A-Za-z0-9]{8,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r")"
)
_FORBIDDEN_DISPLAY_KEY_RE = re.compile(
    r"(?:authorization[_-]?fingerprint|fingerprint|runtime[_-]?binding|"
    r"lease[_-]?token|nonce|token|secret|password|credential)",
    re.IGNORECASE,
)
_FORBIDDEN_RUNTIME_DIGEST_RE = re.compile(
    r"(?:hmac-sha256:[0-9a-f]{64}|lease-v1:[0-9a-f]{64})",
    re.IGNORECASE,
)
_OPAQUE_AUTH_TOKEN_RE = re.compile(
    r"(?:"
    r"agt_tok_[0-9a-f]{32}"
    r"|[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"|bearer(?:[:_-])[A-Za-z0-9._-]{8,}"
    r")",
    re.IGNORECASE,
)
_DEGRADED_DIVERGENCE_CATEGORIES = frozenset(
    {
        DEGRADED_COMPONENT_FAILURE,
        DEGRADED_NO_SNAPSHOT,
        DEGRADED_STALE_JUDGMENT,
    }
)
_NORMALIZED_DIVERGENCE_GRID: Mapping[tuple[Decision, Decision], str | None] = {
    ("allow", "allow"): None,
    ("allow", "ask"): "legacy_allow__v21_defer",
    ("allow", "deny"): "legacy_allow__v21_clear_deny",
    ("ask", "allow"): "legacy_ask__v21_clear_allow",
    ("ask", "ask"): None,
    ("ask", "deny"): "legacy_ask__v21_clear_deny",
    ("deny", "allow"): "legacy_deny__v21_clear_allow",
    ("deny", "ask"): "legacy_deny__v21_defer",
    ("deny", "deny"): None,
}


class RatioMetric(BaseModel):
    """An exact count ratio; zero denominators serialize with ``value=null``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    value: float | None = Field(default=None, ge=0, le=1)

    @model_validator(mode="before")
    @classmethod
    def validate_and_fill_value(cls, data: Any) -> Any:
        if not isinstance(data, Mapping):
            return data
        numerator = data.get("numerator")
        denominator = data.get("denominator")
        if not isinstance(numerator, int) or isinstance(numerator, bool):
            return data
        if not isinstance(denominator, int) or isinstance(denominator, bool):
            return data
        if numerator > denominator:
            raise ValueError("ratio numerator cannot exceed denominator")
        expected = numerator / denominator if denominator else None
        supplied = data.get("value")
        if "value" in data and not _same_optional_float(supplied, expected):
            raise ValueError("ratio value must equal numerator / denominator")
        normalized = dict(data)
        normalized["value"] = expected
        return normalized

    @model_validator(mode="after")
    def validate_derived_value(self) -> RatioMetric:
        if self.numerator > self.denominator:
            raise ValueError("ratio numerator cannot exceed denominator")
        expected = self.numerator / self.denominator if self.denominator else None
        if not _same_optional_float(self.value, expected):
            raise ValueError("ratio value must equal numerator / denominator")
        return self


class ReceiptEligibilityDescriptor(BaseModel):
    """Content-addressed population that freezes the receipt denominator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["receipt-eligibility/1.0"] = "receipt-eligibility/1.0"
    eligibility_revision: str = Field(min_length=1, max_length=128)
    runtime_profile: str = Field(min_length=1, max_length=128)
    eligible_action_keys: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    eligibility_digest: str

    @field_validator("eligibility_revision", "runtime_profile")
    @classmethod
    def validate_identity_token(cls, value: str) -> str:
        return _display_safe_token(value, field_name="eligibility identity")

    @field_validator("eligible_action_keys")
    @classmethod
    def validate_eligible_action_keys(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            _display_safe_token(item, field_name="eligible action key")
        if tuple(sorted(value)) != value or len(set(value)) != len(value):
            raise ValueError("eligible action keys must be sorted and unique")
        return value

    @field_validator("evidence_refs")
    @classmethod
    def validate_descriptor_evidence_refs(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        _validate_display_safe_refs(value)
        if tuple(sorted(value)) != value:
            raise ValueError("eligibility evidence refs must be sorted")
        return value

    @field_validator("eligibility_digest")
    @classmethod
    def validate_digest_shape(cls, value: str) -> str:
        if _SHA256_DIGEST_RE.fullmatch(value) is None:
            raise ValueError("eligibility digest must be a full sha256 digest")
        return value

    @model_validator(mode="after")
    def validate_eligibility_digest(self) -> ReceiptEligibilityDescriptor:
        expected = compute_receipt_eligibility_digest(self)
        if self.eligibility_digest != expected:
            raise ValueError("eligibility digest does not match descriptor content")
        return self


class ReceiptEligibilityExpectation(BaseModel):
    """Server/profile-owned identity used to reject caller-rebased populations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    eligibility_revision: str = Field(min_length=1, max_length=128)
    runtime_profile: str = Field(min_length=1, max_length=128)
    eligibility_digest: str

    @field_validator("eligibility_revision", "runtime_profile")
    @classmethod
    def validate_identity_token(cls, value: str) -> str:
        return _display_safe_token(value, field_name="eligibility expectation")

    @field_validator("eligibility_digest")
    @classmethod
    def validate_digest_shape(cls, value: str) -> str:
        if _SHA256_DIGEST_RE.fullmatch(value) is None:
            raise ValueError("eligibility digest must be a full sha256 digest")
        return value


class ReceiptObservation(BaseModel):
    """One C2-capable action in the frozen receipt denominator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_key: str = Field(min_length=1, max_length=256)
    receipt_state: ReceiptState

    @field_validator("action_key")
    @classmethod
    def validate_action_key(cls, value: str) -> str:
        return _display_safe_token(value, field_name="receipt action key")


class DecisionComparisonObservation(BaseModel):
    """One paired current-official and V2-shadow decision observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_key: str = Field(min_length=1)
    official_decision: Decision
    v2_shadow_decision: Decision
    is_malicious: bool | None = None
    divergence_category: str | None = None

    @field_validator("divergence_category")
    @classmethod
    def validate_divergence_vocabulary(cls, value: str | None) -> str | None:
        if value is not None and value not in DIVERGENCE_VOCABULARY:
            raise ValueError("divergence category is outside the frozen vocabulary")
        return value

    @model_validator(mode="after")
    def validate_grid_category(self) -> DecisionComparisonObservation:
        if self.divergence_category in _DEGRADED_DIVERGENCE_CATEGORIES:
            return self
        expected = _NORMALIZED_DIVERGENCE_GRID[
            (self.official_decision, self.v2_shadow_decision)
        ]
        if (
            self.divergence_category is not None
            and self.divergence_category != expected
        ):
            raise ValueError("divergence category conflicts with paired decisions")
        return self


class DivergenceCategoryCount(BaseModel):
    """One frozen divergence category and its deterministic count."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: str
    count: int = Field(ge=1)

    @field_validator("category")
    @classmethod
    def validate_category(cls, value: str) -> str:
        if value not in DIVERGENCE_VOCABULARY:
            raise ValueError("divergence category is outside the frozen vocabulary")
        return value


class AttackOutcomeObservation(BaseModel):
    """One real attack attempt and its runtime/sandbox-derived outcome."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_key: str = Field(min_length=1)
    outcome: AttackOutcome


class LatencyObservation(BaseModel):
    """One evaluation eligible for latency observation."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    observation_key: str = Field(min_length=1)
    latency_ms: float | None = Field(default=None, ge=0)


class EvidenceCheck(BaseModel):
    """Display-safe evidence for failure injection or flag rollback."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    check_id: str = Field(min_length=1, max_length=128)
    kind: EvidenceCheckKind
    status: EvidenceCheckStatus
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    reason_code: str = Field(min_length=1, max_length=128)

    @field_validator("check_id", "reason_code")
    @classmethod
    def validate_display_token(cls, value: str) -> str:
        return _display_safe_token(value, field_name="evidence check token")

    @field_validator("evidence_refs")
    @classmethod
    def validate_evidence_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        _validate_display_safe_refs(value)
        return value


class PreEnableReportInput(BaseModel):
    """Typed, denominator-explicit inputs for one C10 report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    receipt_eligibility: ReceiptEligibilityDescriptor
    receipt_observations: tuple[ReceiptObservation, ...] = ()
    decision_observations: tuple[DecisionComparisonObservation, ...] = ()
    attack_observations: tuple[AttackOutcomeObservation, ...] = ()
    latency_observations: tuple[LatencyObservation, ...] = ()
    failure_injection: tuple[EvidenceCheck, ...] = Field(min_length=1)
    flag_rollback: tuple[EvidenceCheck, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_observations_and_evidence(self) -> PreEnableReportInput:
        receipt_keys = [
            observation.action_key for observation in self.receipt_observations
        ]
        if len(set(receipt_keys)) != len(receipt_keys):
            raise ValueError("receipt observation keys must be unique")
        if tuple(receipt_keys) != self.receipt_eligibility.eligible_action_keys:
            raise ValueError(
                "receipt observations must canonically and exactly cover frozen eligible action keys"
            )
        for name, observations in (
            ("decision", self.decision_observations),
            ("attack", self.attack_observations),
            ("latency", self.latency_observations),
        ):
            keys = [observation.observation_key for observation in observations]
            if len(set(keys)) != len(keys):
                raise ValueError(f"{name} observation keys must be unique")
            if tuple(sorted(keys)) != tuple(keys):
                raise ValueError(f"{name} observations must be canonically sorted")
        _validate_evidence_checks(
            self.failure_injection,
            expected_kind="failure_injection",
            collection_name="failure_injection",
        )
        _validate_evidence_checks(
            self.flag_rollback,
            expected_kind="flag_rollback",
            collection_name="flag_rollback",
        )
        all_check_ids = [
            check.check_id for check in (*self.failure_injection, *self.flag_rollback)
        ]
        if len(set(all_check_ids)) != len(all_check_ids):
            raise ValueError("evidence check IDs must be unique")
        return self


class LatencySummary(BaseModel):
    """Deterministic nearest-rank latency summary with sample coverage."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    method: Literal["nearest_rank"] = "nearest_rank"
    sample_coverage: RatioMetric
    average_ms: float | None = Field(default=None, ge=0)
    p50_ms: float | None = Field(default=None, ge=0)
    p95_ms: float | None = Field(default=None, ge=0)
    p99_ms: float | None = Field(default=None, ge=0)
    max_ms: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_empty_shape(self) -> LatencySummary:
        values = (
            self.average_ms,
            self.p50_ms,
            self.p95_ms,
            self.p99_ms,
            self.max_ms,
        )
        if self.sample_coverage.numerator == 0 and any(
            value is not None for value in values
        ):
            raise ValueError("latency values require at least one sample")
        if self.sample_coverage.numerator > 0 and any(
            value is None for value in values
        ):
            raise ValueError("latency values are required when samples exist")
        if self.sample_coverage.numerator > 0:
            assert self.average_ms is not None
            assert self.p50_ms is not None
            assert self.p95_ms is not None
            assert self.p99_ms is not None
            assert self.max_ms is not None
            if not self.p50_ms <= self.p95_ms <= self.p99_ms <= self.max_ms:
                raise ValueError("latency percentiles and max must be monotonic")
            if self.average_ms > self.max_ms:
                raise ValueError("average latency cannot exceed max latency")
        return self


class ObservationalEffectGate(BaseModel):
    """Frozen declaration that C10 effect metrics do not gate this build."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["skipped"] = "skipped"
    mode: Literal["observational"] = "observational"
    numerical_thresholds_applied: Literal[False] = False
    reason: Literal["effect_metrics_are_observational"] = (
        "effect_metrics_are_observational"
    )


class PreEnableReport(BaseModel):
    """Persistable C10 evidence report attached to an EvaluationRun."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["pre-enable-report/1.0"] = "pre-enable-report/1.0"
    report_mode: Literal["observational"] = "observational"
    official_decision_source: Literal["current"] = "current"
    v2_decision_mode: Literal["shadow"] = "shadow"
    benign_ask_source: Literal["v2_shadow"] = "v2_shadow"
    receipt_eligibility: ReceiptEligibilityDescriptor
    eligible_action_count: int = Field(ge=0)
    terminal_receipt_count: int = Field(ge=0)
    unknown_attack_outcome_count: int = Field(ge=0)
    receipt_coverage: RatioMetric
    link_conflicts: RatioMetric
    official_v2_divergence: RatioMetric
    divergence_categories: tuple[DivergenceCategoryCount, ...] = ()
    degraded_divergence_count: int = Field(ge=0)
    unexplained_divergence_count: int = Field(ge=0)
    divergence_explanation_coverage: RatioMetric
    benign_ask: RatioMetric
    decision_label_coverage: RatioMetric
    decision_label_availability: MetricAvailability
    final_asr: RatioMetric
    attack_outcome_coverage: RatioMetric
    final_asr_availability: MetricAvailability
    latency: LatencySummary
    failure_injection: tuple[EvidenceCheck, ...] = Field(min_length=1)
    flag_rollback: tuple[EvidenceCheck, ...] = Field(min_length=1)
    functional_evidence_status: EvidenceCheckStatus
    effect_gate: ObservationalEffectGate = Field(
        default_factory=ObservationalEffectGate
    )
    formal_gate_b: Literal["not_asserted"] = "not_asserted"

    @model_validator(mode="after")
    def validate_cross_field_counts(self) -> PreEnableReport:
        if (
            len(self.receipt_eligibility.eligible_action_keys)
            != self.eligible_action_count
        ):
            raise ValueError(
                "eligible action count must come from receipt eligibility descriptor"
            )
        if self.receipt_coverage.denominator != self.eligible_action_count:
            raise ValueError("receipt coverage denominator must equal eligible actions")
        if self.receipt_coverage.numerator != self.terminal_receipt_count:
            raise ValueError("receipt coverage numerator must equal terminal receipts")
        if self.link_conflicts.denominator != self.eligible_action_count:
            raise ValueError("link-conflict denominator must equal eligible actions")
        if (
            self.terminal_receipt_count + self.link_conflicts.numerator
            > self.eligible_action_count
        ):
            raise ValueError(
                "terminal receipts and link conflicts are disjoint eligible states"
            )
        category_names = [item.category for item in self.divergence_categories]
        if tuple(sorted(category_names)) != tuple(category_names) or len(
            set(category_names)
        ) != len(category_names):
            raise ValueError("divergence categories must be sorted and unique")
        categorized = sum(item.count for item in self.divergence_categories)
        if (
            categorized + self.unexplained_divergence_count
            != self.official_v2_divergence.numerator
        ):
            raise ValueError(
                "categorized and unexplained divergence must cover all divergence"
            )
        degraded_from_categories = sum(
            item.count
            for item in self.divergence_categories
            if item.category in _DEGRADED_DIVERGENCE_CATEGORIES
        )
        if self.degraded_divergence_count != degraded_from_categories:
            raise ValueError("degraded divergence count must match category counts")
        if (
            self.divergence_explanation_coverage.denominator
            != self.official_v2_divergence.numerator
            or self.divergence_explanation_coverage.numerator != categorized
        ):
            raise ValueError(
                "divergence explanation coverage must match categorized divergence"
            )
        if (
            self.decision_label_coverage.denominator
            != self.official_v2_divergence.denominator
        ):
            raise ValueError(
                "decision-label coverage denominator must include all comparisons"
            )
        if self.benign_ask.denominator > self.decision_label_coverage.numerator:
            raise ValueError("benign ASK denominator cannot exceed labeled decisions")
        expected_label_availability = _metric_availability(
            measured=self.decision_label_coverage.numerator,
            total=self.decision_label_coverage.denominator,
        )
        if self.decision_label_availability != expected_label_availability:
            raise ValueError(
                "decision-label availability must match decision-label coverage"
            )
        if self.final_asr.denominator != self.attack_outcome_coverage.numerator:
            raise ValueError("Final ASR denominator must include only known outcomes")
        if (
            self.attack_outcome_coverage.numerator + self.unknown_attack_outcome_count
            != self.attack_outcome_coverage.denominator
        ):
            raise ValueError(
                "known and unknown outcome counts must cover all attack attempts"
            )
        expected_availability = _metric_availability(
            measured=self.attack_outcome_coverage.numerator,
            total=self.attack_outcome_coverage.denominator,
        )
        if self.final_asr_availability != expected_availability:
            raise ValueError("Final ASR availability must match outcome coverage")
        _validate_evidence_checks(
            self.failure_injection,
            expected_kind="failure_injection",
            collection_name="failure_injection",
        )
        _validate_evidence_checks(
            self.flag_rollback,
            expected_kind="flag_rollback",
            collection_name="flag_rollback",
        )
        all_check_ids = [
            check.check_id for check in (*self.failure_injection, *self.flag_rollback)
        ]
        if len(set(all_check_ids)) != len(all_check_ids):
            raise ValueError("evidence check IDs must be unique")
        expected_status: EvidenceCheckStatus = (
            "passed"
            if all(
                check.status == "passed"
                for check in (*self.failure_injection, *self.flag_rollback)
            )
            else "failed"
        )
        if self.functional_evidence_status != expected_status:
            raise ValueError(
                "functional evidence status must reflect all evidence checks"
            )
        return self


def receipt_eligibility_digest_projection(
    descriptor: ReceiptEligibilityDescriptor,
) -> dict[str, Any]:
    """Return the canonical descriptor projection without its self digest."""

    projection = descriptor.model_dump(mode="json")
    projection.pop("eligibility_digest", None)
    return projection


def compute_receipt_eligibility_digest(
    descriptor: ReceiptEligibilityDescriptor,
) -> str:
    """Compute the restricted-canonical digest for an eligibility descriptor."""

    return canonical_sha256(receipt_eligibility_digest_projection(descriptor))


def build_receipt_eligibility_descriptor(
    *,
    eligibility_revision: str,
    runtime_profile: str,
    eligible_action_keys: Sequence[str],
    evidence_refs: Sequence[str],
) -> ReceiptEligibilityDescriptor:
    """Build a canonical descriptor; duplicates remain invalid, never deduplicated."""

    projection = {
        "schema_version": "receipt-eligibility/1.0",
        "eligibility_revision": eligibility_revision,
        "runtime_profile": runtime_profile,
        "eligible_action_keys": sorted(eligible_action_keys),
        "evidence_refs": sorted(evidence_refs),
    }
    return ReceiptEligibilityDescriptor.model_validate(
        {
            **projection,
            "eligibility_digest": canonical_sha256(projection),
        }
    )


def validate_receipt_eligibility_descriptor(
    descriptor: ReceiptEligibilityDescriptor | Mapping[str, Any],
    *,
    expected: ReceiptEligibilityExpectation | Mapping[str, Any],
) -> ReceiptEligibilityDescriptor:
    """Bind a caller descriptor to a server/profile-owned expected identity.

    ``expected`` must come from machine profile or server configuration, never
    from the evaluation request being validated.  This external anchor is what
    prevents a caller from deleting a missing action and recomputing a smaller
    internally consistent descriptor.
    """

    validated = (
        descriptor
        if isinstance(descriptor, ReceiptEligibilityDescriptor)
        else ReceiptEligibilityDescriptor.model_validate(descriptor)
    )
    expectation = (
        expected
        if isinstance(expected, ReceiptEligibilityExpectation)
        else ReceiptEligibilityExpectation.model_validate(expected)
    )
    if (
        validated.eligibility_revision != expectation.eligibility_revision
        or validated.runtime_profile != expectation.runtime_profile
        or validated.eligibility_digest != expectation.eligibility_digest
    ):
        raise ValueError(
            "receipt eligibility descriptor does not match the trusted profile anchor"
        )
    return validated


def build_pre_enable_report(
    inputs: PreEnableReportInput | Mapping[str, Any],
    *,
    expected_receipt_eligibility: ReceiptEligibilityExpectation | Mapping[str, Any],
) -> PreEnableReport:
    """Aggregate denominator-explicit observations into a strict C10 report."""

    source = (
        inputs
        if isinstance(inputs, PreEnableReportInput)
        else PreEnableReportInput.model_validate(inputs)
    )
    validate_receipt_eligibility_descriptor(
        source.receipt_eligibility,
        expected=expected_receipt_eligibility,
    )
    eligible_actions = len(source.receipt_eligibility.eligible_action_keys)
    terminal_receipts = sum(
        observation.receipt_state == "authoritative_terminal"
        for observation in source.receipt_observations
    )
    link_conflicts = sum(
        observation.receipt_state == "link_conflict"
        for observation in source.receipt_observations
    )
    comparable_decisions = len(source.decision_observations)
    divergence_categories: dict[str, int] = {}
    unexplained_divergences = 0
    for observation in source.decision_observations:
        category = observation.divergence_category
        expected_category = _NORMALIZED_DIVERGENCE_GRID[
            (observation.official_decision, observation.v2_shadow_decision)
        ]
        if category is None and expected_category is not None:
            unexplained_divergences += 1
        elif category is not None:
            divergence_categories[category] = divergence_categories.get(category, 0) + 1
    categorized_divergences = sum(divergence_categories.values())
    divergences = categorized_divergences + unexplained_divergences
    degraded_divergences = sum(
        count
        for category, count in divergence_categories.items()
        if category in _DEGRADED_DIVERGENCE_CATEGORIES
    )
    benign_decisions = [
        observation
        for observation in source.decision_observations
        if observation.is_malicious is False
    ]
    labeled_decision_count = sum(
        observation.is_malicious is not None
        for observation in source.decision_observations
    )
    benign_asks = sum(
        observation.v2_shadow_decision == "ask" for observation in benign_decisions
    )
    harmful_executions = sum(
        observation.outcome == "harmful_execution"
        for observation in source.attack_observations
    )
    unknown_attack_outcomes = sum(
        observation.outcome == "unknown" for observation in source.attack_observations
    )
    known_attack_outcomes = len(source.attack_observations) - unknown_attack_outcomes
    evidence = (*source.failure_injection, *source.flag_rollback)
    functional_status: EvidenceCheckStatus = (
        "passed" if all(check.status == "passed" for check in evidence) else "failed"
    )
    return PreEnableReport(
        receipt_eligibility=source.receipt_eligibility,
        eligible_action_count=eligible_actions,
        terminal_receipt_count=terminal_receipts,
        unknown_attack_outcome_count=unknown_attack_outcomes,
        receipt_coverage=_ratio(terminal_receipts, eligible_actions),
        link_conflicts=_ratio(link_conflicts, eligible_actions),
        official_v2_divergence=_ratio(divergences, comparable_decisions),
        divergence_categories=tuple(
            DivergenceCategoryCount(category=category, count=count)
            for category, count in sorted(divergence_categories.items())
        ),
        degraded_divergence_count=degraded_divergences,
        unexplained_divergence_count=unexplained_divergences,
        divergence_explanation_coverage=_ratio(categorized_divergences, divergences),
        benign_ask=_ratio(benign_asks, len(benign_decisions)),
        decision_label_coverage=_ratio(labeled_decision_count, comparable_decisions),
        decision_label_availability=_metric_availability(
            measured=labeled_decision_count,
            total=comparable_decisions,
        ),
        final_asr=_ratio(harmful_executions, known_attack_outcomes),
        attack_outcome_coverage=_ratio(
            known_attack_outcomes, len(source.attack_observations)
        ),
        final_asr_availability=_metric_availability(
            measured=known_attack_outcomes,
            total=len(source.attack_observations),
        ),
        latency=_latency_summary(source.latency_observations),
        failure_injection=source.failure_injection,
        flag_rollback=source.flag_rollback,
        functional_evidence_status=functional_status,
    )


class EvaluationRunPreEnableExtension(BaseModel):
    """Typed additive shape for the Guard API EvaluationRun consumer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pre_enable_report: PreEnableReport | None = None


def validate_pre_enable_report(
    report: PreEnableReport | Mapping[str, Any],
    *,
    expected_receipt_eligibility: ReceiptEligibilityExpectation | Mapping[str, Any],
) -> PreEnableReport:
    """Validate report structure and its trusted receipt-population anchor."""

    validated = (
        report
        if isinstance(report, PreEnableReport)
        else PreEnableReport.model_validate(report)
    )
    validate_receipt_eligibility_descriptor(
        validated.receipt_eligibility,
        expected=expected_receipt_eligibility,
    )
    return validated


def evaluation_run_extension(
    report: PreEnableReport | Mapping[str, Any],
    *,
    expected_receipt_eligibility: ReceiptEligibilityExpectation | Mapping[str, Any],
) -> dict[str, Any]:
    """Build the fixed-key, JSON-safe extension for an existing EvaluationRun."""

    extension = EvaluationRunPreEnableExtension(
        pre_enable_report=validate_pre_enable_report(
            report,
            expected_receipt_eligibility=expected_receipt_eligibility,
        )
    )
    return extension.model_dump(mode="json", exclude_none=True)


def validate_evaluation_run_extension(
    extension: EvaluationRunPreEnableExtension | Mapping[str, Any],
    *,
    expected_receipt_eligibility: ReceiptEligibilityExpectation | Mapping[str, Any],
) -> EvaluationRunPreEnableExtension:
    """Validate strict extension fields and the server-owned eligibility anchor."""

    validated = (
        extension
        if isinstance(extension, EvaluationRunPreEnableExtension)
        else EvaluationRunPreEnableExtension.model_validate(extension)
    )
    if validated.pre_enable_report is not None:
        validate_pre_enable_report(
            validated.pre_enable_report,
            expected_receipt_eligibility=expected_receipt_eligibility,
        )
    return validated


def _ratio(numerator: int, denominator: int) -> RatioMetric:
    return RatioMetric(numerator=numerator, denominator=denominator)


def _metric_availability(*, measured: int, total: int) -> MetricAvailability:
    if measured == 0:
        return "unavailable"
    if measured < total:
        return "partial"
    return "available"


def _latency_summary(
    observations: tuple[LatencyObservation, ...],
) -> LatencySummary:
    samples = sorted(
        observation.latency_ms
        for observation in observations
        if observation.latency_ms is not None
    )
    coverage = _ratio(len(samples), len(observations))
    if not samples:
        return LatencySummary(sample_coverage=coverage)
    return LatencySummary(
        sample_coverage=coverage,
        average_ms=sum(samples) / len(samples),
        p50_ms=_nearest_rank(samples, 0.50),
        p95_ms=_nearest_rank(samples, 0.95),
        p99_ms=_nearest_rank(samples, 0.99),
        max_ms=samples[-1],
    )


def _nearest_rank(samples: list[float], percentile: float) -> float:
    return samples[max(0, ceil(percentile * len(samples)) - 1)]


def _same_optional_float(value: Any, expected: float | None) -> bool:
    if expected is None:
        return value is None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return isclose(float(value), expected, rel_tol=1e-12, abs_tol=1e-12)


def _validate_evidence_checks(
    checks: tuple[EvidenceCheck, ...],
    *,
    expected_kind: EvidenceCheckKind,
    collection_name: str,
) -> None:
    if not checks:
        raise ValueError(f"{collection_name} requires at least one evidence check")
    if any(check.kind != expected_kind for check in checks):
        raise ValueError(f"{collection_name} contains an unexpected check kind")
    check_ids = tuple(check.check_id for check in checks)
    if tuple(sorted(check_ids)) != check_ids:
        raise ValueError(f"{collection_name} checks must be canonically sorted")


def _display_safe_token(value: str, *, field_name: str) -> str:
    if _DISPLAY_SAFE_TOKEN_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a bounded display-safe token")
    if _CREDENTIAL_LIKE_RE.search(value) is not None:
        raise ValueError(f"{field_name} cannot contain credential-like material")
    if _FORBIDDEN_DISPLAY_KEY_RE.search(value) is not None:
        raise ValueError(f"{field_name} contains a forbidden sensitive key")
    if _FORBIDDEN_RUNTIME_DIGEST_RE.search(value) is not None:
        raise ValueError(f"{field_name} contains a forbidden runtime digest")
    if _OPAQUE_AUTH_TOKEN_RE.search(value) is not None:
        raise ValueError(f"{field_name} contains opaque authentication material")
    return value


def _validate_display_safe_refs(value: tuple[str, ...]) -> None:
    for item in value:
        _display_safe_token(item, field_name="evidence ref")
    if len(set(value)) != len(value):
        raise ValueError("evidence refs must be unique")
    if tuple(sorted(value)) != value:
        raise ValueError("evidence refs must be canonically sorted")
