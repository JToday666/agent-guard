"""C10 operational pre-enable report contracts and aggregation.

The report is deliberately observational.  It makes evidence completeness and
effect metrics queryable before any decision-changing enable, but it neither
applies a numerical threshold nor asserts that formal Gate B passed.

Each rate carries its numerator and denominator.  Receipt, decision, attack,
and latency observations are separate inputs so one population cannot silently
stand in for another.
"""

from __future__ import annotations

from math import ceil, isclose
from typing import Any, Literal, Mapping

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

__all__ = [
    "AttackOutcomeObservation",
    "DecisionComparisonObservation",
    "EvidenceCheck",
    "LatencyObservation",
    "LatencySummary",
    "PreEnableReport",
    "PreEnableReportInput",
    "RatioMetric",
    "ReceiptObservation",
    "build_pre_enable_report",
    "evaluation_run_extension",
    "validate_pre_enable_report",
]


Decision = Literal["allow", "deny", "ask"]
BenignAskSource = Literal["official", "v2_shadow"]
EvidenceCheckKind = Literal["failure_injection", "flag_rollback"]
EvidenceCheckStatus = Literal["passed", "failed"]
ReceiptState = Literal["authoritative_terminal", "missing", "link_conflict"]
AttackOutcome = Literal["harmful_execution", "prevented", "unknown"]
EVALUATION_RUN_PRE_ENABLE_REPORT_KEY = "pre_enable_report"


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


class ReceiptObservation(BaseModel):
    """One C2-capable action in the frozen receipt denominator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_key: str = Field(min_length=1)
    receipt_state: ReceiptState


class DecisionComparisonObservation(BaseModel):
    """One paired current-official and V2-shadow decision observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_key: str = Field(min_length=1)
    official_decision: Decision
    v2_shadow_decision: Decision
    is_malicious: bool | None = None


class AttackOutcomeObservation(BaseModel):
    """One real attack attempt and its runtime/sandbox-derived outcome."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_key: str = Field(min_length=1)
    outcome: AttackOutcome


class LatencyObservation(BaseModel):
    """One evaluation eligible for latency observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_key: str = Field(min_length=1)
    latency_ms: float | None = Field(default=None, ge=0)


class EvidenceCheck(BaseModel):
    """Display-safe evidence for failure injection or flag rollback."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    check_id: str = Field(min_length=1)
    kind: EvidenceCheckKind
    status: EvidenceCheckStatus
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    summary: str = Field(min_length=1, max_length=240)

    @field_validator("evidence_refs")
    @classmethod
    def validate_evidence_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.strip() for item in value):
            raise ValueError("evidence refs must be non-empty strings")
        if len(set(value)) != len(value):
            raise ValueError("evidence refs must be unique")
        return value


class PreEnableReportInput(BaseModel):
    """Typed, denominator-explicit inputs for one C10 report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    receipt_observations: tuple[ReceiptObservation, ...] = ()
    decision_observations: tuple[DecisionComparisonObservation, ...] = ()
    attack_observations: tuple[AttackOutcomeObservation, ...] = ()
    latency_observations: tuple[LatencyObservation, ...] = ()
    benign_ask_source: BenignAskSource = "v2_shadow"
    failure_injection: tuple[EvidenceCheck, ...] = Field(min_length=1)
    flag_rollback: tuple[EvidenceCheck, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_observations_and_evidence(self) -> PreEnableReportInput:
        for name, observations in (
            ("receipt", self.receipt_observations),
            ("decision", self.decision_observations),
            ("attack", self.attack_observations),
            ("latency", self.latency_observations),
        ):
            keys = [observation.observation_key for observation in observations]
            if len(set(keys)) != len(keys):
                raise ValueError(f"{name} observation keys must be unique")
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

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: Literal["nearest_rank"] = "nearest_rank"
    sample_coverage: RatioMetric
    average_ms: float | None = Field(default=None, ge=0)
    p50_ms: float | None = Field(default=None, ge=0)
    p95_ms: float | None = Field(default=None, ge=0)
    p99_ms: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_empty_shape(self) -> LatencySummary:
        values = (self.average_ms, self.p50_ms, self.p95_ms, self.p99_ms)
        if self.sample_coverage.numerator == 0 and any(
            value is not None for value in values
        ):
            raise ValueError("latency values require at least one sample")
        if self.sample_coverage.numerator > 0 and any(
            value is None for value in values
        ):
            raise ValueError("latency values are required when samples exist")
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
    benign_ask_source: BenignAskSource
    eligible_action_count: int = Field(ge=0)
    terminal_receipt_count: int = Field(ge=0)
    unknown_attack_outcome_count: int = Field(ge=0)
    receipt_coverage: RatioMetric
    link_conflicts: RatioMetric
    official_v2_divergence: RatioMetric
    benign_ask: RatioMetric
    final_asr: RatioMetric
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
        if self.unknown_attack_outcome_count > self.final_asr.denominator:
            raise ValueError("unknown attack outcomes cannot exceed attack attempts")
        if (
            self.final_asr.numerator + self.unknown_attack_outcome_count
            > self.final_asr.denominator
        ):
            raise ValueError("harmful and unknown outcomes are disjoint attack states")
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


def build_pre_enable_report(
    inputs: PreEnableReportInput | Mapping[str, Any],
) -> PreEnableReport:
    """Aggregate denominator-explicit observations into a strict C10 report."""

    source = (
        inputs
        if isinstance(inputs, PreEnableReportInput)
        else PreEnableReportInput.model_validate(inputs)
    )
    eligible_actions = len(source.receipt_observations)
    terminal_receipts = sum(
        observation.receipt_state == "authoritative_terminal"
        for observation in source.receipt_observations
    )
    link_conflicts = sum(
        observation.receipt_state == "link_conflict"
        for observation in source.receipt_observations
    )
    comparable_decisions = len(source.decision_observations)
    divergences = sum(
        observation.official_decision != observation.v2_shadow_decision
        for observation in source.decision_observations
    )
    benign_decisions = [
        observation
        for observation in source.decision_observations
        if observation.is_malicious is False
    ]
    benign_asks = sum(
        _selected_decision(observation, source.benign_ask_source) == "ask"
        for observation in benign_decisions
    )
    harmful_executions = sum(
        observation.outcome == "harmful_execution"
        for observation in source.attack_observations
    )
    unknown_attack_outcomes = sum(
        observation.outcome == "unknown" for observation in source.attack_observations
    )
    evidence = (*source.failure_injection, *source.flag_rollback)
    functional_status: EvidenceCheckStatus = (
        "passed" if all(check.status == "passed" for check in evidence) else "failed"
    )
    return PreEnableReport(
        benign_ask_source=source.benign_ask_source,
        eligible_action_count=eligible_actions,
        terminal_receipt_count=terminal_receipts,
        unknown_attack_outcome_count=unknown_attack_outcomes,
        receipt_coverage=_ratio(terminal_receipts, eligible_actions),
        link_conflicts=_ratio(link_conflicts, eligible_actions),
        official_v2_divergence=_ratio(divergences, comparable_decisions),
        benign_ask=_ratio(benign_asks, len(benign_decisions)),
        final_asr=_ratio(harmful_executions, len(source.attack_observations)),
        latency=_latency_summary(source.latency_observations),
        failure_injection=source.failure_injection,
        flag_rollback=source.flag_rollback,
        functional_evidence_status=functional_status,
    )


def validate_pre_enable_report(
    report: PreEnableReport | Mapping[str, Any],
) -> PreEnableReport:
    """Return the strict typed report accepted by the EvaluationRun extension."""

    if isinstance(report, PreEnableReport):
        return report
    return PreEnableReport.model_validate(report)


def evaluation_run_extension(
    report: PreEnableReport | Mapping[str, Any],
) -> dict[str, Any]:
    """Build the fixed-key, JSON-safe extension for an existing EvaluationRun."""

    validated = validate_pre_enable_report(report)
    return {EVALUATION_RUN_PRE_ENABLE_REPORT_KEY: validated.model_dump(mode="json")}


def _ratio(numerator: int, denominator: int) -> RatioMetric:
    return RatioMetric(numerator=numerator, denominator=denominator)


def _selected_decision(
    observation: DecisionComparisonObservation, source: BenignAskSource
) -> Decision:
    if source == "official":
        return observation.official_decision
    return observation.v2_shadow_decision


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
