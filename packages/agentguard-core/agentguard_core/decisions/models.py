"""Guard decision and audit models."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..ids import new_id, utc_now_iso
from .activation_ack import ActivationAckV1

_RUNTIME_SECRET_MATERIAL = re.compile(r"(?:hmac-sha256|lease-v1):[0-9a-f]{64}")

Decision = Literal["allow", "deny", "ask"]
AuditRecordType = Literal[
    "policy_evaluation", "runtime_outcome", "runtime_observation", "config_audit"
]
ApprovalResolution = Literal["allow_once", "deny"]
RuleOverrideDecision = Literal["ask", "deny"]
RuntimeOutcomeKind = Literal[
    "pre_execution_deny",
    "approval_release",
    "tool_result_modified",
    "tool_result_quarantined",
    "execution_completed",
    "execution_failed",
]
RuntimeExecutionStatus = Literal["not_invoked", "executed", "failed", "unknown"]
RuntimeResultDisposition = Literal[
    "not_applicable", "passed_through", "modified", "quarantined", "unknown"
]
RuntimeEnforcementGateState = Literal[
    "evaluating",
    "allowed",
    "approval_pending",
    "approval_released",
    "blocked",
    "timed_out",
    "binding_failed",
    "unknown",
]
RuntimeBindingCheckStatus = Literal[
    "not_applicable", "not_performed", "passed", "failed", "unknown"
]
RuntimeLeaseConsumeOutcome = Literal[
    "not_applicable",
    "not_attempted",
    "consumed",
    "expired",
    "revoked",
    "rejected",
    "unknown",
]
RuntimeEnforcementReasonCode = Literal[
    "rte-05:binding_exact",
    "rte-05:binding_invalid",
    "rte-05:binding_mismatch",
    "rte-05:approval_not_human",
    "rte-05:approval_not_consumable",
    "rte-05:approval_not_found",
    "rte-05:approval_expired",
    "rte-05:identity_denied",
    "rte-05:approval_timed_out",
    "rte-05:lease_consumed",
    "rte-05:consumption_conflict",
    "rte-05:lease_rejected",
    "rte-05:lease_expired",
    "rte-05:lease_revoked",
    "rte-05:lease_unavailable",
    "rte-05:lease_response_invalid",
    "rte-05:lease_consume_timed_out",
    "rte-05:multiple_binding_conflict",
    "rte-05:correlation_capacity_exhausted",
]


class RuleHit(BaseModel):
    rule_id: str
    rule_name: str | None = None
    severity: str | None = None
    evidence: list[str] = Field(default_factory=list)


class ApprovalIntent(BaseModel):
    options: list[ApprovalResolution] = Field(
        default_factory=lambda: ["allow_once", "deny"]
    )
    resource: str


class GuardDecision(BaseModel):
    """Stateless Core 对单个评估请求的判定结果。

    检测器失败语义：当某个检测器在评估中抛出异常时，``GuardEngine``
    不会外抛异常，而是将其转换为保守检测结果并参与聚合：
    ``decision="ask"``、``categories`` 含 ``detector_failure``，
    ``rule_hits`` 携带检测器标识与异常类别。失败即保守，不提供
    任何 fail-open 配置；异常详情不进入对外 ``reason``，仅留存于
    内部日志。其他检测器照常评估，deny 优先的聚合语义不变。
    """

    decision_id: str = Field(default_factory=lambda: new_id("dec"))
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    severity: str
    categories: list[str] = Field(default_factory=list)
    rule_hits: list[RuleHit] = Field(default_factory=list)
    reason: str
    safe_message: str | None = None
    approval_intent: ApprovalIntent | None = None
    latency_ms: int | None = None

    @property
    def blocked(self) -> bool:
        return self.decision in {"deny", "ask"}


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    audit_id: str = Field(default_factory=lambda: new_id("audit"))
    schema_version: Literal["0.3", "0.4"] = "0.3"
    record_type: AuditRecordType | None = None
    trace_id: str
    case_id: str | None = None
    runtime: str = "langgraph"
    timestamp: str = Field(default_factory=utc_now_iso)
    stage: str = "before_tool_call"
    event_type: str = "tool_call_proposed"
    attack_type: str | None = None
    is_malicious: bool | None = None
    summary: str
    decision: Decision | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    severity: str | None = None
    blocked: bool | None = None
    resource_targets: list[str] = Field(default_factory=list)
    rule_hits: list[str] = Field(default_factory=list)
    reason: str
    links: dict[str, str] = Field(default_factory=dict)
    latency_ms: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _validate_version_and_record_type(self) -> "AuditEvent":
        policy_fields_present = (
            self.decision is not None
            and self.risk_score is not None
            and self.severity is not None
            and self.blocked is not None
        )
        if self.record_type is None:
            if self.schema_version != "0.3":
                raise ValueError("record_type is required for AuditEvent 0.4")
            if not policy_fields_present:
                raise ValueError(
                    "AuditEvent 0.3 requires decision, risk_score, severity and blocked"
                )
            return self
        if self.schema_version != "0.4":
            raise ValueError("record_type is only supported for AuditEvent 0.4")
        if self.record_type in {"policy_evaluation", "config_audit"}:
            if not policy_fields_present:
                raise ValueError(
                    f"AuditEvent record_type '{self.record_type}' requires "
                    "decision, risk_score, severity and blocked"
                )
        return self


class RuntimeOutcomeLinks(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=160)
    decision_id: str = Field(min_length=1, max_length=160)
    policy_audit_id: str = Field(min_length=1, max_length=256)
    action_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        exclude_if=lambda value: value is None,
    )
    approval_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        exclude_if=lambda value: value is None,
    )
    parent_audit_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        exclude_if=lambda value: value is None,
    )
    lease_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        exclude_if=lambda value: value is None,
    )
    consumption_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def _validate_execution_lease_links(self) -> "RuntimeOutcomeLinks":
        if (self.lease_id is None) != (self.consumption_id is None):
            raise ValueError("lease_id and consumption_id must be provided together")
        return self


class RuntimeOutcomeMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=128)
    outcome_kind: RuntimeOutcomeKind
    activation_ack: ActivationAckV1 | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )

    @field_validator("activation_ack", mode="before")
    @classmethod
    def _reject_explicit_null_ack(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("activation_ack must be omitted instead of null")
        return value


class RuntimeInterventionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=2000)


class RuntimeExecutionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: RuntimeExecutionStatus
    receipt_recorded: Literal[True]
    invoked_at: str | None = None
    completed_at: str
    error: str | None = Field(default=None, max_length=2000)
    tool_result_entered_context: bool | None = None
    persisted: bool | None = None

    @model_validator(mode="after")
    def _validate_execution(self) -> "RuntimeExecutionEvidence":
        completed = _runtime_timestamp(self.completed_at, "completed_at")
        self.completed_at = completed.isoformat()
        if self.invoked_at is not None:
            invoked = _runtime_timestamp(self.invoked_at, "invoked_at")
            if invoked > completed:
                raise ValueError("invoked_at must not be later than completed_at")
            self.invoked_at = invoked.isoformat()
        if self.status == "failed" and not self.error:
            raise ValueError("failed runtime outcomes require an error")
        if self.status in {"not_invoked", "executed"} and self.error is not None:
            raise ValueError(f"{self.status} runtime outcomes cannot include an error")
        return self


class RuntimeSideEffectsEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    measurement_status: Literal["measured", "not_measured", "unknown"]
    count: int | None = Field(default=None, ge=0)
    summary: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def _validate_measurement(self) -> "RuntimeSideEffectsEvidence":
        if self.measurement_status == "measured" and self.count is None:
            raise ValueError("measured side effects require a count")
        if self.measurement_status != "measured" and self.count is not None:
            raise ValueError("unmeasured side effects cannot include a count")
        return self


class RuntimeResultEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disposition: RuntimeResultDisposition
    summary: str | None = Field(default=None, max_length=2000)
    sanitized: bool | None = None


class RuntimeApprovalEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str | None = Field(default=None, min_length=1, max_length=160)
    status: Literal[
        "not_required", "pending", "allowed", "denied", "expired", "unknown"
    ]
    decision: ApprovalResolution | None = None
    resolved_at: str | None = None

    @model_validator(mode="after")
    def _validate_approval(self) -> "RuntimeApprovalEvidence":
        if self.resolved_at is not None:
            self.resolved_at = _runtime_timestamp(
                self.resolved_at, "approval.resolved_at"
            ).isoformat()
        if self.status == "not_required":
            if self.approval_id is not None or self.decision is not None:
                raise ValueError(
                    "not_required approval evidence cannot name an approval"
                )
            return self
        if self.status in {"pending", "allowed", "denied", "expired"}:
            if self.approval_id is None:
                raise ValueError(
                    f"{self.status} approval evidence requires approval_id"
                )
        if self.status == "allowed" and self.decision != "allow_once":
            raise ValueError("allowed approval evidence requires allow_once")
        if self.status == "denied" and self.decision != "deny":
            raise ValueError("denied approval evidence requires deny")
        if self.status == "pending" and self.decision is not None:
            raise ValueError("pending approval evidence cannot include a decision")
        return self


class RuntimeEnforcementEvidence(BaseModel):
    """Bounded, non-secret evidence for RTE-05 runtime enforcement."""

    model_config = ConfigDict(extra="forbid")

    gate_state: RuntimeEnforcementGateState
    binding_check_status: RuntimeBindingCheckStatus
    lease_consume_outcome: RuntimeLeaseConsumeOutcome
    reason_codes: list[RuntimeEnforcementReasonCode] = Field(min_length=1, max_length=4)

    @model_validator(mode="after")
    def _validate_reason_codes(self) -> "RuntimeEnforcementEvidence":
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("enforcement reason_codes must be unique")
        return self


class RuntimeOutcomeEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intervention: RuntimeInterventionEvidence
    execution: RuntimeExecutionEvidence
    side_effects: RuntimeSideEffectsEvidence
    result: RuntimeResultEvidence
    approval: RuntimeApprovalEvidence
    enforcement: RuntimeEnforcementEvidence | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )


class RuntimeOutcomeReceipt(AuditEvent):
    """Strict adapter-produced receipt for an observed runtime intervention/result."""

    model_config = ConfigDict(extra="forbid")

    # fmt: off
    audit_id: str = Field(min_length=1, max_length=256)  # pyright: ignore[reportGeneralTypeIssues]
    schema_version: Literal["0.4"] = "0.4"
    record_type: Literal["runtime_outcome"] = "runtime_outcome"
    trace_id: str = Field(min_length=1, max_length=160)
    runtime: str = Field(min_length=1, max_length=64)  # pyright: ignore[reportGeneralTypeIssues]
    timestamp: str  # pyright: ignore[reportGeneralTypeIssues]
    stage: str = Field(min_length=1, max_length=64)  # pyright: ignore[reportGeneralTypeIssues]
    event_type: Literal["runtime_outcome"] = "runtime_outcome"
    summary: str = Field(min_length=1, max_length=1000)
    decision: Decision  # pyright: ignore[reportGeneralTypeIssues]
    risk_score: int = Field(ge=0, le=100)  # pyright: ignore[reportGeneralTypeIssues]
    severity: Literal["low", "medium", "high", "critical"]  # pyright: ignore[reportGeneralTypeIssues]
    blocked: bool  # pyright: ignore[reportGeneralTypeIssues]
    reason: str = Field(min_length=1, max_length=4000)
    links: RuntimeOutcomeLinks  # pyright: ignore[reportGeneralTypeIssues]
    latency_ms: Literal[None] = None
    metadata: RuntimeOutcomeMetadata  # pyright: ignore[reportGeneralTypeIssues]
    evidence: RuntimeOutcomeEvidence  # pyright: ignore[reportGeneralTypeIssues]
    # fmt: on

    @model_validator(mode="after")
    def _validate_receipt(self) -> "RuntimeOutcomeReceipt":
        occurred_at = _runtime_timestamp(self.timestamp, "timestamp")
        self.timestamp = occurred_at.isoformat()
        activation_ack = self.metadata.activation_ack
        if activation_ack is not None:
            if activation_ack.runtime != self.runtime:
                raise ValueError("activation ack runtime must match receipt runtime")
            if activation_ack.agent_id != self.metadata.agent_id:
                raise ValueError("activation ack agent must match receipt agent")
            if (
                _runtime_timestamp(activation_ack.issued_at, "activation_ack.issued_at")
                > occurred_at
            ):
                raise ValueError("activation ack cannot be issued after receipt")
        if self.evidence.execution.completed_at != self.timestamp:
            raise ValueError("execution.completed_at must equal receipt timestamp")
        expected_audit_id = (
            f"audit_outcome_{self.links.event_id}_{self.metadata.outcome_kind}"
        )
        if self.audit_id != expected_audit_id:
            raise ValueError("audit_id does not match the runtime outcome identity")
        status = self.evidence.execution.status
        disposition = self.evidence.result.disposition
        kind = self.metadata.outcome_kind
        enforcement = self.evidence.enforcement
        has_execution_lease = self.links.lease_id is not None
        if self.links.approval_id != self.evidence.approval.approval_id:
            raise ValueError("approval evidence must match the receipt approval link")
        if enforcement is not None:
            consumed = enforcement.lease_consume_outcome == "consumed"
            released_consume = (
                enforcement.binding_check_status == "passed"
                and enforcement.gate_state == "approval_released"
            )
            post_consume_deny_shape = (
                enforcement.gate_state,
                enforcement.binding_check_status,
                frozenset(enforcement.reason_codes),
            )
            blocked_after_consume = kind == "pre_execution_deny" and (
                post_consume_deny_shape
                in {
                    (
                        "binding_failed",
                        "failed",
                        frozenset(
                            {
                                "rte-05:binding_mismatch",
                                "rte-05:lease_consumed",
                            }
                        ),
                    ),
                    (
                        "timed_out",
                        "passed",
                        frozenset(
                            {
                                "rte-05:binding_exact",
                                "rte-05:lease_consume_timed_out",
                            }
                        ),
                    ),
                    (
                        "binding_failed",
                        "passed",
                        frozenset(
                            {
                                "rte-05:binding_exact",
                                "rte-05:lease_expired",
                            }
                        ),
                    ),
                    (
                        "binding_failed",
                        "passed",
                        frozenset(
                            {
                                "rte-05:binding_exact",
                                "rte-05:lease_response_invalid",
                            }
                        ),
                    ),
                    (
                        "binding_failed",
                        "failed",
                        frozenset({"rte-05:multiple_binding_conflict"}),
                    ),
                }
            )
            if consumed and (
                not has_execution_lease
                or self.links.action_id is None
                or self.links.approval_id is None
                or not (released_consume or blocked_after_consume)
                or self.evidence.approval.status != "allowed"
                or self.evidence.approval.decision != "allow_once"
            ):
                raise ValueError(
                    "consumed enforcement requires exact binding, allowed approval, "
                    "a released or post-consume-denied gate, and execution lease links"
                )
            if has_execution_lease and not consumed:
                raise ValueError(
                    "execution lease links require consumed enforcement evidence"
                )
            if enforcement.gate_state == "approval_released" and not consumed:
                raise ValueError(
                    "an approval-released enforcement gate requires a consumed lease"
                )
            if (
                enforcement.gate_state
                in {
                    "binding_failed",
                    "timed_out",
                    "blocked",
                }
                and status != "not_invoked"
            ):
                raise ValueError(
                    "failed enforcement gates require a not-invoked outcome"
                )
        elif has_execution_lease:
            raise ValueError("execution lease links require enforcement evidence")
        if kind == "pre_execution_deny" and (
            status != "not_invoked" or disposition != "not_applicable"
        ):
            raise ValueError("pre_execution_deny requires a not-invoked outcome")
        if kind == "approval_release" and (
            status != "unknown" or self.evidence.approval.status != "allowed"
        ):
            raise ValueError("approval_release requires an allowed approval")
        if kind == "tool_result_modified" and (
            status != "executed" or disposition != "modified"
        ):
            raise ValueError("tool_result_modified requires a modified result")
        if kind == "tool_result_quarantined" and (
            status != "executed" or disposition != "quarantined"
        ):
            raise ValueError("tool_result_quarantined requires a quarantined result")
        if kind == "execution_completed" and status != "executed":
            raise ValueError("execution_completed requires executed status")
        if kind == "execution_failed" and status != "failed":
            raise ValueError("execution_failed requires failed status")
        secret_scan_json = self.model_dump_json(
            exclude={"metadata": {"activation_ack": {"ack_token"}}}
        )
        if _RUNTIME_SECRET_MATERIAL.search(secret_scan_json) is not None:
            raise ValueError(
                "runtime outcome receipts cannot contain strong-binding secret material"
            )
        return self


def _runtime_timestamp(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{field_name} must be an RFC 3339 timestamp") from None
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)
