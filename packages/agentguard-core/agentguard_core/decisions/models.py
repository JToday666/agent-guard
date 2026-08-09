"""Guard decision and audit models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..ids import new_id, utc_now_iso

Decision = Literal["allow", "deny", "ask"]
AuditRecordType = Literal[
    "policy_evaluation", "runtime_outcome", "runtime_observation", "config_audit"
]
ApprovalResolution = Literal["allow_once", "deny"]
RuleOverrideDecision = Literal["ask", "deny"]
EnforcementMode = Literal["enforce", "audit_only", "shadow_deny", "modify"]
DecisionEffectType = Literal["would_block", "patch", "audit", "quarantine"]
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


class DecisionEffect(BaseModel):
    model_config = ConfigDict(extra="allow")

    effect_type: DecisionEffectType
    target: str
    description: str
    patch: dict[str, Any] | None = None


class DecisionEnforcement(BaseModel):
    model_config = ConfigDict(extra="allow")

    mode: EnforcementMode = "enforce"
    actual_decision: Decision
    policy_decision: Decision
    reason: str | None = None


class GuardDecision(BaseModel):
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
    enforcement: DecisionEnforcement | None = None
    effects: list[DecisionEffect] = Field(default_factory=list)

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


class RuntimeOutcomeMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=128)
    outcome_kind: RuntimeOutcomeKind


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
                raise ValueError("not_required approval evidence cannot name an approval")
            return self
        if self.status in {"pending", "allowed", "denied", "expired"}:
            if self.approval_id is None:
                raise ValueError(f"{self.status} approval evidence requires approval_id")
        if self.status == "allowed" and self.decision != "allow_once":
            raise ValueError("allowed approval evidence requires allow_once")
        if self.status == "denied" and self.decision != "deny":
            raise ValueError("denied approval evidence requires deny")
        if self.status == "pending" and self.decision is not None:
            raise ValueError("pending approval evidence cannot include a decision")
        return self


class RuntimeOutcomeEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intervention: RuntimeInterventionEvidence
    execution: RuntimeExecutionEvidence
    side_effects: RuntimeSideEffectsEvidence
    result: RuntimeResultEvidence
    approval: RuntimeApprovalEvidence


class RuntimeOutcomeReceipt(AuditEvent):
    """Strict adapter-produced receipt for an observed runtime intervention/result."""

    model_config = ConfigDict(extra="forbid")

    audit_id: str = Field(min_length=1, max_length=256)
    schema_version: Literal["0.4"] = "0.4"
    record_type: Literal["runtime_outcome"] = "runtime_outcome"
    trace_id: str = Field(min_length=1, max_length=160)
    runtime: str = Field(min_length=1, max_length=64)
    timestamp: str
    stage: str = Field(min_length=1, max_length=64)
    event_type: Literal["runtime_outcome"] = "runtime_outcome"
    summary: str = Field(min_length=1, max_length=1000)
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    severity: Literal["low", "medium", "high", "critical"]
    blocked: bool
    reason: str = Field(min_length=1, max_length=4000)
    links: RuntimeOutcomeLinks
    latency_ms: Literal[None] = None
    metadata: RuntimeOutcomeMetadata
    evidence: RuntimeOutcomeEvidence

    @model_validator(mode="after")
    def _validate_receipt(self) -> "RuntimeOutcomeReceipt":
        occurred_at = _runtime_timestamp(self.timestamp, "timestamp")
        self.timestamp = occurred_at.isoformat()
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
        return self


def _runtime_timestamp(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{field_name} must be an RFC 3339 timestamp") from None
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)
