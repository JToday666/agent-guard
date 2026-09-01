"""AgentGuard adapter event and decision models."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .strong_binding import normalize_approval_resolution

_RUNTIME_SECRET_MATERIAL = re.compile(r"(?:hmac-sha256|lease-v1):[0-9a-f]{64}")

Decision = Literal["allow", "deny", "ask"]
AuditRecordType = Literal[
    "policy_evaluation",
    "runtime_outcome",
    "runtime_observation",
    "config_audit",
]
AttackType = Literal[
    "agent_abuse",
    "file_exfiltration",
    "jailbreak",
    "memory_poisoning",
    "prompt_injection",
    "tool_hijacking",
    "benign",
]
GuardEventType = Literal[
    "tool_call_proposed",
    "context_assembled",
    "model_input_prepared",
    "model_output_produced",
    "tool_result_produced",
    "memory_write_proposed",
    "message_send_proposed",
]
RuntimeOutcomeKind = Literal[
    "pre_execution_deny",
    "approval_release",
    "tool_result_modified",
    "tool_result_quarantined",
    "execution_completed",
    "execution_failed",
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


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


class ToolDescriptor(BaseModel):
    name: str
    category: str
    kind: str
    input_kind: str | None = None
    call_id: str = Field(default_factory=lambda: new_id("call"))


class DerivedResource(BaseModel):
    resource_type: str
    operation: str
    target: str
    data_classification: str | None = None
    direction: str


class SecurityContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    user_task: str = ""
    source_type: str = "dataset"
    source_trust: str = "untrusted"
    channel: str | None = None
    sender_id: str | None = None
    conversation_id: str | None = None
    session_key: str | None = None
    session_id: str | None = None
    run_id: str | None = None
    agent_id: str = "langgraph"
    current_step: str = "before_tool"
    model_intent: str | None = None
    context_sources: list[dict[str, Any]] = Field(default_factory=list)
    visible_source_refs: list[str] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    derived_paths: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolCallEvent(BaseModel):
    schema_version: str = "0.3"
    event_id: str = Field(default_factory=lambda: new_id("evt_tool"))
    event_type: str = "tool_call_proposed"
    runtime: str = "langgraph"
    trace_id: str
    case_id: str | None = None
    attack_type: AttackType | None = None
    is_malicious: bool | None = None
    timestamp: str = Field(default_factory=utc_now_iso)
    security_context: SecurityContext = Field(default_factory=SecurityContext)
    tool: ToolDescriptor
    arguments: dict[str, Any] = Field(default_factory=dict)
    derived_resources: list[DerivedResource] = Field(default_factory=list)
    pre_execution: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuntimeGuardEvent(BaseModel):
    schema_version: str = "0.3"
    event_id: str = Field(default_factory=lambda: new_id("evt_runtime"))
    event_type: GuardEventType
    runtime: str = "langgraph"
    trace_id: str
    case_id: str | None = None
    attack_type: AttackType | None = None
    is_malicious: bool | None = None
    timestamp: str = Field(default_factory=utc_now_iso)
    pre_execution: bool = True
    security_context: SecurityContext = Field(default_factory=SecurityContext)
    payload: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuleHit(BaseModel):
    rule_id: str
    rule_name: str | None = None
    severity: str | None = None
    evidence: list[str] = Field(default_factory=list)


class DecisionAuthority(BaseModel):
    """Display-safe server authority projection carried to the runtime gate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: Literal["current", "v21"]
    mode: Literal["shadow", "limited_enable", "active"]
    selection_basis: Literal["current", "path_allowlist", "profile_all"]
    matched_path_ids: list[str] = Field(default_factory=list)
    legacy_floor_applied: bool
    activation_ref_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    approval_release: Literal["not_applicable", "strong_binding_required", "forbidden"]


class ApprovalReleaseDirectiveV2(BaseModel):
    """Typed Product release sibling retained only for runtime enforcement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["2.0"] = "2.0"
    mode: Literal[
        "not_applicable", "forbidden", "strong_binding", "restricted_allow_once"
    ]
    required_runtime_profile: Literal["C1", "C3"] | None
    human_only: Literal[True]
    single_use: Literal[True]
    action_binding: Literal["exact", "best_effort_host", "none"]
    receipt_requirement: Literal["not_applicable", "required_durable"]
    activation_ref_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    scope_digest: str = Field(pattern=r"^(?:sha256|hmac-sha256):[0-9a-f]{64}$")
    capability_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    residual_boundaries: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_release_shape(self) -> "ApprovalReleaseDirectiveV2":
        expected = {
            "not_applicable": (None, "none", "not_applicable"),
            "forbidden": (None, "none", "not_applicable"),
            "strong_binding": ("C3", "exact", "required_durable"),
            "restricted_allow_once": (
                "C1",
                "best_effort_host",
                "required_durable",
            ),
        }[self.mode]
        if (
            self.required_runtime_profile,
            self.action_binding,
            self.receipt_requirement,
        ) != expected:
            raise ValueError("approval release fields do not match mode")
        if self.mode != "restricted_allow_once" and self.residual_boundaries:
            raise ValueError("only restricted release may carry residual boundaries")
        return self


class PolicyDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: new_id("dec"))
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    severity: str
    rule_hits: list[RuleHit] = Field(default_factory=list)
    reason: str
    safe_message: str | None = None
    approval: dict[str, Any] | None = None
    latency_ms: int | None = None
    # evaluate 响应回显的策略审计 ID（契约 §9.9 links.policy_audit_id），
    # 供 runtime_outcome 回执建立不可变的父记录关联。
    policy_audit_id: str | None = None
    # RTE-05 authorization fingerprint is transient consume input only.  Keep
    # the untrusted raw shape for strict gateway validation, while excluding it
    # from repr/model_dump so it cannot leak through receipts or runtime state.
    enforcement_binding: Any | None = Field(default=None, exclude=True, repr=False)
    # CT-PR-04 plan material is runtime-consumption input, never receipt/audit
    # evidence.  It is intentionally transient just like strong binding data.
    context_plan: Any | None = Field(default=None, exclude=True, repr=False)
    # The server-owned authority projection controls ASK release semantics.  It
    # remains transient on generic decision dumps; receipt builders copy it
    # explicitly when their strict schema supports the field.
    decision_authority: DecisionAuthority | None = Field(
        default=None,
        exclude=True,
        repr=False,
    )
    approval_release_directive: ApprovalReleaseDirectiveV2 | None = Field(
        default=None,
        exclude=True,
        repr=False,
    )

    @model_validator(mode="after")
    def validate_product_release_authority(self) -> "PolicyDecision":
        directive = self.approval_release_directive
        if directive is None:
            return self
        authority = self.decision_authority
        legacy_projection = {
            "not_applicable": "not_applicable",
            "forbidden": "forbidden",
            "strong_binding": "strong_binding_required",
            "restricted_allow_once": "forbidden",
        }[directive.mode]
        if authority is None or not all(
            (
                authority.source == "v21",
                authority.mode == "active",
                authority.selection_basis == "profile_all",
                authority.activation_ref_digest == directive.activation_ref_digest,
                authority.approval_release == legacy_projection,
            )
        ):
            raise ValueError(
                "Product release directive lacks exact V2 authority parity"
            )
        releasable = directive.mode in {
            "strong_binding",
            "restricted_allow_once",
        }
        if self.decision == "ask":
            if releasable != (self.approval is not None):
                raise ValueError(
                    "Product ASK approval does not match its release directive"
                )
        elif directive.mode != "not_applicable" or self.approval is not None:
            raise ValueError("non-ASK Product decision requires not_applicable release")
        return self

    @property
    def blocked(self) -> bool:
        return self.decision in {"deny", "ask"}


class AuditEvent(BaseModel):
    """AuditEvent 0.4 契约形态（契约 §8）。

    Guard API 模式下 policy_evaluation 由 Guard API evaluate writer 唯一写入，
    adapter 不得重复提交（§12.1/§22.1）；本模型用于 legacy Core 路径、
    runtime_observation 与本地结果载体。runtime_outcome 使用严格专用模型。
    """

    audit_id: str = Field(default_factory=lambda: new_id("audit"))
    schema_version: str = "0.4"
    record_type: AuditRecordType = "policy_evaluation"
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
    evidence: dict[str, Any] = Field(default_factory=dict)


class RuntimeOutcomeLinks(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    decision_id: str
    policy_audit_id: str
    action_id: str | None = Field(default=None, exclude_if=lambda value: value is None)
    approval_id: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    parent_audit_id: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    lease_id: str | None = Field(default=None, exclude_if=lambda value: value is None)
    consumption_id: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def validate_execution_lease_pair(self) -> "RuntimeOutcomeLinks":
        if (self.lease_id is None) != (self.consumption_id is None):
            raise ValueError("lease_id and consumption_id must be present together")
        return self


class RuntimeOutcomeMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    outcome_kind: RuntimeOutcomeKind


class RuntimeEnforcementEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gate_state: RuntimeEnforcementGateState
    binding_check_status: RuntimeBindingCheckStatus
    lease_consume_outcome: RuntimeLeaseConsumeOutcome
    reason_codes: list[RuntimeEnforcementReasonCode] = Field(min_length=1, max_length=4)

    @model_validator(mode="after")
    def validate_reason_codes(self) -> "RuntimeEnforcementEvidence":
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("enforcement reason_codes must be unique")
        return self


class RuntimeOutcomeEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intervention: dict[str, Any]
    execution: dict[str, Any]
    side_effects: dict[str, Any]
    result: dict[str, Any]
    approval: dict[str, Any]
    enforcement: RuntimeEnforcementEvidence | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @field_validator("approval")
    @classmethod
    def validate_approval_timestamp(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value.get("resolved_at") is None:
            return value
        return normalize_approval_resolution(value)


class RuntimeOutcomeReceipt(AuditEvent):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.4"] = "0.4"
    record_type: Literal["runtime_outcome"] = "runtime_outcome"
    event_type: Literal["runtime_outcome"] = "runtime_outcome"
    decision: Decision  # pyright: ignore[reportGeneralTypeIssues]
    risk_score: int = Field(ge=0, le=100)  # pyright: ignore[reportGeneralTypeIssues]
    severity: Literal[  # pyright: ignore[reportGeneralTypeIssues]
        "low", "medium", "high", "critical"
    ]
    blocked: bool  # pyright: ignore[reportGeneralTypeIssues]
    links: RuntimeOutcomeLinks  # pyright: ignore[reportGeneralTypeIssues]
    latency_ms: Literal[None] = None
    metadata: RuntimeOutcomeMetadata  # pyright: ignore[reportGeneralTypeIssues]
    evidence: RuntimeOutcomeEvidence  # pyright: ignore[reportGeneralTypeIssues]

    @model_validator(mode="after")
    def validate_identity(self) -> "RuntimeOutcomeReceipt":
        expected = f"audit_outcome_{self.links.event_id}_{self.metadata.outcome_kind}"
        if self.audit_id != expected:
            raise ValueError("runtime outcome audit_id does not match its identity")
        completed_at = self.evidence.execution.get("completed_at")
        if completed_at != self.timestamp:
            raise ValueError("runtime outcome completed_at must equal timestamp")
        if self.evidence.execution.get("receipt_recorded") is not True:
            raise ValueError("runtime outcome must be marked as recorded")
        enforcement = self.evidence.enforcement
        has_execution_lease = self.links.lease_id is not None
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
            blocked_after_consume = (
                self.metadata.outcome_kind == "pre_execution_deny"
                and (
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
            )
            if consumed and (
                not has_execution_lease
                or not (released_consume or blocked_after_consume)
                or self.evidence.approval.get("status") != "allowed"
                or self.evidence.approval.get("decision") != "allow_once"
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
                enforcement.gate_state in {"binding_failed", "timed_out", "blocked"}
                and self.evidence.execution.get("status") != "not_invoked"
            ):
                raise ValueError(
                    "failed enforcement gates require a not-invoked outcome"
                )
        elif has_execution_lease:
            raise ValueError("execution lease links require enforcement evidence")
        if _RUNTIME_SECRET_MATERIAL.search(self.model_dump_json()) is not None:
            raise ValueError(
                "runtime outcome receipts cannot contain strong-binding secret material"
            )
        return self


class ToolExecutionResult(BaseModel):
    tool_name: str
    call_id: str
    executed: bool
    blocked: bool
    decision: Decision | None = None
    status: str
    result: Any = None
    safe_message: str | None = None
    side_effects: list[dict[str, Any]] = Field(default_factory=list)
    event: dict[str, Any] | None = None
    audit_event: dict[str, Any] | None = None
    error: str | None = None
    compatibility: dict[str, Any] | None = None
    compatibility_retry: dict[str, Any] | None = None
    runtime_policy_blocked: bool = False
    approval_mode: str | None = None
    approval_id: str | None = None
    approval_consumed: bool = False
    approval_decision: str | None = None
    approval_wait_latency_ms: int | None = None
    approved_arguments_hash: str | None = None
    tool_executed_after_approval: bool = False
    approval_resolution: dict[str, Any] | None = None
    block_semantics: str | None = None
    counts_as_effective_block: bool = False
    runtime_terminal: bool = False
    terminal_reason: str | None = None
    rag_answer_provenance: dict[str, Any] | None = None
    sanitize_applied: bool = False
    quarantine_applied: bool = False
    runtime_receipt_error: str | None = None
    lease_id: str | None = Field(default=None, exclude_if=lambda value: value is None)
    consumption_id: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @field_validator("approval_resolution")
    @classmethod
    def validate_approval_resolution_timestamp(
        cls, value: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        return normalize_approval_resolution(value)

    @model_validator(mode="after")
    def validate_execution_lease_result_pair(self) -> "ToolExecutionResult":
        if (self.lease_id is None) != (self.consumption_id is None):
            raise ValueError("lease_id and consumption_id must be present together")
        return self
