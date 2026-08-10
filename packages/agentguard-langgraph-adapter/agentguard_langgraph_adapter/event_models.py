"""AgentGuard adapter event and decision models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

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
    action_id: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    approval_id: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    parent_audit_id: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )


class RuntimeOutcomeMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    outcome_kind: RuntimeOutcomeKind


class RuntimeOutcomeEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intervention: dict[str, Any]
    execution: dict[str, Any]
    side_effects: dict[str, Any]
    result: dict[str, Any]
    approval: dict[str, Any]


class RuntimeOutcomeReceipt(AuditEvent):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.4"] = "0.4"
    record_type: Literal["runtime_outcome"] = "runtime_outcome"
    event_type: Literal["runtime_outcome"] = "runtime_outcome"
    decision: Decision  # pyright: ignore[reportGeneralTypeIssues]
    risk_score: int = Field(ge=0, le=100)  # pyright: ignore[reportGeneralTypeIssues]
    severity: Literal["low", "medium", "high", "critical"]  # pyright: ignore[reportGeneralTypeIssues]
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
