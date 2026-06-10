"""Pydantic models for AgentGuard events and AttackBench cases."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


Decision = Literal["allow", "deny", "ask"]
LifecycleEventType = Literal[
    "user_input_received",
    "context_assembled",
    "model_input_prepared",
    "model_output_produced",
    "tool_call_proposed",
    "policy_decided",
    "tool_call_finished",
    "tool_result_persisted",
    "memory_read",
    "memory_write",
    "reply_prepared",
    "message_sending",
    "turn_finished",
]
AttackType = Literal[
    "indirect_prompt_injection",
    "jailbreak",
    "tool_hijack",
    "file_exfiltration",
    "api_abuse",
    "code_exec",
    "memory_poisoning",
    "environment_poisoning",
    "benign",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


class InputPayload(BaseModel):
    source_type: str
    source_trust: str
    payload: str


class TargetBehavior(BaseModel):
    model_config = ConfigDict(extra="allow")

    tool: str
    resource: str | None = None
    operation: str


class SuccessCondition(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str
    tool: str | None = None
    resource: str | None = None
    recipient: str | None = None
    key: str | None = None


class ToolPlanStep(BaseModel):
    model_config = ConfigDict(extra="allow")

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str | None = None
    source_feature: str | None = None


class AttackCase(BaseModel):
    model_config = ConfigDict(extra="allow")

    case_id: str
    attack_type: AttackType
    is_malicious: bool
    runtime_targets: list[str] = Field(default_factory=lambda: ["langgraph"])
    input: InputPayload
    target_behavior: TargetBehavior
    expected_decision: Decision
    success_condition: SuccessCondition
    tool_plan: list[ToolPlanStep] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("runtime_targets")
    @classmethod
    def must_target_langgraph(cls, value: list[str]) -> list[str]:
        if "langgraph" not in value:
            raise ValueError("runtime_targets must include langgraph")
        return value


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
    agent_id: str = "langgraph_demo"
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

    @property
    def blocked(self) -> bool:
        return self.decision in {"deny", "ask"}


class AuditEvent(BaseModel):
    audit_id: str = Field(default_factory=lambda: new_id("audit"))
    schema_version: str = "0.3"
    trace_id: str
    case_id: str | None = None
    runtime: str = "langgraph"
    timestamp: str = Field(default_factory=utc_now_iso)
    stage: str = "before_tool_call"
    event_type: str = "tool_call_proposed"
    summary: str
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    severity: str
    blocked: bool
    resource_targets: list[str] = Field(default_factory=list)
    rule_hits: list[str] = Field(default_factory=list)
    reason: str
    links: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentLifecycleEvent(BaseModel):
    schema_version: str = "0.3"
    event_id: str = Field(default_factory=lambda: new_id("evt_lifecycle"))
    event_type: LifecycleEventType
    runtime: str = "langgraph"
    trace_id: str
    case_id: str | None = None
    attack_type: AttackType | None = None
    is_malicious: bool | None = None
    timestamp: str = Field(default_factory=utc_now_iso)
    stage: str
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)


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
