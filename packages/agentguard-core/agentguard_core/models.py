"""Stateless AgentGuard Core domain models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


Decision = Literal["allow", "deny", "ask"]
ApprovalResolution = Literal["allow_once", "deny"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


class SecurityContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    user_task: str = ""
    source_type: str = "user"
    source_trust: str = "trusted"
    channel: str | None = None
    sender_id: str | None = None
    run_id: str | None = None
    agent_id: str = "main"
    current_step: str = "before_tool"
    model_intent: str | None = None
    context_sources: list[dict[str, Any]] = Field(default_factory=list)
    derived_paths: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolDescriptor(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    category: str = "tool"
    kind: str | None = None
    input_kind: str | None = None
    call_id: str = Field(default_factory=lambda: new_id("call"))

    def model_post_init(self, __context: Any) -> None:
        if self.kind is None:
            self.kind = self.name


class DerivedResource(BaseModel):
    model_config = ConfigDict(extra="allow")

    resource_type: str
    operation: str
    target: str
    data_classification: str | None = None
    direction: str


class ToolCallPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    tool: ToolDescriptor
    arguments: dict[str, Any] = Field(default_factory=dict)
    derived_resources: list[DerivedResource] = Field(default_factory=list)


class GuardEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: str = "0.3"
    event_id: str = Field(default_factory=lambda: new_id("evt"))
    event_type: str = "tool_call_proposed"
    runtime: str = "langgraph"
    trace_id: str
    case_id: str | None = None
    attack_type: str | None = None
    is_malicious: bool | None = None
    timestamp: str = Field(default_factory=utc_now_iso)
    pre_execution: bool = True
    security_context: SecurityContext = Field(default_factory=SecurityContext)
    payload: ToolCallPayload
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuleHit(BaseModel):
    rule_id: str
    rule_name: str | None = None
    severity: str | None = None
    evidence: list[str] = Field(default_factory=list)


class ApprovalIntent(BaseModel):
    options: list[ApprovalResolution] = Field(default_factory=lambda: ["allow_once", "deny"])
    resource: str


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
    attack_type: str | None = None
    is_malicious: bool | None = None
    summary: str
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    severity: str
    blocked: bool
    resource_targets: list[str] = Field(default_factory=list)
    rule_hits: list[str] = Field(default_factory=list)
    reason: str
    links: dict[str, str] = Field(default_factory=dict)
    latency_ms: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyBundle(BaseModel):
    model_config = ConfigDict(extra="allow")

    bundle_id: str = "default"
    version: str = "p0"
    metadata: dict[str, Any] = Field(default_factory=dict)
