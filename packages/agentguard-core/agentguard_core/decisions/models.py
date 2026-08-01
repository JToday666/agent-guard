"""Guard decision and audit models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..ids import new_id, utc_now_iso

Decision = Literal["allow", "deny", "ask"]
ApprovalResolution = Literal["allow_once", "deny"]
RuleOverrideDecision = Literal["ask", "deny"]
EnforcementMode = Literal["enforce", "audit_only", "shadow_deny", "modify"]
DecisionEffectType = Literal["would_block", "patch", "audit", "quarantine"]


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
    schema_version: Literal["0.3"] = "0.3"
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
