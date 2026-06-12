"""Guard API / Control Plane state models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from agentguard_core import GuardDecision, new_id, utc_now_iso
from agentguard_core.models import ApprovalResolution


class ApprovalRequest(BaseModel):
    approval_id: str = Field(default_factory=lambda: new_id("app"))
    trace_id: str
    tool_call_id: str
    requesting_principal_id: str
    runtime: str = "langgraph"
    agent_id: str = "main"
    status: Literal["pending", "resolved", "expired"] = "pending"
    decision_options: list[ApprovalResolution] = Field(default_factory=lambda: ["allow_once", "deny"])
    decision: ApprovalResolution | None = None
    tool: str
    resource: str
    reason: str
    risk_score: int = Field(ge=0, le=100)
    severity: str
    created_at: str = Field(default_factory=utc_now_iso)
    expires_at: str | None = None
    resolved_at: str | None = None


class EvaluationApproval(BaseModel):
    approval_id: str
    status: str
    decision_options: list[ApprovalResolution]


class GuardEvaluationResponse(BaseModel):
    decision: GuardDecision
    approval: EvaluationApproval | None = None
