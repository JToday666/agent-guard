"""Guard API / Control Plane state models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentguard_core import ConfigAuditFinding, GuardDecision, new_id, utc_now_iso
from agentguard_core.models import ApprovalResolution


class ApprovalRequest(BaseModel):
    approval_id: str = Field(default_factory=lambda: new_id("app"))
    trace_id: str
    subject_id: str
    subject_type: str = "tool_call"
    action_id: str
    action_name: str
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

    @model_validator(mode="before")
    @classmethod
    def fill_subject_compatibility_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        values = dict(data)
        subject_id = values.get("subject_id") or values.get("tool_call_id")
        if subject_id is not None:
            values["subject_id"] = subject_id
            values["tool_call_id"] = values.get("tool_call_id") or subject_id
            values["action_id"] = values.get("action_id") or subject_id
        values["subject_type"] = values.get("subject_type") or "tool_call"
        values["action_name"] = values.get("action_name") or values.get("tool") or values["subject_type"]
        return values


class EvaluationApproval(BaseModel):
    approval_id: str
    status: str
    decision_options: list[ApprovalResolution]


class GuardEvaluationResponse(BaseModel):
    decision: GuardDecision
    approval: EvaluationApproval | None = None


class EvaluationAttackSummary(BaseModel):
    asr_before: float | None = Field(default=None, ge=0, le=1)
    asr_after: float | None = Field(default=None, ge=0, le=1)


class EvaluationCase(BaseModel):
    case_id: str
    attack_type: str
    runtime: str
    expected_decision: Literal["allow", "deny", "ask"]
    actual_decision: Literal["allow", "deny", "ask"]
    blocked: bool
    attack_success: bool
    trace_id: str


class EvaluationRun(BaseModel):
    model_config = ConfigDict(extra="allow")

    run_id: str
    run_at: str
    dataset_id: str | None = None
    dataset_version: str | None = None
    asr_before: float | None = Field(default=None, ge=0, le=1)
    asr_after: float | None = Field(default=None, ge=0, le=1)
    per_attack: dict[str, EvaluationAttackSummary] = Field(default_factory=dict)
    per_family: dict[str, Any] = Field(default_factory=dict)
    per_rule: dict[str, Any] = Field(default_factory=dict)
    cases: list[EvaluationCase] = Field(default_factory=list)


class ConfigAuditFindingRecord(BaseModel):
    runtime: str
    target_type: str
    target_id: str
    trace_id: str
    event_id: str
    timestamp: str
    finding: ConfigAuditFinding


AdapterStatus = Literal["loaded", "not_loaded", "error", "unknown"]
AdapterStatusSource = Literal["agentguardctl", "openclaw-plugin-dev", "openclaw-plugin"]


class AdapterStatusRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: AdapterStatus = "unknown"
    loaded: bool = False
    hook_count: int | None = None
    expected_hook_count: int = 16
    last_verified_at: str | None = None
    last_heartbeat_at: str | None = None
    error: str | None = None
    source: AdapterStatusSource | None = None
    runtime: str | None = None
    runtime_id: str | None = None
    agent_id: str | None = None
    plugin_version: str | None = None
    runtime_version: str | None = None
    capabilities: dict[str, Any] = Field(default_factory=dict)
    hooks: list[str] = Field(default_factory=list)
    fail_closed_stages: list[str] = Field(default_factory=list)


class CredentialRecord(BaseModel):
    credential_id: str = Field(default_factory=lambda: new_id("cred"))
    token_hash: str
    principal_type: str
    principal_id: str
    role: str
    scopes: list[str] = Field(default_factory=list)
    runtime: str | None = None
    agent_id: str | None = None
    created_at: str = Field(default_factory=utc_now_iso)
    expires_at: str | None = None
    revoked_at: str | None = None

    def public_dump(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["token_hash"] = "[redacted]"
        return payload


class CredentialCreateRequest(BaseModel):
    principal_type: str
    principal_id: str
    role: str
    scopes: list[str] = Field(default_factory=list)
    runtime: str | None = None
    agent_id: str | None = None
    expires_at: str | None = None
