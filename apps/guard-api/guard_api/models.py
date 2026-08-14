"""Guard API / Control Plane state models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentguard_core import ConfigAuditFinding, GuardDecision, new_id, utc_now_iso
from agentguard_core.actions.models import (
    ActionConstraint,
    DestinationConstraint,
    ResourceConstraint,
)
from agentguard_core.decisions import ApprovalResolution

ADAPTER_CREDENTIAL_SCOPES = (
    "event:evaluate",
    "event:audit:write",
    "approval:wait",
    "adapter:status:write",
)


def _is_sha256_digest(value: str | None) -> bool:
    if value is None or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)


class LlmApprovalReview(BaseModel):
    model_config = ConfigDict(extra="allow")

    reviewer: str = "llm-approval"
    status: Literal["reviewed", "resolved", "kept_pending", "error"] = "reviewed"
    decision: ApprovalResolution | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    reason: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    error: str | None = None
    provider: str | None = None
    model: str | None = None
    reviewed_at: str = Field(default_factory=utc_now_iso)


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(default_factory=lambda: new_id("app"))
    trace_id: str
    subject_id: str
    subject_type: str
    action_id: str
    action_name: str
    requesting_principal_id: str
    runtime: str = "langgraph"
    agent_id: str = "main"
    status: Literal["pending", "resolved", "expired"] = "pending"
    decision_options: list[ApprovalResolution] = Field(
        default_factory=lambda: ["allow_once", "deny"]
    )
    decision: ApprovalResolution | None = None
    resource: str
    reason: str
    risk_score: int = Field(ge=0, le=100)
    severity: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    llm_review: LlmApprovalReview | None = None
    resolution_source: Literal["human", "llm", "system"] | None = None
    resolved_by: str | None = None
    resolution_reason: str | None = None
    created_at: str = Field(default_factory=utc_now_iso)
    expires_at: str
    resolved_at: str | None = None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        created_at = _rfc3339_timestamp(self.created_at, "created_at")
        expires_at = _rfc3339_timestamp(self.expires_at, "expires_at")
        if expires_at <= created_at:
            raise ValueError("expires_at must be later than created_at")
        if self.status == "resolved":
            if self.decision is None or self.resolved_at is None:
                raise ValueError("resolved approvals require decision and resolved_at")
            resolved_at = _rfc3339_timestamp(self.resolved_at, "resolved_at")
            self.resolved_at = resolved_at.astimezone(timezone.utc).isoformat()
        elif self.resolved_at is not None:
            raise ValueError("only resolved approvals may include resolved_at")
        if self.status == "pending" and self.decision is not None:
            raise ValueError("pending approvals cannot include a decision")
        if self.status == "expired" and self.decision not in {None, "deny"}:
            raise ValueError("expired approvals may only derive a deny decision")
        self.created_at = created_at.astimezone(timezone.utc).isoformat()
        self.expires_at = expires_at.astimezone(timezone.utc).isoformat()
        return self


class LlmApprovalReviewInput(BaseModel):
    runtime: str
    resource: str
    reason: str
    risk_score: int = Field(ge=0, le=100)
    severity: str
    evidence: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_approval(cls, approval: ApprovalRequest) -> Self:
        return cls(
            runtime=approval.runtime,
            resource=approval.resource,
            reason=approval.reason,
            risk_score=approval.risk_score,
            severity=approval.severity,
            evidence=approval.evidence,
        )


class EvaluationApproval(BaseModel):
    approval_id: str
    status: str
    decision_options: list[ApprovalResolution]
    decision: ApprovalResolution | None = None
    resolution_source: str | None = None
    resolved_by: str | None = None
    resolution_reason: str | None = None
    llm_review: LlmApprovalReview | None = None


class GuardEvaluationResponse(BaseModel):
    decision: GuardDecision
    approval: EvaluationApproval | None = None
    # 本次评估写入的 policy_evaluation AuditEvent 稳定 ID（§9.9 links.policy_audit_id），
    # 供 Adapter / Plugin 回写 runtime_outcome 时建立关联；无审计写入时为 null。
    policy_audit_id: str | None = None


class EvaluationAttackSummary(BaseModel):
    asr_before: float | None = Field(default=None, ge=0, le=1)
    asr_after: float | None = Field(default=None, ge=0, le=1)


class EvaluationCase(BaseModel):
    case_id: str
    attack_type: str
    runtime: str
    dataset_id: str | None = None
    dataset_version: str | None = None
    case_digest: str | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)
    expected_decision: Literal["allow", "deny", "ask"]
    actual_decision: Literal["allow", "deny", "ask"]
    blocked: bool
    attack_success: bool
    trace_id: str


class EvaluationRegressionGate(BaseModel):
    status: Literal["passed", "failed", "skipped"]
    baseline_run_id: str | None = None
    max_allowed_regression: float | None = Field(default=None, ge=0)
    asr_delta: float | None = None
    failed_case_ids: list[str] = Field(default_factory=list)


class EvaluationRun(BaseModel):
    model_config = ConfigDict(extra="allow")

    run_id: str
    run_at: str
    dataset_id: str | None = None
    dataset_version: str | None = None
    dataset_digest: str | None = None
    dataset_locked: bool = False
    regression_gate: EvaluationRegressionGate | None = None
    asr_before: float | None = Field(default=None, ge=0, le=1)
    asr_after: float | None = Field(default=None, ge=0, le=1)
    per_attack: dict[str, EvaluationAttackSummary] = Field(default_factory=dict)
    per_family: dict[str, Any] = Field(default_factory=dict)
    per_rule: dict[str, Any] = Field(default_factory=dict)
    cases: list[EvaluationCase] = Field(default_factory=list)

    @model_validator(mode="after")
    def fill_case_dataset_metadata(self) -> Self:
        self.run_at = _utc_timestamp(self.run_at, "run_at")
        if self.dataset_locked:
            if (
                not self.dataset_id
                or not self.dataset_version
                or not self.dataset_digest
            ):
                raise ValueError(
                    "locked evaluation datasets require id, version, and digest"
                )
            if not _is_sha256_digest(self.dataset_digest):
                raise ValueError(
                    "locked evaluation dataset digest must be a full sha256 digest"
                )
            if not self.cases:
                raise ValueError("locked evaluation runs require at least one case")
        filled_cases: list[EvaluationCase] = []
        for case in self.cases:
            updates: dict[str, Any] = {}
            if case.dataset_id is None and self.dataset_id is not None:
                updates["dataset_id"] = self.dataset_id
            if case.dataset_version is None and self.dataset_version is not None:
                updates["dataset_version"] = self.dataset_version
            filled = case.model_copy(update=updates) if updates else case
            if self.dataset_locked:
                if filled.dataset_id != self.dataset_id or filled.dataset_version != self.dataset_version:
                    raise ValueError(
                        "locked evaluation case dataset identity must match its run"
                    )
                if not _is_sha256_digest(filled.case_digest):
                    raise ValueError(
                        "locked evaluation cases require a full sha256 digest"
                    )
                provenance = filled.provenance
                if (
                    not isinstance(provenance.get("source"), str)
                    or not isinstance(provenance.get("source_path"), str)
                    or not isinstance(provenance.get("line"), int)
                    or provenance["line"] < 1
                ):
                    raise ValueError(
                        "locked evaluation cases require source, source_path, and positive line provenance"
                    )
            filled_cases.append(filled)
        self.cases = filled_cases
        return self


class ConfigAuditFindingRecord(BaseModel):
    runtime: str
    target_type: str
    target_id: str
    trace_id: str
    event_id: str
    timestamp: str
    finding: ConfigAuditFinding


AdapterStatus = Literal["loaded", "not_loaded", "error", "unknown"]


class AdapterStatusRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AdapterStatus = "unknown"
    loaded: bool = False
    hook_count: int | None = Field(default=None, ge=0)
    expected_hook_count: int | None = Field(default=None, ge=0)
    last_verified_at: str | None = None
    last_heartbeat_at: str | None = None
    error: str | None = None
    source: str | None = None
    runtime_id: str | None = None
    agent_id: str | None = None
    plugin_version: str | None = None
    runtime_version: str | None = None
    capabilities: dict[str, Any] = Field(default_factory=dict)
    hooks: list[str] = Field(default_factory=list)
    fail_closed_stages: list[str] = Field(default_factory=list)
    enforcement_mode: Literal["enforce", "observe", "disabled"] | None = None

    @model_validator(mode="after")
    def normalize_timestamps(self) -> Self:
        if self.last_verified_at is not None:
            self.last_verified_at = _utc_timestamp(
                self.last_verified_at, "last_verified_at"
            )
        if self.last_heartbeat_at is not None:
            self.last_heartbeat_at = _utc_timestamp(
                self.last_heartbeat_at, "last_heartbeat_at"
            )
        return self


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

    @model_validator(mode="after")
    def validate_active_adapter_identity(self) -> Self:
        if self.revoked_at is not None:
            return self
        if (
            self.principal_type != "component"
            or self.role != "adapter"
            or not self.runtime
            or not self.agent_id
            or set(self.scopes) != set(ADAPTER_CREDENTIAL_SCOPES)
        ):
            raise ValueError(
                "active credentials must use the runtime-bound adapter profile"
            )
        return self

    def public_dump(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"token_hash"})


class CredentialCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    )
    runtime: str = Field(
        min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    )
    agent_id: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    )
    expires_at: str | None = None

    @model_validator(mode="after")
    def validate_expiry(self) -> Self:
        if self.expires_at is None:
            return self
        expires_at = _rfc3339_timestamp(self.expires_at, "expires_at")
        if expires_at <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
        self.expires_at = expires_at.astimezone(timezone.utc).isoformat()
        return self


TASK_TEXT_MAX_LENGTH = 4000


class TaskCreateRequest(BaseModel):
    """专用任务入口创建请求（V21-03，01 §30 L1185-1229）。

    冻结语义：``task_id/revision/task_digest/scope_digest`` 一律由服务端
    生成，请求体不得携带；``extra="forbid"`` 结构性拒绝夹带。
    三类约束复用 core authority/actions 冻结模型。
    """

    model_config = ConfigDict(extra="forbid")

    task_text: str = Field(min_length=1, max_length=TASK_TEXT_MAX_LENGTH)
    runtime: str = Field(
        min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    )
    runtime_binding_id: str | None = Field(default=None, min_length=1, max_length=256)
    trace_id: str = Field(min_length=1, max_length=128)
    session_id: str | None = Field(default=None, min_length=1, max_length=128)
    action_constraints: list[ActionConstraint] = Field(default_factory=list)
    resource_constraints: list[ResourceConstraint] = Field(default_factory=list)
    destination_constraints: list[DestinationConstraint] = Field(default_factory=list)


class TaskReviseRequest(TaskCreateRequest):
    """任务修订请求：内容字段 + ``expected_revision`` CAS 锚点。

    幂等语义：同 ``expected_revision`` + 同 canonical request digest 重试
    返回原修订；revision 落后或同 revision 异内容返回 409。
    """

    expected_revision: int = Field(ge=1, strict=True)


class TaskIngressResponse(BaseModel):
    """Task Ingress 响应：服务端生成的 task_id/revision/digests + status。"""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    revision: int = Field(ge=1)
    task_digest: str
    scope_digest: str
    status: Literal["active", "cancelled", "superseded"]


def _rfc3339_timestamp(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"{field_name} must be an RFC 3339 timestamp") from None
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed


def _utc_timestamp(value: str, field_name: str) -> str:
    return _rfc3339_timestamp(value, field_name).astimezone(timezone.utc).isoformat()
