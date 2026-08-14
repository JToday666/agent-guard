"""Storage protocol for Guard API / Control Plane state."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, ContextManager, Protocol

from agentguard_core import (
    AuditEvent,
    ActionCriticReview,
    ConfigAuditEvent,
    ConfigAuditFinding,
    MemoryGuardChange,
    PolicyBundle,
    ProvenanceEdge,
    ProvenanceNode,
)
from agentguard_core.authority import TaskFact

from guard_api.models import (
    AdapterStatusRecord,
    ApprovalRequest,
    ConfigAuditFindingRecord,
    CredentialRecord,
    EvaluationRun,
    LlmApprovalReview,
)


@dataclass(frozen=True, slots=True)
class AuditEventFilters:
    trace_id: str | None = None
    case_id: str | None = None
    runtime: str | None = None
    decision: str | None = None
    limit: int = 500


@dataclass(frozen=True, slots=True)
class AuditWindowQuery:
    """审计链有界读取参数（契约 §5.2/§6.1）。

    upper_sequence 为 None 时以当前链头上界为准；after_sequence 用于
    cursor 续页，只读取 sequence 严格小于它的记录；evaluated_from/to
    使用带时区 datetime 过滤事实发生时间，范围语义为
    [evaluated_from, evaluated_to)。ingested_as_of 限制查询只包含该时点
    已进入审计链的事实。窗口与 cohort 共用本查询。
    """

    upper_sequence: int | None = None
    after_sequence: int | None = None
    evaluated_from: datetime | None = None
    evaluated_to: datetime | None = None
    ingested_as_of: datetime | None = None
    record_type: str | None = None
    trace_id: str | None = None
    case_id: str | None = None
    runtime: str | None = None
    decision: str | None = None
    limit: int = 500


@dataclass(frozen=True, slots=True)
class StoredLaunchCode:
    code_hash: str
    expires_at: str
    used_at: str | None = None


@dataclass(frozen=True, slots=True)
class StoredBrowserSession:
    session_hash: str
    csrf_token: str
    expires_at: str
    revoked_at: str | None = None


@dataclass(frozen=True, slots=True)
class PolicySnapshotRecord:
    revision: int
    policy_bundle: PolicyBundle
    updated_at: str
    updated_by: str


@dataclass(frozen=True, slots=True)
class TaskFactRecord:
    """task_facts 存储记录：TaskFact 全量 + 幂等/CAS 元数据（V21-03）。

    ``canonical_payload`` 为 TaskFact 的 ``model_dump(mode="json")`` 全量
    快照；``request_digest`` 是入口请求内容字段的受限 JCS sha256，与
    ``expected_revision`` 组成幂等重放键；``expected_revision`` 是写入时
    的 CAS 锚点（revision 1 对应 0）。
    """

    task_fact: TaskFact
    canonical_payload: dict[str, Any]
    request_digest: str
    expected_revision: int
    created_at: str


def within_evaluated_range(
    timestamp: str,
    evaluated_from: datetime | None,
    evaluated_to: datetime | None,
) -> bool:
    """判断记录 timestamp 是否落入 [evaluated_from, evaluated_to) 区间。

    两端存储必须经由本函数完成时间 cohort 过滤，避免字符串比较因
    RFC 3339 后缀差异（+00:00 与 Z）产生口径漂移；无法解析的
    timestamp 一律不进入 cohort。
    """

    if evaluated_from is None and evaluated_to is None:
        return True
    try:
        occurred_at = parse_audit_timestamp(timestamp)
    except ValueError:
        return False
    if evaluated_from is not None and occurred_at < evaluated_from:
        return False
    if evaluated_to is not None and occurred_at >= evaluated_to:
        return False
    return True


class AuditTimestampError(ValueError):
    """Raised when an audit fact timestamp is not an aware RFC 3339 value."""


class AuditCanonicalizationError(ValueError):
    """Raised when evidence is outside the RFC 8785 / I-JSON domain."""


def parse_audit_timestamp(timestamp: str) -> datetime:
    """Parse an audit fact timestamp and require an explicit timezone."""

    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        raise AuditTimestampError("audit timestamp must be RFC 3339") from None
    if parsed.tzinfo is None:
        raise AuditTimestampError("audit timestamp must include a timezone")
    return parsed


def classify_audit_record_type(event: AuditEvent) -> str:
    """Resolve the persisted record class for both 0.4 and frozen 0.3 input."""

    if event.record_type:
        return event.record_type
    if event.event_type == "config_audit":
        return "config_audit"
    if event.event_type == "runtime_observation":
        return "runtime_observation"
    return "policy_evaluation"


@dataclass(frozen=True, slots=True)
class AuditIntegrityStatus:
    valid: bool
    event_count: int
    head_hash: str | None
    first_broken_audit_id: str | None = None


class AuditIdConflictError(ValueError):
    """Raised when the same audit_id is re-submitted with different content."""


class ApprovalStateConflictError(ValueError):
    """Raised when an approval can no longer transition from pending."""

    def __init__(self, approval_id: str, status: str) -> None:
        self.approval_id = approval_id
        self.status = status
        super().__init__(f"{approval_id}: {status}")


class MemoryChangeTransitionError(ValueError):
    """记忆变更状态机拒绝的非法转换。

    合法转换见 core `MEMORY_CHANGE_ALLOWED_TRANSITIONS`；同态重复转换
    幂等返回当前状态而非抛出本异常。
    """

    def __init__(self, change_id: str, from_status: str, to_status: str) -> None:
        self.change_id = change_id
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(f"{change_id}: {from_status} -> {to_status}")


class MemoryChangeAlreadyExistsError(ValueError):
    """同 change_id 的记忆变更已存在且本次提交内容不一致。

    create_memory_change 采用「存在即拒绝」语义：重复提交仅在记录
    完全一致时幂等返回既有记录，否则抛本异常，防止以重复 propose
    覆盖提议方 principal/status/内容字段。
    """

    def __init__(self, change_id: str) -> None:
        self.change_id = change_id
        super().__init__(change_id)


def memory_change_is_replay_match(
    existing: MemoryGuardChange, incoming: MemoryGuardChange
) -> bool:
    """判定重复 propose 是否构成幂等重放。

    对齐审计 §12.3 重放语义：除 created_at/updated_at 时间戳外全字段
    一致（含 principal_id、status、内容字段）才视为同一提议的重放；
    任何字段差异（含提议方不同）都判为冲突并拒绝。
    """

    return existing.model_dump(
        mode="json",
        exclude={
            "created_at",
            "updated_at",
        },
    ) == incoming.model_dump(mode="json", exclude={"created_at", "updated_at"})


@dataclass(frozen=True, slots=True)
class MemoryTransitionResult:
    """记忆变更状态转换的结构化结果。

    change 为转换生效后的记录（applied=False 时为当前记录原样）；
    applied 区分「本次调用真正执行了转换」与「已完成转换的幂等重放」，
    服务层仅在 applied=True 时写入转换审计，消除并发落败方的重复入链；
    previous_status 是存储层读到的转换前状态（权威值），服务层不得
    再依赖更新前的陈旧读值。
    """

    change: MemoryGuardChange
    applied: bool
    previous_status: str


class ProvenanceConflictError(ValueError):
    """Raised when a stable provenance ID is bound to conflicting facts."""


class ProvenanceEndpointMissingError(ProvenanceConflictError):
    """Raised when a provenance edge references a missing or foreign node."""


class PolicyRevisionConflictError(ValueError):
    """Raised when a policy write targets a stale revision."""

    def __init__(self, *, expected_revision: int, current_revision: int) -> None:
        self.expected_revision = expected_revision
        self.current_revision = current_revision
        super().__init__(
            f"expected policy revision {expected_revision}, current is {current_revision}"
        )


class TaskRevisionConflictError(ValueError):
    """任务修订的 CAS 锚点与当前 head revision 不一致（V21-03，01 §30）。

    语义与 PolicyRevisionConflictError 对齐：revision 落后或同 revision
    异内容均由存储层拒绝，旧 revision 永不静默覆盖。
    """

    def __init__(self, *, expected_revision: int, current_revision: int) -> None:
        self.expected_revision = expected_revision
        self.current_revision = current_revision
        super().__init__(
            f"expected task revision {expected_revision}, current is {current_revision}"
        )


class EvaluationRunConflictError(ValueError):
    """Raised when an immutable evaluation run ID is reused for new content."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        super().__init__(run_id)


def merge_provenance_node(
    existing: ProvenanceNode, incoming: ProvenanceNode
) -> ProvenanceNode:
    """Merge a deterministic node without degrading or replacing known facts."""

    identity = (existing.trace_id, existing.kind, existing.ref_id)
    incoming_identity = (incoming.trace_id, incoming.kind, incoming.ref_id)
    if identity != incoming_identity:
        raise ProvenanceConflictError(existing.node_id)
    approval_transition = existing.kind == "approval" and _approval_status_can_advance(
        existing.metadata.get("status"), incoming.metadata.get("status")
    )
    mutable = frozenset({"status"}) if approval_transition else frozenset()
    return existing.model_copy(
        update={
            "label": _merge_provenance_value(
                existing.label,
                incoming.label,
                identity=existing.node_id,
                path="label",
                mutable=approval_transition,
            ),
            "timestamp": _earliest_timestamp(existing.timestamp, incoming.timestamp),
            "metadata": _merge_provenance_mapping(
                existing.metadata,
                incoming.metadata,
                identity=existing.node_id,
                mutable_keys=mutable,
            ),
        }
    )


def _approval_status_can_advance(existing: Any, incoming: Any) -> bool:
    """Allow only pending -> terminal approval state transitions."""

    return existing == "pending" and incoming in {"resolved", "expired"}


def merge_provenance_edge(
    existing: ProvenanceEdge, incoming: ProvenanceEdge
) -> ProvenanceEdge:
    """Merge edge metadata while keeping endpoints and relation immutable."""

    identity = (
        existing.trace_id,
        existing.source_node_id,
        existing.target_node_id,
        existing.relation,
    )
    incoming_identity = (
        incoming.trace_id,
        incoming.source_node_id,
        incoming.target_node_id,
        incoming.relation,
    )
    if identity != incoming_identity:
        raise ProvenanceConflictError(existing.edge_id)
    return existing.model_copy(
        update={
            "timestamp": _earliest_timestamp(existing.timestamp, incoming.timestamp),
            "metadata": _merge_provenance_mapping(
                existing.metadata,
                incoming.metadata,
                identity=existing.edge_id,
                mutable_keys=frozenset(),
            ),
        }
    )


def _merge_provenance_mapping(
    existing: dict[str, Any],
    incoming: dict[str, Any],
    *,
    identity: str,
    mutable_keys: frozenset[str],
) -> dict[str, Any]:
    merged = dict(existing)
    for key, value in incoming.items():
        if key not in merged:
            if not _is_unknown_provenance_value(value):
                merged[key] = value
            continue
        current = merged[key]
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _merge_provenance_mapping(
                current,
                value,
                identity=identity,
                mutable_keys=frozenset(),
            )
            continue
        merged[key] = _merge_provenance_value(
            current,
            value,
            identity=identity,
            path=f"metadata.{key}",
            mutable=key in mutable_keys,
        )
    return merged


def _merge_provenance_value(
    existing: Any,
    incoming: Any,
    *,
    identity: str,
    path: str,
    mutable: bool,
) -> Any:
    if _is_unknown_provenance_value(incoming):
        return existing
    if _is_unknown_provenance_value(existing) or existing == incoming or mutable:
        return incoming
    raise ProvenanceConflictError(f"{identity}:{path}")


def _is_unknown_provenance_value(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip() or value.strip().lower() == "unknown"
    if isinstance(value, (list, dict)):
        return not value
    return False


def _earliest_timestamp(existing: str, incoming: str) -> str:
    try:
        existing_at = datetime.fromisoformat(existing.replace("Z", "+00:00"))
        incoming_at = datetime.fromisoformat(incoming.replace("Z", "+00:00"))
    except ValueError:
        if existing == incoming:
            return existing
        raise ProvenanceConflictError("provenance timestamp") from None
    return incoming if incoming_at < existing_at else existing


class ControlPlaneStore(Protocol):
    def initialize(self) -> None: ...

    def health_check(self) -> bool: ...

    def add_audit_event(self, event: AuditEvent) -> bool: ...

    def get_audit_event(self, audit_id: str) -> AuditEvent | None: ...

    def list_audit_events(
        self, filters: AuditEventFilters | None = None
    ) -> list[AuditEvent]: ...

    def read_audit_events_bounded(
        self, query: AuditWindowQuery
    ) -> list[AuditEvent]: ...

    def capture_audit_snapshot(self) -> tuple[int, datetime]: ...

    def get_policy_evaluation_by_event_id(self, event_id: str) -> AuditEvent | None: ...

    def evaluation_transaction(self, event_id: str) -> ContextManager[None]: ...

    def memory_change_transaction(self, change_id: str) -> ContextManager[None]:
        """状态转换与转换审计的原子窗口。

        上下文内的状态条件更新、审计入链与 provenance 写入随同一事务
        提交或回滚；实现必须保证外部读不到「状态已改、审计未入链」
        的中间态。
        """
        ...

    def verify_audit_integrity(self) -> AuditIntegrityStatus: ...

    def add_provenance_node(self, node: ProvenanceNode) -> ProvenanceNode: ...

    def get_provenance_node(self, node_id: str) -> ProvenanceNode | None: ...

    def add_provenance_edge(self, edge: ProvenanceEdge) -> ProvenanceEdge: ...

    def list_provenance(
        self,
        trace_id: str,
        *,
        node_limit: int | None = None,
        edge_limit: int | None = None,
    ) -> tuple[list[ProvenanceNode], list[ProvenanceEdge]]: ...

    def add_config_audit_finding(
        self,
        event: ConfigAuditEvent,
        finding: ConfigAuditFinding,
    ) -> ConfigAuditFinding: ...

    def list_config_audit_findings(
        self,
        *,
        trace_id: str | None = None,
        target_id: str | None = None,
        target_type: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[ConfigAuditFindingRecord]: ...

    def save_evaluation_run(self, run: EvaluationRun | dict) -> dict: ...

    def get_latest_evaluation_run(self) -> dict | None: ...

    def get_evaluation_run(self, run_id: str) -> dict | None: ...

    def list_evaluation_runs(
        self,
        *,
        dataset_id: str | None = None,
        dataset_version: str | None = None,
        limit: int = 100,
    ) -> list[dict]: ...

    def save_adapter_status(
        self, adapter_id: str, status: AdapterStatusRecord | dict
    ) -> dict: ...

    def get_adapter_status(self, adapter_id: str) -> dict | None: ...

    def list_adapter_statuses(self) -> dict[str, dict]: ...

    def create_credential(
        self, credential: CredentialRecord | dict
    ) -> CredentialRecord: ...

    def get_credential_by_token_hash(
        self, token_hash: str
    ) -> CredentialRecord | None: ...

    def list_credentials(self) -> list[CredentialRecord]: ...

    def revoke_credential(
        self, credential_id: str, revoked_at: str
    ) -> CredentialRecord: ...

    def add_action_critic_review(
        self, review: ActionCriticReview
    ) -> ActionCriticReview: ...

    def list_action_critic_reviews(self, trace_id: str) -> list[ActionCriticReview]: ...

    def create_memory_change(self, change: MemoryGuardChange) -> MemoryGuardChange:
        """创建记忆变更记录（存在即拒绝语义）。

        契约：change_id 不存在则插入并返回；同 change_id 已存在且与本次
        提交完全一致（见 memory_change_is_replay_match）则幂等返回既有记录，
        否则抛 MemoryChangeAlreadyExistsError。实现不得以 upsert 覆盖
        既有记录的 principal/status/内容字段。
        """
        ...

    def get_memory_change(self, change_id: str) -> MemoryGuardChange | None: ...

    def update_memory_change_status(
        self, change_id: str, status: str
    ) -> MemoryTransitionResult:
        """按状态机推进记忆变更生命周期。

        契约：不存在抛 KeyError；同态重复幂等返回当前状态（applied=False）；
        非法转换抛 MemoryChangeTransitionError；实现必须用前态条件更新，
        消除 read-modify-write 竞态；返回结果携带 applied 与存储层读到的
        previous_status，供服务层判定是否写入转换审计。
        """
        ...

    def get_policy_snapshot(self) -> PolicyBundle | None: ...

    def get_policy_snapshot_record(self) -> PolicySnapshotRecord | None: ...

    def save_policy_snapshot(
        self,
        policy_bundle: PolicyBundle,
        *,
        expected_revision: int,
        updated_by: str = "system",
    ) -> PolicySnapshotRecord: ...

    def list_policy_snapshot_history(
        self, limit: int = 100
    ) -> list[PolicySnapshotRecord]: ...

    def create_task_fact(self, record: TaskFactRecord) -> TaskFactRecord:
        """追加式写入一条 TaskFact revision（V21-03 CAS 契约）。

        契约：仅当 ``record.expected_revision`` 等于该 task_id 当前 head
        revision（无记录为 0，revision 1 必须携带 expected_revision=0）
        时追加；否则抛 TaskRevisionConflictError。旧 revision 永不覆盖；
        同 (task_id, revision) 重复写入一律拒绝。
        """
        ...

    def get_task_fact(
        self, task_id: str, revision: int | None = None
    ) -> TaskFactRecord | None:
        """读取单条 TaskFact revision；``revision=None`` 时读 head。"""
        ...

    def list_task_fact_revisions(
        self, task_id: str
    ) -> list[TaskFactRecord]:
        """按 revision 升序返回该任务的全部历史 revision。"""
        ...

    def create_approval(self, approval: ApprovalRequest) -> ApprovalRequest: ...

    def list_pending_approvals(self) -> list[ApprovalRequest]: ...

    def list_approvals(
        self,
        trace_id: str | None = None,
        *,
        limit: int | None = None,
    ) -> list[ApprovalRequest]: ...

    def get_approval(self, approval_id: str) -> ApprovalRequest | None: ...

    def resolve_approval(
        self,
        approval_id: str,
        decision: str,
        *,
        resolution_source: str | None = None,
        resolved_by: str | None = None,
        resolution_reason: str | None = None,
        llm_review: LlmApprovalReview | None = None,
    ) -> ApprovalRequest: ...

    def create_launch_code(
        self, code_hash: str, expires_at: str
    ) -> StoredLaunchCode: ...

    def consume_launch_code(
        self, code_hash: str, used_at: str
    ) -> StoredLaunchCode | None: ...

    def create_browser_session(
        self,
        session_hash: str,
        *,
        csrf_token: str,
        expires_at: str,
    ) -> StoredBrowserSession: ...

    def get_browser_session(self, session_hash: str) -> StoredBrowserSession | None: ...

    def revoke_browser_session(self, session_hash: str, revoked_at: str) -> None: ...
