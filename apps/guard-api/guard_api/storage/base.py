"""Storage protocol for Guard API / Control Plane state."""

from __future__ import annotations

from dataclasses import dataclass, field
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
from agentguard_core.security_context import (
    CapabilityGrant,
    ExecutionLease,
    GrantConsumption,
)

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


#: rebuild 输入有界读取的钳制上限（F2）：两个存储实现与 rebuild 消费方
#: 共享本常量，避免钳制值在两处漂移导致截断判定失效。
MAX_REBUILD_INPUT_LIMIT = 1000


@dataclass(frozen=True, slots=True)
class SecurityStateRecord:
    """security_states 存储记录：OnlineSecurityState 全量快照（V21-04）。

    ``canonical_payload`` 为 OnlineSecurityState 的
    ``model_dump(mode="json")`` 全量快照，读回口径统一 ``model_validate``；
    ``state_version`` 是单调版本链锚点（CAS V→V+1，02 §4.1）；
    ``dirty`` / ``dirty_domains`` 承载 projector failure / digest conflict
    的脏态标记（02 §3：失败不得解释为 complete）。
    """

    scope_digest: str
    state_version: int
    canonical_payload: dict[str, Any]
    dirty: bool
    dirty_domains: list[str]
    projector_version: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class ProjectionIdentityRecord:
    """projection_records 存储记录：Projector 幂等键五元组（V21-04, 02 §4）。

    幂等身份为 ``(scope_digest, source_record_type, source_record_id,
    source_revision, projector_version)`` 五元组（禁止只用 event_id）；
    ``delta_digest`` 是同身份重放时的等价性锚点，同身份异 digest 由
    存储层拒绝（ProjectionDigestConflictError，不静默覆盖）；
    ``delta_payload`` 为 SecurityStateDeltaV21 的
    ``model_dump(mode="json")`` 快照，rebuild 据此按规范序重放
    （T-Replay 确定性，05 §12）。
    """

    scope_digest: str
    source_record_type: str
    source_record_id: str
    source_revision: int
    projector_version: str
    delta_digest: str
    delta_payload: dict[str, Any]
    applied_state_version: int
    created_at: str


@dataclass(frozen=True, slots=True)
class GrantConsumptionResult:
    """grant 原子消费结果（V21-06, C4；Phase 0 结构占位）。

    ``lease_token`` 是返回给调用方的明文 lease token（可重试同一值），
    **仅经本返回值交付一次，存储层永不落库**（落库的是
    ``ExecutionLease.token_digest``，01 §15）；``replayed`` 标记同内容
    幂等重放（返回同一 token，不重复扣减 remaining_uses）。
    """

    consumption: GrantConsumption
    lease: ExecutionLease
    lease_token: str = field(repr=False)
    replayed: bool


@dataclass(frozen=True, slots=True)
class EnforcementBindingRecord:
    """Private authoritative ActionIR binding for one approval.

    This record is deliberately a storage-only type.  In particular, the
    authorization fingerprint must never be projected into Approval, Audit,
    Trace, Provenance, Dashboard, Receipt, or log payloads.
    """

    event_id: str
    policy_audit_id: str
    approval_id: str
    action_id: str
    action_type: str
    authorization_fingerprint: str = field(repr=False)
    runtime_binding_id: str
    scope_digest: str
    principal_id: str
    runtime: str
    agent_id: str
    policy_revision: str
    requires_execution_lease: bool
    grant_id: str | None = field(repr=False)
    created_at: str


@dataclass(frozen=True, slots=True)
class ApprovalLeaseConsumeCommand:
    """Trusted, internal command for an approval-bound lease consumption.

    ``credential_token_hash`` and ``lease_token`` are transient inputs only;
    implementations must not persist or include them in exception messages.
    ``expires_at`` is computed by the Guard API service and is bounded again by
    the authoritative approval/grant expiry inside the atomic transaction.
    """

    credential_id: str
    credential_token_hash: str = field(repr=False)
    principal_id: str
    runtime: str
    agent_id: str
    approval_id: str
    action_id: str
    authorization_fingerprint: str = field(repr=False)
    lease_token: str = field(repr=False)
    expires_at: str


class ApprovalLeaseStoreError(Exception):
    """Base for sanitized RTE-05 storage errors."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


class EnforcementBindingConflictError(ApprovalLeaseStoreError):
    """A private binding identity was reused with different immutable facts."""


class ApprovalLeaseAuthorizationError(ApprovalLeaseStoreError):
    """Credential or runtime-bound identity revalidation failed."""


class ApprovalLeaseNotFoundError(ApprovalLeaseStoreError):
    """The requested approval does not exist."""


class ApprovalLeaseNotConsumableError(ApprovalLeaseStoreError):
    """The approval/grant lifecycle does not permit consumption."""


class ApprovalLeaseConsumptionConflictError(ApprovalLeaseStoreError):
    """The request conflicts with the authoritative binding or prior consume."""


class ApprovalLeaseExpiredError(ApprovalLeaseStoreError):
    """The authoritative approval has expired."""


class ApprovalExecutionLeaseExpiredError(ApprovalLeaseStoreError):
    """An exact replay targeted an already expired execution lease."""


class ApprovalExecutionLeaseUnavailableError(ApprovalLeaseStoreError):
    """The private binding or projected runtime grant is not ready."""


class ApprovalExecutionLeaseStateInvalidError(ApprovalLeaseStoreError):
    """Private lease state violates an internal invariant."""


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


class StateVersionConflictError(ValueError):
    """security state 的 CAS 锚点与当前 state_version 不一致（V21-04, 02 §4.1）。

    形态对齐 TaskRevisionConflictError：仅当 ``expected_state_version``
    等于该 scope 当前 state_version（无记录为 0）时 CAS 才可应用，
    旧版本永不静默覆盖。
    """

    def __init__(
        self, *, expected_state_version: int, current_state_version: int
    ) -> None:
        self.expected_state_version = expected_state_version
        self.current_state_version = current_state_version
        super().__init__(
            f"expected security state version {expected_state_version}, "
            f"current is {current_state_version}"
        )


class ProjectionDigestConflictError(ValueError):
    """同一投影身份五元组出现不同 delta_digest（V21-04, 02 §4.1 第 3 分支）。

    形态对齐 TaskRevisionConflictError：digest 冲突 → state dirty +
    security alert，存储层拒绝写入，不静默覆盖。
    """

    def __init__(
        self, *, projection_key: str, existing_digest: str, incoming_digest: str
    ) -> None:
        self.projection_key = projection_key
        self.existing_digest = existing_digest
        self.incoming_digest = incoming_digest
        super().__init__(
            f"projection identity {projection_key}: digest conflict "
            f"({existing_digest} vs {incoming_digest})"
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

    def list_task_fact_revisions(self, task_id: str) -> list[TaskFactRecord]:
        """按 revision 升序返回该任务的全部历史 revision。"""
        ...

    def get_security_state(self, scope_digest: str) -> SecurityStateRecord | None:
        """读取该 scope 的 OnlineSecurityState 存储记录；缺省返回 None（V21-04）。"""
        ...

    def cas_security_state(
        self,
        scope_digest: str,
        expected_state_version: int,
        record: SecurityStateRecord,
    ) -> bool:
        """state version CAS 写入（V21-04, 02 §4.1）。

        契约：仅当该 scope 当前 state_version 等于
        ``expected_state_version``（无记录为 0）时写入 ``record``；
        版本不匹配抛 StateVersionConflictError（memory/postgres 双实现
        统一采用抛异常语义，不返回 False）。旧版本永不静默覆盖。
        """
        ...

    def mark_security_state_dirty(self, scope_digest: str, domains: list[str]) -> None:
        """登记 projector failure / digest conflict 的脏态标记（V21-04, 02 §3）。

        契约：把 ``domains`` 并入既有记录的 dirty_domains 并置 dirty=True，
        ``state_version`` 保持不变（CAS 锚点不受 dirty 标记影响）；
        state 不存在时创建 ``state_version=0`` 的空态脏记录。
        双口径同步（F1）：dirty 域必须同时并入 canonical_payload 内的
        ``dirty_domains``（payload 是 OnlineSecurityState 的
        ``model_dump(mode="json")`` 口径，改动后必须能被
        ``model_validate`` 读回），否则 projector 从 payload 重建状态
        后回写会静默清除失败事实。
        """
        ...

    def record_projection(
        self, record: ProjectionIdentityRecord
    ) -> tuple[ProjectionIdentityRecord, bool]:
        """幂等写入一条投影登记（V21-04, 02 §4 三分支的存储侧锚点）。

        契约：新身份写入成功 → ``(record, True)``；同五元组身份且
        delta_digest 相同已存在 → ``(既有记录, False)`` no-op；同身份
        异 delta_digest → 抛 ProjectionDigestConflictError（不静默覆盖）。
        """
        ...

    def get_projection(
        self,
        scope_digest: str,
        source_record_type: str,
        source_record_id: str,
        source_revision: int,
        projector_version: str,
    ) -> ProjectionIdentityRecord | None:
        """按幂等键五元组读取单条投影登记；缺省返回 None。"""
        ...

    def list_rebuild_inputs(
        self, scope_digest: str, *, limit: int
    ) -> list[ProjectionIdentityRecord]:
        """有界读取该 scope 的 rebuild 输入（V21-04）。

        契约：按 ``applied_state_version`` 升序返回，至多 ``limit`` 条；
        ``limit`` 被钳制到 ``[1, MAX_REBUILD_INPUT_LIMIT]``（调用方判定
        截断时必须用钳制后的有效值）；调用方在返回条数达到有效 limit
        时必须按 fail-closed 处理截断风险（相关域置 partial/dirty），
        不得假设输入完整。
        """
        ...

    def consume_grant(
        self, scope_digest: str, intent_payload: dict[str, Any]
    ) -> GrantConsumptionResult:
        """grant 原子消费（V21-06, 01 §15 / C4；Phase 0 结构占位）。

        契约（Phase 1-V21-06 实现）：Guard API **单事务**内完成
        校验 fingerprint/expiry/remaining_uses → CAS 扣减
        ``remaining_uses`` → 写 GrantConsumption（UNIQUE(grant_id,
        action_id) 幂等防双花）→ 写 ExecutionLease → 返回可重试同一
        token。同内容重放幂等返回同一 token（``replayed=True``）；
        异内容冲突拒绝。明文 lease token 不落库（只存 token_digest）。
        """
        raise NotImplementedError(
            "V21-06: atomic grant consumption is not wired in Phase 0"
        )

    def save_enforcement_binding(
        self, record: EnforcementBindingRecord
    ) -> EnforcementBindingRecord:
        """Persist one immutable private binding, or return its exact replay.

        ``event_id``, ``policy_audit_id`` and ``approval_id`` are unique
        identities.  Reuse with different immutable binding facts is a
        conflict; ``grant_id`` is populated only by
        :meth:`register_approval_grant`.
        """
        ...

    def get_enforcement_binding(
        self, approval_id: str
    ) -> EnforcementBindingRecord | None:
        """Read a private binding by approval ID; never expose it publicly."""
        ...

    def register_approval_grant(
        self,
        binding: EnforcementBindingRecord,
        grant: CapabilityGrant,
    ) -> EnforcementBindingRecord:
        """Idempotently register the exact grant and attach it to a binding."""
        ...

    def consume_approval_execution_lease(
        self, command: ApprovalLeaseConsumeCommand
    ) -> GrantConsumptionResult:
        """Atomically revalidate approval authority and consume one lease."""
        ...

    def get_execution_lease(
        self, scope_digest: str, lease_ref: str
    ) -> ExecutionLease | None:
        """按 lease_id 或 token_digest 读取执行租约（V21-06, 01 §15）。

        ``lease_ref`` 可为 lease_id 或 token_digest；缺省返回 None。
        Phase 1-V21-06 实现。
        """
        raise NotImplementedError(
            "V21-06: execution lease lookup is not wired in Phase 0"
        )

    def expire_or_revoke_lease(
        self, scope_digest: str, lease_id: str, reason: str
    ) -> ExecutionLease:
        """把 lease 推进到 expired/revoked 终态（V21-06, 01 §15）。

        契约（Phase 1-V21-06 实现）：不存在抛 KeyError；已是终态时
        幂等返回当前记录；``reason`` 供审计引用，不落 lease 安全摘要
        白名单。返回转换后的 lease。
        """
        raise NotImplementedError(
            "V21-06: lease expiry/revocation is not wired in Phase 0"
        )

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
