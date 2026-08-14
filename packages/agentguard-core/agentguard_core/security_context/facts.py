"""V2.1 frozen security-context fact scaffolds (V21-04).

字段逐字冻结自
``docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/01_F1字段与契约冻结.md``：

- SourceFact §10, L453-487；
- DeclassificationFact §11, L491-510；
- FlowFact §12, L514-550；
- MemoryFact §13, L554-581；
- CapabilityGrant §14, L585-643；
- GrantConsumption / ExecutionLease §15, L649-678；
- RecentActionFact §16, L684-704；
- RuntimeOutcomeFact / BehaviorAggregate / StickyTaintSummary §16, L709-737；
- GapRange / StateWatermarks §17, L771-783；
- digest 白名单规范 §29, L1162-1181。

本模块为纯新增 scaffold：不引入 DB/HTTP，不被判定路径
（``engine.py`` / ``decisions/policy.py``）引用。

Digest 口径声明（与 ``authority/models.py`` 保持一致，防口径分裂）：

- 所有 digest 统一使用 ``actions/canonical_json.py`` 的受限 JCS
  （RFC 8785 禁 float 子集，01 §29）；
- 每种对象只投影 ``digest_fields()`` 白名单字段，禁止把 ``model_dump``
  全量结果直接作为 digest 输入；
- 白名单冻结规则：``new_id()``/uuid 类纯标识字段与时间戳不进安全摘要；
  语义稳定字段（trust/taint/约束/引用/序列锚点等）必须进。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from ..actions.canonical_json import canonical_sha256
from ..actions.models import (
    ActionEffect,
    ArgumentConstraint,
    DestinationConstraint,
    ResourceConstraint,
)
from ..authority.models import canonical_constraints_projection
from ..signals.models import (
    AuthorityStatus,
    Decision,
    EvidenceOrigin,
    EvidenceRef,
    FactAuthority,
    FlowStrength,
    ImpactClass,
    SequenceDomain,
    SequenceRef,
    TaintLabel,
)

__all__ = [
    "BehaviorAggregate",
    "CapabilityGrant",
    "DeclassificationFact",
    "ExecutionLease",
    "FlowFact",
    "GapRange",
    "GrantConsumption",
    "MemoryFact",
    "RecentActionFact",
    "RuntimeOutcomeFact",
    "SourceFact",
    "StateWatermarks",
    "StickyTaintSummary",
    "fact_digest",
    "fact_digest_projection",
]


def _canonical_value(value: Any) -> Any:
    """把模型/列表递归转为受限 canonical JSON 类型域内的纯数据。"""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


def fact_digest_projection(fact: BaseModel) -> dict[str, Any]:
    """按 ``fact.digest_fields()`` 白名单投影（01 §29, L1184）。

    约束类列表（CapabilityGrant 的三类约束）按集合语义去重并稳定排序，
    其余白名单字段按声明键名原样投影。
    """
    digest_fields = fact.digest_fields()  # type: ignore[attr-defined]
    if isinstance(fact, CapabilityGrant):
        payload: dict[str, Any] = {
            field: _canonical_value(getattr(fact, field))
            for field in sorted(digest_fields)
            if field
            not in {
                "resource_constraints",
                "destination_constraints",
                "argument_constraints",
            }
        }
        normalized = canonical_constraints_projection(
            action_constraints=[],
            resource_constraints=fact.resource_constraints,
            destination_constraints=fact.destination_constraints,
        )
        payload["resource_constraints"] = normalized["resource_constraints"]
        payload["destination_constraints"] = normalized[
            "destination_constraints"
        ]
        payload["argument_constraints"] = sorted(
            (
                item.model_dump(mode="json")
                for item in fact.argument_constraints
            ),
            key=lambda item: canonical_sha256(item),
        )
        return payload
    return {
        field: _canonical_value(getattr(fact, field))
        for field in sorted(digest_fields)
    }


def fact_digest(fact: BaseModel) -> str:
    """``canonical_sha256(白名单投影)``，``sha256:`` 前缀（01 §29）。"""
    return canonical_sha256(fact_digest_projection(fact))


# ---------------------------------------------------------------------------
# SourceFact (01 §10, L453-487)
# ---------------------------------------------------------------------------


class SourceFact(BaseModel):
    """来源事实（01 §10 逐字冻结）。

    冻结语义：``sanitized`` 不作为 ``trust`` 值；净化/降级由
    ``DeclassificationFact`` 表达。``source_id`` 是注册标识（可为随机
    id），不进安全摘要；语义身份由类型/trust/producer/序列锚点承载。
    """

    model_config = ConfigDict(extra="forbid")

    source_id: str
    scope_digest: str

    source_type: Literal[
        "user",
        "web",
        "email",
        "tool_result",
        "mcp",
        "rag",
        "memory",
        "file",
        "model",
        "runtime",
        "other",
    ]

    trust: Literal["trusted", "untrusted", "unknown"]
    verification_state: Literal["verified", "unverified", "not_applicable"]

    origin: EvidenceOrigin
    authority: FactAuthority
    producer: str

    taints: list[TaintLabel]
    first_sequence: SequenceRef | None
    last_sequence: SequenceRef | None
    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29, L1162-1181）。

        排除 ``source_id``（注册标识，可为随机 id）；``scope_digest``
        作为稳定 scope 绑定进入摘要。
        """
        return frozenset(
            {
                "scope_digest",
                "source_type",
                "trust",
                "verification_state",
                "origin",
                "authority",
                "producer",
                "taints",
                "first_sequence",
                "last_sequence",
                "evidence_refs",
            }
        )


# ---------------------------------------------------------------------------
# DeclassificationFact (01 §11, L491-510)
# ---------------------------------------------------------------------------


class DeclassificationFact(BaseModel):
    """净化/降级事实（01 §11 逐字冻结）。

    冻结语义：客户端/Adapter 不能自报 ``sanitized=True`` 后直接清 taint；
    只有 ``producer == "trusted_declassifier"`` 的记录可表达 taint 移除。
    """

    model_config = ConfigDict(extra="forbid")

    declass_id: str
    input_ref: str
    output_ref: str

    removed_taints: list[TaintLabel]
    retained_taints: list[TaintLabel]

    mechanism_id: str
    mechanism_version: str
    policy_revision: str

    producer: Literal["trusted_declassifier"]
    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）。

        排除 ``declass_id``（注册标识）；input/output ref、机制身份与
        taint 变化是语义核心，必须进。
        """
        return frozenset(
            {
                "input_ref",
                "output_ref",
                "removed_taints",
                "retained_taints",
                "mechanism_id",
                "mechanism_version",
                "policy_revision",
                "producer",
                "evidence_refs",
            }
        )


# ---------------------------------------------------------------------------
# FlowFact (01 §12, L514-550)
# ---------------------------------------------------------------------------


class FlowFact(BaseModel):
    """数据/影响流事实（01 §12 逐字冻结）。

    冻结语义：``taints`` 不随 hop 数自动衰减；``strength`` 可因证据质量
    为 exact/strong/possible；LLM 不透明变换默认最多 ``possible``。
    """

    model_config = ConfigDict(extra="forbid")

    flow_id: str
    scope_digest: str

    source_ref: str
    target_ref: str

    relation: Literal[
        "received_from",
        "read_from",
        "derived_from",
        "assembled_into",
        "influenced_by",
        "returned_by",
        "written_to",
        "persisted_to",
        "loaded_from_memory",
        "sent_to",
    ]

    taints: list[TaintLabel]
    strength: FlowStrength
    origin: Literal["observed", "deterministic", "semantic_inferred"]

    sequence: SequenceRef | None
    producer: str
    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）。

        排除 ``flow_id``（注册标识）；source/target、relation、taints、
        strength 是流的安全语义核心，必须进。
        """
        return frozenset(
            {
                "scope_digest",
                "source_ref",
                "target_ref",
                "relation",
                "taints",
                "strength",
                "origin",
                "sequence",
                "producer",
                "evidence_refs",
            }
        )


# ---------------------------------------------------------------------------
# MemoryFact (01 §13, L554-581)
# ---------------------------------------------------------------------------


class MemoryFact(BaseModel):
    """Memory 事实（01 §13 逐字冻结）。

    复用现有 Memory Change Lifecycle，不另造冲突状态机；
    ``change_status`` 与 ``trust_state`` 不混用。
    """

    model_config = ConfigDict(extra="forbid")

    memory_id: str
    change_id: str | None

    change_status: (
        Literal[
            "proposed",
            "quarantined",
            "committed",
            "rejected",
            "rolled_back",
        ]
        | None
    )

    trust_state: Literal["clean", "tainted", "quarantined", "unknown"]
    taints: list[TaintLabel]

    source_refs: list[str]
    last_write_sequence: SequenceRef | None
    last_read_sequence: SequenceRef | None

    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）。

        排除 ``memory_id``/``change_id``（注册/生命周期标识）；
        trust/taint 与来源引用是 memory trust 投影的语义核心。
        """
        return frozenset(
            {
                "change_status",
                "trust_state",
                "taints",
                "source_refs",
                "last_write_sequence",
                "last_read_sequence",
                "evidence_refs",
            }
        )


# ---------------------------------------------------------------------------
# CapabilityGrant (01 §14, L585-643)
# ---------------------------------------------------------------------------


class CapabilityGrant(BaseModel):
    """能力授权投影（01 §14 逐字冻结）。

    冻结语义：Approval record 是权威事实；CapabilityGrant 是可重建安全
    投影。``source_type == human_approval`` 时必须满足
    ``exact_authorization_fingerprint != None``、``usage_limit = 1``、
    ``remaining_uses ∈ {1, 0}``、``delegable = false``。
    ``grant_digest`` 由签发方确定性计算（语义内容摘要），本身进入本模型
    的安全摘要白名单，作为逐字段等价锚点。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2.1"] = "2.1"

    grant_id: str
    scope_digest: str

    source_type: Literal[
        "system_policy",
        "task_compiler",
        "human_approval",
        "trusted_runtime_identity",
    ]
    source_ref: str

    subject_principal_id: str
    subject_agent_id: str | None
    task_id: str | None

    action_types: list[str]
    resource_constraints: list[ResourceConstraint]
    destination_constraints: list[DestinationConstraint]
    argument_constraints: list[ArgumentConstraint]

    exact_authorization_fingerprint: str | None

    usage_limit: int | None
    remaining_uses: int | None

    delegable: bool
    parent_grant_id: str | None

    issued_sequence: SequenceRef | None
    expires_sequence: SequenceRef | None
    expires_at: str | None
    revoked: bool
    revoked_sequence: int | None

    policy_revision: str
    compiler_version: str | None
    grant_digest: str

    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）。

        排除 ``grant_id``（注册标识）、``expires_at`` 与
        ``issued_sequence``（时间戳/签发时点）；授权主体、动作类型、
        约束、用量与撤销态是 grant 的安全语义核心。三类约束按集合语义
        去重并稳定排序（见 ``fact_digest_projection``）。
        """
        return frozenset(
            {
                "schema_version",
                "scope_digest",
                "source_type",
                "source_ref",
                "subject_principal_id",
                "subject_agent_id",
                "task_id",
                "action_types",
                "resource_constraints",
                "destination_constraints",
                "argument_constraints",
                "exact_authorization_fingerprint",
                "usage_limit",
                "remaining_uses",
                "delegable",
                "parent_grant_id",
                "expires_sequence",
                "revoked",
                "revoked_sequence",
                "policy_revision",
                "compiler_version",
                "grant_digest",
                "evidence_refs",
            }
        )


# ---------------------------------------------------------------------------
# GrantConsumption / ExecutionLease (01 §15, L649-678)
# ---------------------------------------------------------------------------


class GrantConsumption(BaseModel):
    """Grant 消费记录（01 §15 逐字冻结）；必须原子/CAS 防双花。"""

    model_config = ConfigDict(extra="forbid")

    consumption_id: str
    grant_id: str
    action_id: str
    authorization_fingerprint: str
    consumed_uses: Literal[1] = 1
    sequence: SequenceRef | None
    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）。

        排除 ``consumption_id``（注册标识）；grant/action 绑定与
        fingerprint 是防双花的语义核心。
        """
        return frozenset(
            {
                "grant_id",
                "action_id",
                "authorization_fingerprint",
                "consumed_uses",
                "sequence",
                "evidence_refs",
            }
        )


class ExecutionLease(BaseModel):
    """执行租约（01 §15 逐字冻结）。

    冻结语义：明文 lease token 不进入 Audit、Dashboard 或 Receipt；
    本模型只保存 ``token_digest``。
    """

    model_config = ConfigDict(extra="forbid")

    lease_id: str
    consumption_id: str
    approval_id: str
    grant_id: str
    action_id: str
    authorization_fingerprint: str
    runtime_binding_id: str
    issued_at: str
    expires_at: str
    token_digest: str
    status: Literal["consumed", "expired", "revoked"]
    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）。

        排除 ``lease_id``（注册标识）与 ``issued_at``/``expires_at``
        （时间戳）；approval/action/fingerprint/binding 绑定与
        ``token_digest`` 是 lease 身份的语义核心。
        """
        return frozenset(
            {
                "consumption_id",
                "approval_id",
                "grant_id",
                "action_id",
                "authorization_fingerprint",
                "runtime_binding_id",
                "token_digest",
                "status",
                "evidence_refs",
            }
        )


# ---------------------------------------------------------------------------
# RecentActionFact (01 §16, L684-704)
# ---------------------------------------------------------------------------


class RecentActionFact(BaseModel):
    """近期动作事实（01 §16 逐字冻结）。

    ``parent_event_ids`` 与稳定 resource/data refs 是 gap localized
    degradation 的一/二级定位依据（02 §7）。
    """

    model_config = ConfigDict(extra="forbid")

    action_id: str
    event_id: str
    agent_id: str
    branch_id: str | None
    parent_event_ids: list[str]
    runtime_sequence: SequenceRef | None

    action_type: str
    impact: ImpactClass
    effects: ActionEffect

    resource_ids: list[str]
    destination_ids: list[str]
    data_refs: list[str]

    authority_status: AuthorityStatus
    final_decision: Decision | None

    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）。

        排除 ``action_id``（注册标识）；``event_id`` 作为稳定事件锚点
        保留（幂等键禁止只用 event_id，但事件身份本身是语义稳定的）。
        """
        return frozenset(
            {
                "event_id",
                "agent_id",
                "branch_id",
                "parent_event_ids",
                "runtime_sequence",
                "action_type",
                "impact",
                "effects",
                "resource_ids",
                "destination_ids",
                "data_refs",
                "authority_status",
                "final_decision",
                "evidence_refs",
            }
        )


# ---------------------------------------------------------------------------
# RuntimeOutcomeFact / BehaviorAggregate / StickyTaintSummary (01 §16)
# ---------------------------------------------------------------------------


class RuntimeOutcomeFact(BaseModel):
    """运行时执行终态事实（01 §16, L709-718 逐字冻结）。"""

    model_config = ConfigDict(extra="forbid")

    action_id: str
    decision_id: str
    policy_audit_id: str
    consumption_id: str | None
    lease_id: str | None
    execution_status: Literal["not_invoked", "executed", "failed", "unknown"]
    receipt_sequence: SequenceRef
    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）。

        ``action_id`` 在此模型中是稳定关联键（receipt 必须关联权威
        action），与 decision/policy/consumption/lease 引用一起进入摘要。
        """
        return frozenset(
            {
                "action_id",
                "decision_id",
                "policy_audit_id",
                "consumption_id",
                "lease_id",
                "execution_status",
                "receipt_sequence",
                "evidence_refs",
            }
        )


class BehaviorAggregate(BaseModel):
    """行为聚合（01 §16, L720-728 逐字冻结；B1-B6 见 02 §14）。"""

    model_config = ConfigDict(extra="forbid")

    aggregate_id: str
    pattern_id: Literal["B1", "B2", "B3", "B4", "B5", "B6"]
    window_start: SequenceRef
    window_end: SequenceRef
    count: int
    confidence: Literal["low", "medium", "high"]
    predecessor_refs: list[str]
    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）。

        排除 ``aggregate_id``（注册标识）；计数型聚合的窗口/计数/
        置信度是语义核心。
        """
        return frozenset(
            {
                "pattern_id",
                "window_start",
                "window_end",
                "count",
                "confidence",
                "predecessor_refs",
                "evidence_refs",
            }
        )


class StickyTaintSummary(BaseModel):
    """Sticky taint 摘要（01 §16, L730-737 逐字冻结）。

    ``CREDENTIAL`` / ``PERSISTENT_UNTRUSTED`` 摘要属于安全保持型驱逐的
    sticky 类（02 §5.1），生命周期结束前不得被普通 LRU 驱逐。
    """

    model_config = ConfigDict(extra="forbid")

    summary_id: str
    taints: list[TaintLabel]
    first_seen: SequenceRef
    last_seen: SequenceRef
    unresolved_flow_refs: list[str]
    memory_refs: list[str]
    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）。

        排除 ``summary_id``（注册标识）；taint 集合与未决引用是
        sticky 语义核心。
        """
        return frozenset(
            {
                "taints",
                "first_seen",
                "last_seen",
                "unresolved_flow_refs",
                "memory_refs",
                "evidence_refs",
            }
        )


# ---------------------------------------------------------------------------
# GapRange / StateWatermarks (01 §17, L771-783)
# ---------------------------------------------------------------------------


class GapRange(BaseModel):
    """序列缺口区间（01 §17, L771-776 逐字冻结）。

    gap 不是全局 ASK：是否影响当前动作由依赖关系定位（02 §7）。
    """

    model_config = ConfigDict(extra="forbid")

    domain: SequenceDomain
    producer_binding_id: str
    start_sequence: int
    end_sequence: int
    reason: str

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）；GapRange 全字段语义稳定。"""
        return frozenset(
            {
                "domain",
                "producer_binding_id",
                "start_sequence",
                "end_sequence",
                "reason",
            }
        )


class StateWatermarks(BaseModel):
    """状态水位与缺口集合（01 §17, L778-783 逐字冻结）。"""

    model_config = ConfigDict(extra="forbid")

    committed_sequence: SequenceRef | None
    projected_sequence: SequenceRef | None
    runtime_receipt_sequence: SequenceRef | None
    memory_sequence: SequenceRef | None
    gaps: list[GapRange]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）；全字段语义稳定。"""
        return frozenset(
            {
                "committed_sequence",
                "projected_sequence",
                "runtime_receipt_sequence",
                "memory_sequence",
                "gaps",
            }
        )
