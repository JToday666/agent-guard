"""OnlineSecurityState 容器（V21-04, 02 §5）。

``docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/02_状态投影_Provenance_Authority.md``
§5 (L146-168) 冻结的 14 子域容器：

```text
task / active_grants / revocations_consumptions / source_index /
sticky_taint_summary / relevant_flows / recent_actions /
behavior_aggregates / memory_index / runtime_outcomes /
execution_leases_consumptions / watermarks_gaps / state_version /
dirty_domains
```

冻结语义：

- OnlineSecurityState 是热路径有界投影，**不是第二 Authority Root**；
  冲突时 Authoritative Record > Derived Projection > Online Cache（02 §2）；
- 安全相关内容必须由 ``SecurityStateDeltaV21`` 的 typed update 重建，
  不允许只存在于进程内私有字段；
- ``SequenceRef.domain + producer_binding_id`` 决定可比较的顺序域，
  不同域禁止直接用整数大小推断先后（见 ``compare_sequence_refs``）；
- 本期只有 ``task``（仅 snapshot 直读权威 head，不经 delta）、
  ``watermarks_gaps``、``state_version``、``dirty_domains`` 有写入路径，
  其余子域为冻结空容器占位，V21-05/06/07 接线；
- ``state_digest()`` 是 T-Replay 锚点（05 §12）：同 authoritative
  records + same projector version → 相同 state digest，允许随机 ID 不同。
  因此 ``applied_projections`` 中的 ``projection_id`` 派生键与
  ``evicted`` 运维标记不进入 digest 白名单。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..actions.canonical_json import canonical_sha256
from ..authority.models import TaskFact
from ..signals.models import CoverageDomain, SequenceRef
from .facts import (
    BehaviorAggregate,
    CapabilityGrant,
    ExecutionLease,
    FlowFact,
    GrantConsumption,
    MemoryFact,
    RecentActionFact,
    RuntimeOutcomeFact,
    SourceFact,
    StateWatermarks,
    StickyTaintSummary,
    _canonical_value,
)

__all__ = [
    "AppliedProjection",
    "OnlineSecurityState",
    "SequenceComparisonError",
    "compare_sequence_refs",
    "state_digest",
    "state_digest_projection",
]


class SequenceComparisonError(ValueError):
    """跨域/跨 producer 的 SequenceRef 顺序比较（fail-closed，02 §5）。

    ``reason_code`` 前缀 ``v21-04:``。
    """

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def compare_sequence_refs(left: SequenceRef, right: SequenceRef) -> int:
    """仅同 ``domain`` + 同 ``producer_binding_id`` 的序列可比。

    返回 ``-1 / 0 / 1``；跨域或跨 producer 直接用整数大小推断先后被
    02 §5 (L168) 禁止，fail-closed 抛 ``SequenceComparisonError``。
    """
    if left.domain != right.domain:
        raise SequenceComparisonError(
            "v21-04:cross_domain_sequence_comparison",
            f"sequence comparison across domains is forbidden: "
            f"{left.domain!r} vs {right.domain!r}",
        )
    if left.producer_binding_id != right.producer_binding_id:
        raise SequenceComparisonError(
            "v21-04:cross_producer_sequence_comparison",
            "sequence comparison across producer bindings is forbidden",
        )
    if left.value < right.value:
        return -1
    if left.value > right.value:
        return 1
    return 0


class AppliedProjection(BaseModel):
    """已应用投影记录登记（幂等重放与 digest 冲突检测的依据）。

    ``projection_key`` 是 02 §4 五元组幂等键（见
    ``delta.projection_identity_key``）；``delta_digest`` 是同一身份重放
    时的等价性锚点（01 §27 权威语义冻结）。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    projection_key: str
    delta_digest: str


class OnlineSecurityState(BaseModel):
    """热路径在线安全状态（02 §5 的 14 子域）。

    本模型不加 ``frozen``：``apply_delta`` / ``apply_safe_eviction`` /
    ``rebuild_state`` 以纯函数语义返回**新实例**，不共享可变子结构；
    冻结语义由各 typed fact 模型与 digest 白名单承载。

    本期写入路径：``task`` 仅由 snapshot 构建时直读权威 TaskFact head
    （不走 delta 投影）；``watermarks_gaps`` / ``state_version`` /
    ``dirty_domains``（含 ``applied_projections`` 登记）由 projector 写入；
    其余容器为冻结空占位。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2.1"] = "2.1"

    # 1) task（权威 head 直读占位；delta 投影不写 task 域）
    task: TaskFact | None = None

    # 2) active_grants
    active_grants: list[CapabilityGrant] = Field(default_factory=list)

    # 3) revocations / consumptions
    revoked_grant_ids: list[str] = Field(default_factory=list)
    grant_consumptions: list[GrantConsumption] = Field(default_factory=list)

    # 4) source_index
    source_index: list[SourceFact] = Field(default_factory=list)

    # 5) sticky_taint_summary
    sticky_taint_summaries: list[StickyTaintSummary] = Field(
        default_factory=list
    )

    # 6) relevant_flows
    relevant_flows: list[FlowFact] = Field(default_factory=list)

    # 7) recent_actions
    recent_actions: list[RecentActionFact] = Field(default_factory=list)

    # 8) behavior_aggregates
    behavior_aggregates: list[BehaviorAggregate] = Field(default_factory=list)

    # 9) memory_index
    memory_index: list[MemoryFact] = Field(default_factory=list)

    # 10) runtime_outcomes
    runtime_outcomes: list[RuntimeOutcomeFact] = Field(default_factory=list)

    # 11) execution_leases / consumptions
    execution_leases: list[ExecutionLease] = Field(default_factory=list)

    # 12) watermarks / gaps
    watermarks: StateWatermarks

    # 13) state_version（单调，02 §4.1）
    state_version: int = 0

    # 14) dirty_domains
    dirty_domains: list[CoverageDomain] = Field(default_factory=list)

    #: 幂等投影登记（02 §4.1 三分支判定依据）；不进 state digest。
    applied_projections: list[AppliedProjection] = Field(default_factory=list)

    #: 安全保持型驱逐已收缩 windowed 域的标记（02 §5.1）：驱逐后无法
    #: 证明 required domain 完整时供 coverage 降 partial。不进 digest。
    evicted: bool = False

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与 ``state_digest`` 的字段白名单（01 §29, L1162-1181）。

        T-Replay 锚点：白名单只覆盖安全内容；``state_version``（单调
        位置量）、``applied_projections``（projection_key 由随机
        source_record_id 派生）与 ``evicted``（运维标记）不进入摘要，
        保证同权威记录 + 同 projector_version 重放得到相同 digest。
        """
        return frozenset(
            {
                "schema_version",
                "task",
                "active_grants",
                "revoked_grant_ids",
                "grant_consumptions",
                "source_index",
                "sticky_taint_summaries",
                "relevant_flows",
                "recent_actions",
                "behavior_aggregates",
                "memory_index",
                "runtime_outcomes",
                "execution_leases",
                "watermarks",
                "dirty_domains",
            }
        )


def state_digest_projection(state: OnlineSecurityState) -> dict[str, Any]:
    """``state_digest`` 的白名单投影；键名与 ``digest_fields()`` 对应。"""
    return {
        field: _canonical_value(getattr(state, field))
        for field in sorted(OnlineSecurityState.digest_fields())
    }


def state_digest(state: OnlineSecurityState) -> str:
    """``canonical_sha256(白名单投影)``（T-Replay 锚点，05 §12）。"""
    return canonical_sha256(state_digest_projection(state))
