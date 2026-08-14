"""SecuritySnapshot 构建与摘要（V21-04, 01 §19）。

字段逐字冻结自
``docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/01_F1字段与契约冻结.md``
§19 (L812-847)。

关键冻结决策：**task 域不走 delta 投影**。01 §27 的
``source_record_type`` 枚举不含 task 记录类型，因此 ``build_snapshot``
的 task 域**直读权威 TaskFact head**（调用方注入
``task_fact_head``）—— Authoritative Record > Derived Projection >
Online Cache（02 §2），天然支持 stale 检测（coverage 对照 head
revision）。``OnlineSecurityState.task`` 占位字段不参与 snapshot 构建。

Snapshot 必须有界；尺寸上限属于 F3，安全保持型驱逐规则属于 F1/F0
（02 §5.1，见 ``eviction.py``）。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from ..actions.canonical_json import canonical_sha256
from ..authority.models import EvaluationClock, SecurityStateScope, TaskFact
from ..decisions.evidence import CoverageMap, RequiredCheckPlan
from ..signals.models import CoverageDomain, SequenceRef
from .coverage import compute_coverage
from .facts import (
    BehaviorAggregate,
    CapabilityGrant,
    DeclassificationFact,
    FlowFact,
    MemoryFact,
    RecentActionFact,
    RuntimeOutcomeFact,
    SourceFact,
    StateWatermarks,
    StickyTaintSummary,
    _canonical_value,
)
from .projector import PROJECTOR_VERSION
from .state import OnlineSecurityState

__all__ = [
    "SecuritySnapshot",
    "build_snapshot",
    "snapshot_digest_projection",
]


class SecuritySnapshot(BaseModel):
    """判定输入快照（01 §19 逐字冻结）。

    冻结语义：

    - ``task`` 是权威 TaskFact head 直读（不经 delta 投影）；
    - ``snapshot_digest`` 白名单排除 ``snapshot_id``（注册标识，可为
      随机 id）；T-Replay：同权威记录 + 同 projector_version 必须得到
      相同 snapshot digest（05 §12），允许随机 ID 不同。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["2.1"] = "2.1"

    snapshot_id: str
    state_version: int
    scope: SecurityStateScope
    evaluation_clock: EvaluationClock

    as_of_sequence: SequenceRef | None
    projector_version: str

    policy_revision: str
    policy_digest: str

    coverage: CoverageMap
    watermarks: StateWatermarks

    task: TaskFact | None
    sources: list[SourceFact]
    grants: list[CapabilityGrant]
    recent_actions: list[RecentActionFact]
    flows: list[FlowFact]
    memory_facts: list[MemoryFact]
    runtime_outcomes: list[RuntimeOutcomeFact]
    behavior_aggregates: list[BehaviorAggregate]
    sticky_taint_summaries: list[StickyTaintSummary]
    declassifications: list[DeclassificationFact]
    dirty_domains: list[CoverageDomain]

    snapshot_digest: str

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与 ``snapshot_digest`` 的字段白名单（01 §29, L1162-1181）。

        排除 ``snapshot_id``（注册标识）与 ``snapshot_digest``（digest
        自身）；键名与 ``snapshot_digest_projection`` 一一对应。
        """
        return frozenset(
            {
                "schema_version",
                "state_version",
                "scope",
                "evaluation_clock",
                "as_of_sequence",
                "projector_version",
                "policy_revision",
                "policy_digest",
                "coverage",
                "watermarks",
                "task",
                "sources",
                "grants",
                "recent_actions",
                "flows",
                "memory_facts",
                "runtime_outcomes",
                "behavior_aggregates",
                "sticky_taint_summaries",
                "declassifications",
                "dirty_domains",
            }
        )


def snapshot_digest_projection(snapshot: SecuritySnapshot) -> dict[str, Any]:
    """``snapshot_digest`` 的白名单投影（01 §29）。

    键名与 ``SecuritySnapshot.digest_fields()`` 一一对应；排除
    ``snapshot_id`` 与 ``snapshot_digest`` 自身。``scope`` 只按
    ``SecurityStateScope.STABLE_SCOPE_FIELDS`` 稳定字段白名单投影
    （沿用 authority/models.py 的 scope digest 口径：``trace_id`` 等
    逐 trace 传输字段不进摘要）。
    """
    projection: dict[str, Any] = {}
    for field in sorted(SecuritySnapshot.digest_fields()):
        if field == "scope":
            scope = snapshot.scope
            projection[field] = _canonical_value(
                {
                    key: getattr(scope, key)
                    for key in SecurityStateScope.STABLE_SCOPE_FIELDS
                }
            )
        else:
            projection[field] = _canonical_value(getattr(snapshot, field))
    return projection


def build_snapshot(
    state: OnlineSecurityState,
    *,
    snapshot_id: str,
    scope: SecurityStateScope,
    evaluation_clock: EvaluationClock,
    policy_revision: str,
    policy_digest: str,
    plan: RequiredCheckPlan,
    task_fact_head: TaskFact | None = None,
    authoritative_head_revision: int | None = None,
    projector_version: str = PROJECTOR_VERSION,
) -> SecuritySnapshot:
    """纯函数构建 ``SecuritySnapshot``。

    - ``scope`` 由调用方注入完整 ``SecurityStateScope`` 对象（01 §19
      冻结字段），与 ``task_fact_head`` 同为注入式权威输入；
    - task 域直读 ``task_fact_head``（权威 head），不使用
      ``state.task``（本期 delta 投影不写 task 域）；
      ``authoritative_head_revision`` 缺省时取 ``task_fact_head.revision``；
    - coverage 由 ``compute_coverage`` 按 02 §6 判定表计算；
    - ``snapshot_digest`` = 白名单投影的受限 JCS sha256（排除
      ``snapshot_id``）。
    """
    if authoritative_head_revision is None and task_fact_head is not None:
        authoritative_head_revision = task_fact_head.revision

    coverage = compute_coverage(
        state,
        plan,
        projector_version=projector_version,
        authoritative_head_revision=authoritative_head_revision,
    )

    snapshot = SecuritySnapshot(
        snapshot_id=snapshot_id,
        state_version=state.state_version,
        scope=scope,
        evaluation_clock=evaluation_clock,
        as_of_sequence=state.watermarks.projected_sequence,
        projector_version=projector_version,
        policy_revision=policy_revision,
        policy_digest=policy_digest,
        coverage=coverage,
        watermarks=state.watermarks,
        task=task_fact_head,
        sources=list(state.source_index),
        grants=list(state.active_grants),
        recent_actions=list(state.recent_actions),
        flows=list(state.relevant_flows),
        memory_facts=list(state.memory_index),
        runtime_outcomes=list(state.runtime_outcomes),
        behavior_aggregates=list(state.behavior_aggregates),
        sticky_taint_summaries=list(state.sticky_taint_summaries),
        declassifications=[],
        dirty_domains=list(state.dirty_domains),
        snapshot_digest="",
    )
    return snapshot.model_copy(
        update={"snapshot_digest": canonical_sha256(snapshot_digest_projection(snapshot))}
    )
