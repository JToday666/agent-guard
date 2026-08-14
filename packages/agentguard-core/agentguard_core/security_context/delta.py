"""V2.1 SecurityStateDeltaV21 与投影记录身份（V21-04）。

字段逐字冻结自
``docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/01_F1字段与契约冻结.md``：

- ProjectionRecordIdentity / WatermarkDelta / SecurityStateDeltaV21
  §27, L1045-1098；
- digest 白名单规范 §29, L1162-1181。

权威语义冻结（01 §27, L1100-1107）：

- ``SecurityStateDeltaV21`` 是 **derived projection contract**，不是新的
  Authority Root；authoritative source record 与 stored delta 冲突时，
  以权威记录为准；
- OnlineState 只能应用 committed delta；
- 同一 ``ProjectionRecordIdentity + projector_version`` 重放必须得到
  相同 ``delta_digest``；
- 存储 delta 可用于历史回放和性能，但不能让 Adapter 自行提交 delta。

关键冻结决策：**task 域不走 delta 投影**。01 §27 的
``source_record_type`` Literal 枚举（逐字核对 L1049-1056）仅含
``policy_evaluation / runtime_outcome / approval / memory_transition /
policy_revision / runtime_observation`` 六类，不含 task 记录类型；
Snapshot 构建时 task 域直读权威 ``TaskFact`` head（Authoritative Record
> Derived Projection，02 §2）。``task_upsert`` 字段按文档保留，但本期
projector 产出的 delta 必须为 ``None``（契约测试断言）。

幂等键冻结（02 §4, L101-111）：五元组
``(scope_digest, source_record_type, source_record_id, source_revision,
projector_version)``；**禁止只用 event_id**。
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
    DeclassificationFact,
    FlowFact,
    GapRange,
    GrantConsumption,
    MemoryFact,
    RecentActionFact,
    RuntimeOutcomeFact,
    SourceFact,
    StickyTaintSummary,
    _canonical_value,
)

__all__ = [
    "SOURCE_RECORD_TYPES",
    "ProjectionRecordIdentity",
    "SecurityStateDeltaV21",
    "WatermarkDelta",
    "delta_digest_projection",
    "projection_identity_key",
]

#: 01 §27 (L1049-1056) 逐字冻结的 source_record_type 枚举。
#: 注意：**不含 task 记录类型** —— task 域不走 delta 投影。
SOURCE_RECORD_TYPES = (
    "policy_evaluation",
    "runtime_outcome",
    "approval",
    "memory_transition",
    "policy_revision",
    "runtime_observation",
)


# ---------------------------------------------------------------------------
# ProjectionRecordIdentity (01 §27, L1048-1059)
# ---------------------------------------------------------------------------


class ProjectionRecordIdentity(BaseModel):
    """投影记录身份（01 §27 逐字冻结）。

    幂等身份由 ``source_record_type + source_record_id + source_revision``
    构成；同 ``source_record_id`` 不同 ``source_revision`` 是**不同**的
    投影身份（event_id-only 幂等键被 02 §4 明令禁止）。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_record_type: Literal[
        "policy_evaluation",
        "runtime_outcome",
        "approval",
        "memory_transition",
        "policy_revision",
        "runtime_observation",
    ]
    source_record_id: str
    source_revision: int
    source_sequence: SequenceRef | None

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）；身份全字段语义稳定。"""
        return frozenset(
            {
                "source_record_type",
                "source_record_id",
                "source_revision",
                "source_sequence",
            }
        )


# ---------------------------------------------------------------------------
# WatermarkDelta (01 §27, L1061-1067)
# ---------------------------------------------------------------------------


class WatermarkDelta(BaseModel):
    """水位增量（01 §27 逐字冻结）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    committed_sequence: SequenceRef | None = None
    projected_sequence: SequenceRef | None = None
    runtime_receipt_sequence: SequenceRef | None = None
    memory_sequence: SequenceRef | None = None
    resolved_gaps: list[GapRange] = Field(default_factory=list)
    new_gaps: list[GapRange] = Field(default_factory=list)

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29）；全字段语义稳定。"""
        return frozenset(
            {
                "committed_sequence",
                "projected_sequence",
                "runtime_receipt_sequence",
                "memory_sequence",
                "resolved_gaps",
                "new_gaps",
            }
        )


# ---------------------------------------------------------------------------
# SecurityStateDeltaV21 (01 §27, L1069-1098)
# ---------------------------------------------------------------------------


class SecurityStateDeltaV21(BaseModel):
    """状态增量（01 §27 逐字冻结）；derived projection contract。

    冻结语义：

    - ``task_upsert`` 按文档保留，但本期 projector 产出必须为 ``None``：
      01 §27 的 ``source_record_type`` 枚举不含 task 记录类型，task 域
      不走 delta 投影（snapshot 直读权威 TaskFact head）；
    - 同一 ``ProjectionRecordIdentity + projector_version`` 重放必须得到
      相同 ``delta_digest``；
    - OnlineState 只能应用 committed delta（F0-8，02 §3）。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["2.1"] = "2.1"

    projection_id: str
    scope_digest: str
    source: ProjectionRecordIdentity

    base_state_version: int
    new_state_version: int
    projector_version: str

    task_upsert: TaskFact | None
    source_upserts: list[SourceFact]
    flow_upserts: list[FlowFact]
    declassification_upserts: list[DeclassificationFact]
    memory_upserts: list[MemoryFact]
    grant_upserts: list[CapabilityGrant]
    grant_revocations: list[str]
    grant_consumptions: list[GrantConsumption]
    action_additions: list[RecentActionFact]
    runtime_outcome_upserts: list[RuntimeOutcomeFact]
    behavior_aggregate_upserts: list[BehaviorAggregate]
    sticky_taint_upserts: list[StickyTaintSummary]

    watermark_delta: WatermarkDelta
    coverage_invalidations: list[CoverageDomain]
    dirty_domain_updates: list[CoverageDomain]

    delta_digest: str

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与 ``delta_digest`` 的字段白名单（01 §29, L1162-1181）。

        排除 ``delta_digest``（digest 自身）与 ``projection_id``
        （注册标识，可为随机 id）；键名与 ``delta_digest_projection``
        的投影键一一对应（契约测试断言两者相等）。
        """
        return frozenset(
            {
                "schema_version",
                "scope_digest",
                "source",
                "base_state_version",
                "new_state_version",
                "projector_version",
                "task_upsert",
                "source_upserts",
                "flow_upserts",
                "declassification_upserts",
                "memory_upserts",
                "grant_upserts",
                "grant_revocations",
                "grant_consumptions",
                "action_additions",
                "runtime_outcome_upserts",
                "behavior_aggregate_upserts",
                "sticky_taint_upserts",
                "watermark_delta",
                "coverage_invalidations",
                "dirty_domain_updates",
            }
        )


def delta_digest_projection(delta: SecurityStateDeltaV21) -> dict[str, Any]:
    """``delta_digest`` 的白名单投影（01 §29）。

    键名与 ``SecurityStateDeltaV21.digest_fields()`` 一一对应；排除
    ``delta_digest`` 自身与 ``projection_id`` 等随机 id。重放确定性要求：
    同 ``ProjectionRecordIdentity + projector_version`` 必须产生相同投影，
    因此 typed upsert 列表顺序由 projector 确定性给出。
    """
    return {
        field: _canonical_value(getattr(delta, field))
        for field in sorted(SecurityStateDeltaV21.digest_fields())
    }


def projection_identity_key(
    scope_digest: str,
    source_record_type: str,
    source_record_id: str,
    source_revision: int,
    projector_version: str,
) -> str:
    """Projector 幂等键（02 §4, L101-111）：五元组的受限 JCS sha256。

    输出 ``sha256:`` 前缀。禁止只用 ``event_id``：同 ``source_record_id``
    不同 ``source_revision``（或不同 ``projector_version``）派生出不同
    幂等键。
    """
    payload = {
        "scope_digest": scope_digest,
        "source_record_type": source_record_type,
        "source_record_id": source_record_id,
        "source_revision": source_revision,
        "projector_version": projector_version,
    }
    return canonical_sha256(payload)
