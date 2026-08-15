"""CT-PR-03a delta_builder：TransientSecurityFacts → SecurityStateDeltaV21 纯函数内核（ct-delta-1，无接线）。

冻结出处（docs/AgentGuard_Context_Isolation_Taint_Tracking_Final_RC/）：

- 01 章 §27 ``SecurityStateDeltaV21`` 为 **derived projection contract**：
  同 ``ProjectionRecordIdentity + projector_version`` 重放必须得到相同
  ``delta_digest``；``task_upsert`` 按文档保留但 projector 产出恒
  ``None``（task 域不走 delta 投影，snapshot 直读权威 TaskFact head）；
- 02 章 §4 幂等键五元组 ``(scope_digest, source_record_type,
  source_record_id, source_revision, projector_version)`` 逐字复用
  ``projection_identity_key``，禁止 event_id-only 幂等键；
- 01 章 §29 ``delta_digest`` 白名单投影：受限 JCS sha256，排除
  ``projection_id`` 与 ``delta_digest`` 自身。

版本裁决登记（两项，契约测试断言引用）：

1. **§18 bump 触发线**：仅当 fact→typed 容器的映射语义变化（容器归属、
   排序/去重口径、身份口径、digest 白名单）时才 bump projector
   version；纯新增事实生产（fact_builder 侧）不触发 bump。
2. **本期不 bump ``PROJECTOR_VERSION`` 的裁决**：本 PR 只向已全接线的
   typed 容器（``v21-07.projector.2`` 的 source/flow/memory upsert
   apply 语义）首次灌入真实 CT 内容，apply 语义零变化，故沿用现行
   ``PROJECTOR_VERSION``，不产生 reprojection 需求。

本模块纪律（CT-PR-03a DoD，零接线）：

- 纯函数内核：单遍确定性映射，无 I/O、无 state mutation、**严禁
  uuid/随机数**（T-FactReplay 重放确定性，契约测试 AST 断言）；
- fail-closed：降级 bundle 或 scope 不一致 → 返回 ``None``，绝不产
  半截 delta；
- ``declassifications`` 恒不映射为 ``declassification_upserts``
  （Non-goal，CT-F0-02：净化只能由 ``trusted_declassifier`` 服务端
  记录表达）；
- 消费方契约呼应 ``build_transient_facts``：``degradations`` 非空
  表示 coverage 部分缺失，本 builder 拒绝消费降级 bundle。

预留扩展点：``_FACT_DELTA_BUILDERS`` 按 ``source_record_type`` 的
派生分发表（仿 fact_builder ``_EVENT_HANDLERS`` 模式），供
CT-PR-05 ``memory_transition`` 未来挂载——届时新增 handler 即完成
派生通道注册，无需改动 ``build_ct_facts_delta`` 主干。
"""

from __future__ import annotations

import logging
import types
from collections.abc import Callable

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    ProjectionRecordIdentity,
    SecurityStateDeltaV21,
    WatermarkDelta,
    delta_digest_projection,
    projection_identity_key,
)
from agentguard_core.security_context.facts import (
    FlowFact,
    MemoryFact,
    SourceFact,
    fact_digest,
)

from .transient import TransientSecurityFacts

logger = logging.getLogger(__name__)

#: 02 章 §12 版本：影响 fact→delta 映射语义/digest 的变化必须 bump。
CT_DELTA_BUILDER_VERSION = "ct-delta-1"

#: 01 §27 source_record_type 枚举（逐字冻结六类之一）：CT 观察类
#: bundle 以 ``runtime_observation`` 身份入投影。
_SOURCE_RECORD_TYPE = "runtime_observation"

#: source_revision 恒 1：单事件 bundle 无修订链（与 evaluation 权威
#: 记录口径一致，仿 v21_pipeline ``_EVALUATION_SOURCE_REVISION``）。
_OBSERVATION_SOURCE_REVISION = 1


def _sorted_deduped_by_digest(facts: tuple) -> list:
    """按 fact digest 确定性排序去重（单遍）。

    排序键为 ``(fact_digest, 全量内容 canonical sha256)``：白名单字段
    全同的两条事实 digest 相等即语义重复，去重后保留排序首位；同
    digest 时的 tie-breaker 取全量内容 canonical dump，保证去重结果
    与输入顺序无关（同 digest 不同注册 id 亦唯一确定胜者）。受限
    JCS sha256 保证 ``delta_digest_projection`` 重放恒定。
    """
    ordered = sorted(
        facts,
        key=lambda fact: (
            fact_digest(fact),
            canonical_sha256(fact.model_dump(mode="json")),
        ),
    )
    result: list = []
    previous_digest: str | None = None
    for fact in ordered:
        digest = fact_digest(fact)
        if digest == previous_digest:
            continue
        previous_digest = digest
        result.append(fact)
    return result


def _build_runtime_observation_upserts(
    bundle: TransientSecurityFacts,
) -> tuple[list[SourceFact], list[FlowFact], list[MemoryFact]]:
    """runtime_observation 派生通道：三类事实容器单遍确定性映射。

    ``bundle.declassifications`` / ``signals`` / ``current_action`` /
    ``evidence_refs`` 不入 typed 容器（前者 CT-F0-02 Non-goal；后三者
    属派生记录/评估材料，白名单扩展随后续 PR 冻结）。
    """
    return (
        _sorted_deduped_by_digest(bundle.source_facts),
        _sorted_deduped_by_digest(bundle.flow_facts),
        _sorted_deduped_by_digest(bundle.memory_facts),
    )


#: 按 source_record_type 的派生分发表（仿 fact_builder
#: ``_EVENT_HANDLERS`` 模式）：CT-PR-05 memory_transition 未来挂载
#: 新 handler 即可，无需改动主干。未注册类型 → fail-closed（返回 None）。
_FACT_DELTA_BUILDERS: types.MappingProxyType[
    str,
    Callable[
        [TransientSecurityFacts],
        tuple[list[SourceFact], list[FlowFact], list[MemoryFact]],
    ],
] = types.MappingProxyType(
    {
        _SOURCE_RECORD_TYPE: _build_runtime_observation_upserts,
    }
)


def build_ct_facts_delta(
    *,
    scope_digest: str,
    source_record_id: str,
    base_state_version: int,
    bundle: TransientSecurityFacts,
) -> SecurityStateDeltaV21 | None:
    """构造 runtime_observation 事实投影的最小确定性 delta（禁 uuid）。

    身份口径逐字仿 ``v21_pipeline.build_evaluation_delta``：

    - ``source_record_type = "runtime_observation"``；
    - ``source_record_id`` 由调用方以命名空间化 ``"ct-facts:{event_id}"``
      形态传入，本函数只消费、不拼装；
    - ``source_revision = 1``（单事件 bundle 无修订链）；
    - ``projection_id`` 由幂等键五元组确定性派生（``projection:`` 前缀
      + ``projection_identity_key`` 受限 JCS sha256）；
    - ``delta_digest = canonical_sha256(delta_digest_projection(delta))``
      （白名单受限 JCS 回填，同身份同 base 重放恒定）。

    fail-closed（绝不产半截 delta，可附 reason 日志说明）：

    - ``bundle.degradations`` 非空 → coverage 部分缺失，拒绝消费
      （呼应 ``build_transient_facts`` 消费方契约）；
    - ``bundle.scope_digest != scope_digest`` → scope 不一致，拒绝
      跨 scope 投影。

    容器口径：``task_upsert`` 恒 ``None``（01 §27 契约硬要求）；
    ``watermark_delta`` 为空水位；``declassification_upserts`` 恒空
    （Non-goal，CT-F0-02）；其余容器（grants / action_additions /
    runtime_outcome / behavior_aggregate / sticky_taint / coverage
    invalidations / dirty domains）本期全空。
    """
    if bundle.degradations:
        logger.warning(
            "ct-delta-builder refused degraded bundle %s (%d degradations)",
            bundle.event_id,
            len(bundle.degradations),
        )
        return None
    if bundle.scope_digest != scope_digest:
        logger.warning(
            "ct-delta-builder refused scope mismatch for bundle %s",
            bundle.event_id,
        )
        return None
    handler = _FACT_DELTA_BUILDERS.get(_SOURCE_RECORD_TYPE)
    if handler is None:  # 分派表未注册 → fail-closed（当前不可达）。
        return None
    source_upserts, flow_upserts, memory_upserts = handler(bundle)
    identity = ProjectionRecordIdentity(
        source_record_type=_SOURCE_RECORD_TYPE,
        source_record_id=source_record_id,
        source_revision=_OBSERVATION_SOURCE_REVISION,
        source_sequence=None,
    )
    projection_key = projection_identity_key(
        scope_digest,
        _SOURCE_RECORD_TYPE,
        source_record_id,
        _OBSERVATION_SOURCE_REVISION,
        PROJECTOR_VERSION,
    )
    delta = SecurityStateDeltaV21(
        projection_id=f"projection:{projection_key}",
        scope_digest=scope_digest,
        source=identity,
        base_state_version=base_state_version,
        new_state_version=base_state_version + 1,
        projector_version=PROJECTOR_VERSION,
        task_upsert=None,
        source_upserts=source_upserts,
        flow_upserts=flow_upserts,
        declassification_upserts=[],
        memory_upserts=memory_upserts,
        grant_upserts=[],
        grant_revocations=[],
        grant_consumptions=[],
        action_additions=[],
        runtime_outcome_upserts=[],
        behavior_aggregate_upserts=[],
        sticky_taint_upserts=[],
        watermark_delta=WatermarkDelta(),
        coverage_invalidations=[],
        dirty_domain_updates=[],
        delta_digest="",
    )
    return delta.model_copy(
        update={"delta_digest": canonical_sha256(delta_digest_projection(delta))}
    )
