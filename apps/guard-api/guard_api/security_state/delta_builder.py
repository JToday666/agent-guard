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

1. **08 章 §18 bump 触发线**（版本号命名规范参 02 章 §12）：仅当
   fact→typed 容器的映射语义变化（容器归属、排序/去重口径、身份
   口径、digest 白名单）时才 bump projector version；纯新增事实生产
   （fact_builder 侧）不触发 bump。本期去重键收紧发生在未接线期，
   无存量投影，故 ``CT_DELTA_BUILDER_VERSION`` 保持 ``ct-delta-1``。
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
派生分发表（仿 fact_builder ``_EVENT_HANDLERS`` 模式，仅结构预留）。
CT-PR-05 ``memory_transition`` 挂载时需**同步扩展分派键与
``build_ct_facts_delta`` 签名**（当前分派键硬编码为
``runtime_observation``，主干只消费该单一通道，未做到新增 handler
即自动接入）。
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
)

from .transient import TransientSecurityFacts

logger = logging.getLogger(__name__)

#: 版本号（bump 触发线出自 08 章 §18，版本命名规范参 02 章 §12）：
#: 影响 fact→delta 映射语义/digest 的变化必须 bump。
CT_DELTA_BUILDER_VERSION = "ct-delta-1"

#: 01 §27 source_record_type 枚举（逐字冻结六类之一）：CT 观察类
#: bundle 以 ``runtime_observation`` 身份入投影。
_SOURCE_RECORD_TYPE = "runtime_observation"

#: source_revision 恒 1：单事件 bundle 无修订链（与 evaluation 权威
#: 记录口径一致，仿 v21_pipeline ``_EVALUATION_SOURCE_REVISION``）。
_OBSERVATION_SOURCE_REVISION = 1


def _sorted_deduped_canonical(facts: tuple) -> list:
    """按全量内容 canonical sha256 确定性排序去重（单遍）。

    映射语义裁决留痕（评审收紧）：去重键为**全量内容**（含注册 id）
    的受限 JCS sha256，只合并**完全相同**的事实，不做基于 fact
    digest 白名单的“语义重复折叠”。原因：``SourceFact`` digest 白
    名单排除注册 id ``source_id``，而 ``FlowFact`` digest 含
    ``source_ref`` 端点——若按白名单 digest 折叠仅 source_id 不同
    的两条语义全同的源，各自 flow 仍引用被折叠的 id，同 delta 内
    产生悬空引用。“语义折叠”推迟到 digest 白名单裁决明确后再
    评估；未来若要语义折叠，须先建立确定性 id remap（同步改写
    flow 端点引用）再折叠，届时属映射语义变化（见模块 docstring
    08 §18 bump 触发线，需 bump）。排序与去重同取全量内容
    canonical sha256 为键，结果与输入顺序无关；受限 JCS 保证
    ``delta_digest_projection`` 重放恒定。
    """
    keyed = sorted(
        ((canonical_sha256(fact.model_dump(mode="json")), fact) for fact in facts),
        key=lambda item: item[0],
    )
    result: list = []
    previous_key: str | None = None
    for key, fact in keyed:
        if key == previous_key:
            continue
        previous_key = key
        result.append(fact)
    return result


def _build_runtime_observation_upserts(
    bundle: TransientSecurityFacts,
) -> tuple[list[SourceFact], list[FlowFact], list[MemoryFact]]:
    """runtime_observation 派生通道：三类事实容器单遍确定性映射。

    ``bundle.declassifications`` / ``signals`` / ``current_action`` /
    ``evidence_refs`` 不入 typed 容器（前者 CT-F0-02 Non-goal；后三者
    属派生记录/评估材料，白名单扩展随后续 PR 冻结）。

    观察项留痕（不改行为）：CT-PR-05 接线前须复核 memory 容器的
    去重键是否需纳入 ``memory_id``（当前 ``MemoryFact`` digest 不含
    ``memory_id``，单事件 bundle 下多 memory 同址不可达；CT-PR-05
    memory_transition 接入后变为可达）。
    """
    return (
        _sorted_deduped_canonical(bundle.source_facts),
        _sorted_deduped_canonical(bundle.flow_facts),
        _sorted_deduped_canonical(bundle.memory_facts),
    )


#: 按 source_record_type 的派生分发表（仿 fact_builder
#: ``_EVENT_HANDLERS`` 模式，仅结构预留）：CT-PR-05 memory_transition
#: 挂载时需同步扩展分派键与 ``build_ct_facts_delta`` 签名。未注册
#: 类型 → fail-closed（返回 None）。
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
      形态传入，本函数只消费、不拼装。观察项留痕（不改行为）：
      CT-PR-03b 接线时须对 ``source_record_id`` 增加 ``"ct-facts:"``
      前缀形态校验（fail-closed 拒绝非法形态）；
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
    invalidations / dirty domains）本期全空。三类事实容器按全量
    内容 canonical sha256 排序去重（语义裁决见
    ``_sorted_deduped_canonical``）。
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
