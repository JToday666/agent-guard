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
2. CT05 在此内核增加 ``memory_transition`` 生命周期映射，并把
   ``PROJECTOR_VERSION`` 提升至 ``ct-05.projector.3``；既有 runtime
   observation 口径保持不变。

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

``_FACT_DELTA_BUILDERS`` 按 ``source_record_type`` 分派；当前覆盖
``runtime_observation`` 与 CT05 ``memory_transition``，其余权威来源由
各自 projector 生产。
"""

from __future__ import annotations

import logging
import types
from collections.abc import Callable
from typing import Any, Literal

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

#: CT 事实当前接入的两类权威来源。其余四类由各自 projector 生产，
#: 不经本 builder。
_RUNTIME_OBSERVATION: Literal["runtime_observation"] = "runtime_observation"
_MEMORY_TRANSITION: Literal["memory_transition"] = "memory_transition"

#: source_revision 恒 1：单事件 bundle 无修订链（与 evaluation 权威
#: 记录口径一致，仿 v21_pipeline ``_EVALUATION_SOURCE_REVISION``）。
_OBSERVATION_SOURCE_REVISION = 1

#: Memory lifecycle 的冻结 revision 映射。proposed/quarantined 是同一
#: 初态层，commit/reject 是互斥终态层，rollback 只能位于第三层。
MEMORY_TRANSITION_REVISIONS = types.MappingProxyType(
    {
        "proposed": 1,
        "quarantined": 1,
        "committed": 2,
        "rejected": 2,
        "rolled_back": 3,
    }
)


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


def _build_memory_transition_upserts(
    fact: MemoryFact,
) -> tuple[list[SourceFact], list[FlowFact], list[MemoryFact]]:
    """Memory lifecycle 派生通道：只写入一条已绑定的 MemoryFact。"""

    return ([], [], [fact])


#: 按 source_record_type 的派生分发表（仿 fact_builder
#: ``_EVENT_HANDLERS`` 模式，仅结构预留）：CT-PR-05 memory_transition
#: 挂载时需同步扩展分派键与 ``build_ct_facts_delta`` 签名。未注册
#: 类型 → fail-closed（返回 None）。
_FACT_DELTA_BUILDERS: types.MappingProxyType[
    str,
    Callable[
        [Any],
        tuple[list[SourceFact], list[FlowFact], list[MemoryFact]],
    ],
] = types.MappingProxyType(
    {
        _RUNTIME_OBSERVATION: _build_runtime_observation_upserts,
        _MEMORY_TRANSITION: _build_memory_transition_upserts,
    }
)


def build_ct_facts_delta(
    *,
    scope_digest: str,
    source_record_id: str,
    base_state_version: int,
    bundle: TransientSecurityFacts | None = None,
    source_record_type: Literal[
        "runtime_observation", "memory_transition"
    ] = _RUNTIME_OBSERVATION,
    source_revision: int | None = None,
    memory_fact: MemoryFact | None = None,
) -> SecurityStateDeltaV21 | None:
    """构造 runtime observation / memory transition 的确定性 delta。

    身份口径逐字仿 ``v21_pipeline.build_evaluation_delta``：

    - runtime：``source_record_type="runtime_observation"``、revision 1；
    - memory：``source_record_type="memory_transition"``、record id 为
      ``change_id``、revision 严格取生命周期冻结映射 1/2/3；
    - ``source_record_id`` 由调用方以命名空间化 ``"ct-facts:{event_id}"``
      形态传入，本函数只消费、不拼装。观察项留痕（不改行为）：
      CT-PR-03b 接线时须对 ``source_record_id`` 增加 ``"ct-facts:"``
      前缀形态校验（fail-closed 拒绝非法形态）；
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
    handler = _FACT_DELTA_BUILDERS.get(source_record_type)
    if handler is None:
        return None
    resolved_revision: int
    source_sequence = None
    if source_record_type == _RUNTIME_OBSERVATION:
        if bundle is None or memory_fact is not None:
            return None
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
        resolved_revision = _OBSERVATION_SOURCE_REVISION
        if source_revision not in (None, resolved_revision):
            return None
        source_upserts, flow_upserts, memory_upserts = handler(bundle)
    else:
        if bundle is not None or memory_fact is None:
            return None
        expected_revision = MEMORY_TRANSITION_REVISIONS.get(
            memory_fact.change_status or ""
        )
        if (
            expected_revision is None
            or source_revision != expected_revision
            or memory_fact.change_id != source_record_id
            or memory_fact.last_write_sequence is None
            or memory_fact.last_write_sequence.domain != "memory"
            or memory_fact.last_write_sequence.producer_binding_id
            != source_record_id
            or memory_fact.last_write_sequence.value != expected_revision
        ):
            logger.warning(
                "ct-delta-builder refused invalid memory transition identity"
            )
            return None
        resolved_revision = expected_revision
        source_sequence = memory_fact.last_write_sequence
        source_upserts, flow_upserts, memory_upserts = handler(memory_fact)
    identity = ProjectionRecordIdentity(
        source_record_type=source_record_type,
        source_record_id=source_record_id,
        source_revision=resolved_revision,
        source_sequence=source_sequence,
    )
    projection_key = projection_identity_key(
        scope_digest,
        source_record_type,
        source_record_id,
        resolved_revision,
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
