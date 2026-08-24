"""Typed upsert handler 中央分发表（V21-05/06/07 Phase 2 集成装配）。

本模块是 V21-05/06/07 三路实施的**中央分发表**：

- 中央分发表 ``TYPED_UPSERT_HANDLERS`` 是模块级不可变 tuple，
  Phase 2 集成 PR 一次性静态装配（11 容器，顺序严格按 01 §27
  ``SecurityStateDeltaV21`` 字段声明序）；各分支 handler 纯函数实现
  在 ``projection/`` 子包内按所有权划分；
- ``CONTAINER_OWNERSHIP`` 声明 11 个 typed upsert 容器（01 §27）到
  三路分支（provenance / capability / behavior）的所有权映射，键集与
  ``TYPED_UPSERT_HANDLERS`` 容器集完全一致（契约测试断言无遗漏
  无多余）；
- **严禁**任何运行时注册 API：装配只能以静态字面量方式一次性
  完成，杜绝导入顺序依赖与静默行为漂移；
- ``apply_delta`` 经 ``apply_typed_updates`` 按本表 tuple 序确定性
  应用非空 typed 容器（容器为空自然跳过），``PROJECTOR_VERSION``
  随集成 PR 唯一一次提升。
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Callable, Literal, Mapping

from .delta import SecurityStateDeltaV21
from .state import OnlineSecurityState

__all__ = [
    "CONTAINER_OWNERSHIP",
    "TYPED_UPSERT_HANDLERS",
    "TypedUpsertHandler",
    "apply_typed_updates",
]

#: typed upsert handler 纯函数签名：消费 delta 中单个容器的 items，
#: 返回新状态（不修改输入）。handler 必须是确定性纯函数（core
#: stateless 纪律）。
TypedUpsertHandler = Callable[[OnlineSecurityState, list[Any]], OnlineSecurityState]

#: 实施分支所有权（Phase 1 三分支隔离纪律）。
ImplementationBranch = Literal["provenance", "capability", "behavior"]

#: 11 个 typed upsert 容器（01 §27）→ 实施分支所有权。
#:
#: - provenance（V21-05）：source / flow / declassification / memory /
#:   sticky taint；
#: - capability（V21-06）：grant upsert / revocation / consumption；
#: - behavior（V21-07）：recent action / runtime outcome / behavior
#:   aggregate。
#:
#: 键集必须与 ``TYPED_UPSERT_HANDLERS`` 容器集一致；契约测试强制断言。
CONTAINER_OWNERSHIP: Mapping[str, ImplementationBranch] = MappingProxyType(
    {
        "source_upserts": "provenance",
        "flow_upserts": "provenance",
        "declassification_upserts": "provenance",
        "memory_upserts": "provenance",
        "sticky_taint_upserts": "provenance",
        "grant_upserts": "capability",
        "grant_revocations": "capability",
        "grant_consumptions": "capability",
        "action_additions": "behavior",
        "runtime_outcome_upserts": "behavior",
        "behavior_aggregate_upserts": "behavior",
    }
)

# 三路 handler 纯函数导入（置于 TypedUpsertHandler / CONTAINER_OWNERSHIP
# 之后：projection 子包模块反向依赖本模块的 TypedUpsertHandler 类型，
# 该顺序打破导入环）。
from .projection.behavior import (  # noqa: E402
    apply_action_additions,
    apply_behavior_aggregate_upserts,
    apply_runtime_outcome_upserts,
)
from .projection.capability import (  # noqa: E402
    apply_grant_consumptions,
    apply_grant_revocations,
    apply_grant_upserts,
)
from .projection.provenance import (  # noqa: E402
    apply_declassification_upserts,
    apply_flow_upserts,
    apply_memory_upserts,
    apply_source_upserts,
    apply_sticky_taint_upserts,
    replay_declassification_effects,
)

#: 中央分发表：(容器名, handler) 的不可变 tuple，按 tuple 序确定性
#: 遍历。顺序严格按 01 §27 ``SecurityStateDeltaV21`` 字段声明序；
#: Phase 2 集成 PR 一次性静态装配，禁止任何运行时追加/替换。
TYPED_UPSERT_HANDLERS: tuple[tuple[str, TypedUpsertHandler], ...] = (
    ("source_upserts", apply_source_upserts),
    ("flow_upserts", apply_flow_upserts),
    ("declassification_upserts", apply_declassification_upserts),
    ("memory_upserts", apply_memory_upserts),
    ("grant_upserts", apply_grant_upserts),
    ("grant_revocations", apply_grant_revocations),
    ("grant_consumptions", apply_grant_consumptions),
    ("action_additions", apply_action_additions),
    ("runtime_outcome_upserts", apply_runtime_outcome_upserts),
    ("behavior_aggregate_upserts", apply_behavior_aggregate_upserts),
    ("sticky_taint_upserts", apply_sticky_taint_upserts),
)


def apply_typed_updates(
    state: OnlineSecurityState, delta: SecurityStateDeltaV21
) -> OnlineSecurityState:
    """按 ``TYPED_UPSERT_HANDLERS`` 的 tuple 序确定性应用 typed update。

    纯函数：逐个 ``(container, handler)`` 取 ``delta`` 对应容器的
    items，非空则调用 handler 返回新状态；容器为空自然跳过，全部
    为空时原样返回输入 state（不复制、不修改）。

    组合后处理（01 §27 声明序兼容，中央表顺序不动）：
    ``declassification_upserts`` 声明序先于 ``sticky_taint_upserts``，
    同 delta 两类并存时 declassification 效果无法施加于 sticky 新增
    摘要；全部容器应用完毕后统一重放同一 delta 的 declassification
    效果（幂等，见 ``provenance.replay_declassification_effects``），
    保证两类容器的施加顺序不影响结果（增量/rebuild 确定性）。

    handler 失败抛各自分支的 fail-closed 异常（``v21-05:`` /
    ``v21-06:`` / ``v21-07:`` 前缀），由编排方置脏相关域；不得静默
    丢弃内容而照常推进 version。
    """
    result = state
    for container, handler in TYPED_UPSERT_HANDLERS:
        items = getattr(delta, container)
        if items:
            result = handler(result, list(items))
    if delta.declassification_upserts and delta.sticky_taint_upserts:
        result = replay_declassification_effects(
            result, list(delta.declassification_upserts)
        )
    return result
