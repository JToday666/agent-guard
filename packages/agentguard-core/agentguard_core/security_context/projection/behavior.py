"""V21-07 behavior 域 typed upsert handler（Phase 1 纯新增，零接线）。

02_状态投影_Provenance_Authority.md §14（B1-B6）与 01_F1字段与契约冻结.md
§16（RecentActionFact / RuntimeOutcomeFact / BehaviorAggregate）的投影
落地 handler。三个纯函数均符合 ``handlers.TypedUpsertHandler`` 签名，
Phase 2 集成 PR 一次性注册进 ``TYPED_UPSERT_HANDLERS``；本模块**不被**
``apply_delta`` / ``compute_coverage`` / ``engine`` 引用。

冻结纪律：

- 纯函数（core stateless）：不修改输入状态，返回 ``model_copy`` 新实例；
  无 IO、无全局可变单例、无 uuid；
- 分区保序（02 §5, L168）：``SequenceRef.domain + producer_binding_id``
  决定可比较的顺序域；本模块**先按分区键分桶**，桶内才用
  ``compare_sequence_refs`` 比较，跨域整数永不直接比较（跨域比较走
  既有 fail-closed 比较器语义）；
- 容量上限不在 handler 内实现：``recent_actions`` 的 bounded 收缩由
  ``eviction.apply_safe_eviction`` 的既有 windowed 语义负责
  （02 §5.1），handler 只做排序插入，不重复实现驱逐；
- 幂等：同 ``action_id`` 的 RecentActionFact 重复到达不重复插入；
  同 ``action_id`` 的 RuntimeOutcomeFact 同内容重复到达幂等 no-op，
  异内容 fail-closed（T-Replay 确定性，禁静默覆盖）。
"""

from __future__ import annotations

from functools import cmp_to_key
from typing import Any, TypeVar

from ..facts import BehaviorAggregate, RecentActionFact, RuntimeOutcomeFact
from ..state import OnlineSecurityState, compare_sequence_refs

__all__ = [
    "BehaviorProjectionError",
    "apply_action_additions",
    "apply_behavior_aggregate_upserts",
    "apply_runtime_outcome_upserts",
    "ordered_by_sequence_partition",
]

#: behavior 域投影错误 reason_code 前缀（与 v21-04 projector 前缀区分）。
_REASON_PREFIX = "v21-07"

#: BehaviorAggregate 置信度序（增量合并时取较高者，确定性）。
_CONFIDENCE_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2}

_T = TypeVar("_T")


class BehaviorProjectionError(ValueError):
    """behavior 域投影 fail-closed 异常；``reason_code`` 前缀 ``v21-07:``。

    异常消息不得包含动作正文、凭据或任何敏感内容。
    """

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _coerce_items(items: list[Any], expected: type[_T], container: str) -> list[_T]:
    """typed upsert 容器元素类型校验（fail-closed，拒绝静默降级）。"""
    coerced: list[_T] = []
    for index, item in enumerate(items):
        if not isinstance(item, expected):
            raise BehaviorProjectionError(
                f"{_REASON_PREFIX}:invalid_{container}_item",
                f"{container}[{index}] must be {expected.__name__}, "
                f"got {type(item).__name__}",
            )
        coerced.append(item)
    return coerced


# ---------------------------------------------------------------------------
# 分区保序工具（02 §5：同 domain + producer 才可比较）
# ---------------------------------------------------------------------------


def _partition_key(
    fact: RecentActionFact,
) -> tuple[str, str] | None:
    """RecentActionFact 的顺序分区键；无 runtime_sequence 不可分区。"""
    sequence = fact.runtime_sequence
    if sequence is None:
        return None
    return (sequence.domain, sequence.producer_binding_id)


def ordered_by_sequence_partition(
    actions: list[RecentActionFact],
) -> list[RecentActionFact]:
    """按 ``(SequenceRef.domain, producer_binding_id)`` 分区保序。

    - 桶按分区键字典序确定性排列；桶内按 ``compare_sequence_refs``
      稳定排序（同桶必然同 domain + producer，比较器不会抛跨域错误）；
    - 同 sequence value 的条目保持到达序（稳定排序）；
    - 无 ``runtime_sequence`` 的条目置于末尾，保持到达序；
    - **跨分区永不比较整数**：不同域的先后不由本函数推断
      （02 §5, L168；跨域比较由 ``compare_sequence_refs`` fail-closed）。
    """
    buckets: dict[tuple[str, str], list[RecentActionFact]] = {}
    unsequenced: list[RecentActionFact] = []
    for fact in actions:
        key = _partition_key(fact)
        if key is None:
            unsequenced.append(fact)
        else:
            buckets.setdefault(key, []).append(fact)

    def _cmp(left: RecentActionFact, right: RecentActionFact) -> int:
        assert left.runtime_sequence is not None
        assert right.runtime_sequence is not None
        return compare_sequence_refs(left.runtime_sequence, right.runtime_sequence)

    ordered: list[RecentActionFact] = []
    for key in sorted(buckets):
        ordered.extend(sorted(buckets[key], key=cmp_to_key(_cmp)))
    ordered.extend(unsequenced)
    return ordered


# ---------------------------------------------------------------------------
# action_additions handler
# ---------------------------------------------------------------------------


def apply_action_additions(
    state: OnlineSecurityState, items: list[Any]
) -> OnlineSecurityState:
    """追加 RecentActionFact 入 ``state.recent_actions``（分区保序）。

    - 同 ``action_id`` 已存在 → 跳过（幂等重放不重复插入）；
    - 合并后按 ``(SequenceRef.domain, producer_binding_id)`` 分区保序
      （见 ``ordered_by_sequence_partition``）；
    - 容量上限不在此实现：驱逐由 ``eviction.apply_safe_eviction`` 的
      既有 windowed 语义负责（02 §5.1），本 handler 只排序插入。
    """
    additions = _coerce_items(items, RecentActionFact, "action_additions")
    if not additions:
        return state

    seen_ids = {fact.action_id for fact in state.recent_actions}
    merged = list(state.recent_actions)
    for fact in additions:
        if fact.action_id in seen_ids:
            continue
        seen_ids.add(fact.action_id)
        merged.append(fact)

    return state.model_copy(
        update={"recent_actions": ordered_by_sequence_partition(merged)}
    )


# ---------------------------------------------------------------------------
# runtime_outcome_upserts handler
# ---------------------------------------------------------------------------


def apply_runtime_outcome_upserts(
    state: OnlineSecurityState, items: list[Any]
) -> OnlineSecurityState:
    """按 ``action_id`` 去重合并入 ``state.runtime_outcomes``。

    同 ``action_id`` 同内容重复到达幂等 no-op；同 ``action_id`` 异内容
    fail-closed 抛 ``v21-07:runtime_outcome_identity_conflict``（「后来者
    覆盖」在增量与 rebuild 顺序分叉时破坏 T-Replay 确定性，禁止静默
    替换）。未知 ``action_id`` 按到达序追加。相对顺序稳定：追加置尾。
    """
    upserts = _coerce_items(items, RuntimeOutcomeFact, "runtime_outcome_upserts")
    if not upserts:
        return state

    merged = list(state.runtime_outcomes)
    index_by_action = {
        outcome.action_id: position for position, outcome in enumerate(merged)
    }
    for outcome in upserts:
        position = index_by_action.get(outcome.action_id)
        if position is None:
            index_by_action[outcome.action_id] = len(merged)
            merged.append(outcome)
            continue
        if merged[position] != outcome:
            raise BehaviorProjectionError(
                f"{_REASON_PREFIX}:runtime_outcome_identity_conflict",
                "same action_id with different runtime outcome content: "
                "fail-closed, silent overwrite would break T-Replay "
                "determinism",
            )

    return state.model_copy(update={"runtime_outcomes": merged})


# ---------------------------------------------------------------------------
# behavior_aggregate_upserts handler
# ---------------------------------------------------------------------------


def _aggregate_partition_key(aggregate: BehaviorAggregate) -> tuple[str, str, str]:
    """聚合增量合并的分区键：``(pattern_id, 窗口序列域, producer)``。"""
    return (
        aggregate.pattern_id,
        aggregate.window_end.domain,
        aggregate.window_end.producer_binding_id,
    )


def _merge_window_edge(existing: Any, incoming: Any, *, take_max: bool) -> Any:
    """窗口端点合并：同 domain + producer 可比时取较小/较大者。

    端点跨域不可比时保守保留既有端点（不推断跨域先后，02 §5）；
    重放序确定，结果仍确定。
    """
    if (
        existing.domain != incoming.domain
        or existing.producer_binding_id != incoming.producer_binding_id
    ):
        return existing
    cmp = compare_sequence_refs(existing, incoming)
    if take_max:
        return existing if cmp >= 0 else incoming
    return existing if cmp <= 0 else incoming


def _merge_ref_lists(
    existing: list[Any], incoming: list[Any], key: Any = None
) -> list[Any]:
    """引用列表确定性合并：既有顺序优先，追加未见项（按身份去重）。"""
    identity = key if key is not None else (lambda item: item)
    seen = {identity(item) for item in existing}
    merged = list(existing)
    for item in incoming:
        if identity(item) not in seen:
            seen.add(identity(item))
            merged.append(item)
    return merged


def apply_behavior_aggregate_upserts(
    state: OnlineSecurityState, items: list[Any]
) -> OnlineSecurityState:
    """增量计数器合并入 ``state.behavior_aggregates``。

    - 按 ``(pattern_id, window_end.domain, window_end.producer_binding_id)``
      查找现有 aggregate：命中 → ``count`` 递增（累加 incoming.count）、
      ``window_end`` 推进（取较大者）、``window_start`` 取较早者、
      ``confidence`` 取较高者、predecessor/evidence refs 确定性合并；
      **不重扫窗口、不全量重算**（增量语义，02 §14）；
    - 不匹配现有 aggregate → 按 delta 携带内容原样并入（新模式）；
      **禁止凭空创建无界条目**：handler 从不合成 delta 未携带的聚合；
    - aggregated 容器容量语义由 02 §5.1 驱逐契约承载，本 handler 只合并。
    """
    upserts = _coerce_items(items, BehaviorAggregate, "behavior_aggregate_upserts")
    if not upserts:
        return state

    merged = list(state.behavior_aggregates)
    for incoming in upserts:
        match_index = next(
            (
                position
                for position, existing in enumerate(merged)
                if _aggregate_partition_key(existing)
                == _aggregate_partition_key(incoming)
            ),
            None,
        )
        if match_index is None:
            merged.append(incoming)
            continue

        existing = merged[match_index]
        confidence = (
            existing.confidence
            if _CONFIDENCE_ORDER[existing.confidence]
            >= _CONFIDENCE_ORDER[incoming.confidence]
            else incoming.confidence
        )
        merged[match_index] = existing.model_copy(
            update={
                "count": existing.count + incoming.count,
                "window_start": _merge_window_edge(
                    existing.window_start,
                    incoming.window_start,
                    take_max=False,
                ),
                "window_end": _merge_window_edge(
                    existing.window_end, incoming.window_end, take_max=True
                ),
                "confidence": confidence,
                "predecessor_refs": _merge_ref_lists(
                    list(existing.predecessor_refs),
                    list(incoming.predecessor_refs),
                ),
                "evidence_refs": _merge_ref_lists(
                    list(existing.evidence_refs),
                    list(incoming.evidence_refs),
                    key=lambda ref: ref.ref_id,
                ),
            }
        )

    return state.model_copy(update={"behavior_aggregates": merged})
