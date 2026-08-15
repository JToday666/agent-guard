"""V21-05 provenance/taint typed upsert handlers（Phase 1 纯新增）。

``docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/02_状态投影_Provenance_Authority.md``
§8-§9 与 ``01_F1字段与契约冻结.md`` §10-§12 的 provenance 分支实施：

- 五个 handler 严格符合 ``handlers.TypedUpsertHandler`` 签名
  ``(state, items) -> OnlineSecurityState``，全部是确定性纯函数：
  返回 ``model_copy`` 新实例，不原地修改输入（core stateless 纪律）；
- **Phase 1 纪律**：本模块不注册进 ``handlers.TYPED_UPSERT_HANDLERS``
  中央分发表（该表保持空 tuple，集成 PR Phase 2 一次性装配）；集成
  语义由消费方以本地构造的 handler tuple 验证；
- 承载决策（``apply_declassification_upserts``）：已核验
  ``state.OnlineSecurityState`` 的 14 子域**没有** declassification
  专属容器（02 §5 容器清单冻结，不得新增字段）。因此
  declassification 的效果**应用于 ``sticky_taint_summaries`` 语义**：
  trusted_declassifier 记录从其 input/output ref 关联的 sticky 摘要中
  移除 ``removed_taints``。效果天然幂等（重复移除无副作用），等价
  于按 ``declass_id`` 去重；
- taint 单调性（02 §9.1）：``TAINT_LABELS`` 五类标签逐字对齐
  ``contract_freeze.yaml`` 的 ``taint_labels``；handler 只做并集传播，
  **不随 hop 数衰减**，唯一的合法移除路径是 trusted_declassifier 的
  DeclassificationFact；
- fail-closed 错误语义（``ProvenanceProjectionError``）：与
  ``projector.ProjectionError`` 同构（``reason_code`` + 消息），但前缀
  为 ``v21-05:`` 且不 import 黑名单模块；异常携带 ``dirty_domains``
  供调用方置脏相关 coverage 域。
"""

from __future__ import annotations

from typing import Iterable

from ...signals.models import (
    CoverageDomain,
    EvidenceRef,
    SequenceRef,
    TaintLabel,
)
from ..facts import (
    DeclassificationFact,
    FlowFact,
    MemoryFact,
    SourceFact,
    StickyTaintSummary,
)
from ..handlers import TypedUpsertHandler
from ..state import (
    OnlineSecurityState,
    SequenceComparisonError,
    compare_sequence_refs,
)

__all__ = [
    "MAX_STICKY_TAINT_SUMMARIES",
    "MAX_SUMMARY_EVIDENCE_REFS",
    "MAX_SUMMARY_REFS",
    "PROVENANCE_TYPED_UPSERT_HANDLERS",
    "ProvenanceProjectionError",
    "TAINT_LABELS",
    "apply_declassification_upserts",
    "apply_flow_upserts",
    "apply_memory_upserts",
    "apply_source_upserts",
    "apply_sticky_taint_upserts",
    "propagate_taints",
]

#: 冻结的五类 taint label（contract_freeze.yaml ``taint_labels`` 逐字）。
TAINT_LABELS: tuple[TaintLabel, ...] = (
    "UNTRUSTED",
    "EXTERNAL_INSTRUCTION",
    "SENSITIVE",
    "CREDENTIAL",
    "PERSISTENT_UNTRUSTED",
)

#: sticky taint 摘要容器容量（02 §5.2 state flooding 防护的 bounded 上限）。
#: 必须小于 2^|TAINT_LABELS|（五类标签只有 32 种不同 taint 集合）：
#: 否则「同 taint 集合安全合并」永远能把容器压回容量内，
#: fail-closed 溢出分支将不可达，违反 C8 不得静默淘汰的冻结纪律。
MAX_STICKY_TAINT_SUMMARIES: int = 16

#: 单个 sticky 摘要内 unresolved flow / memory / evidence ref 的并集上限。
MAX_SUMMARY_REFS: int = 64
MAX_SUMMARY_EVIDENCE_REFS: int = 64

#: 安全保持型 sticky 保护标签（02 §5.1）：永不按普通淘汰移除。
_PROTECTED_LABELS: frozenset[str] = frozenset(
    {"CREDENTIAL", "PERSISTENT_UNTRUSTED"}
)


class ProvenanceProjectionError(ValueError):
    """V21-05 fail-closed 投影异常（ProjectionError 语义，前缀 ``v21-05:``）。

    ``dirty_domains`` 声明调用方应置脏的相关 coverage 域：coverage
    计算把 dirty 域 fail-closed 降 unknown（02 §3）。异常消息不得
    包含 task 正文、server key 或任何敏感内容。
    """

    def __init__(
        self,
        reason_code: str,
        message: str,
        dirty_domains: tuple[CoverageDomain, ...] = (),
    ) -> None:
        if not reason_code.startswith("v21-05:"):
            raise ValueError(
                f"reason_code must start with 'v21-05:', got {reason_code!r}"
            )
        super().__init__(message)
        self.reason_code = reason_code
        self.dirty_domains: tuple[CoverageDomain, ...] = tuple(dirty_domains)


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------


def propagate_taints(*label_sets: Iterable[TaintLabel]) -> list[TaintLabel]:
    """taint 并集传播（02 §9.1 单调性：无 hop 衰减）。

    多组 label 取并集并按冻结枚举序确定性排序；出现未知 label 即
    fail-closed（不得静默忽略未冻结标签）。
    """
    merged: set[str] = set()
    for labels in label_sets:
        for label in labels:
            if label not in TAINT_LABELS:
                raise ProvenanceProjectionError(
                    "v21-05:unknown_taint_label",
                    f"taint label {label!r} is not in the frozen lattice",
                    dirty_domains=("dataflow",),
                )
            merged.add(label)
    order = {label: index for index, label in enumerate(TAINT_LABELS)}
    return sorted(merged, key=lambda label: order[label])  # type: ignore[arg-type]


def _dedupe_by_key(
    existing: Iterable[object],
    incoming: Iterable[object],
    key: str,
    *,
    conflict_reason: str,
    dirty_domain: CoverageDomain,
) -> list[object]:
    """按 ``key`` 属性去重合并：同 key 同内容幂等 no-op，异内容 fail-closed。

    T-Replay 确定性：「后来者覆盖」在增量与 rebuild 顺序分叉时产生
    不一致 digest，因此同 key 异内容抛 ``ProvenanceProjectionError``
    （声明相关域置脏）；结果按 key 确定性排序。异常消息不得包含
    fact 正文等敏感内容。
    """
    merged: dict[str, object] = {}
    for item in [*existing, *incoming]:
        item_key = getattr(item, key)
        stored = merged.get(item_key)
        if stored is not None and stored != item:
            raise ProvenanceProjectionError(
                conflict_reason,
                f"same {key} with different content: fail-closed, silent "
                "overwrite would break T-Replay determinism",
                dirty_domains=(dirty_domain,),
            )
        merged[item_key] = item
    return [merged[item_key] for item_key in sorted(merged)]


def _bounded_union(
    left: list[str], right: list[str], limit: int
) -> list[str]:
    """字符串 ref 的确定性有界并集（排序后截断至 ``limit``）。"""
    return sorted(set(left) | set(right))[:limit]


def _compare_for_merge(left: SequenceRef, right: SequenceRef) -> int:
    """同 domain+producer 才可比较；跨域/跨 producer fail-closed。

    把 ``SequenceComparisonError``（v21-04 前缀）转为本分支的
    ``ProvenanceProjectionError``（v21-05 前缀）并声明相关域置脏。
    """
    try:
        return compare_sequence_refs(left, right)
    except SequenceComparisonError as error:
        raise ProvenanceProjectionError(
            "v21-05:sticky_sequence_cross_domain",
            str(error),
            dirty_domains=("dataflow",),
        ) from error


def _min_sequence(left: SequenceRef, right: SequenceRef) -> SequenceRef:
    if _compare_for_merge(left, right) <= 0:
        return left
    return right


def _max_sequence(left: SequenceRef, right: SequenceRef) -> SequenceRef:
    if _compare_for_merge(left, right) >= 0:
        return left
    return right


def _is_protected_summary(summary: StickyTaintSummary) -> bool:
    """``CREDENTIAL`` / ``PERSISTENT_UNTRUSTED`` 摘要受 sticky 保护（02 §5.1）。"""
    return bool(set(summary.taints) & _PROTECTED_LABELS)


# ---------------------------------------------------------------------------
# handler 1/5：source_upserts
# ---------------------------------------------------------------------------


def apply_source_upserts(
    state: OnlineSecurityState, items: list[SourceFact]
) -> OnlineSecurityState:
    """按 ``source_id`` 去重合并入 ``source_index``（确定性排序）。

    同 id 同内容幂等 no-op；同 id 异内容 fail-closed 抛
    ``v21-05:source_identity_conflict``（T-Replay 确定性）。

    taints/trust 原样保留（02 §9.1 单调性）：本 handler 不移除任何
    taint，净化只由 ``apply_declassification_upserts`` 表达。
    """
    merged = _dedupe_by_key(
        state.source_index,
        items,
        "source_id",
        conflict_reason="v21-05:source_identity_conflict",
        dirty_domain="source",
    )
    return state.model_copy(update={"source_index": merged})


# ---------------------------------------------------------------------------
# handler 2/5：flow_upserts
# ---------------------------------------------------------------------------


def apply_flow_upserts(
    state: OnlineSecurityState, items: list[FlowFact]
) -> OnlineSecurityState:
    """按 ``flow_id`` 去重合并入 ``relevant_flows``（确定性排序）。

    同 id 同内容幂等 no-op；同 id 异内容 fail-closed 抛
    ``v21-05:flow_identity_conflict``（T-Replay 确定性）。

    ``taints`` 不随 hop 衰减；``strength`` 由证据质量决定（02 §9.2），
    handler 不做任何强度升降。
    """
    merged = _dedupe_by_key(
        state.relevant_flows,
        items,
        "flow_id",
        conflict_reason="v21-05:flow_identity_conflict",
        dirty_domain="dataflow",
    )
    return state.model_copy(update={"relevant_flows": merged})


# ---------------------------------------------------------------------------
# handler 3/5：declassification_upserts
# ---------------------------------------------------------------------------


def apply_declassification_upserts(
    state: OnlineSecurityState, items: list[DeclassificationFact]
) -> OnlineSecurityState:
    """把 trusted declassification 效果应用于 sticky taint 摘要。

    **承载决策**：已核验 ``OnlineSecurityState`` 无 declassification
    专属容器（02 §5 十四子域冻结，本期不得新增字段）；按任务约定将
    效果承载于 ``sticky_taint_summaries`` 语义：对每条
    ``producer == "trusted_declassifier"``（Literal 强制）的记录，从
    input/output ref 命中的 sticky 摘要中移除 ``removed_taints``。

    幂等与去重：移除操作天然幂等，重复应用同一 ``declass_id`` 效果
    不变（等价于按 id 去重）；items 内部按 ``declass_id`` 后来者覆盖。

    fail-closed：``removed_taints`` 与 ``retained_taints`` 交集非空 →
    ``v21-05:declassification_conflict``；客户端/Adapter 不能自报
    sanitized 清 taint（01 §11），只有本 handler 消费 trusted
    declassifier 记录这一条路径可以移除 taint。
    """
    by_id: dict[str, DeclassificationFact] = {}
    for item in items:
        by_id[item.declass_id] = item

    summaries = [
        summary.model_copy(deep=True)
        for summary in state.sticky_taint_summaries
    ]
    for item in sorted(by_id.values(), key=lambda entry: entry.declass_id):
        removed = set(item.removed_taints)
        if removed & set(item.retained_taints):
            raise ProvenanceProjectionError(
                "v21-05:declassification_conflict",
                "removed_taints and retained_taints must be disjoint",
                dirty_domains=("dataflow",),
            )
        for summary in summaries:
            refs = set(summary.unresolved_flow_refs) | set(summary.memory_refs)
            if item.input_ref in refs or item.output_ref in refs:
                summary.taints = [
                    label for label in summary.taints if label not in removed
                ]
    return state.model_copy(update={"sticky_taint_summaries": summaries})


# ---------------------------------------------------------------------------
# handler 4/5：memory_upserts
# ---------------------------------------------------------------------------


def apply_memory_upserts(
    state: OnlineSecurityState, items: list[MemoryFact]
) -> OnlineSecurityState:
    """按 ``memory_id`` 去重合并入 ``memory_index``（确定性排序）。

    同 id 同内容幂等 no-op；同 id 异内容 fail-closed 抛
    ``v21-05:memory_identity_conflict``（T-Replay 确定性）。

    Memory lifecycle status 与 trust/taint 分开保存（02 §13 P3），
    handler 不混用两者。
    """
    merged = _dedupe_by_key(
        state.memory_index,
        items,
        "memory_id",
        conflict_reason="v21-05:memory_identity_conflict",
        dirty_domain="memory",
    )
    return state.model_copy(update={"memory_index": merged})


# ---------------------------------------------------------------------------
# handler 5/5：sticky_taint_upserts
# ---------------------------------------------------------------------------


def _merge_evidence_refs(
    left: list[EvidenceRef], right: list[EvidenceRef]
) -> list[EvidenceRef]:
    """evidence ref 的确定性有界并集（按 canonical JSON 去重排序）。"""
    seen: dict[str, EvidenceRef] = {}
    for ref in [*left, *right]:
        seen.setdefault(ref.model_dump_json(), ref)
    return sorted(
        seen.values(), key=lambda ref: ref.model_dump_json()
    )[:MAX_SUMMARY_EVIDENCE_REFS]


def _merge_two_summaries(
    left: StickyTaintSummary, right: StickyTaintSummary
) -> StickyTaintSummary:
    """同一 ``summary_id`` 的安全合并（union taints / min first / max last）。"""
    return StickyTaintSummary(
        summary_id=left.summary_id,
        taints=propagate_taints(left.taints, right.taints),
        first_seen=_min_sequence(left.first_seen, right.first_seen),
        last_seen=_max_sequence(left.last_seen, right.last_seen),
        unresolved_flow_refs=_bounded_union(
            left.unresolved_flow_refs,
            right.unresolved_flow_refs,
            MAX_SUMMARY_REFS,
        ),
        memory_refs=_bounded_union(
            left.memory_refs, right.memory_refs, MAX_SUMMARY_REFS
        ),
        evidence_refs=_merge_evidence_refs(
            left.evidence_refs, right.evidence_refs
        ),
    )


def _merge_same_taint_groups(
    summaries: list[StickyTaintSummary],
) -> list[StickyTaintSummary]:
    """容量超限时只做安全合并：同 taint 集合的摘要合并（无损并集）。

    合并组的新 ``summary_id`` 由成员 id 确定性派生（禁 uuid）；
    受保护标签（CREDENTIAL/PERSISTENT_UNTRUSTED）只会被并入更大的
    taint 并集，永不被淘汰。单元素组原样保留。
    """
    groups: dict[frozenset[str], list[StickyTaintSummary]] = {}
    for summary in summaries:
        groups.setdefault(frozenset(summary.taints), []).append(summary)

    merged: list[StickyTaintSummary] = []
    for _taints, group in sorted(
        groups.items(), key=lambda pair: sorted(pair[0])
    ):
        if len(group) == 1:
            merged.append(group[0])
            continue
        current = group[0]
        for other in group[1:]:
            current = _merge_two_summaries(current, other)
        merged.append(
            current.model_copy(
                update={
                    "summary_id": "sticky-merged:"
                    + ":".join(sorted(s.summary_id for s in group))
                }
            )
        )
    merged.sort(key=lambda summary: summary.summary_id)
    return merged


def apply_sticky_taint_upserts(
    state: OnlineSecurityState, items: list[StickyTaintSummary]
) -> OnlineSecurityState:
    """增量合并入 ``sticky_taint_summaries``（02 §5.1/§5.2 安全保持型）。

    合并语义：

    - 按 ``summary_id`` 去重：同 id 合并 —— union taints（单调，无
      hop 衰减）、min ``first_seen`` / max ``last_seen``（仅同
      domain+producer 可比，跨域比较 fail-closed）、refs 有界并集；
    - 合并后超过 ``MAX_STICKY_TAINT_SUMMARIES`` 时**只做安全合并**
      （同 taint 集合的摘要无损并组合并），禁止任何普通淘汰；
    - 安全合并后仍超限 → 抛 ``ProvenanceProjectionError``
      （``v21-05:sticky_taint_summary_overflow``，``dirty_domains``
      含 ``dataflow``，调用方据此置脏）——不得静默丢弃；
    - ``CREDENTIAL`` / ``PERSISTENT_UNTRUSTED`` 标签的摘要永不被普通
      淘汰（本 handler 不做任何淘汰路径，protected 摘要只会并入
      更大的 taint 并集）。
    """
    by_id: dict[str, StickyTaintSummary] = {}
    for summary in state.sticky_taint_summaries:
        by_id[summary.summary_id] = summary
    for incoming in items:
        existing = by_id.get(incoming.summary_id)
        if existing is None:
            by_id[incoming.summary_id] = incoming
        else:
            by_id[incoming.summary_id] = _merge_two_summaries(
                existing, incoming
            )

    merged = [by_id[summary_id] for summary_id in sorted(by_id)]
    if len(merged) > MAX_STICKY_TAINT_SUMMARIES:
        merged = _merge_same_taint_groups(merged)
    if len(merged) > MAX_STICKY_TAINT_SUMMARIES:
        protected = sum(
            1 for summary in merged if _is_protected_summary(summary)
        )
        raise ProvenanceProjectionError(
            "v21-05:sticky_taint_summary_overflow",
            "sticky taint summaries exceed the bounded capacity after "
            f"safe merging ({len(merged)} > {MAX_STICKY_TAINT_SUMMARIES}, "
            f"{protected} protected); silent eviction is forbidden",
            dirty_domains=("dataflow",),
        )
    return state.model_copy(update={"sticky_taint_summaries": merged})


#: provenance 分支的本地 handler 表（Phase 2 中央装配的确定性蓝本）。
#: **不是**中央分发表：``handlers.TYPED_UPSERT_HANDLERS`` 保持空 tuple，
#: 集成 PR 一次性注册；此表仅供本分支测试验证集成语义。
PROVENANCE_TYPED_UPSERT_HANDLERS: tuple[tuple[str, TypedUpsertHandler], ...] = (
    ("source_upserts", apply_source_upserts),
    ("flow_upserts", apply_flow_upserts),
    ("declassification_upserts", apply_declassification_upserts),
    ("memory_upserts", apply_memory_upserts),
    ("sticky_taint_upserts", apply_sticky_taint_upserts),
)
