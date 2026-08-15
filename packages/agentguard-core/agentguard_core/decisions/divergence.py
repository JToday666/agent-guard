"""V21-08 divergence_category 受控词表与分类（纯新增，零接线）。

契约依据：``11_决策记录_V21-08前置.md`` D2（IMPLEMENTATION 级冻结）：

- ``DecisionEvidenceV21.divergence_category``（01 §28，类型 ``str | None``）
  采用受控词表：``legacy decision ∈ {allow, ask, deny}`` ×
  ``v21 FastDisposition ∈ {CLEAR_ALLOW, DEFER, CLEAR_DENY}`` 九宫格，
  **parity 对角线为 ``None``**（finalize 最小映射
  CLEAR_ALLOW→allow、DEFER→ask、CLEAR_DENY→deny 与 legacy 一致即无分叉）；
- 九宫格外三个**降级类目**：shadow 因降级无法产出可信 disposition 时
  **取代**九宫格值，不得静默归入任何九宫格；第三个类目
  ``degraded_stale_judgment`` 由 ``12_决策记录_V21-09前置.md`` D8
  新增：revalidation stale（评估本身成功、但提交时点上下文已漂移）
  归因于 CAS 竞争而非组件故障，同样取代九宫格值；
- 词表封闭：全部 3×3 + 3 降级类目穷尽，未定义组合 fail-closed
  （抛 ``DivergenceVocabularyError``，不得自造新词）。

优先级裁决（D2 表述"降级类目取代九宫格"按**降级优先**实现）：

- 只要存在 shadow 组件自身降级（``component_id == SHADOW_COMPONENT_ID``，
  含 ActionIR 构建失败 / fusion 求值失败 / snapshot 读取失败 / D4 refs
  截断），disposition 即不可信，直接返回降级类目；
- shadow 降级中 ``reason_codes`` 携带 ``SNAPSHOT_ABSENT_REASON`` 时归
  ``degraded_no_snapshot``（更具体，优先于一般组件失败）；其余归
  ``degraded_component_failure``；
- legacy detector 失败经 ``legacy_adapter`` 产出的降级
  （``component_id`` 为检测器名）**不属于** shadow 组件降级：fusion 已
  经通过 ``required_degradation → DEFER`` 如实消费，九宫格仍可信；
- revalidation stale（D8）经 ``revalidation_stale`` 显式标记归
  ``degraded_stale_judgment``；优先级位于 shadow 组件降级之后
  （组件故障意味着 disposition 本就未可信产出，归因更根本），
  九宫格之前。

本模块只依赖 ``signals.models`` 与标准库，不触碰判定路径。
"""

from __future__ import annotations

from typing import Mapping, Sequence

from ..signals.models import Decision, EvaluationDegradation, FastDisposition

__all__ = [
    "DEGRADED_COMPONENT_FAILURE",
    "DEGRADED_NO_SNAPSHOT",
    "DEGRADED_STALE_JUDGMENT",
    "DIVERGENCE_VOCABULARY",
    "DivergenceVocabularyError",
    "SHADOW_COMPONENT_ID",
    "SNAPSHOT_ABSENT_REASON",
    "classify_divergence",
]

#: shadow 组件降级统一 component_id（供 divergence 分类识别"shadow 自身
#: 故障"与 legacy detector 降级）。
SHADOW_COMPONENT_ID = "v21-08-shadow"

#: snapshot 缺失降级的标记 reason code（01 §25 禁伪造 Snapshot）。
SNAPSHOT_ABSENT_REASON = "v21-08:snapshot_absent"

#: 降级类目（D2 受控词表，逐字；D8 新增 stale 类目）。
DEGRADED_NO_SNAPSHOT = "degraded_no_snapshot"
DEGRADED_COMPONENT_FAILURE = "degraded_component_failure"
#: revalidation stale 受控类目（``12_决策记录_V21-09前置.md`` D8）：
#: 评估本身成功、但提交时点上下文已漂移（CAS 竞争），取代九宫格值。
DEGRADED_STALE_JUDGMENT = "degraded_stale_judgment"

#: 九宫格受控词表（D2 冻结，逐字）：parity 对角线为 ``None``。
DIVERGENCE_GRID: Mapping[tuple[Decision, FastDisposition], str | None] = {
    ("allow", "CLEAR_ALLOW"): None,
    ("allow", "DEFER"): "legacy_allow__v21_defer",
    ("allow", "CLEAR_DENY"): "legacy_allow__v21_clear_deny",
    ("ask", "CLEAR_ALLOW"): "legacy_ask__v21_clear_allow",
    ("ask", "DEFER"): None,
    ("ask", "CLEAR_DENY"): "legacy_ask__v21_clear_deny",
    ("deny", "CLEAR_ALLOW"): "legacy_deny__v21_clear_allow",
    ("deny", "DEFER"): "legacy_deny__v21_defer",
    ("deny", "CLEAR_DENY"): None,
}

#: 封闭词表全集（九宫格非 parity 值 + 三个降级类目），供校验与离线聚合。
DIVERGENCE_VOCABULARY: frozenset[str] = frozenset(
    {
        category
        for category in DIVERGENCE_GRID.values()
        if category is not None
    }
    | {DEGRADED_NO_SNAPSHOT, DEGRADED_COMPONENT_FAILURE, DEGRADED_STALE_JUDGMENT}
)


class DivergenceVocabularyError(ValueError):
    """出现受控词表之外的 legacy × disposition 组合（fail-closed，不自造新词）。"""


def _shadow_degradations(
    degradations: Sequence[EvaluationDegradation],
) -> list[EvaluationDegradation]:
    return [
        degradation
        for degradation in degradations
        if degradation.component_id == SHADOW_COMPONENT_ID
    ]


def classify_divergence(
    legacy_decision: Decision,
    disposition: FastDisposition,
    degradations: Sequence[EvaluationDegradation] = (),
    *,
    revalidation_stale: bool = False,
) -> str | None:
    """把 legacy × v21 双轨结果分类为受控词表类目（纯函数，全覆盖）。

    - 存在 shadow 组件降级 → **降级优先**：``SNAPSHOT_ABSENT_REASON``
      命中 → ``degraded_no_snapshot``；否则 → ``degraded_component_failure``；
    - ``revalidation_stale``（D8：Phase B 五元组/state version
      revalidate 返回 stale）→ ``degraded_stale_judgment``，取代九宫格值；
    - 否则查九宫格：parity 对角线返回 ``None``；
    - 未定义组合抛 ``DivergenceVocabularyError``（fail-closed）。
    """
    shadow_degraded = _shadow_degradations(degradations)
    if shadow_degraded:
        if any(
            SNAPSHOT_ABSENT_REASON in degradation.reason_codes
            for degradation in shadow_degraded
        ):
            return DEGRADED_NO_SNAPSHOT
        return DEGRADED_COMPONENT_FAILURE

    if revalidation_stale:
        return DEGRADED_STALE_JUDGMENT

    try:
        return DIVERGENCE_GRID[(legacy_decision, disposition)]
    except KeyError as exc:
        raise DivergenceVocabularyError(
            "undefined divergence combination: "
            f"legacy={legacy_decision!r}, v21={disposition!r}"
        ) from exc
