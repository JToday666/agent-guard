"""V21-08 DecisionEvidenceV21 组装（纯新增，零接线）。

完整方案 §14（L3155-3177）要求 **DecisionEvidenceV21 不等到后期才做**：
shadow 即保存九项证据——

1. ``assessment_digest``（D1 口径，``decisions/shadow.py`` 已计算）；
2. ``coverage``（七域 CoverageMap）；
3. ``state_version``；
4. authority（``authority_status`` + ``matched_grant_ids``）；
5. flow（``flow_status`` + ``flow_path_refs``）；
6. signal / policy / degradation refs（**只存 id**，D4）；
7. legacy decision；
8. v21 disposition；
9. divergence category（``decisions/divergence.py``）。

refs 上限与截断（``11_决策记录_V21-08前置.md`` D4，IMPLEMENTATION 级）：

- ``signal_ids`` / ``policy_violation_ids`` / ``degradation_ids`` 每类
  **上限 32**，``flow_path_refs`` **上限 16**；
- 超限**截断并记录 degradation**（``failure_kind="overflow"``，登记进
  ``degradation_ids`` 并在其 ``reason_codes`` 留痕，防止静默丢失与
  fail-open）；
- V21-09 起 ``mode`` 解除硬编码：参数默认 ``"shadow"``，默认输出与
  V21-08 逐字节一致（``12_决策记录_V21-09前置.md`` D1：mode 恒
  shadow，``limited_enable``/``active`` 归 V21-11 启用范畴）；
- V21-09 起新增 ``revalidation_stale_reason_codes`` 参数（默认空，
  逐字节回归）：Phase B 五元组 revalidate 返回 stale 时登记
  ``failure_kind="stale"`` 降级并把 ``divergence_category`` 归受控
  类目 ``degraded_stale_judgment``（``12_决策记录_V21-09前置.md``
  D8；01 §22 枚举已含 ``"stale"``，无新增枚举值）；
- ``final_decision = legacy_decision``（04 §1-§2：shadow 期 legacy 是
  唯一官方决策者）；
- ``semantic_judgment_id`` / ``semantic_digest`` 恒 ``None``（V21-13
  预留）；
- envelope 复用既有 ``decision_v21_envelope()``（不改）。

本模块是纯函数：不读时钟、不生成 uuid、不触 IO，同输入必同输出。
"""

from __future__ import annotations

from typing import Any, Literal, Sequence

from ..signals.models import Decision, EvaluationDegradation
from .divergence import SHADOW_COMPONENT_ID, classify_divergence
from .evidence import (
    CoverageMap,
    DecisionEvidenceV21,
    FastAssessment,
    decision_v21_envelope,
)

__all__ = [
    "MAX_DEGRADATION_IDS",
    "MAX_FLOW_PATH_REFS",
    "MAX_POLICY_VIOLATION_IDS",
    "MAX_SIGNAL_IDS",
    "REASON_REFS_TRUNCATED",
    "REVALIDATION_COMPONENT_ID",
    "EvidenceMode",
    "build_decision_evidence_v21",
    "decision_evidence_v21_envelope",
]

#: ``DecisionEvidenceV21.mode`` 的 Literal 全集（01 §28，逐字同步）。
EvidenceMode = Literal["shadow", "limited_enable", "active"]

#: D4 refs 上限（signal/policy/degradation 每类 32，flow_path_refs 16）。
MAX_SIGNAL_IDS = 32
MAX_POLICY_VIOLATION_IDS = 32
MAX_DEGRADATION_IDS = 32
MAX_FLOW_PATH_REFS = 16

#: refs 截断降级的统一 reason code 前缀（D4 留痕口径）。
REASON_REFS_TRUNCATED = "v21-08:refs_truncated"

#: revalidation stale 降级的 component_id（D8）：**不得**归
#: ``SHADOW_COMPONENT_ID``——stale 是"评估成功但提交时点上下文漂移"
#: （CAS 竞争），与组件故障归因不同，divergence 分类据此区分
#: ``degraded_component_failure`` 与 ``degraded_stale_judgment``。
REVALIDATION_COMPONENT_ID = "v21-09-revalidation"


def _truncation_degradation(
    *, event_id: str, field: str, dropped: int
) -> EvaluationDegradation:
    """refs 超限截断的确定性降级记录（D4：禁止静默丢失）。

    ``component_id`` 归 shadow 组件：截断即 shadow 证据链不完整，与
    ``degraded_component_failure`` 同类语义（divergence 分类按降级优先
    消费）。``required_for_action=False``：截断不改变 shadow 期官方
    决策（legacy），只做审计留痕。
    """
    return EvaluationDegradation(
        degradation_id=f"v21-08-refs-truncated:{event_id}:{field}",
        component_id=SHADOW_COMPONENT_ID,
        domain=None,
        required_for_action=False,
        failure_kind="overflow",
        reason_codes=[
            REASON_REFS_TRUNCATED,
            f"{REASON_REFS_TRUNCATED}:{field}",
            f"{REASON_REFS_TRUNCATED}:dropped={dropped}",
        ],
        evidence_refs=[],
    )


def _stale_degradation(
    *, event_id: str, reason_codes: list[str]
) -> EvaluationDegradation:
    """revalidation stale 的确定性降级记录（D8 / 01 §22）。

    ``failure_kind="stale"`` 为 01 §22 既有枚举值；reason_codes 逐项
    登记漂移来源（``v21-09:stale_*``）。``required_for_action=True``：
    stale 意味着 V21-09 权威提交被放弃（fail-closed），但 shadow 期
    官方决策者恒 legacy，降级只影响 v21 证据面。
    """
    return EvaluationDegradation(
        degradation_id=f"v21-09-revalidation-stale:{event_id}",
        component_id=REVALIDATION_COMPONENT_ID,
        domain=None,
        required_for_action=True,
        failure_kind="stale",
        reason_codes=list(reason_codes),
        evidence_refs=[],
    )


def build_decision_evidence_v21(
    assessment: FastAssessment,
    *,
    legacy_decision: Decision,
    snapshot_id: str,
    state_version: int,
    coverage: CoverageMap,
    mode: EvidenceMode = "shadow",
    revalidation_stale_reason_codes: Sequence[str] = (),
) -> DecisionEvidenceV21:
    """组装 shadow 期 ``DecisionEvidenceV21``（§14 九项逐项落字段）。

    入参说明：

    - ``assessment``：``shadow_assess`` 产物（assessment_digest /
      authority / flow / signals / degradations / disposition 的真值源）；
    - ``legacy_decision``：legacy 官方决策（shadow 期 ``final_decision``
      与 divergence 分类的输入）；
    - ``snapshot_id`` / ``state_version``：snapshot 注册身份（snapshot
      缺失时由调用方传 ``shadow.ABSENT_SNAPSHOT_ID`` / ``0`` 哨兵）；
    - ``coverage``：判定时使用的七域 CoverageMap（FastAssessment 冻结
      字段不含 coverage，由编排层注入同一份真值）；
    - ``mode``：运行模式（``DecisionEvidenceV21.mode`` 的 Literal
      全集），默认 ``"shadow"``（``12_决策记录_V21-09前置.md`` D1：
      V21-09 阶段 mode 恒 shadow，调用方只传默认值）。传入
      ``"limited_enable"`` / ``"active"`` 属 V21-11 启用范畴，仅解除
      硬编码预留传值通道；无论何种 mode，``final_decision`` 恒取
      ``legacy_decision``（shadow 期官方决策者是 legacy）；
    - ``revalidation_stale_reason_codes``：Phase B revalidate 返回
      stale 时的漂移 reason codes（``v21-09:stale_*``）；缺省空表 →
      行为与 V21-08 逐字节一致。非空时登记 ``failure_kind="stale"``
      降级进 ``degradation_ids``，并把 ``divergence_category`` 归
      ``degraded_stale_judgment``（D8 降级优先序：shadow 组件降级
      之后、九宫格之前，见 ``classify_divergence``）。

    refs 只存 id 并按 D4 上限截断；截断降级登记进 ``degradation_ids``
    且参与 divergence 分类（降级优先）。``matched_grant_ids`` 不在 D4
    上限清单内，不截断。
    """
    event_id = assessment.event_id
    overflow_degradations: list[EvaluationDegradation] = []

    def _bounded(values: Sequence[str], limit: int, field: str) -> list[str]:
        bounded = list(values[:limit])
        dropped = len(values) - len(bounded)
        if dropped > 0:
            overflow_degradations.append(
                _truncation_degradation(
                    event_id=event_id, field=field, dropped=dropped
                )
            )
        return bounded

    signal_ids = _bounded(
        [signal.signal_id for signal in assessment.signals],
        MAX_SIGNAL_IDS,
        "signal_ids",
    )
    policy_violation_ids = _bounded(
        [violation.violation_id for violation in assessment.policy_violations],
        MAX_POLICY_VIOLATION_IDS,
        "policy_violation_ids",
    )
    flow_path_refs = _bounded(
        assessment.flow.path_refs, MAX_FLOW_PATH_REFS, "flow_path_refs"
    )

    # degradation_ids：assessment 降级 + 截断降级 + revalidation stale
    # 降级一并登记；若合并后仍超上限，为 overflow 截断降级与合并截断
    # 降级预留槽位后再裁剪原始降级（确定性、单轮收敛）：多类截断时
    # 各类的截断留痕记录不得被静默丢弃，合并截断降级自身也恒定在场
    # （D4 禁止静默丢失）。
    stale_codes = list(revalidation_stale_reason_codes)
    stale_degradations = (
        [_stale_degradation(event_id=event_id, reason_codes=stale_codes)]
        if stale_codes
        else []
    )
    degradation_ids = [
        degradation.degradation_id for degradation in assessment.degradations
    ]
    degradation_ids.extend(
        degradation.degradation_id for degradation in overflow_degradations
    )
    degradation_ids.extend(
        degradation.degradation_id for degradation in stale_degradations
    )
    if len(degradation_ids) > MAX_DEGRADATION_IDS:
        overflow_ids = [
            degradation.degradation_id for degradation in overflow_degradations
        ]
        # 预留 overflow 截断登记 + 1 条合并截断降级的槽位。
        original_slots = MAX_DEGRADATION_IDS - len(overflow_ids) - 1
        kept_original = [
            degradation.degradation_id
            for degradation in assessment.degradations
        ][: max(original_slots, 0)]
        dropped = len(degradation_ids) - len(kept_original) - len(overflow_ids) - 1
        merged = _truncation_degradation(
            event_id=event_id, field="degradation_ids", dropped=dropped
        )
        overflow_degradations = [*overflow_degradations, merged]
        degradation_ids = [*kept_original, *overflow_ids, merged.degradation_id]

    # divergence 分类：assessment 降级 + 截断降级一并传入（截断与
    # degraded_component_failure 同类语义，D4）；revalidation stale 经
    # 显式标记归 degraded_stale_judgment（D8，优先级位于 shadow 组件
    # 降级之后、九宫格之前；stale 降级自身 component_id 非 shadow，
    # 不干扰降级优先序）。
    divergence_category = classify_divergence(
        legacy_decision,
        assessment.disposition,
        [
            *assessment.degradations,
            *overflow_degradations,
            *stale_degradations,
        ],
        revalidation_stale=bool(stale_codes),
    )

    return DecisionEvidenceV21(
        assessment_id=assessment.assessment_id,
        assessment_digest=assessment.assessment_digest,
        snapshot_id=snapshot_id,
        snapshot_digest=assessment.snapshot_digest,
        state_version=state_version,
        required_domains=list(assessment.required_check_plan.required_domains),
        coverage=coverage,
        authority_status=assessment.authority.status,
        matched_grant_ids=list(assessment.authority.matched_grant_ids),
        flow_status=assessment.flow.status,
        flow_path_refs=flow_path_refs,
        policy_violation_ids=policy_violation_ids,
        signal_ids=signal_ids,
        degradation_ids=degradation_ids,
        semantic_judgment_id=None,  # V21-13 预留。
        semantic_digest=None,  # V21-13 预留。
        legacy_decision=legacy_decision,
        v21_fast_disposition=assessment.disposition,
        final_decision=legacy_decision,  # shadow 期官方决策者是 legacy。
        mode=mode,
        divergence_category=divergence_category,
        evidence_refs=[],
    )


def decision_evidence_v21_envelope(evidence: DecisionEvidenceV21) -> dict[str, Any]:
    """按 01 §28 版本信封形状包装 evidence（复用既有 envelope 函数）。"""
    return decision_v21_envelope(evidence.model_dump(mode="json"))
