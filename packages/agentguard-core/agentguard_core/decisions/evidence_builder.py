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
- shadow 期 ``mode="shadow"``、``final_decision = legacy_decision``
  （04 §1-§2：legacy 是唯一官方决策者）；
- ``semantic_judgment_id`` / ``semantic_digest`` 恒 ``None``（V21-13
  预留）；
- envelope 复用既有 ``decision_v21_envelope()``（不改）。

本模块是纯函数：不读时钟、不生成 uuid、不触 IO，同输入必同输出。
"""

from __future__ import annotations

from typing import Any, Sequence

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
    "build_decision_evidence_v21",
    "decision_evidence_v21_envelope",
]

#: D4 refs 上限（signal/policy/degradation 每类 32，flow_path_refs 16）。
MAX_SIGNAL_IDS = 32
MAX_POLICY_VIOLATION_IDS = 32
MAX_DEGRADATION_IDS = 32
MAX_FLOW_PATH_REFS = 16

#: refs 截断降级的统一 reason code 前缀（D4 留痕口径）。
REASON_REFS_TRUNCATED = "v21-08:refs_truncated"


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


def build_decision_evidence_v21(
    assessment: FastAssessment,
    *,
    legacy_decision: Decision,
    snapshot_id: str,
    state_version: int,
    coverage: CoverageMap,
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
      字段不含 coverage，由编排层注入同一份真值）。

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

    # degradation_ids：assessment 降级 + 截断降级一并登记；若合并后仍超
    # 上限，保留前 31 条原始降级 + 1 条合并截断降级（确定性、单轮收敛，
    # 保证截断留痕记录自身不被截断丢失）。
    degradation_ids = [
        degradation.degradation_id for degradation in assessment.degradations
    ]
    degradation_ids.extend(
        degradation.degradation_id for degradation in overflow_degradations
    )
    if len(degradation_ids) > MAX_DEGRADATION_IDS:
        kept_original = [
            degradation.degradation_id
            for degradation in assessment.degradations
        ][: MAX_DEGRADATION_IDS - 1]
        dropped = len(degradation_ids) - len(kept_original) - 1
        merged = _truncation_degradation(
            event_id=event_id, field="degradation_ids", dropped=dropped
        )
        overflow_degradations = [
            *[
                degradation
                for degradation in overflow_degradations
                if degradation.degradation_id in kept_original
            ],
            merged,
        ]
        degradation_ids = [*kept_original, merged.degradation_id]

    # divergence 分类：assessment 降级 + 截断降级一并传入（截断与
    # degraded_component_failure 同类语义，D4）。
    divergence_category = classify_divergence(
        legacy_decision,
        assessment.disposition,
        [*assessment.degradations, *overflow_degradations],
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
        mode="shadow",
        divergence_category=divergence_category,
        evidence_refs=[],
    )


def decision_evidence_v21_envelope(evidence: DecisionEvidenceV21) -> dict[str, Any]:
    """按 01 §28 版本信封形状包装 evidence（复用既有 envelope 函数）。"""
    return decision_v21_envelope(evidence.model_dump(mode="json"))
