"""Legacy DetectionResult → V2.1 signal adapter (V21-01 scaffold).

Pure additive mapping layer: converts legacy ``DetectionResult`` objects into
V2.1 ``SecuritySignal`` / ``EvaluationDegradation`` scaffolds. It never
imports ``engine`` or ``decisions/policy`` and is never referenced by the
decision path; the legacy conservative ASK behavior stays untouched during
migration.
"""

from __future__ import annotations

import hashlib

from ..decisions.results import DetectionResult
from .models import EvaluationDegradation, EvidenceRef, ImpactClass, SecuritySignal

__all__ = [
    "legacy_detection_to_signal",
    "legacy_failure_to_degradation",
]

_DETECTOR_FAILURE_PREFIX = "detector_failure:"

# severity → ImpactClass 表驱动映射（注意 ImpactClass 用 moderate 而非 medium）。
# legacy risk_score/severity 仅作为迁移 metadata，不进入 V2.1 Fusion 真值。
_SEVERITY_TO_IMPACT: dict[str, ImpactClass] = {
    "low": "low",
    "medium": "moderate",
    "high": "high",
    "critical": "critical",
}


def _parse_detector_failure_name(rule_id: str) -> str | None:
    """从 engine.py 的 ``detector_failure:{Name}`` 格式解析检测器名。

    畸形 rule_id（如恰为 ``detector_failure:``）解析出的名字为空，此时返回
    None，保证两条消费路径一致：signal 映射回退用 ``rule_id`` 作
    detector_id，degradation 映射不产出 component_id 为空的无效记录。
    """
    if rule_id.startswith(_DETECTOR_FAILURE_PREFIX):
        name = rule_id[len(_DETECTOR_FAILURE_PREFIX) :]
        return name or None
    return None


def _impact_for_result(result: DetectionResult) -> ImpactClass:
    """severity 表驱动映射；severity 为 None 时按 risk_score 阈值回退。

    回退阈值与 ``decisions/policy.py::_severity_for_score`` 一致：
    ``>=90 critical / >=70 high / >=40 moderate / 其余 low``。
    该派生值仅作为迁移 metadata，不进入 V2.1 Fusion 真值。
    """
    if result.severity is not None:
        impact = _SEVERITY_TO_IMPACT.get(result.severity)
        if impact is not None:
            return impact
    score = result.risk_score
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "moderate"
    return "low"


def _stable_evidence_digest(evidence: list[str]) -> str:
    """对 evidence 列表计算稳定 sha256 摘要。

    编码先写入条数，再逐条以 ``\x00`` 前缀写入内容，保证编码单射：
    ``["a\nb"]`` 与 ``["a", "b"]`` 不会得到相同摘要。条目顺序保持 RuleHit
    原始顺序（语义有序）。V21-02 canonicalization（RFC 8785 JCS）落地后
    升级为 JCS digest。
    """
    hasher = hashlib.sha256()
    hasher.update(str(len(evidence)).encode("utf-8"))
    for item in evidence:
        hasher.update(b"\x00")
        hasher.update(item.encode("utf-8"))
    return hasher.hexdigest()


def legacy_detection_to_signal(
    result: DetectionResult, *, event_id: str
) -> SecuritySignal:
    """把单条 legacy DetectionResult 映射为确定性 SecuritySignal。

    约束：

    - ``signal_id`` / digest 全部确定性派生（同一输入恒定同输出），不使用
      uuid4；
    - detector_failure 类结果的 ``detector_id`` 从
      ``rule_id`` 的 ``detector_failure:{Name}`` 格式解析（见
      ``engine.py::_detector_failure_result``），其余取 ``rule_hit.rule_id``；
    - impact 由 severity 表驱动映射，severity 为 None 时按 risk_score 阈值
      回退；legacy risk_score 仅作为迁移 metadata，不进入 Fusion 真值；
    - legacy 检测器为确定性输出，故 ``confidence="high"``。该取值仅描述
      scaffold 结构确定性，不代表检测器语义置信度。

    EvidenceRef 的 digest 是对 ``rule_hit.evidence`` 列表的稳定 sha256
    （单射编码）；V21-02 canonicalization（RFC 8785 JCS）落地后升级为
    JCS digest。
    """
    rule_hit = result.rule_hit
    detector_id = _parse_detector_failure_name(rule_hit.rule_id) or rule_hit.rule_id
    signal_id = f"sig_{event_id}_{rule_hit.rule_id}"
    evidence_ref = EvidenceRef(
        ref_id=f"ev_{event_id}_{rule_hit.rule_id}",
        kind="policy_rule",
        record_type="guard_decision",
        record_id=event_id,
        digest=_stable_evidence_digest(rule_hit.evidence),
        redaction_state="none",
    )
    return SecuritySignal(
        signal_id=signal_id,
        detector_id=detector_id,
        category=result.category,
        scope="event",
        impact=_impact_for_result(result),
        confidence="high",
        evidence_group=rule_hit.rule_id,
        reason_codes=[rule_hit.rule_id],
        evidence_refs=[evidence_ref],
        facts=[],
        tags=["legacy"],
    )


def legacy_failure_to_degradation(
    result: DetectionResult,
    *,
    event_id: str,
) -> EvaluationDegradation | None:
    """detector_failure 类结果映射为 EvaluationDegradation；其余返回 None。

    ``component_id`` 为从 ``detector_failure:{Name}`` 解析出的检测器名
    （畸形 rule_id 解析为空时返回 None，不产出无效降级记录）；
    ``degradation_id`` 派生加入 ``event_id``，与 ``signal_id`` 口径一致。
    迁移期继续保留 legacy conservative ASK 契约，该降级记录只作为结构化
    scaffold 产出。
    """
    rule_hit = result.rule_hit
    detector_name = _parse_detector_failure_name(rule_hit.rule_id)
    if detector_name is None:
        return None
    return EvaluationDegradation(
        degradation_id=f"deg_{event_id}_{rule_hit.rule_id}",
        component_id=detector_name,
        domain=None,
        required_for_action=True,
        failure_kind="unavailable",
        reason_codes=[rule_hit.rule_id],
        evidence_refs=[],
    )
