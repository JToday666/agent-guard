"""V21-09 finalize 纯函数：FastAssessment(+SemanticJudgment?) → GuardDecision。

契约依据：

- 03 §14（L495-522）finalize 优先级：CLEAR_DENY→deny；CLEAR_ALLOW→allow；
  DEFER 且 semantic=None→ask；semantic binding invalid/stale→ask；
  **Hard deny 永远不由 Semantic 降级**（CLEAR_DENY 分支先于任何 semantic
  消费，语义上不可达降级路径）。
- ``12_决策记录_V21-09前置.md`` D7：finalize → GuardDecision 全字段口径
  冻结——decision 沿用 ``_SHADOW_FINALIZE_MAP`` 语义；risk_score/severity
  由 disposition × impact 确定性映射表给出（risk_score 仅兼容用途，
  03 §15）；reason/categories 由 ``assessment.reason_codes`` 派生；
  ``rule_hits`` 恒空表；``decision_id`` 确定性派生显式传入（禁 uuid
  default_factory）；``latency_ms`` 恒 None（禁 wall-clock）。

模块纪律（对齐 ``test_v21_08_fusion.py`` AST 守卫）：不 import
time/datetime/uuid/random；不 import legacy 判定路径
（engine / decisions.policy / decisions.results）。V21-09 semantic 恒
None（D1），semantic 分支以纯函数钩子形态预留（V21-13 接入）。
"""

from __future__ import annotations

from typing import Mapping

from ..actions.canonical_json import canonical_sha256
from ..semantic.models import SemanticJudgment
from ..signals.models import Decision, FastDisposition, ImpactClass
from .evidence import FastAssessment
from .models import GuardDecision
from .revalidation import validate_semantic_binding

__all__ = [
    "FINALIZE_DECISION_MAP",
    "FINALIZE_RISK_SEVERITY_MAP",
    "NO_REASON_CODES_REASON",
    "derive_final_audit_id",
    "derive_final_decision_id",
    "finalize_v21",
]

#: reason_codes 为空时的确定性 reason 哨兵（不引入自由文本）。
NO_REASON_CODES_REASON = "v21-09:no_reason_codes"

#: disposition → legacy Decision 映射，沿用
#: ``decisions/shadow.py::_SHADOW_FINALIZE_MAP`` 语义（D7-1）：
#: CLEAR_DENY→deny、DEFER→ask、CLEAR_ALLOW→allow。
FINALIZE_DECISION_MAP: Mapping[FastDisposition, Decision] = {
    "CLEAR_DENY": "deny",
    "DEFER": "ask",
    "CLEAR_ALLOW": "allow",
}

#: D7-2 确定性映射表：disposition × impact → (risk_score, severity)。
#: impact 取 03 §4 冻结四级；severity 取既有代码词表
#: critical/high/medium/low。risk_score 仅兼容用途（03 §15）：旧 API
#: 兼容 / Dashboard 排序 / 人类可读 risk band，decision 不依赖分数阈值。
FINALIZE_RISK_SEVERITY_MAP: Mapping[
    tuple[FastDisposition, ImpactClass], tuple[int, str]
] = {
    ("CLEAR_DENY", "critical"): (95, "critical"),
    ("CLEAR_DENY", "high"): (85, "high"),
    ("CLEAR_DENY", "moderate"): (70, "medium"),
    ("CLEAR_DENY", "low"): (55, "medium"),
    ("DEFER", "critical"): (80, "high"),
    ("DEFER", "high"): (65, "medium"),
    ("DEFER", "moderate"): (50, "medium"),
    ("DEFER", "low"): (35, "low"),
    ("CLEAR_ALLOW", "critical"): (30, "low"),
    ("CLEAR_ALLOW", "high"): (20, "low"),
    ("CLEAR_ALLOW", "moderate"): (10, "low"),
    ("CLEAR_ALLOW", "low"): (5, "low"),
}


def _final_decision_identity(
    assessment: FastAssessment, *, semantic_digest: str | None
) -> dict[str, str | None]:
    """finalize 产物确定性身份的规范投影（D7-5）。

    派生输入为 assessment 身份（``assessment_id`` +
    ``assessment_digest``），``semantic_digest`` 存在时并入——同输入必
    同 id（T-Replay 锚点语义；01 §29 "random UUID 禁入安全摘要"同源口径）。
    """
    return {
        "assessment_digest": assessment.assessment_digest,
        "assessment_id": assessment.assessment_id,
        "semantic_digest": semantic_digest,
    }


def derive_final_decision_id(
    assessment: FastAssessment, *, semantic_digest: str | None = None
) -> str:
    """``GuardDecision.decision_id`` 确定性派生（D7-5，禁 uuid）。

    仿 ``derive_assessment_id`` 范式：前缀 + ``canonical_sha256`` 稳定
    身份投影。finalize 调用方**必须**以本函数产物显式传入
    ``finalize_v21``，不得触发 ``GuardDecision.decision_id`` 的
    ``new_id("dec")`` uuid 默认工厂。
    """
    return "dec:" + canonical_sha256(
        _final_decision_identity(assessment, semantic_digest=semantic_digest)
    )


def derive_final_audit_id(
    assessment: FastAssessment, *, semantic_digest: str | None = None
) -> str:
    """finalize 产物配套审计记录的确定性 ``audit_id`` 派生。

    ``GuardDecision`` 本身不含 ``audit_id`` 字段（AuditEvent 侧字段，
    默认 ``new_id("audit")`` uuid）；权威记录编排层（guard-api Phase B）
    构造 policy_evaluation 审计记录时应以本函数产物显式赋值，保证
    replay 同输入同身份（禁 uuid 默认触发，同源 D7-5 口径）。
    """
    return "audit:" + canonical_sha256(
        _final_decision_identity(assessment, semantic_digest=semantic_digest)
    )


def _derive_reason(reason_codes: list[str]) -> str:
    """reason：受控 reason code 的规范化拼接（D7-3，不引入自由文本）。"""
    if not reason_codes:
        return NO_REASON_CODES_REASON
    return "; ".join(reason_codes)


def _derive_categories(reason_codes: list[str]) -> list[str]:
    """categories：reason code 的域前缀归类（D7-3，确定性排序去重）。

    取受控 reason code（``v21-*`` 阶段前缀）的域前缀段
    （``v21-08:hard_policy_deny:H-3`` → ``hard_policy_deny``）。
    """
    domains: set[str] = set()
    for code in reason_codes:
        parts = code.split(":")
        if len(parts) >= 2 and parts[0].startswith("v21-"):
            domains.add(parts[1])
    return sorted(domains)


def finalize_v21(
    assessment: FastAssessment,
    semantic: SemanticJudgment | None = None,
    *,
    decision_id: str,
) -> GuardDecision:
    """V21-09 正式 finalize（完整方案 §15，L3194-3198）。

    03 §14 完整优先级：

    1. ``CLEAR_DENY`` → ``deny``——Hard deny 永远不由 Semantic 降级：
       本分支先于任何 semantic 消费，semantic 无法触及；
    2. ``CLEAR_ALLOW`` → ``allow``；
    3. ``DEFER``：semantic=None → ``ask``（V21-09 恒此分支，D1）；
       semantic binding invalid/stale（``validate_semantic_binding``
       五 digest 比对失败，含指纹漂移与过期）→ ``ask``；binding 有效
       时保持 shadow 阶段语义（03 §11 Stage 1 / 03 §14
       ``semantic_stage == "shadow"``）→ ``ask``——upgrade_only 与
       de-escalation 属 V21-13+ 冻结前置，分支留形不放开。

    GuardDecision 全字段按 D7 口径确定性填充：risk_score/severity 查
    ``FINALIZE_RISK_SEVERITY_MAP``；reason/categories 由
    ``assessment.reason_codes`` 派生；``rule_hits`` 恒空表（D7-4）；
    ``latency_ms`` 恒 None（D7-6，禁 wall-clock）；``decision_id`` 由
    调用方显式传入（``derive_final_decision_id``，禁 uuid 默认触发）。

    V21-09 产物只进证据信封与权威记录（D1），绝不取代 ``evaluate()``
    的 legacy 官方响应。
    """
    if not decision_id:
        raise ValueError(
            "finalize_v21 requires an explicitly derived decision_id "
            "(D7-5: deterministic derivation, uuid default forbidden)"
        )

    disposition = assessment.disposition
    if disposition == "CLEAR_DENY":
        decision: Decision = "deny"
    elif disposition == "CLEAR_ALLOW":
        decision = "allow"
    else:  # DEFER
        if semantic is None:
            decision = "ask"
        elif not validate_semantic_binding(assessment, semantic):
            # semantic binding invalid/stale（03 §14 L508-509）：
            # 五 digest 指纹漂移或过期 → 保守 ASK（fail-closed）。
            decision = "ask"
        else:
            # binding 有效：V21-09 semantic 处于 shadow 阶段
            # （03 §14 ``semantic_stage == "shadow"``），judgment 不改
            # 变 final decision；stage2/stage3 分支留待 V21-13+。
            decision = "ask"

    risk_score, severity = FINALIZE_RISK_SEVERITY_MAP[(disposition, assessment.impact)]
    return GuardDecision(
        decision_id=decision_id,
        decision=decision,
        risk_score=risk_score,
        severity=severity,
        categories=_derive_categories(assessment.reason_codes),
        rule_hits=[],
        reason=_derive_reason(assessment.reason_codes),
        safe_message=None,
        approval_intent=None,
        latency_ms=None,
    )
