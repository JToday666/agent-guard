"""V2.1 decision evidence scaffold (V21-01).

Placeholder models for the closed decision-evidence loop defined in
``docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/01_F1字段与契约冻结.md``.
Fields are frozen verbatim from the contract document; fusion, snapshot and
digest computation are implemented in later V21 stages. This module only
imports ``..signals.models`` plus stdlib/pydantic and never touches the
legacy decision path.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from ..signals.models import (
    AuthorityStatus,
    AuthorityVerdict,
    CoverageDomain,
    CoverageStatus,
    Decision,
    EvaluationDegradation,
    EvidenceRef,
    FastDisposition,
    FlowStatus,
    FlowVerdict,
    ImpactClass,
    PolicyViolation,
    SecuritySignal,
    SequenceRef,
)

__all__ = [
    "CoverageMap",
    "DecisionEvidenceV21",
    "DomainCoverage",
    "FastAssessment",
    "RequiredCheckPlan",
    "SemanticRoutingAssessment",
    "decision_v21_envelope",
]


# ---------------------------------------------------------------------------
# RequiredCheckPlan (01 §18, L789-803)
# ---------------------------------------------------------------------------


class RequiredCheckPlan(BaseModel):
    """由 ActionIR + PolicySnapshot 确定的必检计划，不由 LLM 决定。

    V21-01 scaffold：仅冻结字段，计划生成逻辑在后续阶段实现。
    """

    model_config = ConfigDict(extra="forbid")

    plan_id: str
    impact: ImpactClass

    required_domains: list[CoverageDomain]
    optional_domains: list[CoverageDomain]

    required_capabilities: list[str]
    semantic_resolvable_dimensions: list[
        Literal[
            "task_alignment",
            "instruction_semantics",
            "intent_ambiguity",
        ]
    ]

    reason_codes: list[str]


# ---------------------------------------------------------------------------
# SemanticRoutingAssessment (01 §24, L950-958)
# ---------------------------------------------------------------------------


class SemanticRoutingAssessment(BaseModel):
    """取代悬空的 semantic 自由谓词。

    V21-01 scaffold：仅冻结字段；semantic 路由判定在 shadow 阶段接入。
    """

    model_config = ConfigDict(extra="forbid")

    eligible: bool

    hard_deny_present: bool
    semantic_resolvable: bool
    required_facts_available: bool

    reason_codes: list[str]


# ---------------------------------------------------------------------------
# DomainCoverage / CoverageMap (01 §17, L753-767)
# ---------------------------------------------------------------------------


class DomainCoverage(BaseModel):
    """单个 coverage domain 的覆盖状态。

    V21-01 scaffold：仅冻结字段；projector 与水位推进在后续阶段实现。
    """

    model_config = ConfigDict(extra="forbid")

    domain: CoverageDomain
    status: CoverageStatus
    as_of_sequence: SequenceRef | None
    projector_version: str
    reason_codes: list[str]


class CoverageMap(BaseModel):
    """7 个固定 coverage domain 的覆盖快照。

    V21-01 scaffold：字段与顺序逐字冻结自 01 §17。
    """

    model_config = ConfigDict(extra="forbid")

    task: DomainCoverage
    source: DomainCoverage
    capability: DomainCoverage
    behavior: DomainCoverage
    dataflow: DomainCoverage
    memory: DomainCoverage
    runtime_outcome: DomainCoverage


# ---------------------------------------------------------------------------
# FastAssessment (01 §25, L965-995)
# ---------------------------------------------------------------------------


class FastAssessment(BaseModel):
    """V2.1 快路径评估记录。

    V2.1 ``assess()`` 必须有 Snapshot；兼容 ``evaluate()`` 在迁移期继续走
    legacy 路径，不创建伪 Snapshot。

    V21-01 scaffold：``assessment_id`` 与各 digest 字段为必填 ``str``，由
    调用方确定性提供（不使用 uuid default_factory）；canonical digest
    计算在 V21-08 shadow 期实现（``11_决策记录_V21-08前置.md`` D1，
    见 01 §29），V21-09 正式 assess/finalize 复用同一计算函数。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2.1"] = "2.1"

    assessment_id: str
    event_id: str
    action_id: str

    disposition: FastDisposition
    impact: ImpactClass

    required_check_plan: RequiredCheckPlan

    policy_violations: list[PolicyViolation]
    signals: list[SecuritySignal]
    degradations: list[EvaluationDegradation]

    authority: AuthorityVerdict
    flow: FlowVerdict

    semantic_routing: SemanticRoutingAssessment

    reason_codes: list[str]
    evidence_refs: list[EvidenceRef]

    authorization_fingerprint: str
    audit_fingerprint: str
    task_digest: str | None
    policy_digest: str
    snapshot_digest: str
    assessment_digest: str

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29, L1162-1181）。

        只声明白名单；摘要计算在 V21-08 shadow 期实现（``11_决策记录_
        V21-08前置.md`` D1：``decisions/shadow.py::compute_assessment_digest``），
        V21-09 复用同一函数。禁止纳入
        wall-clock latency、random UUID、display-only reason、provider
        request id、debug metadata；``assessment_digest`` 自身不进入自身
        摘要输入。
        """
        return frozenset(
            {
                "schema_version",
                "event_id",
                "action_id",
                "disposition",
                "impact",
                "required_check_plan",
                "policy_violations",
                "signals",
                "degradations",
                "authority",
                "flow",
                "semantic_routing",
                "reason_codes",
                "evidence_refs",
                "authorization_fingerprint",
                "audit_fingerprint",
                "task_digest",
                "policy_digest",
                "snapshot_digest",
            }
        )


# ---------------------------------------------------------------------------
# DecisionEvidenceV21 (01 §28, L1114-1147)
# ---------------------------------------------------------------------------


class DecisionEvidenceV21(BaseModel):
    """V2.1 判定证据闭环记录；不修改公开 GuardDecision 前置契约。

    V21-01 scaffold：字段逐字冻结自 01 §28；fusion 与 divergence 归因在
    后续阶段实现。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2.1"] = "2.1"

    assessment_id: str
    assessment_digest: str
    snapshot_id: str
    snapshot_digest: str
    state_version: int

    required_domains: list[CoverageDomain]
    coverage: CoverageMap

    authority_status: AuthorityStatus
    matched_grant_ids: list[str]

    flow_status: FlowStatus
    flow_path_refs: list[str]

    policy_violation_ids: list[str]
    signal_ids: list[str]
    degradation_ids: list[str]

    semantic_judgment_id: str | None
    semantic_digest: str | None

    legacy_decision: Decision | None
    v21_fast_disposition: FastDisposition
    final_decision: Decision

    mode: Literal["shadow", "limited_enable", "active"]
    divergence_category: str | None

    evidence_refs: list[EvidenceRef]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29, L1162-1181）。

        只声明白名单，不实现摘要计算。禁止纳入 wall-clock latency、random
        UUID、display-only reason、provider request id、debug metadata；
        引用型 ``evidence_refs`` 由其各自记录的 digest 覆盖，不重复进入。
        """
        return frozenset(
            {
                "schema_version",
                "assessment_id",
                "assessment_digest",
                "snapshot_id",
                "snapshot_digest",
                "state_version",
                "required_domains",
                "coverage",
                "authority_status",
                "matched_grant_ids",
                "flow_status",
                "flow_path_refs",
                "policy_violation_ids",
                "signal_ids",
                "degradation_ids",
                "semantic_judgment_id",
                "semantic_digest",
                "legacy_decision",
                "v21_fast_disposition",
                "final_decision",
                "mode",
                "divergence_category",
            }
        )


def decision_v21_envelope(payload: dict[str, Any]) -> dict[str, Any]:
    """按 01 §28 (L1149-1158) 的版本信封形状包装 audit evidence payload。"""
    return {
        "decision_v21": {
            "schema_version": "2.1",
            "payload": payload,
        }
    }
