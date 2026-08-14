"""V2.1 frozen signal models (01_F1 字段与契约冻结).

Pure additive scaffold for the V21-01 contract stage: these models only
declare frozen fields and enum values from
``docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/01_F1字段与契约冻结.md``.
They carry no DB/HTTP dependencies and are never referenced by the legacy
decision path (``engine.py`` / ``decisions/policy.py``).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from ..decisions.models import Decision

__all__ = [
    "AuthorityStatus",
    "AuthorityVerdict",
    "CoverageDomain",
    "CoverageStatus",
    "Decision",
    "EvaluationDegradation",
    "EvidenceOrigin",
    "EvidenceRef",
    "FactAuthority",
    "FactRef",
    "FastDisposition",
    "FlowStatus",
    "FlowStrength",
    "FlowVerdict",
    "ImpactClass",
    "PolicyTier",
    "PolicyViolation",
    "SecuritySignal",
    "SequenceDomain",
    "SequenceRef",
    "TaintLabel",
]

# ---------------------------------------------------------------------------
# Frozen base enums (01 §1, L11-65; CoverageDomain §17, L743-751)
# ---------------------------------------------------------------------------

FastDisposition = Literal["CLEAR_ALLOW", "CLEAR_DENY", "DEFER"]

CoverageStatus = Literal[
    "complete",
    "partial",
    "stale",
    "unknown",
    "not_applicable",
]

ImpactClass = Literal["low", "moderate", "high", "critical"]
EvidenceOrigin = Literal["observed", "derived", "model_judgment"]
FactAuthority = Literal[
    "authoritative",
    "trusted_claim",
    "untrusted_claim",
    "model_judgment",
]

FlowStrength = Literal["exact", "strong", "possible"]
TaintLabel = Literal[
    "UNTRUSTED",
    "EXTERNAL_INSTRUCTION",
    "SENSITIVE",
    "CREDENTIAL",
    "PERSISTENT_UNTRUSTED",
]

PolicyTier = Literal[
    "system_invariant",
    "system_hard_policy",
    "tenant_hard_policy",
    "review_policy",
]

AuthorityStatus = Literal[
    "authorized",
    "unauthorized",
    "unknown",
    "not_required",
]

FlowStatus = Literal[
    "safe",
    "violation",
    "uncertain",
    "not_applicable",
]

SequenceDomain = Literal["audit", "runtime", "memory", "receipt", "policy"]

CoverageDomain = Literal[
    "task",
    "source",
    "capability",
    "behavior",
    "dataflow",
    "memory",
    "runtime_outcome",
]


# ---------------------------------------------------------------------------
# SequenceRef (01 §5, L164-167)
# ---------------------------------------------------------------------------


class SequenceRef(BaseModel):
    """跨记录顺序锚点；不同 domain 的 sequence 禁止直接比较。"""

    model_config = ConfigDict(extra="forbid")

    domain: SequenceDomain
    producer_binding_id: str
    value: int


# ---------------------------------------------------------------------------
# EvidenceRef (01 §2, L74-98)
# ---------------------------------------------------------------------------

EvidenceKind = Literal[
    "guard_event",
    "audit_event",
    "task_fact",
    "source_fact",
    "flow_fact",
    "memory_fact",
    "capability_grant",
    "recent_action",
    "policy_rule",
    "runtime_receipt",
    "semantic_judgment",
    "declassification",
    "degradation",
]


class EvidenceRef(BaseModel):
    """稳定可解析证据引用。

    ``record_id`` 必须能从审计/事实注册表稳定定位；``json_pointer`` 只定位
    结构化 evidence；``digest`` 用于验证被引用 evidence 未漂移。
    """

    model_config = ConfigDict(extra="forbid")

    ref_id: str
    kind: EvidenceKind
    record_type: str
    record_id: str
    json_pointer: str | None = None
    digest: str
    redaction_state: Literal["none", "redacted", "summary_only"]

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29, L1162-1181）。

        只声明白名单，不实现摘要计算；canonical digest 计算留待后续阶段。
        禁止纳入 wall-clock latency、random UUID、display-only reason、
        provider request id、debug metadata 与非稳定顺序日志。
        """
        return frozenset(
            {
                "ref_id",
                "kind",
                "record_type",
                "record_id",
                "json_pointer",
                "redaction_state",
            }
        )


# ---------------------------------------------------------------------------
# FactRef (01 §3, L112-127)
# ---------------------------------------------------------------------------


class FactRef(BaseModel):
    """SecuritySignal 对事实的轻量引用；事实正文由对应 typed fact 承载。"""

    model_config = ConfigDict(extra="forbid")

    fact_id: str
    fact_type: Literal[
        "task",
        "source",
        "flow",
        "memory",
        "capability",
        "action",
        "runtime_outcome",
        "declassification",
    ]
    origin: EvidenceOrigin
    authority: FactAuthority
    evidence_refs: list[EvidenceRef]


# ---------------------------------------------------------------------------
# SecuritySignal (01 §20, L852-867)
# ---------------------------------------------------------------------------


class SecuritySignal(BaseModel):
    """V2.1 检测器输出契约。

    冻结语义（01 §20）：

    - 不含 final ``decision``；信号不直接给出放行/拦截结论，最终判定由
      Fusion 阶段产出。
    - 不把 ``confidence`` 当概率；它只是检测器对自身输出的置信分级。
    - legacy ``risk_score`` 只能作为迁移 metadata，不进入新 Fusion 的核心
      真值（本模型因此也不携带 risk_score 字段）。
    - 同一证据组不得重复叠加为多个独立证据。
    """

    model_config = ConfigDict(extra="forbid")

    signal_id: str
    detector_id: str
    category: str

    scope: Literal["event", "sequence", "flow", "authority"]
    impact: ImpactClass
    confidence: Literal["low", "medium", "high"]

    evidence_group: str
    reason_codes: list[str]
    evidence_refs: list[EvidenceRef]
    facts: list[FactRef]

    tags: list[str]


# ---------------------------------------------------------------------------
# PolicyViolation (01 §21, L881-889)
# ---------------------------------------------------------------------------


class PolicyViolation(BaseModel):
    """策略违规记录；``system_invariant`` 不能通过普通 override 降级。"""

    model_config = ConfigDict(extra="forbid")

    violation_id: str
    rule_id: str
    policy_tier: PolicyTier
    effect: Literal["ask", "deny"]

    reason_codes: list[str]
    evidence_refs: list[EvidenceRef]


# ---------------------------------------------------------------------------
# EvaluationDegradation (01 §22, L898-918)
# ---------------------------------------------------------------------------


class EvaluationDegradation(BaseModel):
    """评估组件降级记录。

    当前 detector failure contract 迁移后应映射到这个模型；在迁移前继续
    保持现有 conservative ASK 行为。
    """

    model_config = ConfigDict(extra="forbid")

    degradation_id: str
    component_id: str
    domain: CoverageDomain | None

    required_for_action: bool

    failure_kind: Literal[
        "unavailable",
        "timeout",
        "invalid_output",
        "stale",
        "sequence_gap",
        "overflow",
        "dirty_projection",
        "unsupported",
    ]

    reason_codes: list[str]
    evidence_refs: list[EvidenceRef]


# ---------------------------------------------------------------------------
# AuthorityVerdict / FlowVerdict (01 §23, L927-941)
# ---------------------------------------------------------------------------


class AuthorityVerdict(BaseModel):
    """Authority 维度判定。"""

    model_config = ConfigDict(extra="forbid")

    status: AuthorityStatus
    matched_grant_ids: list[str]
    missing_capabilities: list[str]
    explicit_scope_mismatches: list[str]
    evidence_refs: list[EvidenceRef]


class FlowVerdict(BaseModel):
    """Data flow 维度判定。"""

    model_config = ConfigDict(extra="forbid")

    status: FlowStatus
    strongest_strength: FlowStrength | None
    taints: list[TaintLabel]
    external_sink: bool
    path_refs: list[str]
    evidence_refs: list[EvidenceRef]
