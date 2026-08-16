"""Decision models and merge logic for AgentGuard Core."""

from .models import (
    ApprovalIntent,
    ApprovalResolution,
    AuditEvent,
    AuditRecordType,
    Decision,
    GuardDecision,
    RuntimeBindingCheckStatus,
    RuntimeEnforcementEvidence,
    RuntimeEnforcementGateState,
    RuntimeEnforcementReasonCode,
    RuntimeLeaseConsumeOutcome,
    RuntimeOutcomeReceipt,
    RuleHit,
    RuleOverrideDecision,
)
from .policy import build_guard_decision
from .results import DetectionResult

__all__ = [
    "ApprovalIntent",
    "ApprovalResolution",
    "AuditEvent",
    "AuditRecordType",
    "Decision",
    "DetectionResult",
    "FusionBehaviorRule",
    "FusionFlowRule",
    "FusionInfluenceRule",
    "FusionMatrix",
    "FusionMatrixError",
    "FusionMemoryRule",
    "FastAssessment",
    "GuardDecision",
    "RuntimeBindingCheckStatus",
    "RuntimeEnforcementEvidence",
    "RuntimeEnforcementGateState",
    "RuntimeEnforcementReasonCode",
    "RuntimeLeaseConsumeOutcome",
    "RuntimeOutcomeReceipt",
    "RuleHit",
    "RuleOverrideDecision",
    "build_guard_decision",
    "dedupe_evidence_groups",
    "evaluate_fusion",
    "load_fusion_matrix",
]

# V21-08 fusion 求值器（纯新增导出）。必须放在本文件末尾：fusion 依赖
# ``security_context``，而 ``security_context.snapshot`` 反向导入
# ``decisions.evidence``——先完成上述既有导出，保证环上的
# ``decisions.models``/``decisions.evidence`` 已就绪，避免部分初始化环。
from .fusion import (  # noqa: E402
    FusionBehaviorRule,
    FusionFlowRule,
    FusionInfluenceRule,
    FusionMatrix,
    FusionMatrixError,
    FusionMemoryRule,
    dedupe_evidence_groups,
    evaluate_fusion,
    load_fusion_matrix,
)
from .evidence import FastAssessment  # noqa: E402
