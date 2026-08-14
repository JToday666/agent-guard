"""V2.1 security signal contracts and legacy adapter scaffold (V21-01)."""

from __future__ import annotations

from .legacy_adapter import (
    legacy_detection_to_signal,
    legacy_failure_to_degradation,
)
from .models import (
    AuthorityStatus,
    AuthorityVerdict,
    CoverageDomain,
    CoverageStatus,
    Decision,
    EvaluationDegradation,
    EvidenceOrigin,
    EvidenceRef,
    FactAuthority,
    FactRef,
    FastDisposition,
    FlowStatus,
    FlowStrength,
    FlowVerdict,
    ImpactClass,
    PolicyTier,
    PolicyViolation,
    SecuritySignal,
    SequenceDomain,
    SequenceRef,
    TaintLabel,
)

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
    "legacy_detection_to_signal",
    "legacy_failure_to_degradation",
]
