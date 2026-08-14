"""Detector result models for Core decision merging."""

from __future__ import annotations

from dataclasses import dataclass

from .models import RuleHit


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """legacy compatibility type（07_当前代码改造映射.md §5）。

    V2.1 迁移期保留本类型；正式检测器输出将迁移到
    ``agentguard_core.signals.models.SecuritySignal``，待所有正式 detector
    不再依赖 DetectionResult 后再考虑内部删除。
    """

    decision: str
    risk_score: int
    category: str
    rule_hit: RuleHit
    reason: str
    approval_resource: str | None = None
    severity: str | None = None
