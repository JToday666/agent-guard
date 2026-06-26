"""Detector result models for Core decision merging."""

from __future__ import annotations

from dataclasses import dataclass

from .models import RuleHit


@dataclass(frozen=True, slots=True)
class DetectionResult:
    decision: str
    risk_score: int
    category: str
    rule_hit: RuleHit
    reason: str
    approval_resource: str | None = None
    severity: str | None = None
