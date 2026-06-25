"""Base detector protocol and shared rule override helpers."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ..decisions import DetectionResult
from ..events import GuardEvent
from ..policies import PolicyBundle


class Detector:
    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        raise NotImplementedError


def is_rule_disabled(rule_id: str, policies: PolicyBundle) -> bool:
    return rule_id in set(policies.disabled_rules)


def apply_rule_override(result: DetectionResult, policies: PolicyBundle) -> DetectionResult | None:
    if is_rule_disabled(result.rule_hit.rule_id, policies):
        return None
    override = policies.rule_overrides.get(result.rule_hit.rule_id)
    if override is None:
        return result
    updates: dict[str, Any] = {}
    if override.decision is not None:
        updates["decision"] = override.decision
    if override.risk_score is not None:
        updates["risk_score"] = override.risk_score
    if override.severity is not None:
        updates["severity"] = override.severity
        updates["rule_hit"] = result.rule_hit.model_copy(update={"severity": override.severity})
    return replace(result, **updates) if updates else result
