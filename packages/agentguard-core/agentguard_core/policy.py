"""Policy engine for P0 stateless Core decisions."""

from __future__ import annotations

from time import perf_counter

from .detectors import DetectionResult
from .models import ApprovalIntent, GuardDecision, RuleHit, new_id


def build_guard_decision(results: list[DetectionResult], *, started_at: float) -> GuardDecision:
    latency_ms = int((perf_counter() - started_at) * 1000)
    if not results:
        return GuardDecision(
            decision_id=new_id("dec"),
            decision="allow",
            risk_score=0,
            severity="low",
            categories=[],
            rule_hits=[],
            reason="No P0 policy rule was triggered.",
            safe_message=None,
            approval_intent=None,
            latency_ms=latency_ms,
        )

    risk_score = max(item.risk_score for item in results)
    rule_hits: list[RuleHit] = [item.rule_hit for item in results]
    if any(item.decision == "deny" for item in results):
        decision = "deny"
    elif any(item.decision == "ask" for item in results):
        decision = "ask"
    else:
        decision = "allow"

    return GuardDecision(
        decision_id=new_id("dec"),
        decision=decision,
        risk_score=risk_score,
        severity=_decision_severity(results, risk_score),
        categories=list(dict.fromkeys(item.category for item in results)),
        rule_hits=rule_hits,
        reason="; ".join(dict.fromkeys(item.reason for item in results)),
        safe_message=_safe_message(decision),
        approval_intent=_approval_intent(decision, results),
        latency_ms=latency_ms,
    )


def _severity_for_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _decision_severity(results: list[DetectionResult], risk_score: int) -> str:
    severities = [item.severity for item in results if item.severity is not None]
    if not severities:
        return _severity_for_score(risk_score)
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return max(severities, key=lambda item: severity_order.get(item, 0))


def _safe_message(decision: str) -> str | None:
    if decision == "deny":
        return "This tool call was blocked by AgentGuard Core."
    if decision == "ask":
        return "This tool call requires approval before it can continue."
    return None


def _approval_intent(decision: str, results: list[DetectionResult]) -> ApprovalIntent | None:
    if decision != "ask":
        return None
    for result in results:
        if result.approval_resource:
            return ApprovalIntent(resource=result.approval_resource)
    return ApprovalIntent(resource="")
