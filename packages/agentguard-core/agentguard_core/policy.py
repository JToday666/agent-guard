"""Policy engine for P0 formal Core decisions."""

from __future__ import annotations

from time import perf_counter

from .detectors import DetectionResult
from .models import PolicyDecision, RuleHit, new_id


def build_policy_decision(results: list[DetectionResult], *, started_at: float) -> PolicyDecision:
    latency_ms = int((perf_counter() - started_at) * 1000)
    if not results:
        return PolicyDecision(
            decision_id=new_id("dec"),
            decision="allow",
            risk_score=0,
            severity="low",
            rule_hits=[],
            reason="No P0 policy rule was triggered.",
            safe_message=None,
            approval=None,
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

    return PolicyDecision(
        decision_id=new_id("dec"),
        decision=decision,
        risk_score=risk_score,
        severity=_severity_for_score(risk_score),
        rule_hits=rule_hits,
        reason="; ".join(dict.fromkeys(item.reason for item in results)),
        safe_message=_safe_message(decision),
        approval=None,
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


def _safe_message(decision: str) -> str | None:
    if decision == "deny":
        return "This tool call was blocked by AgentGuard Core."
    if decision == "ask":
        return "This tool call requires approval before it can continue."
    return None

