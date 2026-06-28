"""Deterministic and optional LLM-backed action review."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from ..decisions import GuardDecision
from ..events import GuardEvent
from ..resources import derive_resources
from .models import ActionCriticReview


class ActionCritic:
    def __init__(
        self,
        *,
        llm_provider: Callable[[GuardEvent, GuardDecision], ActionCriticReview] | None = None,
    ) -> None:
        self.llm_provider = llm_provider

    def review(self, event: GuardEvent, decision: GuardDecision) -> ActionCriticReview:
        if self.llm_provider is not None:
            try:
                return self.llm_provider(event, decision)
            except Exception:
                fallback = self._deterministic_review(event, decision)
                return fallback.model_copy(
                    update={
                        "degraded": True,
                        "evidence": [*fallback.evidence, "llm_fallback=true"],
                    }
                )
        return self._deterministic_review(event, decision)

    def _deterministic_review(self, event: GuardEvent, decision: GuardDecision) -> ActionCriticReview:
        resources = derive_resources(event)
        reasons: list[str] = []
        evidence: list[str] = []
        source_trust = event.security_context.source_trust.lower()
        if source_trust == "untrusted":
            reasons.append("source_trust=untrusted")
        for resource in resources:
            target = resource.target.lower()
            evidence.append(f"target={resource.target}")
            if any(marker in target for marker in ("private", "secret", "token", ".env", "key")):
                reasons.append("sensitive_target=true")
        if decision.decision == "allow" and decision.risk_score >= 70:
            reasons.append("allow_high_risk=true")
        verdict: Literal["pass", "warn", "fail"] = "warn" if len(reasons) >= 2 else "pass"
        return ActionCriticReview(
            trace_id=event.trace_id,
            event_id=event.event_id,
            reviewer="deterministic",
            verdict=verdict,
            confidence=0.72 if verdict == "warn" else 0.9,
            reasons=list(dict.fromkeys(reasons)),
            evidence=list(dict.fromkeys(evidence)),
        )
