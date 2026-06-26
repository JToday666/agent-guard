"""P2 domain models and local review helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .decisions import GuardDecision
from .events import GuardEvent
from .ids import new_id, utc_now_iso
from .resources import derive_resources


FindingSeverity = Literal["low", "medium", "high", "critical"]


class ConfigAuditFinding(BaseModel):
    model_config = ConfigDict(extra="allow")

    finding_id: str = Field(default_factory=lambda: new_id("finding"))
    severity: FindingSeverity
    category: str
    title: str
    subject: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    recommendation: str | None = None


class ConfigAuditEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: str = Field(default_factory=lambda: new_id("cfg"))
    runtime: str
    target_type: str
    target_id: str
    action: str
    findings: list[ConfigAuditFinding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=utc_now_iso)


class ConfigAuditResult(BaseModel):
    decision: Literal["allow", "block"]
    findings: list[ConfigAuditFinding] = Field(default_factory=list)
    reason: str


class ProvenanceNode(BaseModel):
    model_config = ConfigDict(extra="allow")

    node_id: str = Field(default_factory=lambda: new_id("node"))
    trace_id: str
    kind: str
    ref_id: str
    label: str
    timestamp: str = Field(default_factory=utc_now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProvenanceEdge(BaseModel):
    model_config = ConfigDict(extra="allow")

    edge_id: str = Field(default_factory=lambda: new_id("edge"))
    trace_id: str
    source_node_id: str
    target_node_id: str
    relation: str
    timestamp: str = Field(default_factory=utc_now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditIntegrityMetadata(BaseModel):
    sequence: int = Field(ge=1)
    prev_hash: str | None = None
    event_hash: str
    canonicalization: str = "json:v1"


class MemoryGuardChange(BaseModel):
    model_config = ConfigDict(extra="allow")

    change_id: str = Field(default_factory=lambda: new_id("memchg"))
    trace_id: str
    namespace: str
    key: str
    value_preview: str = ""
    operation: str = "write"
    source_trust: str = "trusted"
    status: Literal["proposed", "quarantined", "committed", "rejected", "rolled_back"] = "proposed"
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ActionCriticReview(BaseModel):
    model_config = ConfigDict(extra="allow")

    review_id: str = Field(default_factory=lambda: new_id("crit"))
    trace_id: str
    event_id: str
    reviewer: str
    verdict: Literal["pass", "warn", "fail"]
    confidence: float = Field(ge=0, le=1)
    reasons: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    degraded: bool = False
    created_at: str = Field(default_factory=utc_now_iso)


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


def evaluate_config_audit(event: ConfigAuditEvent) -> ConfigAuditResult:
    blocking = [finding for finding in event.findings if finding.severity in {"high", "critical"}]
    if blocking:
        return ConfigAuditResult(
            decision="block",
            findings=event.findings,
            reason="Configuration audit found high or critical risk findings.",
        )
    return ConfigAuditResult(
        decision="allow",
        findings=event.findings,
        reason="Configuration audit did not find blocking findings.",
    )
