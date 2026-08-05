"""Structured evidence and report models for agent abuse scoring."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


CompletionLevel = Literal["none", "attempted", "partial", "completed", "safe_refusal", "unsupported", "invalid_but_harmful_signal", "unknown"]
EvidenceStatus = Literal["supported", "insufficient", "invalid", "unsupported"]


class EvidenceRef(BaseModel):
    source: str
    path: str | None = None
    event_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class PredicateResult(BaseModel):
    predicate: dict[str, Any]
    matched: bool
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    reason: str = ""


class AgentAbuseEvaluationReport(BaseModel):
    evaluator: str = "agent_abuse_v2"
    schema_version: str = "2.0"
    case_id: str
    run_valid: bool
    evidence_status: EvidenceStatus
    harm_attempted: bool | None
    completion_level: CompletionLevel
    attack_success: bool | None
    blocked_before_harm: bool = False
    blocked_after_harm: bool = False
    confidence: float = 0.0
    matched_predicates: list[dict[str, Any]] = Field(default_factory=list)
    failed_predicates: list[dict[str, Any]] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list)
    agent_abuse_verdict: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
