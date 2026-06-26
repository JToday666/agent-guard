"""Configuration audit domain models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..ids import new_id, utc_now_iso

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
