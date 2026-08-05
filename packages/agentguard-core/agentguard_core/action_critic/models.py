"""Action Critic domain models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..ids import new_id, utc_now_iso


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
