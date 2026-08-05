"""Memory Guard domain models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..ids import new_id, utc_now_iso


class MemoryGuardChange(BaseModel):
    model_config = ConfigDict(extra="allow")

    change_id: str = Field(default_factory=lambda: new_id("memchg"))
    trace_id: str
    namespace: str
    key: str
    value_preview: str = ""
    operation: str = "write"
    source_trust: str = "trusted"
    status: Literal[
        "proposed", "quarantined", "committed", "rejected", "rolled_back"
    ] = "proposed"
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)
