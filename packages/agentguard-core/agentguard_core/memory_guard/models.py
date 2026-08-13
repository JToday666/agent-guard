"""Memory Guard domain models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..ids import new_id, utc_now_iso


class MemoryGuardChange(BaseModel):
    # extra=forbid：身份绑定后拒绝未声明字段，避免旁路携带内容。
    model_config = ConfigDict(extra="forbid")

    change_id: str = Field(default_factory=lambda: new_id("memchg"))
    trace_id: str
    namespace: str
    key: str
    value_preview: str = ""
    operation: str = "write"
    # 默认 unknown：未声明来源信任级别的变更不得被隐式信任。
    source_trust: str = "unknown"
    # 提议方身份绑定；历史存量记录无绑定（None），生命周期处置由 API 层拒绝。
    runtime: str | None = None
    agent_id: str | None = None
    principal_id: str | None = None
    status: Literal[
        "proposed", "quarantined", "committed", "rejected", "rolled_back"
    ] = "proposed"
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)
