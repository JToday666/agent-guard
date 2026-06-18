"""Demo agent lifecycle event models and helpers."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from ..adapter.event_models import AttackType, new_id, utc_now_iso


LifecycleEventType = Literal[
    "user_input_received",
    "context_assembled",
    "model_input_prepared",
    "model_output_produced",
    "tool_call_proposed",
    "policy_decided",
    "tool_call_finished",
    "tool_result_persisted",
    "memory_read",
    "memory_write",
    "reply_prepared",
    "message_sending",
    "turn_finished",
]


class AgentLifecycleEvent(BaseModel):
    schema_version: str = "0.3"
    event_id: str = Field(default_factory=lambda: new_id("evt_lifecycle"))
    event_type: LifecycleEventType
    runtime: str = "langgraph"
    trace_id: str
    case_id: str | None = None
    attack_type: AttackType | None = None
    is_malicious: bool | None = None
    timestamp: str = Field(default_factory=utc_now_iso)
    stage: str
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)

