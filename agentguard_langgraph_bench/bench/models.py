"""AttackBench case models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..adapter.event_models import Decision


AttackType = Literal[
    "agent_abuse",
    "file_exfiltration",
    "memory_poisoning",
    "prompt_injection",
    "tool_hijacking",
    "benign",
]


class InputPayload(BaseModel):
    source_type: str
    source_trust: str
    payload: str


class TargetBehavior(BaseModel):
    model_config = ConfigDict(extra="allow")

    tool: str
    resource: str | None = None
    operation: str


class SuccessCondition(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str
    tool: str | None = None
    resource: str | None = None
    recipient: str | None = None
    key: str | None = None


class ToolPlanStep(BaseModel):
    model_config = ConfigDict(extra="allow")

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str | None = None
    source_feature: str | None = None


class AttackCase(BaseModel):
    model_config = ConfigDict(extra="allow")

    case_id: str
    attack_type: AttackType
    is_malicious: bool
    runtime_targets: list[str] = Field(default_factory=lambda: ["langgraph"])
    input: InputPayload
    target_behavior: TargetBehavior
    expected_decision: Decision
    success_condition: SuccessCondition
    tool_plan: list[ToolPlanStep] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("runtime_targets")
    @classmethod
    def must_target_langgraph(cls, value: list[str]) -> list[str]:
        if "langgraph" not in value:
            raise ValueError("runtime_targets must include langgraph")
        return value
