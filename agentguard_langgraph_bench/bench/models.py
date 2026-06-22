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
    model_config = ConfigDict(extra="allow")

    source_type: str
    source_trust: str
    payload: str
    naturalistic_payload: str | None = None
    closure_payload: str | None = None


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


class ClosurePlanStep(BaseModel):
    model_config = ConfigDict(extra="allow")

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str | None = None
    source_feature: str | None = None
    expected_result: dict[str, Any] | None = None


class AttackCase(BaseModel):
    model_config = ConfigDict(extra="allow")

    case_id: str
    attack_type: AttackType
    is_malicious: bool
    runtime_targets: list[str] = Field(default_factory=lambda: ["any"])
    adapter_hints: dict[str, Any] = Field(default_factory=dict)
    input: InputPayload
    target_behavior: TargetBehavior
    expected_decision: Decision
    success_condition: SuccessCondition
    tool_plan: list[ToolPlanStep] = Field(default_factory=list)
    guided_success_plan: list[ClosurePlanStep] = Field(default_factory=list)
    closure_plan: list[ClosurePlanStep] = Field(default_factory=list)
    closure_spec: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("runtime_targets")
    @classmethod
    def normalize_runtime_targets(cls, value: list[str]) -> list[str]:
        cleaned = [str(item).strip().lower() for item in value if str(item).strip()]
        return cleaned or ["any"]


def supports_runtime(case: AttackCase, runtime: str) -> bool:
    targets = {str(item).strip().lower() for item in case.runtime_targets or ["any"]}
    return "any" in targets or str(runtime).strip().lower() in targets
