"""GuardEvent model and raw payload contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..ids import new_id, utc_now_iso
from .payloads import (
    ContextBuildPayload,
    GuardEventType,
    GuardPayload,
    MemoryEventPayload,
    MessageSendPayload,
    ModelCallPayload,
    SecurityContext,
    ToolCallPayload,
    ToolResultPayload,
)

_EVENT_PAYLOAD_CONTRACT: dict[GuardEventType, type[BaseModel]] = {
    "tool_call_proposed": ToolCallPayload,
    "context_assembled": ContextBuildPayload,
    "model_input_prepared": ModelCallPayload,
    "model_output_produced": ModelCallPayload,
    "tool_result_produced": ToolResultPayload,
    "memory_write_proposed": MemoryEventPayload,
    "message_send_proposed": MessageSendPayload,
}

_MODEL_EVENT_PHASE_CONTRACT: dict[GuardEventType, Literal["input", "output"]] = {
    "model_input_prepared": "input",
    "model_output_produced": "output",
}

# These callbacks describe observations after the represented execution/model
# boundary. Runtime producers may omit ``pre_execution`` for compatibility, in
# which case the server-owned event contract supplies False. An explicit True
# is contradictory and must be rejected before policy or approval side effects.
_POST_EXECUTION_EVENT_TYPES: frozenset[GuardEventType] = frozenset(
    {"model_output_produced", "tool_result_produced"}
)


@dataclass(frozen=True, slots=True)
class RawPayloadContract:
    payload_required_fields: tuple[str, ...]
    nested_required_fields: Mapping[str, tuple[str, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )


_RAW_PAYLOAD_CONTRACTS: Mapping[str, RawPayloadContract] = MappingProxyType(
    {
        "tool_call_proposed": RawPayloadContract(
            payload_required_fields=("tool", "arguments", "derived_resources"),
            nested_required_fields=MappingProxyType({"tool": ("name",)}),
        ),
        "context_assembled": RawPayloadContract(
            payload_required_fields=("sources", "will_enter_context", "sanitized"),
            nested_required_fields=MappingProxyType(
                {
                    "sources[]": (
                        "source_id",
                        "source_type",
                        "source_trust",
                        "summary",
                        "contains_instruction_like_text",
                        "contains_sensitive_data",
                    )
                }
            ),
        ),
        "model_input_prepared": RawPayloadContract(
            payload_required_fields=(
                "phase",
                "content_preview",
                "contains_instruction_like_text",
                "contains_sensitive_data",
                "sanitized",
            ),
        ),
        "model_output_produced": RawPayloadContract(
            payload_required_fields=(
                "phase",
                "content_preview",
                "contains_instruction_like_text",
                "contains_sensitive_data",
                "sanitized",
            ),
        ),
        "tool_result_produced": RawPayloadContract(
            payload_required_fields=(
                "tool",
                "result",
                "will_enter_context",
                "will_persist",
                "sanitized",
                "contains_sensitive_data",
                "contains_instruction_like_text",
            ),
            nested_required_fields=MappingProxyType(
                {
                    "tool": ("name", "call_id"),
                    "result": ("content_preview", "content_type", "size_bytes"),
                }
            ),
        ),
        "memory_write_proposed": RawPayloadContract(
            payload_required_fields=("memory", "will_persist", "requires_approval"),
            nested_required_fields=MappingProxyType(
                {
                    "memory": (
                        "namespace",
                        "key",
                        "value_preview",
                        "source_trust",
                        "operation",
                    )
                }
            ),
        ),
        "message_send_proposed": RawPayloadContract(
            payload_required_fields=("channel", "recipient", "content_preview"),
        ),
    }
)


def guard_event_raw_payload_contracts() -> Mapping[str, RawPayloadContract]:
    return _RAW_PAYLOAD_CONTRACTS


def _missing_required_fields(
    data: dict[str, Any], required_fields: tuple[str, ...]
) -> list[str]:
    return [field for field in required_fields if field not in data]


def _raise_missing_raw_payload_fields(
    event_type: str, path: str, missing: list[str]
) -> None:
    fields = ", ".join(missing)
    location = f"payload.{path}" if path else "payload"
    raise ValueError(
        f"event_type={event_type} {location} missing required field(s): {fields}"
    )


def _validate_nested_raw_payload_contract(
    event_type: str,
    payload: dict[str, Any],
    contract: RawPayloadContract,
) -> None:
    for path, required_fields in contract.nested_required_fields.items():
        if path.endswith("[]"):
            key = path.removesuffix("[]")
            value = payload.get(key)
            if not isinstance(value, list):
                continue
            for index, item in enumerate(value):
                if not isinstance(item, dict):
                    continue
                missing = _missing_required_fields(item, required_fields)
                if missing:
                    _raise_missing_raw_payload_fields(
                        event_type, f"{key}[{index}]", missing
                    )
            continue

        value = payload.get(path)
        if not isinstance(value, dict):
            continue
        missing = _missing_required_fields(value, required_fields)
        if missing:
            _raise_missing_raw_payload_fields(event_type, path, missing)


class GuardEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: Literal["0.3"] = "0.3"
    event_id: str = Field(default_factory=lambda: new_id("evt"))
    event_type: GuardEventType = "tool_call_proposed"
    runtime: str = "langgraph"
    trace_id: str
    case_id: str | None = None
    attack_type: str | None = None
    is_malicious: bool | None = None
    timestamp: str = Field(default_factory=utc_now_iso)
    pre_execution: bool = True
    security_context: SecurityContext = Field(default_factory=SecurityContext)
    payload: GuardPayload
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def validate_raw_payload_contract(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        event_type = data.get("event_type", "tool_call_proposed")
        if event_type in _POST_EXECUTION_EVENT_TYPES:
            if data.get("pre_execution") is True:
                raise ValueError(
                    f"event_type={event_type} cannot be marked pre_execution"
                )
            if "pre_execution" not in data:
                data = {**data, "pre_execution": False}
        payload = data.get("payload")
        if not isinstance(payload, dict):
            return data

        event_type_value = str(event_type)
        contract = _RAW_PAYLOAD_CONTRACTS.get(event_type_value)
        if contract is None:
            return data
        missing = _missing_required_fields(payload, contract.payload_required_fields)
        if missing:
            _raise_missing_raw_payload_fields(event_type_value, "", missing)
        _validate_nested_raw_payload_contract(event_type_value, payload, contract)

        return data

    @model_validator(mode="after")
    def validate_event_payload_contract(self) -> GuardEvent:
        if self.event_type in _POST_EXECUTION_EVENT_TYPES and self.pre_execution:
            raise ValueError(
                f"event_type={self.event_type} cannot be marked pre_execution"
            )
        expected_payload = _EVENT_PAYLOAD_CONTRACT[self.event_type]
        if not isinstance(self.payload, expected_payload):
            raise ValueError(
                f"event_type={self.event_type} requires payload={expected_payload.__name__}"
            )

        expected_phase = _MODEL_EVENT_PHASE_CONTRACT.get(self.event_type)
        if expected_phase is not None:
            payload = self.payload
            if (
                not isinstance(payload, ModelCallPayload)
                or payload.phase != expected_phase
            ):
                raise ValueError(
                    f"event_type={self.event_type} requires ModelCallPayload phase={expected_phase}"
                )

        return self
