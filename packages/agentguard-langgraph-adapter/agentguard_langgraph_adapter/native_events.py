"""Complete, bounded event projections for the native Product consumer.

The frozen wire calls its policy text fields ``preview``. Native evaluation
places the complete protected projection there; only audit writers may redact.
Legacy adapter builders deliberately retain their compatibility behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, TYPE_CHECKING, Literal

from .context_guard import source_content
from .event_models import (
    AuditEvent,
    DerivedResource,
    PolicyDecision,
    RuntimeGuardEvent,
    SecurityContext,
    ToolCallEvent,
    ToolDescriptor,
    utc_now_iso,
)
from .langgraph_adapter import (
    _contains_instruction_like_text,
    _contains_sensitive_text,
)
from .runtime_receipts import build_runtime_outcome

if TYPE_CHECKING:
    from .langgraph_adapter import LangGraphAdapter
    from .native_tools import PreparedNativeToolCall

MAX_NATIVE_CONTENT_BYTES = 64 * 1024
MAX_NATIVE_EVENT_BYTES = 128 * 1024


class NativeBoundaryError(ValueError):
    """A fixed diagnostic, never a representation of model or tool content."""


def _native_identifier(value: object) -> bool:
    return (
        type(value) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", value) is not None
    )


@dataclass(frozen=True, slots=True, repr=False)
class NativeModelOrigin:
    """Correlate an action with its actual, fully receipted model output.

    This carrier never grants authority. The API verifies the original policy,
    full arguments, scope and accepted receipts independently.
    """

    model_output_audit_id: str
    model_source_ref: str
    call_id: str

    def __post_init__(self) -> None:
        self.to_mapping()

    def __repr__(self) -> str:
        return "NativeModelOrigin(<redacted>)"

    def to_mapping(self) -> dict[str, str]:
        if (
            not _native_identifier(self.model_output_audit_id)
            or not _native_identifier(self.call_id)
            or type(self.model_source_ref) is not str
            or not self.model_source_ref.startswith("source:model:")
            or not _native_identifier(self.model_source_ref[len("source:model:") :])
        ):
            raise NativeBoundaryError("native_model_origin_invalid")
        return {
            "model_output_audit_id": self.model_output_audit_id,
            "model_source_ref": self.model_source_ref,
            "call_id": self.call_id,
        }


def _action_origin(
    prepared: PreparedNativeToolCall,
    security: dict[str, Any],
    origin: NativeModelOrigin,
) -> dict[str, str]:
    if type(origin) is not NativeModelOrigin:
        raise NativeBoundaryError("native_model_origin_invalid")
    value = origin.to_mapping()
    refs = security.get("visible_source_refs")
    if (
        value["call_id"] != prepared.call_id
        or security.get("source_type") != "model"
        or security.get("source_trust") != "unknown"
        or type(refs) is not list
        or any(type(ref) is not str for ref in refs)
        or len(refs) != len(set(refs))
        or value["model_source_ref"] not in refs
    ):
        raise NativeBoundaryError("native_model_origin_mismatch")
    return value


def native_json(value: Any, *, limit: int = MAX_NATIVE_EVENT_BYTES) -> str:
    """Snapshot the restricted JSON subset without invoking custom serializers."""

    def check(item: Any, depth: int) -> None:
        if depth > 32:
            raise NativeBoundaryError("native_content_invalid")
        if item is None or type(item) in (str, bool):
            return
        if type(item) is int and abs(item) <= 9007199254740991:
            return
        if type(item) is list:
            for child in item:
                check(child, depth + 1)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                check(child, depth + 1)
            return
        raise NativeBoundaryError("native_content_invalid")

    try:
        check(value, 0)
        wire = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        if len(wire.encode("utf-8")) > limit:
            raise NativeBoundaryError("native_content_too_large")
        return wire
    except NativeBoundaryError:
        raise
    except Exception:
        raise NativeBoundaryError("native_content_invalid") from None


def native_text(value: Any) -> str:
    text = (
        value
        if type(value) is str
        else native_json(value, limit=MAX_NATIVE_CONTENT_BYTES)
    )
    try:
        if len(text.encode("utf-8")) > MAX_NATIVE_CONTENT_BYTES:
            raise NativeBoundaryError("native_content_too_large")
        return text
    except UnicodeError:
        raise NativeBoundaryError("native_content_invalid") from None


def _bounded(event: Any) -> Any:
    native_json(event.model_dump(mode="json"))
    return event


class NativeGuardEventBuilder:
    def __init__(self, adapter: LangGraphAdapter) -> None:
        self.adapter = adapter

    def _context(
        self,
        security: dict[str, Any],
        step: str,
        resources: list[dict[str, Any]] | None = None,
    ) -> SecurityContext:
        frozen = json.loads(native_json(security))
        configured = self.adapter.config.agent_id
        if frozen.get("agent_id", configured) != configured:
            raise NativeBoundaryError("native_agent_identity_mismatch")
        frozen["agent_id"] = configured
        frozen["current_step"] = step
        frozen["derived_paths"] = [
            item["target"]
            for item in resources or []
            if item["resource_type"] == "file"
        ]
        try:
            return SecurityContext.model_validate(frozen)
        except Exception:
            raise NativeBoundaryError("native_security_context_invalid") from None

    def _event(
        self,
        event_type: Any,
        payload: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        *,
        resources: list[dict[str, Any]] | None = None,
        pre_execution: bool = True,
    ) -> RuntimeGuardEvent:
        metadata = {
            "adapter": "agentguard_langgraph_adapter",
            "hook": event_type,
            "native_full_content": True,
        }
        if isinstance(security.get("task_id"), str):
            metadata["task_id"] = security["task_id"]
        event = RuntimeGuardEvent(
            event_type=event_type,
            runtime="langgraph",
            trace_id=trace_id,
            security_context=self._context(security, event_type, resources),
            payload=payload,
            pre_execution=pre_execution,
            metadata=metadata,
        )
        # Core uses tool.call_id for tools, explicit action_id for memory, and
        # act_<event_id> for every other event (including model and message).
        if event_type not in {"tool_result_produced", "memory_write_proposed"}:
            event.payload["action_id"] = f"act_{event.event_id}"
        return _bounded(event)

    def build_context(
        self, sources: list[dict[str, Any]], security: dict[str, Any], trace_id: str
    ) -> RuntimeGuardEvent:
        snapshot = json.loads(native_json(sources))
        event = self.adapter.build_context_event(
            sources=snapshot, security=security, trace_id=trace_id
        )
        event.security_context = self._context(security, "context_assembled")
        for source, descriptor in zip(snapshot, event.payload["sources"]):
            # Full source text is sent only through the private policy request.
            descriptor["summary"] = native_text(source_content(source))
        # Context is a preparation checkpoint, not a separately invoked action.
        event.metadata["native_full_content"] = True
        return _bounded(event)

    def build_model(
        self,
        *,
        phase: Literal["input", "output"],
        content: Any,
        security: dict[str, Any],
        trace_id: str,
        provider: str,
        model: str,
        context_identity: dict[str, Any] | None = None,
        model_call_id: str | None = None,
        model_input_audit_id: str | None = None,
    ) -> RuntimeGuardEvent:
        if phase not in {"input", "output"} or (
            not _native_identifier(model_input_audit_id)
            if phase == "output"
            else model_input_audit_id is not None
        ):
            raise NativeBoundaryError("native_model_input_identity_invalid")
        identity = json.loads(
            native_json({} if context_identity is None else context_identity)
        )
        if type(identity) is not dict or not set(identity) <= {
            "context_plan_id",
            "context_plan_digest",
            "context_ref",
            "visible_source_refs",
        }:
            raise NativeBoundaryError("native_context_identity_invalid")
        text = native_text(content)
        payload = {
            "phase": phase,
            "content_preview": text,
            "provider": provider,
            "model": model,
            "contains_instruction_like_text": _contains_instruction_like_text(text),
            "contains_sensitive_data": _contains_sensitive_text(text),
            "sanitized": False,
            "tool_plan": [],
            **identity,
        }
        event = self._event(
            "model_input_prepared" if phase == "input" else "model_output_produced",
            payload,
            security,
            trace_id,
            pre_execution=phase == "input",
        )
        if model_call_id is not None:
            event.metadata["model_call_id"] = model_call_id
        if model_input_audit_id is not None:
            event.metadata["product_model_input_audit_id"] = model_input_audit_id
        return _bounded(event)

    def build_tool_call(
        self,
        prepared: PreparedNativeToolCall,
        security: dict[str, Any],
        trace_id: str,
        *,
        model_origin: NativeModelOrigin,
    ) -> ToolCallEvent:
        prepared.assert_current()
        security = json.loads(native_json(security))
        origin = _action_origin(prepared, security, model_origin)
        arguments, resources = prepared.arguments(), prepared.resources()
        native_json(arguments, limit=MAX_NATIVE_CONTENT_BYTES)
        event = ToolCallEvent(
            runtime="langgraph",
            trace_id=trace_id,
            tool=ToolDescriptor(
                name=prepared.name,
                category=prepared.category,
                kind=prepared.kind,
                call_id=prepared.call_id,
            ),
            arguments=arguments,
            derived_resources=[
                DerivedResource.model_validate(item) for item in resources
            ],
            security_context=self._context(security, "tool_call_proposed", resources),
            metadata={
                "adapter": "agentguard_langgraph_adapter",
                "hook": "tool_call_proposed",
                "native_full_content": True,
                "descriptor_digest": prepared.descriptor_digest,
                "product_model_content": origin,
                **(
                    {"task_id": security["task_id"]}
                    if isinstance(security.get("task_id"), str)
                    else {}
                ),
            },
        )
        return _bounded(event)

    def build_specialized_action(
        self,
        prepared: PreparedNativeToolCall,
        security: dict[str, Any],
        trace_id: str,
        *,
        model_origin: NativeModelOrigin,
    ) -> RuntimeGuardEvent | None:
        prepared.assert_current()
        security = json.loads(native_json(security))
        origin = _action_origin(prepared, security, model_origin)
        arguments, resources = prepared.arguments(), prepared.resources()
        if prepared.event_type == "memory_write_proposed":
            namespace, key = resources[0]["target"].rsplit("/", 1)
            if key != arguments["key"]:
                raise NativeBoundaryError("native_memory_identity_mismatch")
            payload = {
                "action_id": prepared.call_id,
                "memory": {
                    "namespace": namespace,
                    "key": key,
                    "value_preview": native_text(arguments["value"]),
                    "source_trust": security.get("source_trust", "untrusted"),
                    "operation": "write",
                },
                "will_persist": True,
                "requires_approval": security.get("source_trust", "untrusted")
                not in {"trusted", "user"},
            }
        elif prepared.event_type == "message_send_proposed":
            text = native_text(arguments["message"])
            payload = {
                "channel": arguments["channel"],
                "recipient": arguments["target"],
                "content_preview": text,
                "contains_sensitive_data": _contains_sensitive_text(text),
                "sanitized": False,
                "derived_resources": resources,
            }
        else:
            return None
        event = self._event(
            prepared.event_type, payload, security, trace_id, resources=resources
        )
        event.metadata["product_model_content"] = origin
        event.metadata["product_tool_call"] = {
            "tool_name": prepared.name,
            "call_id": prepared.call_id,
        }
        return _bounded(event)

    def build_tool_result(
        self,
        prepared: PreparedNativeToolCall,
        result: Any,
        security: dict[str, Any],
        trace_id: str,
    ) -> RuntimeGuardEvent:
        prepared.assert_current()
        text = native_text(result)
        resources = prepared.resources()
        return self._event(
            "tool_result_produced",
            {
                "tool": {
                    "name": prepared.name,
                    "category": prepared.category,
                    "kind": prepared.kind,
                    "call_id": prepared.call_id,
                },
                "result": {
                    "content_preview": text,
                    "content_type": (
                        "text/plain" if type(result) is str else "application/json"
                    ),
                    "size_bytes": len(text.encode("utf-8")),
                },
                "will_enter_context": True,
                "will_persist": False,
                "sanitized": False,
                "contains_sensitive_data": _contains_sensitive_text(text),
                "contains_instruction_like_text": _contains_instruction_like_text(text),
                "derived_resources": resources,
            },
            security,
            trace_id,
            resources=resources,
            pre_execution=False,
        )

    def build_action_start(
        self,
        event: Any,
        decision: PolicyDecision,
        *,
        start_kind: Literal["tool_call", "model_call"],
        approval_resolution: dict[str, Any] | None = None,
        enforcement: Any = None,
        lease_id: str | None = None,
        consumption_id: str | None = None,
        timestamp: str | None = None,
    ) -> AuditEvent:
        if start_kind not in {"tool_call", "model_call"}:
            raise NativeBoundaryError("native_start_kind_invalid")
        occurred = timestamp or utc_now_iso()
        # Use the existing strict link/ACK selection once, without asserting
        # that this temporary outcome or any invocation has taken place.
        anchor = build_runtime_outcome(
            event,
            decision,
            execution_status="not_invoked",
            approval_resolution=approval_resolution,
            completed_at=occurred,
            enforcement=enforcement,
            lease_id=lease_id,
            consumption_id=consumption_id,
        )
        evidence = anchor.evidence.model_dump(mode="json")
        evidence["execution"].update(
            status="unknown",
            receipt_recorded=False,
            invoked_at=None,
            completed_at=None,
            tool_result_entered_context=None,
            persisted=None,
        )
        evidence["side_effects"] = {
            "measurement_status": "unknown",
            "count": None,
            "summary": "Invocation has not begun.",
        }
        evidence["result"] = {
            "disposition": "unknown",
            "summary": None,
            "sanitized": None,
        }
        links = anchor.links.model_dump(mode="json")
        links["parent_audit_id"] = anchor.links.policy_audit_id
        receipt = AuditEvent(
            audit_id=f"audit_commit_{event.event_id}",
            record_type="runtime_observation",
            trace_id=event.trace_id,
            timestamp=occurred,
            stage=f"{start_kind}_committed",
            event_type=f"{start_kind}_committed",
            summary="Durable action intent before invocation.",
            reason="Invocation requires a recorded intent and a released local ticket.",
            links=links,
            resource_targets=anchor.resource_targets,
            metadata={
                "agent_id": anchor.metadata.agent_id,
                "observation_state": "action_intent",
            },
            evidence=evidence,
        )
        receipt._product_activation_ack = anchor.metadata.activation_ack
        return receipt
