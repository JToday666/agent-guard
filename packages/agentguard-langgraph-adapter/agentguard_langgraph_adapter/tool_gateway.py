"""Generic guarded tool gateway for LangGraph-style tool runtimes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .event_models import ToolExecutionResult, new_id
from .langgraph_adapter import blocked_result
from .tool_compat import tool_result_with_compatibility


@dataclass(slots=True)
class GuardedToolGateway:
    guard_adapter: Any
    tool_runtime: Any

    def invoke_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        raw_arguments: dict[str, Any] | None = None,
        compatibility: dict[str, Any] | None = None,
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
        case_context: dict[str, Any] | None = None,
    ) -> ToolExecutionResult:
        call_id = call_id or new_id("call")
        security_for_event = dict(security)
        if raw_arguments is not None or compatibility is not None:
            metadata = dict(security_for_event.get("metadata") or {})
            metadata["compatibility"] = {
                "raw_arguments": dict(raw_arguments or {}),
                "normalized_arguments": dict(arguments),
                **dict(compatibility or {}),
            }
            security_for_event["metadata"] = metadata
        event, decision = self.guard_adapter.evaluate_before_tool(
            tool_name=tool_name,
            arguments=arguments,
            security=security_for_event,
            trace_id=trace_id,
            call_id=call_id,
        )
        audit_event = self.guard_adapter.build_audit_event(event, decision)
        if compatibility is not None:
            event.metadata["compatibility"] = dict(compatibility)
            audit_event.metadata["compatibility"] = dict(compatibility)
        self.guard_adapter.submit_audit_event(audit_event)

        if decision.decision in {"deny", "ask"}:
            result = blocked_result(
                tool_name=tool_name,
                call_id=call_id,
                event=event,
                decision=decision,
                audit_event=audit_event,
            )
            return ToolExecutionResult.model_validate(
                tool_result_with_compatibility(result.model_dump(), compatibility or _compatibility_from_event(event))
            )

        before = self.tool_runtime.snapshot() if hasattr(self.tool_runtime, "snapshot") else None
        try:
            result = self.tool_runtime.invoke(tool_name, arguments)
            side_effects = self.tool_runtime.diff(before) if before is not None and hasattr(self.tool_runtime, "diff") else []
            payload = ToolExecutionResult(
                tool_name=tool_name,
                call_id=call_id,
                executed=True,
                blocked=False,
                decision=decision.decision,
                status="executed",
                result=result,
                safe_message=None,
                side_effects=side_effects,
                event=event.model_dump(),
                audit_event=audit_event.model_dump(),
            )
            return ToolExecutionResult.model_validate(
                tool_result_with_compatibility(payload.model_dump(), compatibility or _compatibility_from_event(event))
            )
        except Exception as exc:
            side_effects = self.tool_runtime.diff(before) if before is not None and hasattr(self.tool_runtime, "diff") else []
            payload = ToolExecutionResult(
                tool_name=tool_name,
                call_id=call_id,
                executed=False,
                blocked=False,
                decision=decision.decision,
                status="error",
                result=None,
                safe_message=None,
                side_effects=side_effects,
                event=event.model_dump(),
                audit_event=audit_event.model_dump(),
                error=str(exc),
            )
            return ToolExecutionResult.model_validate(
                tool_result_with_compatibility(payload.model_dump(), compatibility or _compatibility_from_event(event))
            )


def _compatibility_from_event(event: Any) -> dict[str, Any]:
    metadata = getattr(event, "metadata", None)
    if isinstance(metadata, dict) and isinstance(metadata.get("compatibility"), dict):
        return dict(metadata["compatibility"])
    if hasattr(event, "model_dump"):
        dumped = event.model_dump()
        metadata = dumped.get("metadata") if isinstance(dumped, dict) else {}
        if isinstance(metadata, dict) and isinstance(metadata.get("compatibility"), dict):
            return dict(metadata["compatibility"])
        if isinstance(dumped, dict) and isinstance(dumped.get("compatibility"), dict):
            return dict(dumped["compatibility"])
    return {}
