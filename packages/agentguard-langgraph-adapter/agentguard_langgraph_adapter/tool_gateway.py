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

        if decision.decision == "deny" or _ask_was_not_approved(
            self.guard_adapter, decision
        ):
            result = blocked_result(
                tool_name=tool_name,
                call_id=call_id,
                event=event,
                decision=decision,
                audit_event=audit_event,
            )
            return ToolExecutionResult.model_validate(
                tool_result_with_compatibility(
                    result.model_dump(),
                    compatibility or _compatibility_from_event(event),
                )
            )

        memory_gate = _evaluate_memory_write_gate(
            self.guard_adapter,
            tool_name=tool_name,
            arguments=arguments,
            security=security_for_event,
            trace_id=trace_id,
            call_id=call_id,
            compatibility=compatibility or _compatibility_from_event(event),
        )
        if memory_gate is not None:
            return memory_gate

        before = (
            self.tool_runtime.snapshot()
            if hasattr(self.tool_runtime, "snapshot")
            else None
        )
        try:
            result = self.tool_runtime.invoke(tool_name, arguments)
            side_effects = (
                self.tool_runtime.diff(before)
                if before is not None and hasattr(self.tool_runtime, "diff")
                else []
            )
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
            payload = _apply_tool_result_guard(
                self.guard_adapter,
                payload=payload,
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                side_effects=side_effects,
                security=security_for_event,
                trace_id=trace_id,
                call_id=call_id,
            )
            return ToolExecutionResult.model_validate(
                tool_result_with_compatibility(
                    payload.model_dump(),
                    compatibility or _compatibility_from_event(event),
                )
            )
        except Exception as exc:
            side_effects = (
                self.tool_runtime.diff(before)
                if before is not None and hasattr(self.tool_runtime, "diff")
                else []
            )
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
                tool_result_with_compatibility(
                    payload.model_dump(),
                    compatibility or _compatibility_from_event(event),
                )
            )


def _compatibility_from_event(event: Any) -> dict[str, Any]:
    metadata = getattr(event, "metadata", None)
    if isinstance(metadata, dict) and isinstance(metadata.get("compatibility"), dict):
        return dict(metadata["compatibility"])
    if hasattr(event, "model_dump"):
        dumped = event.model_dump()
        metadata = dumped.get("metadata") if isinstance(dumped, dict) else {}
        if isinstance(metadata, dict) and isinstance(
            metadata.get("compatibility"), dict
        ):
            return dict(metadata["compatibility"])
        if isinstance(dumped, dict) and isinstance(dumped.get("compatibility"), dict):
            return dict(dumped["compatibility"])
    return {}


def _evaluate_memory_write_gate(
    guard_adapter: Any,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    security: dict[str, Any],
    trace_id: str,
    call_id: str,
    compatibility: dict[str, Any],
) -> ToolExecutionResult | None:
    if tool_name != "memory_write" or not hasattr(
        guard_adapter, "evaluate_memory_write"
    ):
        return None
    event, decision = guard_adapter.evaluate_memory_write(
        arguments=arguments,
        security=security,
        trace_id=trace_id,
    )
    audit_event = guard_adapter.build_audit_event(event, decision)
    guard_adapter.submit_audit_event(audit_event)
    if decision.decision != "deny" and not _ask_was_not_approved(
        guard_adapter, decision
    ):
        return None
    payload = ToolExecutionResult(
        tool_name=tool_name,
        call_id=call_id,
        executed=False,
        blocked=True,
        decision=decision.decision,
        status="blocked",
        result=None,
        safe_message=decision.safe_message
        or "The memory write was blocked by AgentGuard.",
        side_effects=[],
        event=_dump_event(event),
        audit_event=audit_event.model_dump(),
        block_semantics=_block_semantics(decision),
        counts_as_effective_block=decision.decision == "deny",
    )
    return ToolExecutionResult.model_validate(
        tool_result_with_compatibility(payload.model_dump(), compatibility)
    )


def _apply_tool_result_guard(
    guard_adapter: Any,
    *,
    payload: ToolExecutionResult,
    tool_name: str,
    arguments: dict[str, Any],
    result: Any,
    side_effects: list[dict[str, Any]],
    security: dict[str, Any],
    trace_id: str,
    call_id: str,
) -> ToolExecutionResult:
    if not hasattr(guard_adapter, "evaluate_tool_result"):
        return payload
    event, decision = guard_adapter.evaluate_tool_result(
        tool_name=tool_name,
        arguments=arguments,
        result=result,
        security=security,
        trace_id=trace_id,
        call_id=call_id,
        will_enter_context=True,
        will_persist=_tool_result_will_persist(tool_name, side_effects),
    )
    audit_event = guard_adapter.build_audit_event(event, decision)
    guard_adapter.submit_audit_event(audit_event)
    if decision.decision != "deny" and not _ask_was_not_approved(
        guard_adapter, decision
    ):
        return payload
    payload.blocked = True
    payload.decision = decision.decision
    payload.status = "quarantined"
    payload.result = None
    payload.safe_message = (
        decision.safe_message
        or "The tool result was quarantined by AgentGuard before entering context."
    )
    payload.event = _dump_event(event)
    payload.audit_event = audit_event.model_dump()
    payload.quarantine_applied = True
    payload.counts_as_effective_block = decision.decision == "deny"
    payload.block_semantics = _block_semantics(decision)
    return payload


def _tool_result_will_persist(
    tool_name: str, side_effects: list[dict[str, Any]]
) -> bool:
    if tool_name in {"memory_write", "rag_answer"}:
        return True
    for effect in side_effects:
        text = " ".join(str(value).lower() for value in effect.values())
        if "persist" in text or "memory" in text:
            return True
    return False


def _dump_event(event: Any) -> dict[str, Any]:
    if isinstance(event, dict):
        return event
    if hasattr(event, "model_dump"):
        dumped = event.model_dump()
        return dumped if isinstance(dumped, dict) else {}
    return {}


def _block_semantics(decision: Any) -> str:
    return (
        "policy_deny"
        if getattr(decision, "decision", None) == "deny"
        else "approval_block"
    )


def _ask_was_not_approved(guard_adapter: Any, decision: Any) -> bool:
    if getattr(decision, "decision", None) != "ask":
        return False
    approval_id = _approval_id(getattr(decision, "approval", None))
    if not approval_id or not hasattr(guard_adapter, "wait_for_approval"):
        return True
    resolution = guard_adapter.wait_for_approval(approval_id)
    if not isinstance(resolution, dict) or resolution.get("status") != "resolved":
        return True
    return str(resolution.get("decision") or "").lower() not in {
        "allow",
        "allow_once",
        "allow_session",
    }


def _approval_id(approval: Any) -> str | None:
    if isinstance(approval, dict):
        value = approval.get("approval_id") or approval.get("id")
        return str(value) if value else None
    return None
