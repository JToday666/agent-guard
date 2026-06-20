"""Guarded gateway that all benchmark tool calls pass through."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentguard_langgraph_bench.adapter.event_models import ToolExecutionResult, new_id
from agentguard_langgraph_bench.adapter.langgraph_adapter import blocked_result


@dataclass(slots=True)
class GuardedToolGateway:
    guard_adapter: Any
    tool_runtime: Any

    def invoke_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ) -> ToolExecutionResult:
        call_id = call_id or new_id("call")
        event, decision = self.guard_adapter.evaluate_before_tool(
            tool_name=tool_name,
            arguments=arguments,
            security=security,
            trace_id=trace_id,
            call_id=call_id,
        )
        audit_event = self.guard_adapter.build_audit_event(event, decision)
        self.guard_adapter.submit_audit_event(audit_event)

        if decision.decision in {"deny", "ask"}:
            return blocked_result(
                tool_name=tool_name,
                call_id=call_id,
                event=event,
                decision=decision,
                audit_event=audit_event,
            )

        before = self.tool_runtime.snapshot()
        try:
            result = self.tool_runtime.invoke(tool_name, arguments)
            return ToolExecutionResult(
                tool_name=tool_name,
                call_id=call_id,
                executed=True,
                blocked=False,
                decision=decision.decision,
                status="executed",
                result=result,
                safe_message=None,
                side_effects=self.tool_runtime.diff(before),
                event=event.model_dump(),
                audit_event=audit_event.model_dump(),
            )
        except Exception as exc:
            return ToolExecutionResult(
                tool_name=tool_name,
                call_id=call_id,
                executed=False,
                blocked=False,
                decision=decision.decision,
                status="error",
                result=None,
                safe_message=None,
                side_effects=self.tool_runtime.diff(before),
                event=event.model_dump(),
                audit_event=audit_event.model_dump(),
                error=str(exc),
            )
