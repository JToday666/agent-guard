"""ToolCallEvent mapping helpers for the LangGraph adapter layer."""

from __future__ import annotations

from typing import Any

from .event_models import ToolCallEvent
from .langgraph_adapter import LangGraphAdapter


def build_tool_call_event(
    adapter: LangGraphAdapter,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    security: dict[str, Any],
    trace_id: str,
    call_id: str | None = None,
) -> ToolCallEvent:
    return adapter.build_tool_call_event(
        tool_name=tool_name,
        arguments=arguments,
        security=security,
        trace_id=trace_id,
        call_id=call_id,
    )


__all__ = ["build_tool_call_event"]
