"""Generic Guard adapter for AgentGuard Core decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentguard_langgraph_bench.adapter.core_client import CoreClientProtocol
from agentguard_langgraph_bench.adapter.langgraph_adapter import LangGraphAdapter
from .config import GuardConfig


@dataclass(slots=True)
class GuardAdapter(LangGraphAdapter):
    config: GuardConfig
    core_client: CoreClientProtocol | None = None

    def build_tool_call_event(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ):
        event = LangGraphAdapter.build_tool_call_event(
            self,
            tool_name=tool_name,
            arguments=arguments,
            security=security,
            trace_id=trace_id,
            call_id=call_id,
        )
        event.security_context.agent_id = self.config.agent_id
        event.metadata["adapter"] = self.config.agent_id
        return event

__all__ = ["GuardAdapter"]
