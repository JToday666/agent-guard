"""Non-invasive guarded tool node for LangGraph or direct runner use."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .event_models import ToolExecutionResult, new_id
from .langgraph_adapter import LangGraphAdapter


@dataclass(slots=True)
class SecureToolNode:
    gateway: Any

    def __init__(
        self,
        gateway: Any | None = None,
        *,
        adapter: LangGraphAdapter | None = None,
        tool_registry: Any | None = None,
    ) -> None:
        if gateway is None:
            if adapter is None or tool_registry is None:
                raise TypeError("SecureToolNode requires either gateway or adapter + tool_registry")
            from agentguard_langgraph_bench.bench.runtime.tool_gateway import GuardedToolGateway

            gateway = GuardedToolGateway(guard_adapter=adapter, tool_runtime=tool_registry)
        self.gateway = gateway

    def invoke_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ) -> ToolExecutionResult:
        return self.gateway.invoke_tool(
            tool_name=tool_name,
            arguments=arguments,
            security=security,
            trace_id=trace_id,
            call_id=call_id,
        )

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        security = dict(state.get("security") or {})
        trace_id = state.get("trace_id") or security.get("trace_id") or new_id("trace")
        calls = state.get("tool_calls") or []
        previous_results = list(state.get("tool_results") or [])
        results = []
        latest_rag_retrievals: dict[tuple[str, str], dict[str, Any]] = {}
        blocked_rag_retrievals: set[tuple[str, str]] = set()
        for call in calls:
            tool_name = call["name"]
            arguments = dict(call.get("args") or {})
            if tool_name == "rag_answer":
                key = _rag_key(arguments)
                if key in blocked_rag_retrievals:
                    results.append(_skipped_rag_answer(tool_name, call.get("id") or new_id("call")).model_dump())
                    continue
                arguments = _enrich_rag_answer_arguments(arguments, latest_rag_retrievals.get(key))
            result = self.invoke_tool(
                tool_name=tool_name,
                arguments=arguments,
                security=security,
                trace_id=trace_id,
                call_id=call.get("id"),
            )
            results.append(result.model_dump())
            if tool_name == "rag_retrieve":
                key = _rag_key(arguments)
                if result.blocked or result.status != "executed":
                    blocked_rag_retrievals.add(key)
                elif isinstance(result.result, dict):
                    latest_rag_retrievals[key] = result.result
        return {
            **state,
            "trace_id": trace_id,
            "tool_results": previous_results + results,
            "last_tool_results": results,
            "tool_calls": [],
        }


def _rag_key(arguments: dict[str, Any]) -> tuple[str, str]:
    return (str(arguments.get("dataset") or ""), str(arguments.get("question_id") or ""))


def _enrich_rag_answer_arguments(arguments: dict[str, Any], retrieval: dict[str, Any] | None) -> dict[str, Any]:
    if not retrieval:
        return arguments
    enriched = dict(arguments)
    if not enriched.get("contexts"):
        enriched["contexts"] = list(retrieval.get("contexts") or [])
    meta = retrieval.get("meta") if isinstance(retrieval.get("meta"), dict) else {}
    if "mode" not in enriched and meta.get("mode"):
        enriched["mode"] = meta["mode"]
    return enriched


def _skipped_rag_answer(tool_name: str, call_id: str) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_name=tool_name,
        call_id=call_id,
        executed=False,
        blocked=True,
        decision="deny",
        status="skipped_dependency",
        result=None,
        safe_message="rag_answer was skipped because rag_retrieve was blocked.",
        side_effects=[],
        event=None,
        audit_event=None,
        error=None,
    )


GuardedToolNode = SecureToolNode
