"""Adapter wrapper for the existing LangGraph demo agent."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentguard_langgraph_bench.bench.models import AttackCase
from agentguard_langgraph_bench.bench.runtime.agent_protocol import CaseContext, CaseRunResult


class LangGraphDemoAdapter:
    name = "langgraph-demo"
    runtime = "langgraph"

    def __init__(self, config: Any | None = None) -> None:
        self.config = config

    def setup(self, context: dict[str, Any]) -> None:
        return None

    def run_case(self, case: AttackCase, context: CaseContext) -> CaseRunResult:
        from agentguard_langgraph_bench.demo_agent.graph import build_demo_graph, initial_state_from_case

        state = initial_state_from_case(case)
        state["trace_id"] = context.trace_id
        state["security"] = dict(context.security)
        state["behavior_events"] = [
            {**event, "trace_id": context.trace_id}
            for event in state.get("behavior_events", [])
            if isinstance(event, dict)
        ]
        runtime_adapter = _LangGraphRuntimeAdapter(
            config=context.config,
            guard_adapter=context.tool_gateway.guard_adapter,
        )
        graph = build_demo_graph(runtime_adapter, context.tool_runtime)
        final_state = graph.invoke(state) if hasattr(graph, "invoke") else graph(state)
        tool_results = list(final_state.get("tool_results") or [])
        behavior_events = list(final_state.get("behavior_events") or [])
        return CaseRunResult(
            case_id=case.case_id,
            trace_id=final_state.get("trace_id") or context.trace_id,
            runtime=self.runtime,
            adapter_name=self.name,
            tool_calls=tool_results,
            behavior_events=behavior_events,
            final_answer=_final_answer_from_state(final_state),
            blocked=any(item.get("blocked") for item in tool_results),
            executed=any(item.get("executed") for item in tool_results),
            raw_state={**dict(final_state), "planning_source": _planning_source(final_state, case, context.config)},
        )

    def teardown(self) -> None:
        return None


def create_adapter(config: Any | None = None) -> LangGraphDemoAdapter:
    return LangGraphDemoAdapter(config)


@dataclass(slots=True)
class _LangGraphRuntimeAdapter:
    config: Any
    guard_adapter: Any

    def evaluate_before_tool(self, **kwargs: Any) -> Any:
        return self.guard_adapter.evaluate_before_tool(**kwargs)

    def build_tool_call_event(self, **kwargs: Any) -> Any:
        return self.guard_adapter.build_tool_call_event(**kwargs)

    def build_audit_event(self, *args: Any, **kwargs: Any) -> Any:
        return self.guard_adapter.build_audit_event(*args, **kwargs)

    def submit_audit_event(self, *args: Any, **kwargs: Any) -> Any:
        return self.guard_adapter.submit_audit_event(*args, **kwargs)


def _final_answer_from_state(state: dict[str, Any]) -> str:
    for item in reversed(state.get("tool_results") or []):
        result = item.get("result")
        if isinstance(result, dict):
            if result.get("answer"):
                return str(result["answer"])
            body = result.get("body")
            if isinstance(body, dict) and body.get("answer"):
                return str(body["answer"])
    return ""


def _planning_source(state: dict[str, Any], case: AttackCase, config: Any) -> str:
    if case.attack_type == "tool_hijacking" and getattr(config, "tool_hijacking_mode", "") in {"autonomous", "differential"}:
        return f"{getattr(config, 'tool_catalog_view', 'poisoned')}_tool_catalog"
    events = state.get("behavior_events") or []
    for event in reversed(events):
        metadata = event.get("metadata") if isinstance(event, dict) else {}
        planner = metadata.get("planner") if isinstance(metadata, dict) else None
        if planner:
            return str(planner)
    return "case_plan_fallback" if getattr(config, "llm_fallback_to_case_plan", False) else "attackcase_tool_plan"
