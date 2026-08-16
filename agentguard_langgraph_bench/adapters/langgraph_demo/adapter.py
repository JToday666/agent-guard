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
        from agentguard_langgraph_bench.bench.runtime.termination import initialize_runtime_state

        state = initial_state_from_case(case)
        state = initialize_runtime_state(state, case, context.config)
        state["trace_id"] = context.trace_id
        state["security"] = dict(context.security)
        state["security"]["tool_hijacking_context"] = dict(context.tool_hijacking_context or {})
        state["behavior_events"] = [
            {**event, "trace_id": context.trace_id}
            for event in state.get("behavior_events", [])
            if isinstance(event, dict)
        ]
        runtime_adapter = _LangGraphRuntimeAdapter(
            config=context.config,
            guard_adapter=context.tool_gateway.guard_adapter,
        )
        graph = build_demo_graph(runtime_adapter, context.tool_runtime, tool_gateway=context.tool_gateway)
        invoke_config = {"recursion_limit": int(getattr(context.config, "langgraph_recursion_limit", 100) or 100)}
        final_state = graph.invoke(state, config=invoke_config) if hasattr(graph, "invoke") else graph(state)
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
            blocked=any(item.get("blocked") and not item.get("runtime_policy_blocked") for item in tool_results),
            executed=any(item.get("executed") for item in tool_results),
            raw_state={
                **dict(final_state),
                "instrumentation_plan_mode": getattr(context.config, "instrumentation_plan_mode", "guided"),
                "agent_visible_payload_mode": getattr(context.config, "agent_visible_payload_mode", "original"),
                "planning_source": _planning_source(final_state, case, context.config),
                "guided_plan_applied": _guided_plan_applied(final_state),
                "fallback_applied": _fallback_applied(final_state),
                "langgraph_graph_module": getattr(context.config, "langgraph_graph_module", "") or "agentguard_langgraph_bench.demo_agent.graph",
                "langgraph_graph_object": getattr(context.config, "langgraph_graph_object", "") or "build_demo_graph",
                "langgraph_recursion_limit": getattr(context.config, "langgraph_recursion_limit", None),
                "llm_planning_evidence": list(final_state.get("llm_planning_evidence") or []),
            },
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

    def evaluate_context(self, **kwargs: Any) -> Any:
        return self.guard_adapter.evaluate_context(**kwargs)

    def evaluate_model_input(self, **kwargs: Any) -> Any:
        return self.guard_adapter.evaluate_model_input(**kwargs)

    def evaluate_model_output(self, **kwargs: Any) -> Any:
        return self.guard_adapter.evaluate_model_output(**kwargs)

    def evaluate_tool_result(self, **kwargs: Any) -> Any:
        return self.guard_adapter.evaluate_tool_result(**kwargs)

    def evaluate_memory_write(self, **kwargs: Any) -> Any:
        return self.guard_adapter.evaluate_memory_write(**kwargs)

    def evaluate_message_send(self, **kwargs: Any) -> Any:
        return self.guard_adapter.evaluate_message_send(**kwargs)

    def build_tool_call_event(self, **kwargs: Any) -> Any:
        return self.guard_adapter.build_tool_call_event(**kwargs)

    def build_message_send_event(self, **kwargs: Any) -> Any:
        return self.guard_adapter.build_message_send_event(**kwargs)

    def build_audit_event(self, *args: Any, **kwargs: Any) -> Any:
        return self.guard_adapter.build_audit_event(*args, **kwargs)

    def submit_audit_event(self, *args: Any, **kwargs: Any) -> Any:
        return self.guard_adapter.submit_audit_event(*args, **kwargs)

    def wait_for_approval(self, *args: Any, **kwargs: Any) -> Any:
        return self.guard_adapter.wait_for_approval(*args, **kwargs)


def _final_answer_from_state(state: dict[str, Any]) -> str:
    if state.get("last_model_content"):
        return str(state["last_model_content"])
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
    if getattr(config, "instrumentation_plan_mode", "") == "replay":
        return "deterministic_replay"
    events = state.get("behavior_events") or []
    for event in reversed(events):
        metadata = event.get("metadata") if isinstance(event, dict) else {}
        planner = metadata.get("planner") if isinstance(metadata, dict) else None
        if planner:
            return str(planner)
    if (
        case.attack_type == "tool_hijacking"
        and getattr(config, "instrumentation_plan_mode", "") == "autonomous"
        and getattr(config, "llm_enabled", False)
    ):
        return "llm_autonomous"
    return "case_plan_fallback" if getattr(config, "llm_fallback_to_case_plan", False) else "attackcase_tool_plan"


def _guided_plan_applied(state: dict[str, Any]) -> bool:
    events = state.get("behavior_events") or []
    for event in events:
        metadata = event.get("metadata") if isinstance(event, dict) else {}
        if isinstance(metadata, dict) and metadata.get("guided_plan_applied"):
            return True
    return False


def _fallback_applied(state: dict[str, Any]) -> bool:
    events = state.get("behavior_events") or []
    for event in events:
        metadata = event.get("metadata") if isinstance(event, dict) else {}
        if isinstance(metadata, dict) and metadata.get("fallback_applied"):
            return True
    return False
