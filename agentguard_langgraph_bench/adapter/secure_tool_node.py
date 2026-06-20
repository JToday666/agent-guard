"""Non-invasive guarded tool node for LangGraph or direct runner use."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .event_models import ToolExecutionResult, new_id
from .langgraph_adapter import LangGraphAdapter


BROWSER_SESSION_TOOLS = {
    "browser_navigate",
    "browser_extract_text",
    "browser_input",
    "browser_click",
    "browser_inspect",
}


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
        state_events = list(state.get("behavior_events") or [])
        runtime_context = dict(state.get("runtime_context") or {})
        results = []
        latest_rag_retrievals: dict[tuple[str, str], dict[str, Any]] = {}
        blocked_rag_retrievals: set[tuple[str, str]] = set()
        for call in calls:
            tool_name = call["name"]
            arguments = dict(call.get("args") or {})
            arguments = _bind_runtime_arguments(state, runtime_context, tool_name, arguments)
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
            event_state = {**state, "behavior_events": state_events}
            state_events = _append_tool_lifecycle_events(event_state, result.model_dump(), len(previous_results) + len(results))
            _update_runtime_context(runtime_context, tool_name, result)
            if tool_name == "rag_retrieve":
                key = _rag_key(arguments)
                if result.blocked or result.status != "executed":
                    blocked_rag_retrievals.add(key)
                elif isinstance(result.result, dict):
                    latest_rag_retrievals[key] = result.result
        stop_reason = state.get("stop_reason") or ""
        if any(item.get("blocked") for item in results):
            stop_reason = "blocked"
        return {
            **state,
            "trace_id": trace_id,
            "tool_results": previous_results + results,
            "last_tool_results": results,
            "tool_calls": [],
            "runtime_context": runtime_context,
            "behavior_events": state_events,
            "stop_reason": stop_reason,
        }


def _bind_runtime_arguments(
    state: dict[str, Any],
    runtime_context: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    if tool_name not in BROWSER_SESSION_TOOLS:
        return arguments
    session_id = str(arguments.get("session_id") or "").strip()
    if session_id and session_id != "default":
        return arguments
    bound = _current_case_browser_session(state, runtime_context)
    if not bound:
        raise RuntimeError("browser session is not initialized for this case")
    enriched = dict(arguments)
    enriched["session_id"] = bound
    return enriched


def _current_case_browser_session(state: dict[str, Any], runtime_context: dict[str, Any]) -> str:
    candidate = str(runtime_context.get("browser_session_id") or "").strip()
    if candidate and candidate != "default":
        return candidate
    security = state.get("security") or {}
    case_id = str(security.get("case_id") or "").strip()
    if case_id:
        return case_id
    attack_case = state.get("attack_case") or {}
    if isinstance(attack_case, dict):
        case_id = str(attack_case.get("case_id") or "").strip()
        if case_id:
            return case_id
    return ""


def _update_runtime_context(runtime_context: dict[str, Any], tool_name: str, result: ToolExecutionResult) -> None:
    if result.status != "executed" or not isinstance(result.result, dict):
        return
    payload = result.result
    if tool_name == "browser_start" and payload.get("session_id"):
        runtime_context["browser_session_id"] = payload["session_id"]
        if payload.get("url"):
            runtime_context["browser_url"] = payload["url"]
        if payload.get("source_path"):
            runtime_context["browser_source_path"] = payload["source_path"]
    elif tool_name == "browser_navigate" and payload.get("url"):
        runtime_context["browser_url"] = payload["url"]


def _append_tool_lifecycle_events(state: dict[str, Any], item: dict[str, Any], sequence_index: int) -> list[dict[str, Any]]:
    events = list(state.get("behavior_events") or [])
    event = item.get("event") or {}
    audit_event = item.get("audit_event") or {}
    tool_name = item.get("tool_name")
    call_id = item.get("call_id")
    base_metadata = {
        "tool_name": tool_name,
        "call_id": call_id,
        "executed": item.get("executed"),
        "blocked": item.get("blocked"),
        "status": item.get("status"),
        "round_index": state.get("round_index"),
        "sequence_index": sequence_index,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
    }
    events.append(
        _lifecycle_event(
            state,
            "tool_call_proposed",
            "before_tool_call",
            f"Tool call proposed: {tool_name}.",
            {**base_metadata, "arguments": event.get("arguments"), "derived_resources": event.get("derived_resources", [])},
        )
    )
    events.append(
        _lifecycle_event(
            state,
            "policy_decided",
            "before_tool_call",
            f"Policy decision for {tool_name}: {item.get('decision')}.",
            {
                **base_metadata,
                "decision": item.get("decision"),
                "risk_score": audit_event.get("risk_score"),
                "severity": audit_event.get("severity"),
                "reason": audit_event.get("reason"),
            },
        )
    )
    events.append(
        _lifecycle_event(
            state,
            "tool_call_finished",
            "after_tool_call",
            f"Tool call finished: {tool_name}.",
            {
                **base_metadata,
                "result_summary": _summarize_result(item.get("result")),
                "error": item.get("error"),
                "side_effect_count": len(item.get("side_effects") or []),
            },
        )
    )
    if item.get("side_effects"):
        events.append(
            _lifecycle_event(
                state,
                "tool_result_persisted",
                "after_tool_call",
                f"Tool result side effects recorded for {tool_name}.",
                {**base_metadata, "side_effects": item.get("side_effects")},
            )
        )
    if tool_name == "memory_write":
        events.append(
            _lifecycle_event(
                state,
                "memory_write",
                "after_tool_call",
                "Memory write behavior observed.",
                {**base_metadata, "result_summary": _summarize_result(item.get("result"))},
            )
        )
    return events


def _lifecycle_event(
    state: dict[str, Any],
    event_type: str,
    stage: str,
    summary: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    security = state.get("security") or {}
    return {
        "schema_version": "0.3",
        "event_id": new_id("evt_lifecycle"),
        "event_type": event_type,
        "trace_id": state.get("trace_id") or security.get("trace_id") or new_id("trace"),
        "runtime": security.get("runtime") or "langgraph",
        "case_id": security.get("case_id"),
        "attack_type": security.get("attack_type"),
        "is_malicious": security.get("is_malicious"),
        "stage": stage,
        "summary": summary,
        "metadata": metadata or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _summarize_result(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, str):
        return result[:240]
    try:
        return json.dumps(result, ensure_ascii=False, sort_keys=True)[:240]
    except Exception:
        return repr(result)[:240]


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
