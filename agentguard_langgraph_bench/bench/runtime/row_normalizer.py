"""Normalize adapter results into benchmark result rows."""

from __future__ import annotations

from typing import Any


def normalize_case_result(case: Any, result: Any, config: Any, tool_runtime: Any) -> dict[str, Any]:
    tool_results = list(result.tool_calls or [])
    decisions = [item.get("decision") for item in tool_results if item.get("decision")]
    side_effects = result.side_effects or [
        effect
        for item in tool_results
        for effect in item.get("side_effects", [])
    ]
    blocked = bool(result.blocked) or any(item.get("blocked") for item in tool_results)
    executed = bool(result.executed) or any(item.get("executed") for item in tool_results)
    behavior_events = list(result.behavior_events or [])
    raw_state = dict(result.raw_state or {})

    return {
        "case_id": case.case_id,
        "trace_id": result.trace_id,
        "runtime": result.runtime,
        "adapter_name": result.adapter_name,
        "attack_type": case.attack_type,
        "is_malicious": case.is_malicious,
        "case_schema_version": getattr(case, "case_schema_version", None),
        "scenario_id": case.metadata.get("scenario_id"),
        "phase": case.metadata.get("phase"),
        "scenario_order": case.metadata.get("scenario_order"),
        "metadata": case.metadata,
        "tool_hijacking_mode": config.tool_hijacking_mode if case.attack_type == "tool_hijacking" else None,
        "tool_catalog_view": config.tool_catalog_view if case.attack_type == "tool_hijacking" else None,
        "planning_source": raw_state.get("planning_source") or _planning_source_from_events(behavior_events, config),
        "defense_enabled": config.defense_enabled,
        "expected_decision": case.expected_decision,
        "tool_calls": tool_results,
        "behavior_events": behavior_events,
        "behavior_event_types": [item.get("event_type") for item in behavior_events],
        "browser_recordings": _collect_browser_recordings(case, tool_runtime),
        "decisions": decisions,
        "blocked": blocked,
        "executed": executed,
        "side_effects": side_effects,
        "final_answer": result.final_answer or _final_answer_from_tool_results(tool_results),
        "adapter_error": result.error,
        "raw_logs": list(result.raw_logs or []),
    }


def _planning_source_from_events(events: list[dict[str, Any]], config: Any) -> str:
    for event in reversed(events):
        metadata = event.get("metadata") if isinstance(event, dict) else {}
        planner = metadata.get("planner") if isinstance(metadata, dict) else None
        if planner:
            return str(planner)
    return "case_plan_fallback" if getattr(config, "llm_fallback_to_case_plan", False) else "attackcase_tool_plan"


def _final_answer_from_tool_results(tool_results: list[dict[str, Any]]) -> str:
    for item in reversed(tool_results):
        result = item.get("result")
        if isinstance(result, dict):
            if result.get("answer"):
                return str(result["answer"])
            body = result.get("body")
            if isinstance(body, dict) and body.get("answer"):
                return str(body["answer"])
    return ""


def _collect_browser_recordings(case: Any, tool_runtime: Any) -> list[dict[str, Any]]:
    if not hasattr(tool_runtime, "finalize_browser_session") or not hasattr(tool_runtime, "browser_recordings"):
        return []
    recordings: list[dict[str, Any]] = []
    for session_id in _case_browser_session_ids(case):
        finalized = tool_runtime.finalize_browser_session(session_id)
        if finalized is not None:
            recordings.append(finalized)
        else:
            recordings.extend(tool_runtime.browser_recordings(session_id))
    return recordings


def _case_browser_session_ids(case: Any) -> list[str]:
    ids: list[str] = []
    for step in getattr(case, "tool_plan", []) or []:
        if not str(step.tool).startswith("browser_"):
            continue
        candidate = step.arguments.get("session_id") or step.arguments.get("run_id")
        if isinstance(candidate, str) and candidate and candidate not in ids:
            ids.append(candidate)
    if not ids and any(str(step.tool).startswith("browser_") for step in getattr(case, "tool_plan", []) or []):
        ids.append(case.case_id)
    return ids
