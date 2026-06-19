"""Tool-hijacking scoring helpers."""

from __future__ import annotations

from typing import Any

from agentguard_langgraph_bench.bench.mcpsafety import ToolHijackingConfig, evaluate_tool_hijacking, hijacking_config_from_metadata
from agentguard_langgraph_bench.bench.models import AttackCase


def build_tool_hijacking_report(case: AttackCase, row: dict[str, Any]) -> dict[str, Any]:
    tool_results = list(row.get("tool_calls") or [])
    executed_mcp_calls = [
        item
        for item in tool_results
        if item.get("executed") and item.get("tool_name") == "mcp_call"
    ]
    config = _hijacking_config_for_row(case, executed_mcp_calls)
    return evaluate_tool_hijacking(
        config=config,
        tool_calls=executed_mcp_calls,
        task_completed=bool(row.get("executed")) and not bool(row.get("blocked")),
        blocked=bool(row.get("blocked")),
        normal_oracle=case_extra_dict(case, "normal_oracle"),
        attack_oracle=case_extra_dict(case, "attack_oracle"),
        task_oracle=case_extra_dict(case, "task_oracle"),
        safety_oracle=case_extra_dict(case, "safety_oracle"),
        sequence_oracle=case_extra_dict(case, "sequence_oracle"),
        permission_oracle=case_extra_dict(case, "permission_oracle"),
        response_oracle=case_extra_dict(case, "response_oracle"),
        final_answer=str(row.get("final_answer") or ""),
        side_effects=row.get("side_effects") or [],
    )


def attach_tool_hijacking_report(case: AttackCase, row: dict[str, Any], config: Any | None = None) -> dict[str, Any]:
    if case.attack_type != "tool_hijacking":
        return row
    row["hijacking_report"] = build_tool_hijacking_report(case, row)
    return row


def case_extra_dict(case: AttackCase, key: str) -> dict[str, Any]:
    value = getattr(case, key, None)
    return dict(value) if isinstance(value, dict) else {}


def case_extra_list(case: AttackCase, key: str) -> list[Any]:
    value = getattr(case, key, None)
    return list(value) if isinstance(value, list) else []


def _hijacking_config_for_row(case: AttackCase, tool_results: list[dict[str, Any]]) -> ToolHijackingConfig:
    for item in tool_results:
        event = item.get("event")
        if not isinstance(event, dict):
            continue
        arguments = event.get("arguments")
        if not isinstance(arguments, dict):
            continue
        hijacking = arguments.get("hijacking")
        if isinstance(hijacking, dict):
            return ToolHijackingConfig.from_payload(hijacking)

    config = hijacking_config_from_metadata(case.metadata)
    if config.target_tool or config.hijacked_tool or not tool_results:
        return config

    event_args = (tool_results[0].get("event") or {}).get("arguments")
    if not isinstance(event_args, dict):
        return config
    payload = config.model_dump()
    payload["target_server"] = payload.get("target_server") or event_args.get("server") or ""
    payload["target_tool"] = payload.get("target_tool") or event_args.get("tool") or ""
    inner_args = event_args.get("arguments")
    if isinstance(inner_args, dict) and config.mode == "argument_hijacking":
        payload["argument_mutation"] = payload.get("argument_mutation") or {
            key: value
            for key, value in inner_args.items()
            if key not in {"question", "attack_category", "poisoned_metadata"}
        }
    return ToolHijackingConfig.from_payload(payload)
