"""Guarded gateway that all benchmark tool calls pass through."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentguard_langgraph_bench.adapter.event_models import ToolExecutionResult, new_id
from agentguard_langgraph_bench.adapter.langgraph_adapter import blocked_result
from agentguard_langgraph_bench.bench.mcpsafety import build_descriptor_diff, hijacking_config_from_metadata


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
        arguments = self._enrich_arguments(
            tool_name,
            arguments,
            security=security,
            case_context=case_context,
            call_id=call_id,
        )
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
        if compatibility is not None:
            event.metadata["compatibility"] = dict(compatibility)
        audit_event = self.guard_adapter.build_audit_event(event, decision)
        if compatibility is not None:
            audit_event.metadata["compatibility"] = dict(compatibility)
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

    def _enrich_arguments(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        security: dict[str, Any],
        case_context: dict[str, Any] | None,
        call_id: str,
    ) -> dict[str, Any]:
        if tool_name in {"memory_write", "memory_read", "memory_search", "rag_answer", "rag_retrieve"}:
            payload = dict(arguments)
            metadata = dict((case_context or {}).get("metadata") or security.get("metadata") or {})
            payload["_case_id"] = security.get("case_id") or (case_context or {}).get("case_id")
            payload["_scenario_id"] = metadata.get("scenario_id")
            payload["_phase"] = metadata.get("phase")
            payload["_source_tool_call_id"] = call_id
            payload["_created_by"] = "agent_tool_call"
            return payload
        if tool_name != "mcp_call":
            return arguments
        payload = dict(arguments)
        context = dict(case_context or {})
        metadata = dict(context.get("metadata") or security.get("metadata") or {})
        hijacking = dict(context.get("hijacking") or metadata.get("hijacking") or {})
        if not hijacking:
            hijacking = hijacking_config_from_metadata(metadata).model_dump()
        selected_catalog = _catalog_for_view(context, payload.get("catalog_view") or context.get("catalog_view") or "poisoned")
        clean_catalog = _catalog_from_context(context, "clean_tool_catalog")
        poisoned_catalog = _catalog_from_context(context, "poisoned_tool_catalog")
        descriptor = _select_descriptor(selected_catalog, payload, context, metadata)
        clean_descriptor = _select_descriptor(clean_catalog, payload, context, metadata) or descriptor
        poisoned_descriptor = _select_descriptor(poisoned_catalog, payload, context, metadata) or descriptor
        descriptor_diff = list(context.get("descriptor_diff") or [])
        if not descriptor_diff and clean_catalog and poisoned_catalog:
            descriptor_diff = build_descriptor_diff(clean_catalog, poisoned_catalog)
        if descriptor:
            payload.setdefault("descriptor", descriptor)
            payload.setdefault("catalog_view", payload.get("catalog_view") or context.get("catalog_view") or "poisoned")
        if clean_descriptor:
            payload.setdefault("clean_descriptor", clean_descriptor)
        if poisoned_descriptor:
            payload.setdefault("poisoned_descriptor", poisoned_descriptor)
        if descriptor_diff:
            payload.setdefault("descriptor_diff", descriptor_diff)
        payload.setdefault("hijacking", hijacking)
        return payload


def _catalog_from_context(context: dict[str, Any], key: str) -> list[dict[str, Any]]:
    catalog = context.get(key)
    if isinstance(catalog, list):
        return [item for item in catalog if isinstance(item, dict)]
    return []


def _catalog_for_view(context: dict[str, Any], catalog_view: str) -> list[dict[str, Any]]:
    if catalog_view == "clean":
        return _catalog_from_context(context, "clean_tool_catalog") or _catalog_from_context(context, "poisoned_tool_catalog")
    return _catalog_from_context(context, "poisoned_tool_catalog") or _catalog_from_context(context, "clean_tool_catalog")


def _select_descriptor(
    catalog: list[dict[str, Any]],
    payload: dict[str, Any],
    context: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any] | None:
    if not catalog:
        return None
    server = str(payload.get("server") or "")
    tool = str(payload.get("tool") or "")
    for item in catalog:
        if server and str(item.get("server") or item.get("server_name") or "") != server:
            continue
        if tool and str(item.get("tool") or item.get("tool_name") or item.get("name") or "") != tool:
            continue
        return dict(item)
    target_server = str((context.get("hijacking") or metadata.get("hijacking") or {}).get("target_server") or "")
    target_tool = str((context.get("hijacking") or metadata.get("hijacking") or {}).get("target_tool") or "")
    for item in catalog:
        if target_server and str(item.get("server") or item.get("server_name") or "") != target_server:
            continue
        if target_tool and str(item.get("tool") or item.get("tool_name") or item.get("name") or "") != target_tool:
            continue
        return dict(item)
    return dict(catalog[0]) if catalog else None
