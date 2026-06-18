"""Non-invasive guarded tool node for LangGraph or direct runner use."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .event_models import ToolExecutionResult, new_id
from .langgraph_adapter import LangGraphAdapter, blocked_result


@dataclass(slots=True)
class SecureToolNode:
    adapter: LangGraphAdapter
    tool_registry: Any

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
        event, decision = self.adapter.evaluate_before_tool(
            tool_name=tool_name,
            arguments=arguments,
            security=security,
            trace_id=trace_id,
            call_id=call_id,
        )
        audit_event = self.adapter.build_audit_event(event, decision)
        self.adapter.submit_audit_event(audit_event)

        if decision.decision in {"deny", "ask"}:
            return blocked_result(
                tool_name=tool_name,
                call_id=call_id,
                event=event,
                decision=decision,
                audit_event=audit_event,
            )

        before = self._snapshot_side_effects()
        try:
            result = self.tool_registry.invoke(tool_name, arguments)
        except Exception as exc:
            return ToolExecutionResult(
                tool_name=tool_name,
                call_id=call_id,
                executed=True,
                blocked=False,
                decision=decision.decision,
                status="error",
                result=None,
                safe_message=None,
                side_effects=self._side_effect_delta(before),
                event=event.model_dump(),
                audit_event=audit_event.model_dump(),
                error=str(exc),
            )

        return ToolExecutionResult(
            tool_name=tool_name,
            call_id=call_id,
            executed=True,
            blocked=False,
            decision=decision.decision,
            status="executed",
            result=result,
            safe_message=None,
            side_effects=self._side_effect_delta(before),
            event=event.model_dump(),
            audit_event=audit_event.model_dump(),
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

    def _snapshot_side_effects(self) -> dict[str, tuple[int, int]]:
        sandbox = self.tool_registry.sandbox_dir.resolve()
        snapshot: dict[str, tuple[int, int]] = {}
        if not sandbox.exists():
            return snapshot
        for file_path in sandbox.rglob("*"):
            if file_path.is_file():
                stat = file_path.stat()
                snapshot[str(file_path.resolve())] = (stat.st_size, stat.st_mtime_ns)
        return snapshot

    def _side_effect_delta(self, before: dict[str, tuple[int, int]]) -> list[dict[str, Any]]:
        effects: list[dict[str, Any]] = []
        after = self._snapshot_side_effects()
        for path in sorted(set(before) | set(after)):
            old_size, old_mtime = before.get(path, (0, 0))
            new_size, new_mtime = after.get(path, (0, 0))
            if new_size == old_size and new_mtime == old_mtime:
                continue
            effects.append({"path": path, "bytes_delta": new_size - old_size})
        return effects


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
