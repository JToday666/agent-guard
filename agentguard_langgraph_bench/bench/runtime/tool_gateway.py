"""Guarded gateway that all benchmark tool calls pass through."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from agentguard_langgraph_bench.adapter.event_models import ToolExecutionResult, new_id
from agentguard_langgraph_bench.adapter.langgraph_adapter import blocked_result
from agentguard_langgraph_bench.bench.mcpsafety import build_descriptor_diff, hijacking_config_from_metadata


@dataclass(slots=True)
class GuardedToolGateway:
    guard_adapter: Any
    tool_runtime: Any
    approval_mode: str = "fail-closed"
    approval_timeout: float = 60.0

    def __post_init__(self) -> None:
        self.approval_mode = str(self.approval_mode or "fail-closed").strip().lower()
        if self.approval_mode not in {"fail-closed", "wait"}:
            raise ValueError("approval_mode must be one of: fail-closed, wait")
        if self.approval_timeout <= 0:
            raise ValueError("approval_timeout must be greater than 0")

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

        if decision.decision == "deny":
            return _annotate_result(
                blocked_result(
                    tool_name=tool_name,
                    call_id=call_id,
                    event=event,
                    decision=decision,
                    audit_event=audit_event,
                ),
                approval_mode=self.approval_mode,
                block_semantics="policy_deny",
                counts_as_effective_block=True,
                sanitize_applied=_decision_has_effect(decision, "patch"),
                quarantine_applied=_decision_has_effect(decision, "quarantine"),
            )

        if decision.decision == "ask":
            approval_id = _approval_id(getattr(decision, "approval", None))
            arguments_hash = _arguments_hash(arguments)
            if self.approval_mode == "fail-closed" or not approval_id:
                return _annotate_result(
                    blocked_result(
                        tool_name=tool_name,
                        call_id=call_id,
                        event=event,
                        decision=decision,
                        audit_event=audit_event,
                    ),
                    approval_mode=self.approval_mode,
                    approval_id=approval_id,
                    approved_arguments_hash=arguments_hash,
                    block_semantics="ask_as_block",
                    counts_as_effective_block=False,
                )

            approval_resolution, latency_ms = _wait_for_approval(
                self.guard_adapter,
                approval_id=approval_id,
                timeout_seconds=self.approval_timeout,
            )
            approval_decision = _approval_decision(approval_resolution)
            approval_status = str(approval_resolution.get("status") or "").strip().lower()
            approval_consumed = approval_status == "resolved"
            approved_arguments_hash = _approval_hash(approval_resolution) or arguments_hash
            approval_metadata = {
                "approval_mode": self.approval_mode,
                "approval_id": approval_id,
                "approval_consumed": approval_consumed,
                "approval_decision": approval_decision,
                "approval_wait_latency_ms": latency_ms,
                "approved_arguments_hash": approved_arguments_hash,
                "tool_executed_after_approval": False,
            }
            if approval_decision in {"allow", "allow_once", "allow_session"}:
                mismatch_reason = _approval_binding_mismatch(
                    approval_resolution,
                    tool_call_id=call_id,
                    tool_name=tool_name,
                    trace_id=trace_id,
                    arguments_hash=arguments_hash,
                )
                if mismatch_reason:
                    return _annotate_result(
                        blocked_result(
                            tool_name=tool_name,
                            call_id=call_id,
                            event=event,
                            decision=decision,
                            audit_event=audit_event,
                        ),
                        **approval_metadata,
                        block_semantics="approval_binding_mismatch",
                        counts_as_effective_block=False,
                        safe_message=f"Approval did not match the reviewed tool call: {mismatch_reason}",
                    )
            else:
                block_semantics = "approval_denied_before_harm"
                counts_as_effective_block = True
                if approval_decision == "timeout":
                    block_semantics = "approval_timeout_block"
                    counts_as_effective_block = False
                elif approval_status == "expired" or approval_decision == "expired":
                    block_semantics = "approval_expired_block"
                    counts_as_effective_block = False
                return _annotate_result(
                    blocked_result(
                        tool_name=tool_name,
                        call_id=call_id,
                        event=event,
                        decision=decision,
                        audit_event=audit_event,
                    ),
                    **approval_metadata,
                    block_semantics=block_semantics,
                    counts_as_effective_block=counts_as_effective_block,
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
                approval_mode=self.approval_mode if decision.decision == "ask" else None,
                approval_id=approval_id if decision.decision == "ask" else None,
                approval_consumed=True if decision.decision == "ask" else False,
                approval_decision=approval_decision if decision.decision == "ask" else None,
                approval_wait_latency_ms=latency_ms if decision.decision == "ask" else None,
                approved_arguments_hash=approved_arguments_hash if decision.decision == "ask" else None,
                tool_executed_after_approval=True if decision.decision == "ask" else False,
                block_semantics="approval_allow_continue" if decision.decision == "ask" else None,
                counts_as_effective_block=False,
                sanitize_applied=_decision_has_effect(decision, "patch"),
                quarantine_applied=_decision_has_effect(decision, "quarantine"),
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
                approval_mode=self.approval_mode if decision.decision == "ask" else None,
                approval_id=approval_id if decision.decision == "ask" else None,
                approval_consumed=True if decision.decision == "ask" else False,
                approval_decision=approval_decision if decision.decision == "ask" else None,
                approval_wait_latency_ms=latency_ms if decision.decision == "ask" else None,
                approved_arguments_hash=approved_arguments_hash if decision.decision == "ask" else None,
                tool_executed_after_approval=True if decision.decision == "ask" else False,
                block_semantics="approval_allow_continue" if decision.decision == "ask" else None,
                counts_as_effective_block=False,
                sanitize_applied=_decision_has_effect(decision, "patch"),
                quarantine_applied=_decision_has_effect(decision, "quarantine"),
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


def _annotate_result(result: ToolExecutionResult, **updates: Any) -> ToolExecutionResult:
    clean_updates = {key: value for key, value in updates.items() if value is not None}
    return result.model_copy(update=clean_updates)


def _approval_id(approval: Any) -> str | None:
    if not isinstance(approval, dict):
        return None
    value = approval.get("approval_id") or approval.get("id")
    return str(value) if value else None


def _arguments_hash(arguments: dict[str, Any]) -> str:
    payload = json.dumps(arguments, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _approval_hash(resolution: dict[str, Any]) -> str | None:
    value = resolution.get("approved_arguments_hash") or resolution.get("arguments_hash")
    return str(value) if value else None


def _approval_decision(resolution: dict[str, Any]) -> str:
    status = str(resolution.get("status") or "").strip().lower()
    decision = str(resolution.get("decision") or "").strip().lower()
    if status == "timeout":
        return "timeout"
    return decision or status or "unknown"


def _wait_for_approval(guard_adapter: Any, *, approval_id: str, timeout_seconds: float) -> tuple[dict[str, Any], int]:
    started = time.monotonic()
    deadline = started + timeout_seconds
    last_resolution: dict[str, Any] = {"status": "pending", "decision": None}
    while True:
        remaining = max(deadline - time.monotonic(), 0.0)
        resolution = _call_wait_for_approval(guard_adapter, approval_id, remaining)
        if isinstance(resolution, dict):
            last_resolution = dict(resolution)
        else:
            last_resolution = {"status": "error", "decision": "deny", "error": "approval wait returned non-object"}
        status = str(last_resolution.get("status") or "").strip().lower()
        if status != "pending":
            return last_resolution, int((time.monotonic() - started) * 1000)
        if time.monotonic() >= deadline:
            timeout_resolution = dict(last_resolution)
            timeout_resolution["status"] = "timeout"
            timeout_resolution["decision"] = "timeout"
            return timeout_resolution, int((time.monotonic() - started) * 1000)
        time.sleep(min(0.25, max(deadline - time.monotonic(), 0.0)))


def _call_wait_for_approval(guard_adapter: Any, approval_id: str, timeout_seconds: float) -> dict[str, Any]:
    wait = getattr(guard_adapter, "wait_for_approval", None)
    if not callable(wait):
        return {"status": "error", "decision": "deny", "error": "guard adapter does not support approval wait"}
    try:
        return wait(approval_id, timeout=timeout_seconds)
    except TypeError:
        return wait(approval_id)


def _approval_binding_mismatch(
    resolution: dict[str, Any],
    *,
    tool_call_id: str,
    tool_name: str,
    trace_id: str,
    arguments_hash: str,
) -> str | None:
    expected = {
        "tool_call_id": tool_call_id,
        "call_id": tool_call_id,
        "subject_id": tool_call_id,
        "action_id": tool_call_id,
        "tool_name": tool_name,
        "action_name": tool_name,
        "tool": tool_name,
        "trace_id": trace_id,
        "arguments_hash": arguments_hash,
        "approved_arguments_hash": arguments_hash,
    }
    for key, expected_value in expected.items():
        if key not in resolution or resolution.get(key) in {None, ""}:
            continue
        if str(resolution.get(key)) != str(expected_value):
            return key
    return None


def _decision_has_effect(decision: Any, effect_type: str) -> bool:
    effects = getattr(decision, "effects", None)
    if not isinstance(effects, list):
        return False
    for effect in effects:
        if isinstance(effect, dict) and str(effect.get("type") or "") == effect_type:
            return True
        if str(getattr(effect, "type", "")) == effect_type:
            return True
    return False
