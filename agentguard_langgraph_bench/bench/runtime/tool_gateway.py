"""Guarded gateway that all benchmark tool calls pass through."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from agentguard_langgraph_adapter.runtime_receipts import (
    ExecutionStatus,
    TraceLifecycleState,
    build_runtime_outcome,
    build_tool_started_observation,
    build_trace_lifecycle_observation,
    runtime_receipts_enabled,
    submit_runtime_receipt,
)
from agentguard_langgraph_adapter.tool_gateway import (
    _apply_tool_result_guard,
    _compatibility_from_event,
    _evaluate_memory_write_gate,
    _evaluate_message_send_gate,
    adapter_submits_policy_audit,
)
from agentguard_langgraph_bench.adapter.event_models import (
    ToolExecutionResult,
    new_id,
    utc_now_iso,
)
from agentguard_langgraph_bench.adapter.langgraph_adapter import blocked_result
from agentguard_langgraph_bench.bench.mcpsafety import (
    build_descriptor_diff,
    hijacking_config_from_metadata,
)


@dataclass(slots=True)
class GuardedToolGateway:
    guard_adapter: Any
    tool_runtime: Any
    approval_mode: str = "fail-closed"
    approval_timeout: float = 60.0
    _last_receipt_by_trace: dict[str, str] = field(default_factory=dict, init=False, repr=False)

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
        # Guard API evaluate owns policy_evaluation. Share the reusable
        # adapter's mode decision so the actual AttackBench path cannot submit
        # the duplicate record that Guard API correctly rejects.
        audit_event = None
        if adapter_submits_policy_audit(self.guard_adapter):
            audit_event = self.guard_adapter.build_audit_event(event, decision)
            if compatibility is not None:
                audit_event.metadata["compatibility"] = dict(compatibility)
            self.guard_adapter.submit_audit_event(audit_event)

        if decision.decision == "deny":
            receipt_error = self._record_outcome(
                event,
                decision,
                execution_status="not_invoked",
                intervention_type="policy_deny",
                intervention_reason="Policy denied the action before the tool runtime was invoked.",
            )
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
                runtime_terminal=True,
                terminal_reason="policy_deny",
                sanitize_applied=_decision_has_effect(decision, "patch"),
                quarantine_applied=_decision_has_effect(decision, "quarantine"),
                runtime_receipt_error=receipt_error,
            )

        approval_id: str | None = None
        approval_resolution: dict[str, Any] | None = None
        approval_decision: str | None = None
        latency_ms: float | None = None
        approved_arguments_hash: str | None = None
        if decision.decision == "ask":
            approval_id = _approval_id(getattr(decision, "approval", None))
            arguments_hash = _arguments_hash(arguments)
            if self.approval_mode == "fail-closed" or not approval_id:
                approval_resolution = {
                    "status": "not_waited",
                    "decision": "deny",
                    "reason": "approval_mode_fail_closed",
                }
                receipt_error = self._record_outcome(
                    event,
                    decision,
                    execution_status="not_invoked",
                    approval_resolution=approval_resolution,
                    intervention_type="approval_not_obtained",
                    intervention_reason="The configured fail-closed mode did not release the action for execution.",
                )
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
                    approval_resolution=approval_resolution,
                    approved_arguments_hash=arguments_hash,
                    block_semantics="ask_as_block",
                    counts_as_effective_block=False,
                    runtime_terminal=True,
                    terminal_reason="ask_as_block",
                    runtime_receipt_error=receipt_error,
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
                "approval_resolution": approval_resolution,
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
                    receipt_error = self._record_outcome(
                        event,
                        decision,
                        execution_status="not_invoked",
                        approval_resolution=approval_resolution,
                        intervention_type="approval_binding_mismatch",
                        intervention_reason=("The approval did not match the reviewed tool call, so the runtime was not invoked."),
                    )
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
                        runtime_terminal=True,
                        terminal_reason="approval_binding_mismatch",
                        safe_message=f"Approval did not match the reviewed tool call: {mismatch_reason}",
                        runtime_receipt_error=receipt_error,
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
                receipt_error = self._record_outcome(
                    event,
                    decision,
                    execution_status="not_invoked",
                    approval_resolution=approval_resolution,
                    intervention_type=block_semantics,
                    intervention_reason="The approval path ended before the tool runtime was invoked.",
                )
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
                    runtime_terminal=True,
                    terminal_reason=block_semantics,
                    runtime_receipt_error=receipt_error,
                )

        compatibility_payload = compatibility or _compatibility_from_event(event)
        secondary_gate = _evaluate_memory_write_gate(
            self.guard_adapter,
            tool_name=tool_name,
            arguments=arguments,
            security=security_for_event,
            trace_id=trace_id,
            call_id=call_id,
            compatibility=compatibility_payload,
        )
        if secondary_gate is None:
            secondary_gate = _evaluate_message_send_gate(
                self.guard_adapter,
                tool_name=tool_name,
                arguments=arguments,
                security=security_for_event,
                trace_id=trace_id,
                call_id=call_id,
                compatibility=compatibility_payload,
            )
        if secondary_gate is not None:
            return _annotate_result(
                secondary_gate,
                approval_mode=self.approval_mode,
                runtime_terminal=True,
                terminal_reason=secondary_gate.block_semantics or "secondary_gate",
            )

        invoked_at = utc_now_iso()
        start_audit_id: str | None = None
        if self._supports_action_receipts(decision):
            started = build_tool_started_observation(
                event,
                decision,
                approval_resolution=approval_resolution,
                timestamp=invoked_at,
            )
            start_error = self._record_receipt(started)
            if start_error is not None:
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
                    approval_consumed=True,
                    approval_decision=approval_decision,
                    approval_wait_latency_ms=latency_ms,
                    approved_arguments_hash=approved_arguments_hash,
                    approval_resolution=approval_resolution,
                    block_semantics="runtime_receipt_failure",
                    counts_as_effective_block=False,
                    runtime_terminal=True,
                    terminal_reason="runtime_receipt_failure",
                    safe_message="The tool call was not executed because its start receipt could not be recorded.",
                    runtime_receipt_error=start_error,
                )
            start_audit_id = started.audit_id

        before = self.tool_runtime.snapshot()
        try:
            result = self.tool_runtime.invoke(tool_name, arguments)
            side_effects = self.tool_runtime.diff(before)
            payload = ToolExecutionResult(
                tool_name=tool_name,
                call_id=call_id,
                executed=True,
                blocked=False,
                decision=decision.decision,
                status="executed",
                result=result,
                safe_message=None,
                side_effects=side_effects,
                event=event.model_dump(),
                audit_event=_dump_audit_event(audit_event),
                approval_mode=self.approval_mode if decision.decision == "ask" else None,
                approval_id=approval_id if decision.decision == "ask" else None,
                approval_consumed=True if decision.decision == "ask" else False,
                approval_decision=approval_decision if decision.decision == "ask" else None,
                approval_wait_latency_ms=latency_ms if decision.decision == "ask" else None,
                approved_arguments_hash=approved_arguments_hash if decision.decision == "ask" else None,
                approval_resolution=approval_resolution if decision.decision == "ask" else None,
                tool_executed_after_approval=True if decision.decision == "ask" else False,
                block_semantics="approval_allow_continue" if decision.decision == "ask" else None,
                counts_as_effective_block=False,
                runtime_terminal=False,
                terminal_reason=None,
                rag_answer_provenance=result.get("rag_answer_provenance") if tool_name == "rag_answer" and isinstance(result, dict) else None,
                sanitize_applied=_decision_has_effect(decision, "patch"),
                quarantine_applied=_decision_has_effect(decision, "quarantine"),
                runtime_receipt_error=None,
            )
            payload, result_outcome_attempted = _apply_tool_result_guard(
                self.guard_adapter,
                payload=payload,
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                side_effects=side_effects,
                security=security_for_event,
                trace_id=trace_id,
                call_id=call_id,
                invoked_at=invoked_at,
                side_effects_measured=True,
            )
            if not result_outcome_attempted:
                payload.runtime_receipt_error = self._record_outcome(
                    event,
                    decision,
                    execution_status="executed",
                    approval_resolution=(
                        approval_resolution if decision.decision == "ask" else None
                    ),
                    invoked_at=invoked_at,
                    side_effects=side_effects,
                    side_effects_measured=True,
                    parent_audit_id=start_audit_id,
                )
            return payload
        except Exception as exc:
            side_effects = self.tool_runtime.diff(before)
            receipt_error = self._record_outcome(
                event,
                decision,
                execution_status="failed",
                approval_resolution=(approval_resolution if decision.decision == "ask" else None),
                invoked_at=invoked_at,
                error=str(exc),
                side_effects=side_effects,
                side_effects_measured=True,
                parent_audit_id=start_audit_id,
            )
            return ToolExecutionResult(
                tool_name=tool_name,
                call_id=call_id,
                executed=False,
                blocked=False,
                decision=decision.decision,
                status="error",
                result=None,
                safe_message=None,
                side_effects=side_effects,
                event=event.model_dump(),
                audit_event=_dump_audit_event(audit_event),
                error=str(exc),
                approval_mode=self.approval_mode if decision.decision == "ask" else None,
                approval_id=approval_id if decision.decision == "ask" else None,
                approval_consumed=True if decision.decision == "ask" else False,
                approval_decision=approval_decision if decision.decision == "ask" else None,
                approval_wait_latency_ms=latency_ms if decision.decision == "ask" else None,
                approved_arguments_hash=approved_arguments_hash if decision.decision == "ask" else None,
                approval_resolution=approval_resolution if decision.decision == "ask" else None,
                tool_executed_after_approval=True if decision.decision == "ask" else False,
                block_semantics="approval_allow_continue" if decision.decision == "ask" else None,
                counts_as_effective_block=False,
                sanitize_applied=_decision_has_effect(decision, "patch"),
                quarantine_applied=_decision_has_effect(decision, "quarantine"),
                runtime_receipt_error=receipt_error,
            )

    def record_trace_lifecycle(
        self,
        *,
        trace_id: str,
        state: TraceLifecycleState,
        runtime: str,
        case_id: str | None = None,
        reason: str | None = None,
    ) -> str | None:
        """Persist an explicit trace boundary and return a bounded diagnostic."""

        if not runtime_receipts_enabled(self.guard_adapter):
            return None
        receipt = build_trace_lifecycle_observation(
            trace_id=trace_id,
            state=state,
            runtime=runtime,
            case_id=case_id,
            parent_audit_id=self._last_receipt_by_trace.get(trace_id),
            reason=reason,
        )
        return self._record_receipt(receipt)

    def _supports_action_receipts(self, decision: Any) -> bool:
        return bool(runtime_receipts_enabled(self.guard_adapter) and getattr(decision, "policy_audit_id", None))

    def _record_outcome(
        self,
        event: Any,
        decision: Any,
        *,
        execution_status: ExecutionStatus,
        approval_resolution: dict[str, Any] | None = None,
        invoked_at: str | None = None,
        error: str | None = None,
        side_effects: list[dict[str, Any]] | None = None,
        side_effects_measured: bool = False,
        parent_audit_id: str | None = None,
        intervention_type: str | None = None,
        intervention_reason: str | None = None,
    ) -> str | None:
        if not self._supports_action_receipts(decision):
            return None
        receipt = build_runtime_outcome(
            event,
            decision,
            execution_status=execution_status,
            approval_resolution=approval_resolution,
            invoked_at=invoked_at,
            error=error,
            side_effects=side_effects,
            side_effects_measured=side_effects_measured,
            parent_audit_id=parent_audit_id,
            intervention_type=intervention_type,
            intervention_reason=intervention_reason,
        )
        return self._record_receipt(receipt)

    def _record_receipt(self, receipt: Any) -> str | None:
        error = submit_runtime_receipt(self.guard_adapter, receipt)
        if error is None:
            self._last_receipt_by_trace[receipt.trace_id] = receipt.audit_id
        return error

    def _enrich_arguments(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        security: dict[str, Any],
        case_context: dict[str, Any] | None,
        call_id: str,
    ) -> dict[str, Any]:
        if tool_name in {
            "memory_write",
            "memory_read",
            "memory_search",
            "rag_answer",
            "rag_retrieve",
        }:
            payload = dict(arguments)
            metadata = dict((case_context or {}).get("metadata") or security.get("metadata") or {})
            payload["_case_id"] = security.get("case_id") or (case_context or {}).get("case_id")
            payload["_scenario_id"] = metadata.get("scenario_id")
            payload["_phase"] = metadata.get("phase")
            payload["_source_tool_call_id"] = call_id
            payload["_created_by"] = "agent_tool_call"
            if tool_name == "rag_answer":
                self._enrich_rag_answer_arguments(payload)
            return payload
        if tool_name != "mcp_call":
            return arguments
        payload = dict(arguments)
        context = dict(case_context or {})
        metadata = dict(context.get("metadata") or security.get("metadata") or {})
        hijacking = dict(context.get("hijacking") or metadata.get("hijacking") or {})
        if not hijacking:
            hijacking = hijacking_config_from_metadata(metadata).model_dump()
        selected_catalog = _catalog_for_view(
            context,
            payload.get("catalog_view") or context.get("catalog_view") or "poisoned",
        )
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
            payload.setdefault(
                "catalog_view",
                payload.get("catalog_view") or context.get("catalog_view") or "poisoned",
            )
        if clean_descriptor:
            payload.setdefault("clean_descriptor", clean_descriptor)
        if poisoned_descriptor:
            payload.setdefault("poisoned_descriptor", poisoned_descriptor)
        if descriptor_diff:
            payload.setdefault("descriptor_diff", descriptor_diff)
        payload.setdefault("hijacking", hijacking)
        return payload

    def _enrich_rag_answer_arguments(self, payload: dict[str, Any]) -> None:
        latest = getattr(self.tool_runtime, "latest_rag_retrieval", None)
        if not callable(latest):
            return
        provenance = latest(
            case_id=payload.get("_case_id"),
            dataset=str(payload.get("dataset") or ""),
            question_id=str(payload.get("question_id") or ""),
        )
        if not isinstance(provenance, dict):
            return
        if not payload.get("contexts") and provenance.get("contexts"):
            payload["contexts"] = list(provenance.get("contexts") or [])
        for key in (
            "context_docs",
            "source_trust",
            "answer_source",
            "rag_answer_provenance",
        ):
            if payload.get(key) in (None, "", []):
                value = provenance.get(key)
                if value not in (None, "", []):
                    payload[key] = value


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


def _dump_audit_event(audit_event: Any | None) -> dict[str, Any] | None:
    if audit_event is None:
        return None
    dumped = audit_event.model_dump() if hasattr(audit_event, "model_dump") else audit_event
    return dumped if isinstance(dumped, dict) else None


def _approval_id(approval: Any) -> str | None:
    if not isinstance(approval, dict):
        return None
    value = approval.get("approval_id") or approval.get("id")
    return str(value) if value else None


def _arguments_hash(arguments: dict[str, Any]) -> str:
    payload = json.dumps(
        arguments,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
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
            last_resolution = {
                "status": "error",
                "decision": "deny",
                "error": "approval wait returned non-object",
            }
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
        return {
            "status": "error",
            "decision": "deny",
            "error": "guard adapter does not support approval wait",
        }
    try:
        resolution = wait(approval_id, timeout=timeout_seconds)
    except TypeError:
        resolution = wait(approval_id)
    if isinstance(resolution, dict):
        return dict(resolution)
    return {
        "status": "error",
        "decision": "deny",
        "error": "approval wait returned non-object",
    }


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
