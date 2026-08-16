"""Generic guarded tool gateway for LangGraph-style tool runtimes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .event_models import AuditEvent, ToolExecutionResult, new_id, utc_now_iso
from .langgraph_adapter import blocked_result
from .runtime_receipts import (
    ExecutionStatus,
    ResultDisposition,
    build_runtime_outcome,
    build_tool_started_observation,
    runtime_receipts_enabled,
    submit_runtime_receipt,
)
from .tool_compat import tool_result_with_compatibility


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
        # Guard API 模式下策略审计由 evaluate writer 唯一写入，adapter 不再
        # 重复提交（契约 §12.1/§22.1）；仅 legacy Core 保留自提交路径。
        audit_event: AuditEvent | None = None
        if adapter_submits_policy_audit(self.guard_adapter):
            audit_event = self.guard_adapter.build_audit_event(event, decision)
            assert audit_event is not None
            if compatibility is not None:
                audit_event.metadata["compatibility"] = dict(compatibility)
            audit_error = _submit_audit_event(self.guard_adapter, audit_event)
            if audit_error is not None:
                return _audit_failure_result(
                    tool_name=tool_name,
                    call_id=call_id,
                    event=event,
                    audit_event=audit_event,
                    error=audit_error,
                )

        approval_blocked, approval_resolution = _resolve_approval(
            self.guard_adapter, decision
        )
        if decision.decision == "deny" or approval_blocked:
            result = blocked_result(
                tool_name=tool_name,
                call_id=call_id,
                event=event,
                decision=decision,
                audit_event=audit_event,
            )
            result.runtime_receipt_error = _submit_runtime_outcome(
                self.guard_adapter,
                event,
                decision,
                execution_status="not_invoked",
                approval_resolution=approval_resolution,
                intervention_type=(
                    "policy_deny"
                    if decision.decision == "deny"
                    else "approval_not_obtained"
                ),
                intervention_reason=(
                    "Policy denied the action before the tool runtime was invoked."
                    if decision.decision == "deny"
                    else "The action did not receive an approval that released it for execution."
                ),
            )
            return ToolExecutionResult.model_validate(
                tool_result_with_compatibility(
                    result.model_dump(),
                    compatibility or _compatibility_from_event(event),
                )
            )

        memory_gate = _evaluate_memory_write_gate(
            self.guard_adapter,
            tool_name=tool_name,
            arguments=arguments,
            security=security_for_event,
            trace_id=trace_id,
            call_id=call_id,
            compatibility=compatibility or _compatibility_from_event(event),
        )
        if memory_gate is not None:
            return memory_gate

        invoked_at = utc_now_iso()
        start_audit_id: str | None = None
        if _supports_runtime_outcome(self.guard_adapter, decision):
            started = build_tool_started_observation(
                event,
                decision,
                approval_resolution=approval_resolution,
                timestamp=invoked_at,
            )
            start_error = submit_runtime_receipt(self.guard_adapter, started)
            if start_error is not None:
                result = blocked_result(
                    tool_name=tool_name,
                    call_id=call_id,
                    event=event,
                    decision=decision,
                    audit_event=audit_event,
                )
                result.status = "audit_error"
                result.safe_message = (
                    "The tool call was not executed because its start "
                    "receipt could not be recorded."
                )
                result.error = start_error
                result.runtime_receipt_error = start_error
                result.block_semantics = "runtime_receipt_failure"
                result.counts_as_effective_block = False
                return ToolExecutionResult.model_validate(
                    tool_result_with_compatibility(
                        result.model_dump(),
                        compatibility or _compatibility_from_event(event),
                    )
                )
            start_audit_id = started.audit_id

        side_effects_measured = bool(
            hasattr(self.tool_runtime, "snapshot")
            and hasattr(self.tool_runtime, "diff")
        )
        before = self.tool_runtime.snapshot() if side_effects_measured else None
        try:
            result = self.tool_runtime.invoke(tool_name, arguments)
            side_effects = (
                self.tool_runtime.diff(before) if side_effects_measured else []
            )
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
                side_effects_measured=side_effects_measured,
            )
            if not result_outcome_attempted:
                payload.runtime_receipt_error = _submit_runtime_outcome(
                    self.guard_adapter,
                    event,
                    decision,
                    execution_status="executed",
                    approval_resolution=approval_resolution,
                    invoked_at=invoked_at,
                    side_effects=side_effects,
                    side_effects_measured=side_effects_measured,
                    parent_audit_id=start_audit_id,
                )
            return ToolExecutionResult.model_validate(
                tool_result_with_compatibility(
                    payload.model_dump(),
                    compatibility or _compatibility_from_event(event),
                )
            )
        except Exception as exc:
            side_effects = (
                self.tool_runtime.diff(before) if side_effects_measured else []
            )
            payload = ToolExecutionResult(
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
                runtime_receipt_error=_submit_runtime_outcome(
                    self.guard_adapter,
                    event,
                    decision,
                    execution_status="failed",
                    approval_resolution=approval_resolution,
                    invoked_at=invoked_at,
                    error=str(exc),
                    side_effects=side_effects,
                    side_effects_measured=side_effects_measured,
                    parent_audit_id=start_audit_id,
                ),
            )
            return ToolExecutionResult.model_validate(
                tool_result_with_compatibility(
                    payload.model_dump(),
                    compatibility or _compatibility_from_event(event),
                )
            )


def _compatibility_from_event(event: Any) -> dict[str, Any]:
    metadata = getattr(event, "metadata", None)
    if isinstance(metadata, dict) and isinstance(metadata.get("compatibility"), dict):
        return dict(metadata["compatibility"])
    if hasattr(event, "model_dump"):
        dumped = event.model_dump()
        metadata = dumped.get("metadata") if isinstance(dumped, dict) else {}
        if isinstance(metadata, dict) and isinstance(
            metadata.get("compatibility"), dict
        ):
            return dict(metadata["compatibility"])
        if isinstance(dumped, dict) and isinstance(dumped.get("compatibility"), dict):
            return dict(dumped["compatibility"])
    return {}


def _evaluate_memory_write_gate(
    guard_adapter: Any,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    security: dict[str, Any],
    trace_id: str,
    call_id: str,
    compatibility: dict[str, Any],
) -> ToolExecutionResult | None:
    if tool_name != "memory_write" or not hasattr(
        guard_adapter, "evaluate_memory_write"
    ):
        return None
    event, decision = guard_adapter.evaluate_memory_write(
        arguments={**arguments, "_source_tool_call_id": call_id},
        security=security,
        trace_id=trace_id,
    )
    audit_event: AuditEvent | None = None
    if adapter_submits_policy_audit(guard_adapter):
        audit_event = guard_adapter.build_audit_event(event, decision)
        assert audit_event is not None
        audit_error = _submit_audit_event(guard_adapter, audit_event)
        if audit_error is not None:
            return _audit_failure_result(
                tool_name=tool_name,
                call_id=call_id,
                event=event,
                audit_event=audit_event,
                error=audit_error,
                compatibility=compatibility,
            )
    approval_blocked, approval_resolution = _resolve_approval(guard_adapter, decision)
    if decision.decision != "deny" and not approval_blocked:
        return None
    payload = ToolExecutionResult(
        tool_name=tool_name,
        call_id=call_id,
        executed=False,
        blocked=True,
        decision=decision.decision,
        status="blocked",
        result=None,
        safe_message=decision.safe_message
        or "The memory write was blocked by AgentGuard.",
        side_effects=[],
        event=_dump_event(event),
        audit_event=_dump_audit_event(audit_event),
        block_semantics=_block_semantics(decision),
        counts_as_effective_block=decision.decision == "deny",
        runtime_receipt_error=_submit_runtime_outcome(
            guard_adapter,
            event,
            decision,
            execution_status="not_invoked",
            approval_resolution=approval_resolution,
            intervention_type=(
                "policy_deny"
                if decision.decision == "deny"
                else "approval_not_obtained"
            ),
            intervention_reason="The memory write gate stopped the action before the runtime was invoked.",
        ),
    )
    return ToolExecutionResult.model_validate(
        tool_result_with_compatibility(payload.model_dump(), compatibility)
    )


def _apply_tool_result_guard(
    guard_adapter: Any,
    *,
    payload: ToolExecutionResult,
    tool_name: str,
    arguments: dict[str, Any],
    result: Any,
    side_effects: list[dict[str, Any]],
    security: dict[str, Any],
    trace_id: str,
    call_id: str,
    invoked_at: str,
    side_effects_measured: bool,
) -> tuple[ToolExecutionResult, bool]:
    if not hasattr(guard_adapter, "evaluate_tool_result"):
        return payload, False
    event, decision = guard_adapter.evaluate_tool_result(
        tool_name=tool_name,
        arguments=arguments,
        result=result,
        security=security,
        trace_id=trace_id,
        call_id=call_id,
        will_enter_context=True,
        will_persist=_tool_result_will_persist(tool_name, side_effects),
    )
    audit_event: AuditEvent | None = None
    if adapter_submits_policy_audit(guard_adapter):
        audit_event = guard_adapter.build_audit_event(event, decision)
        assert audit_event is not None
        audit_error = _submit_audit_event(guard_adapter, audit_event)
        if audit_error is not None:
            payload.blocked = True
            payload.status = "audit_error"
            payload.result = None
            payload.safe_message = "The tool result was withheld because AgentGuard audit submission failed."
            payload.error = audit_error
            payload.audit_event = audit_event.model_dump()
            payload.quarantine_applied = True
            payload.block_semantics = "audit_failure"
            payload.counts_as_effective_block = False
            return payload, False
    approval_blocked, approval_resolution = _resolve_approval(guard_adapter, decision)
    outcome_attempted = _supports_runtime_outcome(guard_adapter, decision)
    if decision.decision != "deny" and not approval_blocked:
        payload.runtime_receipt_error = _submit_runtime_outcome(
            guard_adapter,
            event,
            decision,
            execution_status="executed",
            approval_resolution=approval_resolution,
            invoked_at=invoked_at,
            side_effects=side_effects,
            side_effects_measured=side_effects_measured,
        )
        return payload, outcome_attempted
    payload.blocked = True
    payload.decision = decision.decision
    payload.status = "quarantined"
    payload.result = None
    payload.safe_message = (
        decision.safe_message
        or "The tool result was quarantined by AgentGuard before entering context."
    )
    payload.event = _dump_event(event)
    payload.audit_event = _dump_audit_event(audit_event)
    payload.quarantine_applied = True
    payload.counts_as_effective_block = decision.decision == "deny"
    payload.block_semantics = _block_semantics(decision)
    payload.runtime_receipt_error = _submit_runtime_outcome(
        guard_adapter,
        event,
        decision,
        execution_status="executed",
        approval_resolution=approval_resolution,
        invoked_at=invoked_at,
        side_effects=side_effects,
        side_effects_measured=side_effects_measured,
        result_disposition="quarantined",
        result_sanitized=False,
        intervention_type="tool_result_quarantine",
        intervention_reason="The tool executed, but its result was withheld from Agent context.",
    )
    return payload, outcome_attempted


def _tool_result_will_persist(
    tool_name: str, side_effects: list[dict[str, Any]]
) -> bool:
    if tool_name in {"memory_write", "rag_answer"}:
        return True
    for effect in side_effects:
        text = " ".join(str(value).lower() for value in effect.values())
        if "persist" in text or "memory" in text:
            return True
    return False


def _dump_event(event: Any) -> dict[str, Any]:
    if isinstance(event, dict):
        return event
    if hasattr(event, "model_dump"):
        dumped = event.model_dump()
        return dumped if isinstance(dumped, dict) else {}
    return {}


def _dump_audit_event(audit_event: AuditEvent | None) -> dict[str, Any] | None:
    if audit_event is None:
        return None
    return audit_event.model_dump()


def adapter_submits_policy_audit(guard_adapter: Any) -> bool:
    """判断 adapter 是否仍需自行提交策略审计。

    Guard API v0.3 模式下 POST /v1/guard/evaluate 已在服务端唯一写入
    policy_evaluation（契约 §10/§22.1），adapter 重复提交会被 §12.1 守卫
    拒绝并造成指标重复；legacy Core 没有 evaluate writer，保留 adapter
    自提交路径。
    """
    config = getattr(guard_adapter, "config", None)
    mode = getattr(config, "core_api_mode", getattr(config, "api_mode", None))
    return mode == "legacy"


def _block_semantics(decision: Any) -> str:
    return (
        "policy_deny"
        if getattr(decision, "decision", None) == "deny"
        else "approval_block"
    )


def _resolve_approval(
    guard_adapter: Any, decision: Any
) -> tuple[bool, dict[str, Any] | None]:
    if getattr(decision, "decision", None) != "ask":
        return False, None
    approval_id = _approval_id(getattr(decision, "approval", None))
    if not approval_id or not hasattr(guard_adapter, "wait_for_approval"):
        return True, {
            "status": "unavailable",
            "decision": None,
            "approval_id": approval_id,
        }
    resolution = guard_adapter.wait_for_approval(approval_id)
    if not isinstance(resolution, dict):
        return True, {
            "status": "error",
            "decision": None,
            "approval_id": approval_id,
        }
    approved = resolution.get("status") == "resolved" and str(
        resolution.get("decision") or ""
    ).lower() in {
        "allow",
        "allow_once",
        "allow_session",
    }
    return not approved, dict(resolution)


def _supports_runtime_outcome(guard_adapter: Any, decision: Any) -> bool:
    return bool(
        runtime_receipts_enabled(guard_adapter)
        and getattr(decision, "policy_audit_id", None)
    )


def _submit_runtime_outcome(
    guard_adapter: Any,
    event: Any,
    decision: Any,
    *,
    execution_status: ExecutionStatus,
    approval_resolution: dict[str, Any] | None = None,
    invoked_at: str | None = None,
    error: str | None = None,
    side_effects: list[dict[str, Any]] | None = None,
    side_effects_measured: bool = False,
    result_disposition: ResultDisposition | None = None,
    result_sanitized: bool | None = None,
    parent_audit_id: str | None = None,
    intervention_type: str | None = None,
    intervention_reason: str | None = None,
) -> str | None:
    if not _supports_runtime_outcome(guard_adapter, decision):
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
        result_disposition=result_disposition,
        result_sanitized=result_sanitized,
        parent_audit_id=parent_audit_id,
        intervention_type=intervention_type,
        intervention_reason=intervention_reason,
    )
    return submit_runtime_receipt(guard_adapter, receipt)


def _approval_id(approval: Any) -> str | None:
    if isinstance(approval, dict):
        value = approval.get("approval_id") or approval.get("id")
        return str(value) if value else None
    return None


def _submit_audit_event(guard_adapter: Any, audit_event: Any) -> str | None:
    try:
        response = guard_adapter.submit_audit_event(audit_event)
    except Exception as exc:
        return f"Audit submission failed: {exc}"
    if isinstance(response, dict) and response.get("ok") is False:
        return f"Audit submission failed: {response.get('error') or 'unknown error'}"
    return None


def _audit_failure_result(
    *,
    tool_name: str,
    call_id: str,
    event: Any,
    audit_event: Any,
    error: str,
    compatibility: dict[str, Any] | None = None,
) -> ToolExecutionResult:
    payload = ToolExecutionResult(
        tool_name=tool_name,
        call_id=call_id,
        executed=False,
        blocked=True,
        decision="deny",
        status="audit_error",
        result=None,
        safe_message="The tool call was blocked because AgentGuard audit submission failed.",
        side_effects=[],
        event=_dump_event(event),
        audit_event=_dump_event(audit_event),
        error=error,
        block_semantics="audit_failure",
        counts_as_effective_block=False,
    )
    return ToolExecutionResult.model_validate(
        tool_result_with_compatibility(payload.model_dump(), compatibility or {})
    )
