"""Generic guarded tool gateway for LangGraph-style tool runtimes."""

from __future__ import annotations

import time
from copy import deepcopy
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
from .strong_binding import (
    ApprovalResolutionValidationError,
    EnforcementEvidence,
    ExecutionLeaseCorrelation,
    StrongBindingFailure,
    StrongBindingRelease,
    authorize_strong_approval,
    normalize_approval_resolution,
    raw_enforcement_binding,
    validate_strong_release_for_invocation,
)
from .tool_compat import tool_result_with_compatibility


@dataclass(slots=True)
class GuardedToolGateway:
    guard_adapter: Any
    tool_runtime: Any
    approval_timeout: float = 60.0
    approval_poll_interval: float = 0.25

    def __post_init__(self) -> None:
        if self.approval_timeout <= 0:
            raise ValueError("approval_timeout must be greater than 0")
        if self.approval_poll_interval <= 0:
            raise ValueError("approval_poll_interval must be greater than 0")

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
        # Freeze the complete invocation projection before evaluate.  Caller
        # mutation during human wait cannot alter the arguments later invoked.
        arguments = deepcopy(arguments)
        raw_arguments = deepcopy(raw_arguments)
        compatibility = deepcopy(compatibility)
        security_for_event = deepcopy(security)
        case_context = deepcopy(case_context)
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

        strong_release: StrongBindingRelease | None = None
        if _should_attempt_strong_binding(decision):
            try:
                strong_release = authorize_strong_approval(
                    self.guard_adapter,
                    decision,
                    expected_action_id=_event_action_id(event) or call_id,
                    expected_runtime_binding_id=_expected_runtime_binding_id(
                        self.guard_adapter
                    ),
                    approval_id=_approval_id(getattr(decision, "approval", None)),
                    timeout_seconds=self.approval_timeout,
                    poll_interval_seconds=self.approval_poll_interval,
                )
            except StrongBindingFailure as failure:
                return _strong_binding_failure_result(
                    self.guard_adapter,
                    tool_name=tool_name,
                    call_id=call_id,
                    event=event,
                    decision=decision,
                    audit_event=audit_event,
                    compatibility=compatibility or _compatibility_from_event(event),
                    failure=failure,
                )
        if strong_release is not None:
            approval_blocked = False
            approval_resolution = strong_release.approval_resolution
        else:
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

        memory_gate, memory_release, memory_receipt_context = (
            _evaluate_memory_write_gate(
                self.guard_adapter,
                tool_name=tool_name,
                arguments=arguments,
                security=security_for_event,
                trace_id=trace_id,
                call_id=call_id,
                compatibility=compatibility or _compatibility_from_event(event),
                approval_timeout=self.approval_timeout,
                approval_poll_interval=self.approval_poll_interval,
            )
        )
        if memory_gate is not None:
            return memory_gate
        if memory_release is not None:
            assert memory_receipt_context is not None
            if strong_release is not None:
                failure = _multiple_binding_failure(memory_release)
                return _strong_binding_failure_result(
                    self.guard_adapter,
                    tool_name=tool_name,
                    call_id=call_id,
                    event=event,
                    decision=decision,
                    audit_event=audit_event,
                    compatibility=compatibility or _compatibility_from_event(event),
                    failure=failure,
                    receipt_event=memory_receipt_context[0],
                    receipt_decision=memory_receipt_context[1],
                )
            strong_release = memory_release
            approval_resolution = memory_release.approval_resolution

        receipt_event, receipt_decision = (
            memory_receipt_context
            if memory_release is not None and memory_receipt_context is not None
            else (event, decision)
        )
        message_gate, message_release, message_receipt_context = _evaluate_message_send_gate(
            self.guard_adapter,
            tool_name=tool_name,
            arguments=arguments,
            security=security_for_event,
            trace_id=trace_id,
            call_id=call_id,
            compatibility=compatibility or _compatibility_from_event(event),
            approval_timeout=self.approval_timeout,
            approval_poll_interval=self.approval_poll_interval,
        )
        if message_gate is not None:
            return message_gate
        if message_release is not None:
            if strong_release is not None:
                failure = _multiple_binding_failure(message_release)
                assert message_receipt_context is not None
                return _strong_binding_failure_result(
                    self.guard_adapter,
                    tool_name=tool_name,
                    call_id=call_id,
                    event=event,
                    decision=decision,
                    audit_event=audit_event,
                    compatibility=compatibility or _compatibility_from_event(event),
                    failure=failure,
                    receipt_event=message_receipt_context[0],
                    receipt_decision=message_receipt_context[1],
                )
            strong_release = message_release
            approval_resolution = message_release.approval_resolution
            assert message_receipt_context is not None
            receipt_event, receipt_decision = message_receipt_context

        lease_id = strong_release.lease.lease_id if strong_release is not None else None
        consumption_id = (
            strong_release.lease.consumption_id if strong_release is not None else None
        )
        enforcement = strong_release.enforcement if strong_release is not None else None

        side_effects_measured = bool(
            hasattr(self.tool_runtime, "snapshot")
            and hasattr(self.tool_runtime, "diff")
        )
        before = self.tool_runtime.snapshot() if side_effects_measured else None

        if strong_release is not None:
            try:
                validate_strong_release_for_invocation(strong_release)
            except StrongBindingFailure as failure:
                return _strong_binding_failure_result(
                    self.guard_adapter,
                    tool_name=tool_name,
                    call_id=call_id,
                    event=event,
                    decision=decision,
                    audit_event=audit_event,
                    compatibility=compatibility or _compatibility_from_event(event),
                    failure=failure,
                    receipt_event=receipt_event,
                    receipt_decision=receipt_decision,
                )

        invoked_at = utc_now_iso()
        start_audit_id: str | None = None
        if _supports_runtime_outcome(self.guard_adapter, receipt_decision):
            started = build_tool_started_observation(
                receipt_event,
                receipt_decision,
                approval_resolution=approval_resolution,
                timestamp=invoked_at,
                enforcement=enforcement,
                lease_id=lease_id,
                consumption_id=consumption_id,
            )
            start_error = submit_runtime_receipt(self.guard_adapter, started)
            if start_error is not None:
                # Lease consumption already happened, but the invocation
                # boundary was never entered.  Best-effort a terminal fact with
                # the same non-secret IDs so the consumed authorization is not
                # left uncorrelated.
                terminal_error = _submit_runtime_outcome(
                    self.guard_adapter,
                    receipt_event,
                    receipt_decision,
                    execution_status="not_invoked",
                    approval_resolution=approval_resolution,
                    intervention_type="runtime_receipt_failure",
                    intervention_reason="The start receipt failed before runtime invocation.",
                    enforcement=enforcement,
                    lease_id=lease_id,
                    consumption_id=consumption_id,
                )
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
                result.runtime_receipt_error = terminal_error or start_error
                result.block_semantics = "runtime_receipt_failure"
                result.counts_as_effective_block = False
                result.lease_id = lease_id
                result.consumption_id = consumption_id
                return ToolExecutionResult.model_validate(
                    tool_result_with_compatibility(
                        result.model_dump(),
                        compatibility or _compatibility_from_event(event),
                    )
                )
            start_audit_id = started.audit_id
            # The live lease authorized the action when this receipt persisted.
            # Do not turn later clock movement into a false start + not_invoked.
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
                approval_id=(
                    _approval_id(getattr(receipt_decision, "approval", None))
                    if strong_release is not None
                    else None
                ),
                approval_consumed=strong_release is not None,
                approval_decision=(
                    "allow_once" if strong_release is not None else None
                ),
                approval_wait_latency_ms=(
                    strong_release.approval_wait_latency_ms
                    if strong_release is not None
                    else None
                ),
                approval_resolution=(
                    strong_release.approval_resolution
                    if strong_release is not None
                    else None
                ),
                tool_executed_after_approval=strong_release is not None,
                lease_id=lease_id,
                consumption_id=consumption_id,
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
                receipt_event=receipt_event,
                receipt_decision=receipt_decision,
                approval_resolution=approval_resolution,
                enforcement=enforcement,
                lease_id=lease_id,
                consumption_id=consumption_id,
            )
            if not result_outcome_attempted:
                payload.runtime_receipt_error = _submit_runtime_outcome(
                    self.guard_adapter,
                    receipt_event,
                    receipt_decision,
                    execution_status="executed",
                    approval_resolution=approval_resolution,
                    invoked_at=invoked_at,
                    side_effects=side_effects,
                    side_effects_measured=side_effects_measured,
                    parent_audit_id=start_audit_id,
                    enforcement=enforcement,
                    lease_id=lease_id,
                    consumption_id=consumption_id,
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
                approval_id=(
                    _approval_id(getattr(receipt_decision, "approval", None))
                    if strong_release is not None
                    else None
                ),
                approval_consumed=strong_release is not None,
                approval_decision=(
                    "allow_once" if strong_release is not None else None
                ),
                approval_wait_latency_ms=(
                    strong_release.approval_wait_latency_ms
                    if strong_release is not None
                    else None
                ),
                approval_resolution=(
                    strong_release.approval_resolution
                    if strong_release is not None
                    else None
                ),
                tool_executed_after_approval=strong_release is not None,
                runtime_receipt_error=_submit_runtime_outcome(
                    self.guard_adapter,
                    receipt_event,
                    receipt_decision,
                    execution_status="failed",
                    approval_resolution=approval_resolution,
                    invoked_at=invoked_at,
                    error=str(exc),
                    side_effects=side_effects,
                    side_effects_measured=side_effects_measured,
                    parent_audit_id=start_audit_id,
                    enforcement=enforcement,
                    lease_id=lease_id,
                    consumption_id=consumption_id,
                ),
                lease_id=lease_id,
                consumption_id=consumption_id,
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
    approval_timeout: float,
    approval_poll_interval: float,
) -> tuple[
    ToolExecutionResult | None,
    StrongBindingRelease | None,
    tuple[Any, Any] | None,
]:
    if tool_name != "memory_write" or not hasattr(
        guard_adapter, "evaluate_memory_write"
    ):
        return None, None, None
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
            return (
                _audit_failure_result(
                    tool_name=tool_name,
                    call_id=call_id,
                    event=event,
                    audit_event=audit_event,
                    error=audit_error,
                    compatibility=compatibility,
                ),
                None,
                None,
            )
    strong_release: StrongBindingRelease | None = None
    if _should_attempt_strong_binding(decision):
        try:
            strong_release = authorize_strong_approval(
                guard_adapter,
                decision,
                expected_action_id=_event_action_id(event) or call_id,
                expected_runtime_binding_id=_expected_runtime_binding_id(guard_adapter),
                approval_id=_approval_id(getattr(decision, "approval", None)),
                timeout_seconds=approval_timeout,
                poll_interval_seconds=approval_poll_interval,
            )
        except StrongBindingFailure as failure:
            return (
                _strong_binding_failure_result(
                    guard_adapter,
                    tool_name=tool_name,
                    call_id=call_id,
                    event=event,
                    decision=decision,
                    audit_event=audit_event,
                    compatibility=compatibility,
                    failure=failure,
                ),
                None,
                None,
            )
    if strong_release is not None:
        approval_blocked = False
        approval_resolution = strong_release.approval_resolution
    else:
        approval_blocked, approval_resolution = _resolve_approval(
            guard_adapter, decision
        )
    if decision.decision != "deny" and not approval_blocked:
        return (
            None,
            strong_release,
            (event, decision) if strong_release is not None else None,
        )
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
    return (
        ToolExecutionResult.model_validate(
            tool_result_with_compatibility(payload.model_dump(), compatibility)
        ),
        None,
        None,
    )


def _evaluate_message_send_gate(
    guard_adapter: Any,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    security: dict[str, Any],
    trace_id: str,
    call_id: str,
    compatibility: dict[str, Any],
    approval_timeout: float,
    approval_poll_interval: float,
) -> tuple[
    ToolExecutionResult | None,
    StrongBindingRelease | None,
    tuple[Any, Any] | None,
]:
    if tool_name != "send_email" or not hasattr(
        guard_adapter, "evaluate_message_send"
    ):
        return None, None, None
    event, decision = guard_adapter.evaluate_message_send(
        arguments=arguments,
        security=security,
        trace_id=trace_id,
        call_id=call_id,
    )
    audit_event: AuditEvent | None = None
    if adapter_submits_policy_audit(guard_adapter):
        audit_event = guard_adapter.build_audit_event(event, decision)
        assert audit_event is not None
        audit_error = _submit_audit_event(guard_adapter, audit_event)
        if audit_error is not None:
            return (
                _audit_failure_result(
                    tool_name=tool_name,
                    call_id=call_id,
                    event=event,
                    audit_event=audit_event,
                    error=audit_error,
                    compatibility=compatibility,
                ),
                None,
                None,
            )
    strong_release: StrongBindingRelease | None = None
    if _should_attempt_strong_binding(decision):
        try:
            strong_release = authorize_strong_approval(
                guard_adapter,
                decision,
                expected_action_id=_event_action_id(event) or call_id,
                expected_runtime_binding_id=_expected_runtime_binding_id(guard_adapter),
                approval_id=_approval_id(getattr(decision, "approval", None)),
                timeout_seconds=approval_timeout,
                poll_interval_seconds=approval_poll_interval,
            )
        except StrongBindingFailure as failure:
            return (
                _strong_binding_failure_result(
                    guard_adapter,
                    tool_name=tool_name,
                    call_id=call_id,
                    event=event,
                    decision=decision,
                    audit_event=audit_event,
                    compatibility=compatibility,
                    failure=failure,
                ),
                None,
                None,
            )
    if strong_release is not None:
        approval_blocked = False
        approval_resolution = strong_release.approval_resolution
    else:
        approval_blocked, approval_resolution = _resolve_approval(
            guard_adapter,
            decision,
            timeout_seconds=approval_timeout,
            poll_interval_seconds=approval_poll_interval,
        )
    if decision.decision != "deny" and not approval_blocked:
        return (
            None,
            strong_release,
            (event, decision) if strong_release is not None else None,
        )
    payload = ToolExecutionResult(
        tool_name=tool_name,
        call_id=call_id,
        executed=False,
        blocked=True,
        decision=decision.decision,
        status="blocked",
        result=None,
        safe_message=decision.safe_message
        or "The outbound message was blocked by AgentGuard.",
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
            intervention_reason="The message gate stopped outbound delivery before the runtime was invoked.",
        ),
    )
    return (
        ToolExecutionResult.model_validate(
            tool_result_with_compatibility(payload.model_dump(), compatibility)
        ),
        None,
        None,
    )


def _multiple_binding_failure(release: StrongBindingRelease) -> StrongBindingFailure:
    return StrongBindingFailure(
        EnforcementEvidence(
            gate_state="binding_failed",
            binding_check_status="failed",
            lease_consume_outcome="consumed",
            reason_codes=("rte-05:multiple_binding_conflict",),
        ),
        approval_resolution=release.approval_resolution,
        approval_wait_latency_ms=release.approval_wait_latency_ms,
        correlation=ExecutionLeaseCorrelation(
            lease_id=release.lease.lease_id,
            consumption_id=release.lease.consumption_id,
        ),
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
    receipt_event: Any,
    receipt_decision: Any,
    approval_resolution: dict[str, Any] | None,
    enforcement: Any | None,
    lease_id: str | None,
    consumption_id: str | None,
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
    approval_blocked, result_approval_resolution = _resolve_approval(
        guard_adapter, decision
    )
    if decision.decision != "deny" and not approval_blocked:
        # A non-intervening result check is a content checkpoint, not the
        # terminal action receipt. Let the caller retain the original
        # tool-call policy identity when it records execution completion.
        return payload, False
    outcome_attempted = _supports_runtime_outcome(guard_adapter, decision)
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
        receipt_event if enforcement is not None else event,
        receipt_decision if enforcement is not None else decision,
        execution_status="executed",
        approval_resolution=(
            approval_resolution
            if enforcement is not None
            else result_approval_resolution
        ),
        invoked_at=invoked_at,
        side_effects=side_effects,
        side_effects_measured=side_effects_measured,
        result_disposition="quarantined",
        result_sanitized=False,
        intervention_type="tool_result_quarantine",
        intervention_reason="The tool executed, but its result was withheld from Agent context.",
        enforcement=enforcement,
        lease_id=lease_id,
        consumption_id=consumption_id,
    )
    return payload, (
        _supports_runtime_outcome(guard_adapter, receipt_decision)
        if enforcement is not None
        else outcome_attempted
    )


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


def _event_action_id(event: Any) -> str | None:
    dumped = _dump_event(event)
    direct = dumped.get("action_id")
    if isinstance(direct, str) and direct:
        return direct
    payload = dumped.get("payload")
    if isinstance(payload, dict):
        action_id = payload.get("action_id")
        if isinstance(action_id, str) and action_id:
            return action_id
        tool = payload.get("tool")
    else:
        tool = dumped.get("tool")
    if isinstance(tool, dict):
        call_id = tool.get("call_id") or tool.get("tool_call_id")
        if isinstance(call_id, str) and call_id:
            return call_id
    return None


def _expected_runtime_binding_id(guard_adapter: Any) -> str | None:
    config = getattr(guard_adapter, "config", None)
    value = getattr(config, "runtime_binding_id", None)
    return value if isinstance(value, str) and value else None


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
    guard_adapter: Any,
    decision: Any,
    *,
    timeout_seconds: float | None = None,
    poll_interval_seconds: float = 0.5,
) -> tuple[bool, dict[str, Any] | None]:
    """Resolve ASK, optionally polling the non-blocking approval endpoint.

    Only the message-send gate supplies a timeout budget. The primary tool,
    memory-write, and post-execution gates keep the existing single-probe,
    fail-closed behavior by leaving ``timeout_seconds`` unset.
    """
    if getattr(decision, "decision", None) != "ask":
        return False, None
    release = _v21_approval_release(decision)
    if release == "forbidden":
        # An unreleasable V2 ASK is a policy intervention, not a pending human
        # workflow.  Waiting here would recreate the legacy C1 escape hatch.
        return True, {
            "status": "forbidden",
            "decision": "deny",
            "approval_id": None,
            "reason": "v21_ask_release_forbidden",
        }
    if release == "strong_binding_required":
        # A valid bound path is consumed before this helper is reached.  Getting
        # here therefore means the binding was missing; never fall back to the
        # unbound C1 approval wait path.
        return True, {
            "status": "unavailable",
            "decision": "deny",
            "approval_id": _approval_id(getattr(decision, "approval", None)),
            "reason": "v21_strong_binding_missing",
        }
    approval_id = _approval_id(getattr(decision, "approval", None))
    if not approval_id or not hasattr(guard_adapter, "wait_for_approval"):
        return True, {
            "status": "unavailable",
            "decision": None,
            "approval_id": approval_id,
        }
    deadline = time.monotonic() + timeout_seconds if timeout_seconds else None
    poll_interval = max(0.1, min(poll_interval_seconds, 5.0))
    resolution: Any = None
    while True:
        resolution = guard_adapter.wait_for_approval(approval_id)
        if not isinstance(resolution, dict):
            return True, {
                "status": "error",
                "decision": None,
                "approval_id": approval_id,
            }
        try:
            resolution = normalize_approval_resolution(resolution)
        except ApprovalResolutionValidationError:
            return True, {
                "status": "error",
                "decision": "deny",
                "approval_id": approval_id,
                "reason": "approval_resolution_invalid",
            }
        status = str(resolution.get("status") or "").strip().lower()
        if status != "pending":
            break
        if deadline is None or time.monotonic() >= deadline:
            break
        time.sleep(min(poll_interval, max(deadline - time.monotonic(), 0.0)))
    approved = resolution.get("status") == "resolved" and str(
        resolution.get("decision") or ""
    ).lower() in {
        "allow",
        "allow_once",
        "allow_session",
    }
    return not approved, resolution


def _v21_approval_release(decision: Any) -> str | None:
    authority = getattr(decision, "decision_authority", None)
    if authority is None:
        return None
    if hasattr(authority, "model_dump"):
        authority = authority.model_dump(mode="json")
    if not isinstance(authority, dict):
        # A malformed server projection attached to an ASK is never allowed to
        # weaken into the legacy approval path.
        return "forbidden"
    if authority.get("source") != "v21":
        return None
    release = authority.get("approval_release")
    if release in {"strong_binding_required", "forbidden"}:
        return str(release)
    return "forbidden"


def _should_attempt_strong_binding(decision: Any) -> bool:
    release = _v21_approval_release(decision)
    if release == "forbidden":
        return False
    binding_present = raw_enforcement_binding(decision) is not None
    if release == "strong_binding_required":
        return binding_present
    # Legacy/current ASK behavior remains unchanged: a response that carries an
    # RTE binding uses the existing strong path; otherwise C1 remains available.
    return binding_present


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
    enforcement: Any | None = None,
    lease_id: str | None = None,
    consumption_id: str | None = None,
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
        enforcement=enforcement,
        lease_id=lease_id,
        consumption_id=consumption_id,
    )
    return submit_runtime_receipt(guard_adapter, receipt)


def _strong_binding_failure_result(
    guard_adapter: Any,
    *,
    tool_name: str,
    call_id: str,
    event: Any,
    decision: Any,
    audit_event: AuditEvent | None,
    compatibility: dict[str, Any],
    failure: StrongBindingFailure,
    receipt_event: Any | None = None,
    receipt_decision: Any | None = None,
    parent_audit_id: str | None = None,
) -> ToolExecutionResult:
    binding_event = receipt_event if receipt_event is not None else event
    binding_decision = receipt_decision if receipt_decision is not None else decision
    result = blocked_result(
        tool_name=tool_name,
        call_id=call_id,
        event=event,
        decision=decision,
        audit_event=audit_event,
    )
    timed_out = failure.evidence.gate_state == "timed_out"
    result.status = "blocked"
    result.safe_message = (
        "The tool call timed out before the strong-approved action reached invocation."
        if timed_out
        else "The tool call was blocked because its strong approval binding could not be verified."
    )
    result.block_semantics = (
        "strong_binding_timeout" if timed_out else "strong_binding_failure"
    )
    result.counts_as_effective_block = False
    result.runtime_terminal = True
    result.terminal_reason = result.block_semantics
    result.approval_id = _approval_id(getattr(binding_decision, "approval", None))
    result.approval_resolution = failure.approval_resolution
    result.approval_wait_latency_ms = failure.approval_wait_latency_ms
    lease_id = (
        failure.correlation.lease_id if failure.correlation is not None else None
    )
    consumption_id = (
        failure.correlation.consumption_id
        if failure.correlation is not None
        else None
    )
    result.lease_id = lease_id
    result.consumption_id = consumption_id
    if failure.approval_resolution is not None:
        result.approval_decision = (
            str(failure.approval_resolution.get("decision") or "") or None
        )
        result.approval_consumed = (
            failure.approval_resolution.get("status") == "resolved"
        )
    result.runtime_receipt_error = _submit_runtime_outcome(
        guard_adapter,
        binding_event,
        binding_decision,
        execution_status="not_invoked",
        approval_resolution=failure.approval_resolution,
        intervention_type="approval_not_obtained",
        intervention_reason="Strong approval binding was not valid at the invocation boundary.",
        parent_audit_id=parent_audit_id,
        enforcement=failure.evidence,
        lease_id=lease_id,
        consumption_id=consumption_id,
    )
    return ToolExecutionResult.model_validate(
        tool_result_with_compatibility(result.model_dump(), compatibility)
    )


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
