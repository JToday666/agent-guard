"""One Product invocation boundary for native tools and native model calls."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
from threading import Lock
from typing import Any, Callable, Literal, TYPE_CHECKING, cast

from .activation_ack import ActivationAckV1, ProductActivationError
from .event_models import (
    PolicyDecision,
    RuntimeGuardEvent,
    ToolCallEvent,
    ToolExecutionResult,
    utc_now_iso,
)
from .native_tools import PreparedNativeToolCall
from .product_delivery import ProductReceiptDeliveryResult
from .runtime_receipts import ExecutionStatus, build_runtime_outcome
from .strong_binding import (
    StrongBindingFailure,
    StrongBindingRelease,
    authorize_strong_approval,
    validate_strong_release_for_invocation,
)

if TYPE_CHECKING:
    from .langgraph_adapter import LangGraphAdapter
    from .native_events import NativeGuardEventBuilder, NativeModelOrigin


def assert_product_execution_available() -> None:
    """B09 replaces this fixed fuse with the complete composition check."""
    raise ProductActivationError("product_execution_unavailable")


@dataclass(frozen=True, slots=True)
class GuardedResultDisposition:
    safe_value: Any = field(repr=False)
    quarantined: bool
    delivery: ProductReceiptDeliveryResult
    sanitized: bool = False
    summary: str = ""


@dataclass(frozen=True, slots=True)
class GuardedInvocationResult:
    invocation_status: ExecutionStatus
    value: Any = field(repr=False)
    quarantined: bool
    delivery: ProductReceiptDeliveryResult
    error_code: str | None = None


class GuardedExecutionTemplate:
    def __init__(
        self,
        adapter: LangGraphAdapter,
        *,
        event_builder: NativeGuardEventBuilder,
        approval_timeout: float = 60.0,
        approval_poll_interval: float = 0.25,
    ) -> None:
        if any(
            type(value) not in (int, float) or not math.isfinite(value) or value <= 0
            for value in (approval_timeout, approval_poll_interval)
        ):
            raise ProductActivationError("execution_configuration_invalid")
        self._adapter = adapter
        self._events = event_builder
        self._approval_timeout = approval_timeout
        self._approval_poll = approval_poll_interval
        # Held across evaluate, approval, invoke, isolation and final receipt.
        self._slot = Lock()

    def execute_action(
        self,
        prepared: PreparedNativeToolCall,
        *,
        security: dict[str, Any],
        trace_id: str,
        invoke_once: Callable[[], Any],
        model_origin: NativeModelOrigin,
    ) -> ToolExecutionResult:
        assert_product_execution_available()
        if not isinstance(prepared, PreparedNativeToolCall):
            raise ProductActivationError("native_tool_call_invalid")
        if not self._slot.acquire(blocking=False):
            return self._tool_result(prepared, _failure("action_already_active"))
        try:
            prepared.assert_current()
            self._adapter.product_action_barrier.assert_ready()
            security = deepcopy(security)
            specialized = self._events.build_specialized_action(
                prepared, security, trace_id, model_origin=model_origin
            )
            event = (
                specialized
                if specialized is not None
                else self._events.build_tool_call(
                    prepared, security, trace_id, model_origin=model_origin
                )
            )
            # The adapter's serializer accepts both frozen event model shapes.
            decision = self._adapter.evaluate_guard_event(cast(Any, event))
            self._assert_authority(decision)
            if decision.decision == "deny":
                return self._tool_result(
                    prepared, self._deny(event, decision, "policy_deny")
                )
            action_id = (
                f"act_{event.event_id}"
                if event.event_type == "message_send_proposed"
                else prepared.call_id
            )
            release = None
            if decision.decision == "ask":
                directive = decision.approval_release_directive
                if directive is None or directive.mode != "strong_binding":
                    return self._tool_result(
                        prepared,
                        self._deny(event, decision, "approval_release_forbidden"),
                    )
                try:
                    release = authorize_strong_approval(
                        self._adapter,
                        decision,
                        expected_action_id=action_id,
                        expected_runtime_binding_id=self._adapter.config.runtime_binding_id,
                        approval_id=(decision.approval or {}).get("approval_id"),
                        timeout_seconds=self._approval_timeout,
                        poll_interval_seconds=self._approval_poll,
                    )
                    if release is None:
                        return self._tool_result(
                            prepared,
                            self._deny(event, decision, "approval_release_forbidden"),
                        )
                except StrongBindingFailure as failure:
                    return self._tool_result(
                        prepared,
                        self._deny(
                            event, decision, "strong_binding_failed", failure=failure
                        ),
                    )

            def invoke() -> Any:
                prepared.assert_current()
                return invoke_once()

            def postprocess(value: Any) -> GuardedResultDisposition:
                checked = self._events.build_tool_result(
                    prepared, value, security, trace_id
                )
                policy = self._adapter.evaluate_guard_event(checked)
                self._assert_authority(policy)
                blocked = policy.decision != "allow"
                receipt = build_runtime_outcome(
                    checked,
                    policy,
                    execution_status="executed",
                    invoked_at=utc_now_iso(),
                    result_disposition="quarantined" if blocked else "passed_through",
                    result_summary=(
                        "Native tool result was withheld."
                        if blocked
                        else "Native tool result passed the content gate."
                    ),
                )
                delivery = self._adapter.submit_product_receipt(receipt)
                return GuardedResultDisposition(
                    None if blocked else deepcopy(value),
                    blocked,
                    delivery,
                )

            result = self._run_guarded_action(
                event,
                decision,
                action_id=action_id,
                invoke_once=invoke,
                postprocess=postprocess,
                start_kind="tool_call",
                strong_release=release,
                approval_resolution=release.approval_resolution if release else None,
            )
            return self._tool_result(
                prepared, result, decision=decision, strong_release=release
            )
        except Exception:
            return self._tool_result(prepared, _failure("native_action_failed"))
        finally:
            self._slot.release()

    def run_guarded_action(
        self,
        event: RuntimeGuardEvent | ToolCallEvent,
        decision: PolicyDecision,
        *,
        action_id: str,
        invoke_once: Callable[[], Any],
        postprocess: Callable[[Any], GuardedResultDisposition],
        start_kind: Literal["tool_call", "model_call"],
        strong_release: StrongBindingRelease | None = None,
        approval_resolution: dict[str, Any] | None = None,
    ) -> GuardedInvocationResult:
        assert_product_execution_available()
        if not self._slot.acquire(blocking=False):
            return _failure("action_already_active")
        try:
            return self._run_guarded_action(
                event,
                decision,
                action_id=action_id,
                invoke_once=invoke_once,
                postprocess=postprocess,
                start_kind=start_kind,
                strong_release=strong_release,
                approval_resolution=approval_resolution,
            )
        finally:
            self._slot.release()

    def _run_guarded_action(
        self,
        event: RuntimeGuardEvent | ToolCallEvent,
        decision: PolicyDecision,
        *,
        action_id: str,
        invoke_once: Callable[[], Any],
        postprocess: Callable[[Any], GuardedResultDisposition],
        start_kind: Literal["tool_call", "model_call"],
        strong_release: StrongBindingRelease | None,
        approval_resolution: dict[str, Any] | None,
    ) -> GuardedInvocationResult:
        barrier = self._adapter.product_action_barrier
        ready = False
        begin_attempted = False
        try:
            if (
                start_kind not in {"tool_call", "model_call"}
                or not callable(invoke_once)
                or not callable(postprocess)
            ):
                raise ProductActivationError("execution_configuration_invalid")
            self._assert_authority(decision)
            event = event.model_copy(deep=True)
            decision = decision.model_copy(deep=True)
            approval_resolution = deepcopy(approval_resolution)
            if decision.decision != "allow" and not (
                decision.decision == "ask" and strong_release is not None
            ):
                return self._deny(event, decision, "approval_release_forbidden")
            barrier.assert_ready()
            ready = True
            # Observe current identity without replacing this action's ACK carrier.
            self._adapter._product_client().snapshot_product_ack()
            ack = (
                decision._consumption_activation_ack
                if strong_release
                else decision._evaluation_activation_ack
            )
            if (
                not isinstance(ack, ActivationAckV1)
                or ack.remaining_seconds(
                    now=datetime.now(timezone.utc),
                    max_age_seconds=getattr(
                        self._adapter.config, "activation_ack_max_age_seconds", 120
                    ),
                )
                <= 0
            ):
                raise ProductActivationError("activation_ack_expired")
            if strong_release is not None:
                validate_strong_release_for_invocation(strong_release)
            started = self._events.build_action_start(
                event,
                decision,
                start_kind=start_kind,
                approval_resolution=approval_resolution,
                timestamp=utc_now_iso(),
                **_release_fields(strong_release),
            )
            begin_attempted = True
            begun = barrier.begin_action(
                action_id=action_id, event_id=event.event_id, start_receipt=started
            )
            if begun.delivery.status != "recorded" or begun.ticket is None:
                delivery = begun.delivery
                if begun.abort_proof is not None:
                    terminal = build_runtime_outcome(
                        event,
                        decision,
                        execution_status="not_invoked",
                        approval_resolution=approval_resolution,
                        parent_audit_id=started.audit_id,
                        intervention_type="runtime_receipt_failure",
                        intervention_reason="Start confirmation failed before the invocation boundary.",
                        **_release_fields(strong_release),
                    )
                    delivery = barrier.abort_action(begun.abort_proof, terminal)
                return GuardedInvocationResult(
                    "not_invoked", None, True, delivery, "runtime_start_unconfirmed"
                )
        except StrongBindingFailure as failure:
            return self._deny(event, decision, "strong_binding_failed", failure=failure)
        except Exception:
            if ready and not begin_attempted and strong_release is not None:
                return self._deny(
                    event,
                    decision,
                    "runtime_start_failed",
                    strong_release=strong_release,
                    approval_resolution=approval_resolution,
                )
            return _failure("runtime_start_failed")

        # Start confirmation commits exactly one callback. No refresh, retry, or
        # approval re-consumption is permitted between this point and invocation.
        invoked_at = utc_now_iso()
        try:
            value = invoke_once()
        except Exception:
            try:
                terminal = build_runtime_outcome(
                    event,
                    decision,
                    execution_status="failed",
                    invoked_at=invoked_at,
                    error="Native invocation failed.",
                    parent_audit_id=started.audit_id,
                    approval_resolution=approval_resolution,
                    **_release_fields(strong_release),
                )
                delivered = barrier.finish_action(begun.ticket, terminal)
            except Exception:
                return _unrecorded_outcome(barrier, begun.ticket, "failed")
            return GuardedInvocationResult(
                "failed",
                None,
                True,
                delivered,
                "native_invocation_failed",
            )
        except BaseException:
            barrier.mark_action_unknown(begun.ticket)
            raise

        try:
            disposition = postprocess(value)
            if not isinstance(disposition, GuardedResultDisposition) or not isinstance(
                disposition.delivery, ProductReceiptDeliveryResult
            ):
                raise ValueError
            safe_value = deepcopy(disposition.safe_value)
        except Exception:
            disposition = GuardedResultDisposition(
                None,
                True,
                ProductReceiptDeliveryResult(
                    "failed", error_code="result_checkpoint_failed"
                ),
            )
            safe_value = None
        except BaseException:
            barrier.mark_action_unknown(begun.ticket)
            raise
        try:
            publish = (
                not disposition.quarantined
                and disposition.delivery.status == "recorded"
            )
            if disposition.delivery.status in {"failed", "permanent_rejected"}:
                barrier.block_actions()
            terminal = build_runtime_outcome(
                event,
                decision,
                execution_status="executed",
                invoked_at=invoked_at,
                parent_audit_id=started.audit_id,
                approval_resolution=approval_resolution,
                result_summary="The native invocation completed; publication is separately gated.",
                **_release_fields(strong_release),
            )
            # Content checkpoints never replace the original action's anchor.
            terminal.evidence.execution["tool_result_entered_context"] = False
            terminal.evidence.result["disposition"] = (
                "quarantined"
                if not publish
                else ("modified" if disposition.sanitized else "passed_through")
            )
            terminal.evidence.result["sanitized"] = disposition.sanitized
            delivery = barrier.finish_action(begun.ticket, terminal)
            combined = _combine_delivery(disposition.delivery, delivery)
        except Exception:
            return _unrecorded_outcome(barrier, begun.ticket, "executed")
        return GuardedInvocationResult(
            "executed",
            safe_value if publish and combined.status == "recorded" else None,
            not publish,
            combined,
            (
                None
                if publish and combined.status == "recorded"
                else "runtime_result_withheld"
            ),
        )

    @staticmethod
    def _assert_authority(decision: PolicyDecision) -> None:
        authority = decision.decision_authority
        directive = decision.approval_release_directive
        ack = decision._evaluation_activation_ack
        if (
            authority is None
            or directive is None
            or not isinstance(ack, ActivationAckV1)
            or (authority.source, authority.mode, authority.selection_basis)
            != ("v21", "active", "profile_all")
            or authority.matched_path_ids
            # The official selector may conservatively raise an action to
            # ASK/DENY. That is never permission to execute: ASK still needs
            # its exact strong release, and a floored ALLOW is invalid.
            or (authority.legacy_floor_applied and decision.decision == "allow")
            or authority.activation_ref_digest != ack.activation_ref_digest
            or directive.activation_ref_digest != ack.activation_ref_digest
            or directive.capability_digest != ack.capability_digest
            or not decision.policy_audit_id
        ):
            raise ProductActivationError("official_authority_required")

    def _deny(
        self,
        event: Any,
        decision: PolicyDecision,
        code: str,
        *,
        failure: StrongBindingFailure | None = None,
        strong_release: StrongBindingRelease | None = None,
        approval_resolution: dict[str, Any] | None = None,
    ) -> GuardedInvocationResult:
        try:
            fields: dict[str, Any] = {}
            if strong_release is not None:
                fields = {
                    **_release_fields(strong_release),
                    "approval_resolution": deepcopy(approval_resolution),
                }
            if failure is not None:
                fields = {
                    "enforcement": failure.evidence,
                    "approval_resolution": failure.approval_resolution,
                }
                if failure.correlation is not None:
                    fields.update(
                        lease_id=failure.correlation.lease_id,
                        consumption_id=failure.correlation.consumption_id,
                    )
            receipt = build_runtime_outcome(
                event,
                decision,
                execution_status="not_invoked",
                intervention_type="policy_deny",
                intervention_reason="The native action was blocked before invocation.",
                **fields,
            )
            delivery = self._adapter.submit_product_receipt(receipt)
        except Exception:
            delivery = ProductReceiptDeliveryResult(
                "failed", error_code="denial_receipt_failed"
            )
        return GuardedInvocationResult("not_invoked", None, True, delivery, code)

    @staticmethod
    def _tool_result(
        prepared: PreparedNativeToolCall,
        result: GuardedInvocationResult,
        *,
        decision: PolicyDecision | None = None,
        strong_release: StrongBindingRelease | None = None,
    ) -> ToolExecutionResult:
        allowed = (
            result.invocation_status == "executed"
            and not result.quarantined
            and result.delivery.status == "recorded"
        )
        return ToolExecutionResult(
            tool_name=prepared.name,
            call_id=prepared.call_id,
            decision=decision.decision if decision else None,
            executed=result.invocation_status in {"executed", "failed"},
            blocked=not allowed,
            status=(
                "executed"
                if allowed
                else (
                    "quarantined"
                    if result.invocation_status == "executed"
                    else "blocked"
                )
            ),
            result=result.value if allowed else None,
            error=result.error_code,
            safe_message=(
                None if allowed else "The native action or its result was withheld."
            ),
            quarantine_applied=result.quarantined
            and result.invocation_status == "executed",
            runtime_receipt_status=(
                "recorded" if result.delivery.status == "recorded" else "failed"
            ),
            runtime_receipt_error=(
                None if result.delivery.status == "recorded" else result.delivery.status
            ),
            block_semantics=None if allowed else result.error_code,
            approval_id=(
                strong_release.approval_resolution.get("approval_id")
                if strong_release
                else None
            ),
            approval_consumed=strong_release is not None,
            approval_decision="allow_once" if strong_release else None,
            approval_wait_latency_ms=(
                strong_release.approval_wait_latency_ms if strong_release else None
            ),
            tool_executed_after_approval=strong_release is not None
            and result.invocation_status in {"executed", "failed"},
            lease_id=strong_release.lease.lease_id if strong_release else None,
            consumption_id=(
                strong_release.lease.consumption_id if strong_release else None
            ),
        )


def _release_fields(release: StrongBindingRelease | None) -> dict[str, Any]:
    return (
        {}
        if release is None
        else {
            "enforcement": release.enforcement,
            "lease_id": release.lease.lease_id,
            "consumption_id": release.lease.consumption_id,
        }
    )


def _unrecorded_outcome(
    barrier: Any, ticket: Any, status: ExecutionStatus
) -> GuardedInvocationResult:
    try:
        barrier.mark_action_unknown(ticket)
    except Exception:
        # A closed or unavailable store already prevents a new invocation.
        pass
    return GuardedInvocationResult(
        status,
        None,
        True,
        ProductReceiptDeliveryResult(
            "failed", error_code="action_terminal_unavailable"
        ),
        "action_terminal_unavailable",
    )


def _failure(code: str) -> GuardedInvocationResult:
    return GuardedInvocationResult(
        "not_invoked",
        None,
        True,
        ProductReceiptDeliveryResult("failed", error_code=code),
        code,
    )


def _combine_delivery(
    first: ProductReceiptDeliveryResult, second: ProductReceiptDeliveryResult
) -> ProductReceiptDeliveryResult:
    priority = {
        "recorded": 0,
        "queued_durable": 1,
        "permanent_rejected": 2,
        "failed": 3,
    }
    return first if priority[first.status] > priority[second.status] else second
