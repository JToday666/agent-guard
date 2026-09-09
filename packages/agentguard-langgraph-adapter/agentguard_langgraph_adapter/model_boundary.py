"""One guarded model call using only a validated, immutable context snapshot."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Callable, TYPE_CHECKING

from .context_guard import validate_and_prepare_context
from .event_models import utc_now_iso
from .native_events import (
    NativeBoundaryError,
    NativeGuardEventBuilder,
    native_json,
    native_text,
)
from .product_delivery import ProductReceiptDeliveryResult
from .runtime_receipts import ExecutionStatus, build_runtime_outcome

if TYPE_CHECKING:
    from .execution_template import GuardedExecutionTemplate
    from .langgraph_adapter import LangGraphAdapter

_SOURCE_KEYS = {
    "role",
    "content",
    "source_id",
    "source_type",
    "source_trust",
    "tool_calls",
    "tool_call_id",
    "name",
}


@dataclass(frozen=True, slots=True)
class NativeModelOutput:
    _json: str = field(repr=False)

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> NativeModelOutput:
        snapshot = json.loads(native_json(value))
        if (
            type(snapshot) is not dict
            or set(snapshot) != {"content", "tool_calls", "invalid_tool_calls"}
            or type(snapshot["content"]) not in {str, list}
            or type(snapshot["tool_calls"]) is not list
            or type(snapshot["invalid_tool_calls"]) is not list
            or len(snapshot["tool_calls"]) > 1
        ):
            raise NativeBoundaryError("native_model_output_invalid")
        native_text(snapshot)
        return cls(native_json(snapshot))

    def to_mapping(self) -> dict[str, Any]:
        return json.loads(self._json)


@dataclass(frozen=True, slots=True)
class PreparedNativeContext:
    _messages_json: str = field(repr=False)
    plan_id: str
    plan_digest: str
    context_ref: str
    visible_source_refs: tuple[str, ...]

    def messages(self) -> list[dict[str, Any]]:
        return json.loads(self._messages_json)

    def identity(self) -> dict[str, Any]:
        return {
            "context_plan_id": self.plan_id,
            "context_plan_digest": self.plan_digest,
            "context_ref": self.context_ref,
            "visible_source_refs": list(self.visible_source_refs),
        }


@dataclass(frozen=True, slots=True)
class NativeModelResult:
    output: NativeModelOutput | None = field(repr=False)
    blocked: bool
    invocation_status: ExecutionStatus
    delivery: ProductReceiptDeliveryResult | None
    error_code: str | None = None
    visible_source_refs: tuple[str, ...] = ()
    output_source_ref: str | None = None
    output_policy_audit_id: str | None = None


def _snapshot_sources(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    snapshot = json.loads(native_json(sources))
    if type(snapshot) is not list or not snapshot or len(snapshot) > 20:
        raise NativeBoundaryError("native_context_sources_invalid")
    for source in snapshot:
        if (
            type(source) is not dict
            or set(source) - _SOURCE_KEYS
            or not {"role", "content"} <= set(source)
            or source["role"] not in {"system", "user", "assistant", "tool"}
        ):
            raise NativeBoundaryError("native_context_source_invalid")
        native_text(source["content"])
        if "tool_calls" in source and (
            source["role"] != "assistant"
            or type(source["tool_calls"]) is not list
            or len(source["tool_calls"]) > 1
        ):
            raise NativeBoundaryError("native_context_correlation_invalid")
        if "tool_call_id" in source and (
            source["role"] != "tool"
            or type(source["tool_call_id"]) is not str
            or not source["tool_call_id"]
        ):
            raise NativeBoundaryError("native_context_correlation_invalid")
        if source["role"] == "tool" and "tool_call_id" not in source:
            raise NativeBoundaryError("native_context_correlation_missing")
        if "name" in source and (type(source["name"]) is not str or not source["name"]):
            raise NativeBoundaryError("native_context_correlation_invalid")
    return snapshot


def _validate_message_protocol(messages: list[dict[str, Any]]) -> None:
    pending: tuple[str, str] | None = None
    seen: set[str] = set()
    for message in messages:
        if message["role"] == "tool":
            if (
                pending is None
                or message.get("tool_call_id") != pending[0]
                or message.get("name", pending[1]) != pending[1]
            ):
                raise NativeBoundaryError("native_context_correlation_invalid")
            pending = None
            continue
        if pending is not None:
            raise NativeBoundaryError("native_context_correlation_missing")
        calls = message.get("tool_calls", [])
        if calls:
            call = calls[0]
            if (
                type(call) is not dict
                or set(call) - {"id", "name", "args", "type"}
                or not {"id", "name", "args"} <= set(call)
                or type(call["id"]) is not str
                or not call["id"]
                or type(call["name"]) is not str
                or not call["name"]
                or type(call["args"]) is not dict
                or call.get("type", "tool_call") != "tool_call"
                or call["id"] in seen
            ):
                raise NativeBoundaryError("native_context_correlation_invalid")
            seen.add(call["id"])
            pending = (call["id"], call["name"])
    if pending is not None:
        raise NativeBoundaryError("native_context_correlation_missing")


def _prepare_context(
    sources: list[dict[str, Any]], event: Any, decision: Any
) -> PreparedNativeContext:
    plan = json.loads(native_json(decision.context_plan))
    prepared = validate_and_prepare_context(
        event_id=event.event_id,
        runtime="langgraph",
        sources=sources,
        event_sources=event.payload["sources"],
        context_plan=plan,
    )
    # The strict plan consumer owns inclusion/order/content transformation.
    # Carry only correlation fields from each corresponding included source;
    # these then enter the complete model-input evaluation as well.
    messages = list(prepared.messages)
    included = [
        source
        for source, chunk in zip(sources, plan["chunks"])
        if chunk["transform_state"] in {"preserved", "annotated"}
    ]
    if not messages or len(included) != len(messages):
        raise NativeBoundaryError("native_context_empty")
    for message, source in zip(messages, included):
        for key in ("tool_calls", "tool_call_id", "name"):
            if key in source:
                message[key] = source[key]
    _validate_message_protocol(messages)
    return PreparedNativeContext(
        native_json(messages),
        prepared.plan_id,
        prepared.plan_digest,
        prepared.context_ref,
        prepared.visible_source_refs,
    )


class GuardedModelBoundary:
    """No fallback messages, automatic model retries, or C1 ASK release."""

    def __init__(
        self,
        adapter: LangGraphAdapter,
        *,
        event_builder: NativeGuardEventBuilder,
        executor: GuardedExecutionTemplate,
    ) -> None:
        self.adapter = adapter
        self.event_builder = event_builder
        self.executor = executor

    def _checkpoint(
        self, event: Any, decision: Any, *, accepted: bool
    ) -> ProductReceiptDeliveryResult:
        self.executor._assert_authority(decision)
        now = utc_now_iso()
        observed = accepted or event.event_type == "model_output_produced"
        receipt = build_runtime_outcome(
            event,
            decision,
            execution_status="executed" if observed else "not_invoked",
            invoked_at=now if observed else None,
            completed_at=now,
            side_effects=[],
            side_effects_measured=True,
            result_disposition=(
                "passed_through"
                if accepted
                else "quarantined" if observed else "not_applicable"
            ),
            result_summary=(
                "Native content checkpoint completed."
                if accepted
                else "Native content was withheld."
            ),
        )
        return self.adapter.submit_product_receipt(receipt)

    def invoke(
        self,
        *,
        sources: list[dict[str, Any]],
        security: dict[str, Any],
        trace_id: str,
        model_call_id: str,
        invoke_model: Callable[[list[dict[str, Any]]], Any],
        normalize_output: Callable[[Any], NativeModelOutput],
        provider: str,
        model: str,
        tool_descriptors: list[dict[str, Any]],
        _permit: Any = None,
    ) -> NativeModelResult:
        # Import lazily: the execution template only TYPE_CHECKING-imports the
        # event builder, keeping the base SDK independent of native Host deps.
        from .execution_template import (
            GuardedResultDisposition,
            assert_product_execution_available,
        )
        from .product_composition import (
            invocation_subject,
            action_subject,
            delegated_invocation,
        )

        assert_product_execution_available(
            owner=self,
            permit=_permit,
            callback=invoke_model,
            subject=invocation_subject(
                dict(
                    sources=sources,
                    security=security,
                    trace_id=trace_id,
                    model_call_id=model_call_id,
                    provider=provider,
                    model=model,
                    tool_descriptors=tool_descriptors,
                )
            ),
            postprocess=normalize_output,
        )

        invoked = False
        returned = False
        try:
            frozen_sources = _snapshot_sources(sources)
            frozen_security = json.loads(native_json(security))
            descriptors = json.loads(native_json(tool_descriptors))
            if type(descriptors) is not list or any(
                type(item) is not dict for item in descriptors
            ):
                raise NativeBoundaryError("native_model_descriptors_invalid")
            context_event = self.event_builder.build_context(
                frozen_sources, frozen_security, trace_id
            )
            context_decision = self.adapter.evaluate_guard_event(context_event)
            self.executor._assert_authority(context_decision)
            if context_decision.decision != "allow":
                delivery = self._checkpoint(
                    context_event, context_decision, accepted=False
                )
                return NativeModelResult(
                    None, True, "not_invoked", delivery, "native_context_blocked"
                )
            try:
                prepared = _prepare_context(
                    frozen_sources, context_event, context_decision
                )
            except Exception:
                delivery = self._checkpoint(
                    context_event, context_decision, accepted=False
                )
                return NativeModelResult(
                    None, True, "not_invoked", delivery, "native_context_plan_invalid"
                )
            delivery = self._checkpoint(context_event, context_decision, accepted=True)
            if delivery.status != "recorded":
                return NativeModelResult(
                    None, True, "not_invoked", delivery, "native_checkpoint_unrecorded"
                )
            frozen_security["visible_source_refs"] = list(prepared.visible_source_refs)
            input_event = self.event_builder.build_model(
                phase="input",
                content={"messages": prepared.messages(), "tools": descriptors},
                security=frozen_security,
                trace_id=trace_id,
                provider=provider,
                model=model,
                context_identity=prepared.identity(),
                model_call_id=model_call_id,
            )
            input_decision = self.adapter.evaluate_guard_event(input_event)
            self.executor._assert_authority(input_decision)
            if not input_decision.policy_audit_id:
                raise NativeBoundaryError("native_model_input_identity_invalid")
            if input_decision.decision != "allow":
                delivery = self._checkpoint(input_event, input_decision, accepted=False)
                return NativeModelResult(
                    None, True, "not_invoked", delivery, "native_model_input_blocked"
                )

            output_source_ref: str | None = None
            output_policy_audit_id: str | None = None

            def postprocess(raw: Any) -> GuardedResultDisposition:
                nonlocal output_source_ref, output_policy_audit_id
                try:
                    normalized = normalize_output(raw)
                    if type(normalized) is not NativeModelOutput:
                        raise NativeBoundaryError("native_model_output_invalid")
                    # Snapshot even a normalizer-provided wrapper before policy.
                    output = NativeModelOutput.from_mapping(normalized.to_mapping())
                    projection = output.to_mapping()
                    output_event = self.event_builder.build_model(
                        phase="output",
                        content=projection,
                        security=frozen_security,
                        trace_id=trace_id,
                        provider=provider,
                        model=model,
                        model_call_id=model_call_id,
                        model_input_audit_id=input_decision.policy_audit_id,
                    )
                    output_decision = self.adapter.evaluate_guard_event(output_event)
                    self.executor._assert_authority(output_decision)
                    accepted = (
                        output_decision.decision == "allow"
                        and not projection["invalid_tool_calls"]
                        and bool(output_decision.policy_audit_id)
                    )
                    checkpoint = self._checkpoint(
                        output_event, output_decision, accepted=accepted
                    )
                    if accepted and checkpoint.status == "recorded":
                        # This is provenance for the current proposed action,
                        # never authority to reuse opaque model text as history.
                        output_source_ref = f"source:model:{output_event.event_id}"
                        output_policy_audit_id = output_decision.policy_audit_id
                    return GuardedResultDisposition(
                        safe_value=output if accepted else None,
                        quarantined=not accepted,
                        delivery=checkpoint,
                        summary="Native model output checked.",
                    )
                except Exception:
                    return GuardedResultDisposition(
                        safe_value=None,
                        quarantined=True,
                        delivery=ProductReceiptDeliveryResult(
                            "failed", error_code="native_model_output_invalid"
                        ),
                        summary="Native model output withheld.",
                    )

            def invoke_once() -> Any:
                nonlocal invoked, returned
                invoked = True
                raw = invoke_model(prepared.messages())
                returned = True
                return raw

            action_id = f"act_{input_event.event_id}"
            with delegated_invocation(
                _permit,
                owner=self,
                executor=self.executor,
                callback=invoke_once,
                subject=action_subject(
                    input_event, input_decision, action_id, "model_call"
                ),
                postprocess=postprocess,
            ) as action_permit:
                invocation = self.executor.run_guarded_action(
                    input_event,
                    input_decision,
                    action_id=action_id,
                    invoke_once=invoke_once,
                    postprocess=postprocess,
                    start_kind="model_call",
                    _permit=action_permit,
                )
            safe_output = (
                invocation.value
                if type(invocation.value) is NativeModelOutput
                and invocation.invocation_status == "executed"
                and invocation.delivery.status == "recorded"
                and not invocation.quarantined
                else None
            )
            return NativeModelResult(
                safe_output,
                safe_output is None,
                invocation.invocation_status,
                invocation.delivery,
                None if safe_output is not None else "native_model_result_withheld",
                prepared.visible_source_refs if safe_output is not None else (),
                output_source_ref if safe_output is not None else None,
                output_policy_audit_id if safe_output is not None else None,
            )
        except Exception:
            return NativeModelResult(
                None,
                True,
                "executed" if returned else "failed" if invoked else "not_invoked",
                None,
                "native_model_boundary_failed",
            )
