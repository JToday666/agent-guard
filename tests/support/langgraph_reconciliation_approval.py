"""Actual SDK strong release/start-abort producer; TEST transport, no invocation."""

from dataclasses import asdict
import hashlib

import httpx
from agentguard_langgraph_adapter.event_models import RuntimeGuardEvent
from agentguard_langgraph_adapter.execution_template import _release_fields
from agentguard_langgraph_adapter.native_events import NativeGuardEventBuilder
from agentguard_langgraph_adapter.product_action_barrier import ProductActionBarrier
from agentguard_langgraph_adapter.product_outbox import _encode
from agentguard_langgraph_adapter.runtime_receipts import build_runtime_outcome
from agentguard_langgraph_adapter.strong_binding import authorize_strong_approval


def prepare_strong_ask_abort(adapter, outbox, data, decision):
    """Follow the execution template's real start-unconfirmed abort branch."""
    assert decision.decision == "ask"
    assert decision.approval_release_directive is not None
    assert decision.approval_release_directive.mode == "strong_binding"
    assert decision.approval
    approval_id = decision.approval["approval_id"]
    with httpx.Client(base_url=data["baseUrl"], trust_env=False, timeout=3) as client:
        launch = client.post(
            "/v1/auth/browser/launch",
            headers={"Authorization": f"Bearer {data['controlToken']}"},
        )
        launch.raise_for_status()
        exchanged = client.post(
            "/v1/auth/browser/exchange",
            json={"launch_code": launch.json()["launch_code"]},
        )
        exchanged.raise_for_status()
        path = f"/v1/approvals/{approval_id}/resolve"
        denied = client.post(
            path,
            json={"decision": "allow_once"},
            headers={"X-AgentGuard-CSRF": "invalid-test-csrf"},
        )
        assert denied.status_code == 403
        resolved = client.post(
            path,
            json={"decision": "allow_once"},
            headers={"X-AgentGuard-CSRF": exchanged.json()["csrf_token"]},
        )
        resolved.raise_for_status()
    binding = decision.enforcement_binding
    assert binding is not None
    action_id = binding["action_id"]
    release = authorize_strong_approval(
        adapter,
        decision,
        expected_action_id=action_id,
        expected_runtime_binding_id=data["runtimeBindingId"],
        approval_id=approval_id,
        timeout_seconds=5,
        poll_interval_seconds=0.01,
    )
    assert release is not None
    ack = decision._consumption_activation_ack
    assert ack is not None
    assert ack.header_value() != decision._evaluation_activation_ack.header_value()
    event = RuntimeGuardEvent.model_validate(data["event"])
    start = NativeGuardEventBuilder(adapter).build_action_start(
        event,
        decision,
        start_kind="tool_call",
        approval_resolution=release.approval_resolution,
        **_release_fields(release),
    )
    barrier = ProductActionBarrier(outbox)
    begun = barrier.begin_action(
        action_id=action_id, event_id=event.event_id, start_receipt=start
    )
    assert begun.ticket is None
    assert begun.abort_proof is not None
    assert begun.delivery.status == "permanent_rejected"
    receipt = build_runtime_outcome(
        event,
        decision,
        execution_status="not_invoked",
        approval_resolution=release.approval_resolution,
        parent_audit_id=start.audit_id,
        intervention_type="runtime_receipt_failure",
        intervention_reason="Start confirmation failed before the invocation boundary.",
        **_release_fields(release),
    )
    delivered = barrier.abort_action(begun.abort_proof, receipt)
    return receipt, {
        "delivered": asdict(delivered),
        "startAuditId": start.audit_id,
        "startWireDigest": hashlib.sha256(
            _encode(start.model_dump(mode="json"))
        ).hexdigest(),
        "approvalId": approval_id,
        "leaseId": release.lease.lease_id,
        "consumptionId": release.lease.consumption_id,
        "consumptionAckDigest": "sha256:"
        + hashlib.sha256(ack.header_value().encode()).hexdigest(),
        "operator": "automated-synthetic-http-test",
        "nativeInvocations": 0,
    }
