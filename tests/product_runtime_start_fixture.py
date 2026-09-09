"""Actual SDK start serialization for synthetic unit protocol inputs only."""

from pathlib import Path
from types import SimpleNamespace
from datetime import datetime

from agentguard_core import AuditEvent
from agentguard_langgraph_adapter.activation_ack import ActivationAckV1
from agentguard_langgraph_adapter.config import AgentGuardLangGraphConfig
from agentguard_langgraph_adapter.event_models import PolicyDecision, RuntimeGuardEvent
from agentguard_langgraph_adapter.langgraph_adapter import LangGraphAdapter
from agentguard_langgraph_adapter.native_events import NativeGuardEventBuilder
from agentguard_langgraph_adapter.product_outbox import _encode
from guard_api.services.audit import AuditService
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.test_product_runtime_policy_evidence import _save


def build_policy_start(
    root: Path, replay_fixture, parent, raw_receipt_wire, *, evidence_root: Path
):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    replay = replay_fixture
    wire = raw_receipt_wire
    if replay.event.runtime != "langgraph" or parent.decision not in {"allow", "ask"}:
        raise ValueError("synthetic start requires released LangGraph target")
    approval_id = wire["links"].get("approval_id")
    decision_data = replay.authority.selected_decision.model_dump(mode="json")
    decision_data.update(
        policy_audit_id=parent.audit_id,
        decision_authority=replay.authority.decision_authority.model_dump(mode="json"),
        approval_release_directive=replay.authority.approval_release_directive.model_dump(
            mode="json"
        ),
        approval={"approval_id": approval_id} if approval_id else None,
    )
    decision = PolicyDecision.model_validate(decision_data)
    ack = ActivationAckV1.model_validate(replay.ack.model_dump(mode="json"))
    decision._evaluation_activation_ack = ack
    decision._consumption_activation_ack = ack if approval_id else None
    event = RuntimeGuardEvent.model_validate(replay.event.model_dump(mode="json"))
    factory = NativeGuardEventBuilder(
        LangGraphAdapter(
            config=AgentGuardLangGraphConfig(agent_id=event.security_context.agent_id)
        )
    )
    resolution = (
        {
            "approval_id": approval_id,
            "status": "resolved",
            "decision": "allow_once",
            "resolved_at": wire["evidence"]["approval"]["resolved_at"],
        }
        if approval_id
        else None
    )
    start = factory.build_action_start(
        event,
        decision,
        start_kind="tool_call",
        approval_resolution=resolution,
        enforcement=wire["evidence"].get("enforcement"),
        lease_id=wire["links"].get("lease_id"),
        consumption_id=wire["links"].get("consumption_id"),
        timestamp=wire["evidence"]["execution"]["invoked_at"],
    )
    payload = start.model_dump(mode="json")
    assert "activation_ack" not in payload["metadata"]
    assert start._product_activation_ack.to_wire() == ack.to_wire()
    parsed = AuditEvent.model_validate(payload)
    records = MemoryControlPlaneStore(
        audit_clock=lambda: datetime.fromisoformat(start.timestamp)
    )
    service = AuditService(store=records)
    response = service.submit(service.prepare_submission(parsed, raw_payload=payload))
    accepted = records.get_audit_event(parsed.audit_id)
    assert accepted is not None

    def save(name, value):
        return _save(root, name, value, evidence_root=evidence_root)

    raw = save("wire.json", _encode(payload))
    confirmation = {
        "method": "POST",
        "path": "/v1/audit/events",
        "request_raw_sha256": raw["raw_sha256"],
        "status": 200,
        "response": response,
        "confirmed_at": wire["evidence"]["execution"]["invoked_at"],
    }
    document = {
        "schema_version": "agentguard-product-policy-start/1",
        "authority_kind": "synthetic_contract_fixture",
        "execution_scope": "isolated_contract_fixture",
        "runtime": "langgraph",
        "scope_id": replay.scope_id,
        "candidate_manifest_digest": replay.replay["candidate_manifest_digest"],
        "adapter_artifact_digest": replay.replay["adapter_artifact_digest"],
        "wire": raw,
        "accepted": save("accepted.json", accepted.model_dump(mode="json")),
        "ack": save("ack.json", replay.ack.model_dump(mode="json")),
        "confirmation": save("confirmation.json", confirmation),
    }
    reference = save("start.json", document)
    return SimpleNamespace(
        reference=reference,
        document=document,
        start=parsed,
        accepted=accepted,
        confirmation=confirmation,
        start_audit_id=start.audit_id,
    )
