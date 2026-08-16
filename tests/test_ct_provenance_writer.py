from __future__ import annotations

import copy

import pytest

from agentguard_core import ProvenanceEdge, ProvenanceNode
from agentguard_core.actions.canonical_json import canonical_sha256
from guard_api.services.ct_projection import decode_ct_transient_facts
from guard_api.storage.base import CtProvenanceBatchConflictError
from guard_api.storage.memory import MemoryControlPlaneStore

from tests.test_ct_state_wiring import _ct_event, _ingress_task, _settings, _stack


def _evaluated_store() -> tuple[MemoryControlPlaneStore, str]:
    store = MemoryControlPlaneStore()
    settings = _settings()
    task_id, _ = _ingress_task(store, settings=settings)
    evaluation, _, _ = _stack(store, settings=settings)
    evaluation.evaluate(
        _ct_event(
            event_id="evt_ct_provenance",
            event_type="tool_result_produced",
            task_id=task_id,
            call_id="call_ct_provenance",
        ),
        requesting_principal_id="cred_adapter_main",
    )
    return store, "trace_ct_wiring_1"


def test_committed_full_envelope_materializes_strict_typed_graph() -> None:
    store, trace_id = _evaluated_store()
    nodes, edges = store.list_provenance(trace_id)
    typed_nodes = [n for n in nodes if n.metadata.get("contract") == "ct-provenance/1.0"]
    typed_edges = [e for e in edges if e.metadata.get("contract") == "ct-provenance/1.0"]
    assert {(n.kind, n.ref_id) for n in typed_nodes} == {
        ("action", "action:call_ct_provenance"),
        ("source", "tool_result:binding:cred_adapter_main:call_ct_provenance"),
    }
    assert len(typed_edges) == 1
    edge = typed_edges[0]
    assert edge.relation == edge.metadata["flow_relation"] == "returned_by"
    assert edge.metadata["coverage"] == "complete"
    assert edge.edge_id == "ctedge:" + canonical_sha256(
        {
            "trace_id": trace_id,
            "flow_id": edge.metadata["flow_id"],
            "source_ref": edge.metadata["source_ref"],
            "target_ref": edge.metadata["target_ref"],
            "flow_relation": edge.metadata["flow_relation"],
        }
    )
    node_ids = {node.node_id for node in typed_nodes}
    assert edge.source_node_id in node_ids
    assert edge.target_node_id in node_ids
    assert edge.metadata["evidence_refs"][0]["json_pointer"] == (
        "/evidence/ct_transient_facts"
    )


def test_decoder_distinguishes_root_budget_drop_and_digest_tamper() -> None:
    dropped = decode_ct_transient_facts(
        {"_budget_dropped": True, "_envelope_sha256": "sha256:" + "a" * 64}
    )
    assert dropped.kind == "budget_dropped"

    store, _ = _evaluated_store()
    audit = store.get_policy_evaluation_by_event_id("evt_ct_provenance")
    assert audit is not None
    tampered = audit.model_copy(deep=True)
    evidence = copy.deepcopy(tampered.evidence)
    evidence["ct_transient_facts"]["payload"]["bundle_digest"] = (
        "sha256:" + "f" * 64
    )
    tampered.evidence = evidence
    decoded = decode_ct_transient_facts(tampered)
    assert decoded.kind == "invalid"
    assert "ct-envelope:bundle_digest_mismatch" in decoded.issues


def test_ct_batch_rejects_same_flow_with_different_content_atomically() -> None:
    store = MemoryControlPlaneStore()
    nodes = [
        ProvenanceNode(
            node_id=f"ctnode:{index}",
            trace_id="trace-flow-conflict",
            kind="other",
            ref_id=f"ref:{index}",
            label="fixture",
            metadata={},
        )
        for index in (1, 2, 3)
    ]

    def edge(edge_id: str, target: str) -> ProvenanceEdge:
        return ProvenanceEdge(
            edge_id=edge_id,
            trace_id="trace-flow-conflict",
            source_node_id="ctnode:1",
            target_node_id=target,
            relation="derived_from",
            metadata={
                "contract": "ct-provenance/1.0",
                "kind": "edge",
                "flow_id": "flow:immutable",
            },
        )

    store.write_ct_provenance_batch(nodes[:2], [edge("ctedge:1", "ctnode:2")])
    with pytest.raises(CtProvenanceBatchConflictError):
        store.write_ct_provenance_batch(nodes, [edge("ctedge:2", "ctnode:3")])
    persisted_nodes, persisted_edges = store.list_provenance("trace-flow-conflict")
    assert {node.node_id for node in persisted_nodes} == {"ctnode:1", "ctnode:2"}
    assert [item.edge_id for item in persisted_edges] == ["ctedge:1"]


def test_repair_is_idempotent_for_typed_provenance() -> None:
    store, trace_id = _evaluated_store()
    audit = store.get_policy_evaluation_by_event_id("evt_ct_provenance")
    assert audit is not None
    before = tuple(
        item.model_dump(mode="json")
        for collection in store.list_provenance(trace_id)
        for item in collection
    )
    from guard_api.services import AuditService

    AuditService(store=store).repair_provenance(audit)
    after = tuple(
        item.model_dump(mode="json")
        for collection in store.list_provenance(trace_id)
        for item in collection
    )
    assert after == before
