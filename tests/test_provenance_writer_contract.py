"""Deterministic provenance materialization and stable-ID contracts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from agentguard_core import AuditEvent, ProvenanceEdge, ProvenanceNode
from guard_api.models import ApprovalRequest
from guard_api.services.approval import ApprovalService
from guard_api.services.audit import AuditService
from guard_api.services.provenance import ProvenanceWriter
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import (
    ControlPlaneStore,
    ProvenanceConflictError,
    ProvenanceEndpointMissingError,
)
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import get_test_database_url, reset_control_plane_schema


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "runtime_safety_trace_v04.json"


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(params=("memory", "postgres"))
def provenance_store(request: pytest.FixtureRequest) -> ControlPlaneStore:
    if request.param == "memory":
        return MemoryControlPlaneStore()
    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    store = PostgresControlPlaneStore(database_url)
    store.initialize()
    return store


def _materialize_fixture(
    store: ControlPlaneStore,
) -> tuple[dict[str, Any], dict[str, ProvenanceNode]]:
    fixture = _fixture()
    writer = ProvenanceWriter(store=store)
    for row in fixture["source_facts"]["approvals"]:
        store.create_approval(ApprovalRequest.model_validate(row))
    for row in fixture["source_facts"]["audit_events"]:
        event = AuditEvent.model_validate(row)
        store.add_audit_event(event)
        persisted = store.get_audit_event(event.audit_id)
        assert persisted is not None
        writer.record_audit_event(persisted)
    nodes, _ = store.list_provenance(fixture["source_facts"]["trace_id"])
    return fixture, {node.node_id: node for node in nodes}


def _policy_event(
    trace_id: str, suffix: str, *, action_id: str | None = None
) -> AuditEvent:
    event_id = f"event-{suffix}"
    decision_id = f"decision-{suffix}"
    action_id = action_id or f"action-{suffix}"
    return AuditEvent(
        audit_id=f"audit-{suffix}",
        schema_version="0.4",
        record_type="policy_evaluation",
        trace_id=trace_id,
        timestamp="2026-08-08T00:00:00Z",
        summary="工具调用已完成策略判断",
        decision="allow",
        risk_score=0,
        severity="low",
        blocked=False,
        reason="允许执行",
        links={
            "event_id": event_id,
            "decision_id": decision_id,
            "action_id": action_id,
        },
        evidence={
            "guard_event": {
                "event_id": event_id,
                "event_type": "tool_call_proposed",
                "user_task": "整理报告",
                "source": {
                    "source_id": "operator",
                    "type": "user_request",
                    "label": "用户请求",
                    "trust_level": "trusted",
                },
                "context_sources": [],
                "model_intent": "读取报告",
                "tool": {"name": "read_file", "call_id": action_id},
                "normalized_resources": [],
            },
            "guard_decision": {
                "decision_id": decision_id,
                "decision": "allow",
                "risk_score": 0,
                "severity": "low",
                "rule_hits": [],
                "reason": "允许执行",
            },
            "policy": {
                "bundle_id": "shared-policy",
                "version": "7",
                "revision": None,
                "canonical_digest": "sha256:abc",
            },
        },
    )


def test_writer_materializes_the_frozen_demo_graph_with_raw_refs(
    provenance_store: ControlPlaneStore,
) -> None:
    store = provenance_store
    fixture, nodes = _materialize_fixture(store)
    trace_id = fixture["source_facts"]["trace_id"]
    _, edges = store.list_provenance(trace_id)
    edge_by_id = {edge.edge_id: edge for edge in edges}

    expected_node_ids = {
        row["node_id"] for row in fixture["provenance_response"]["nodes"]
    }
    expected_edge_ids = {
        row["edge_id"] for row in fixture["provenance_response"]["edges"]
    }
    assert expected_node_ids <= nodes.keys()
    assert expected_edge_ids <= edge_by_id.keys()

    assert nodes["audit:audit_policy_code_exec_001"].ref_id == (
        "audit_policy_code_exec_001"
    )
    assert nodes["action:call_code_exec_001"].ref_id == "call_code_exec_001"
    assert f"policy:{trace_id}:demo-runtime-safety:1" in nodes
    assert all(
        edge.metadata["relation_type"]
        in {"causal", "detection", "policy", "approval", "execution", "audit"}
        for edge in edges
    )
    assert all(
        edge.source_node_id in nodes and edge.target_node_id in nodes for edge in edges
    )
    assert all(
        edge.edge_id
        == f"edge:{edge.relation}:{edge.source_node_id}:{edge.target_node_id}"
        for edge in edges
    )


def test_policy_nodes_are_scoped_to_each_trace() -> None:
    store = MemoryControlPlaneStore()
    writer = ProvenanceWriter(store=store)

    for trace_id, suffix in (("trace-a", "a"), ("trace-b", "b")):
        event = _policy_event(trace_id, suffix)
        store.add_audit_event(event)
        persisted = store.get_audit_event(event.audit_id)
        assert persisted is not None
        writer.record_audit_event(persisted)

    assert store.get_provenance_node("policy:trace-a:shared-policy:7") is not None
    assert store.get_provenance_node("policy:trace-b:shared-policy:7") is not None


def test_action_node_accepts_multiple_policy_checks_for_one_action() -> None:
    store = MemoryControlPlaneStore()
    writer = ProvenanceWriter(store=store)

    for suffix in ("check-a", "check-b"):
        event = _policy_event("trace-action-checks", suffix, action_id="shared-action")
        store.add_audit_event(event)
        persisted = store.get_audit_event(event.audit_id)
        assert persisted is not None
        writer.record_audit_event(persisted)

    action = store.get_provenance_node("action:shared-action")
    assert action is not None
    assert "event_id" not in action.metadata
    _, edges = store.list_provenance("trace-action-checks")
    assert {
        edge.target_node_id
        for edge in edges
        if edge.source_node_id == action.node_id and edge.relation == "evaluated_to"
    } == {"decision:decision-check-a", "decision:decision-check-b"}


def test_node_upsert_fills_unknowns_without_degrading_known_facts() -> None:
    store = MemoryControlPlaneStore()
    base = ProvenanceNode(
        node_id="decision:stable",
        trace_id="trace-upsert",
        kind="decision",
        ref_id="stable",
        label="allow",
        timestamp="2026-08-08T00:00:01Z",
        metadata={"decision": "allow", "severity": None},
    )
    store.add_provenance_node(base)
    enriched = store.add_provenance_node(
        base.model_copy(
            update={
                "timestamp": "2026-08-08T00:00:02Z",
                "metadata": {"decision": "allow", "severity": "low"},
            }
        )
    )
    replayed = store.add_provenance_node(
        base.model_copy(
            update={"metadata": {"decision": "allow", "severity": "unknown"}}
        )
    )

    assert enriched.metadata["severity"] == "low"
    assert replayed.metadata["severity"] == "low"
    assert replayed.timestamp == "2026-08-08T00:00:01Z"

    with pytest.raises(ProvenanceConflictError):
        store.add_provenance_node(
            base.model_copy(update={"metadata": {"decision": "deny"}})
        )


def test_approval_upsert_allows_only_pending_to_terminal_progression() -> None:
    store = MemoryControlPlaneStore()
    pending = ProvenanceNode(
        node_id="approval:stable",
        trace_id="trace-upsert",
        kind="approval",
        ref_id="stable",
        label="pending",
        metadata={"status": "pending", "decision": None, "resolved_at": None},
    )
    resolved = pending.model_copy(
        update={
            "label": "allow_once",
            "metadata": {
                "status": "resolved",
                "decision": "allow_once",
                "resolved_at": "2026-08-08T00:00:03Z",
            },
        }
    )
    store.add_provenance_node(pending)
    stored = store.add_provenance_node(resolved)

    assert stored.label == "allow_once"
    assert stored.metadata["status"] == "resolved"

    with pytest.raises(ProvenanceConflictError):
        store.add_provenance_node(pending)
    with pytest.raises(ProvenanceConflictError):
        store.add_provenance_node(
            resolved.model_copy(
                update={
                    "label": "deny",
                    "metadata": {"status": "resolved", "decision": "deny"},
                }
            )
        )


def test_approval_service_updates_the_existing_provenance_node() -> None:
    store = MemoryControlPlaneStore()
    writer = ProvenanceWriter(store=store)
    store.add_provenance_node(
        ProvenanceNode(
            node_id="decision:approval-decision",
            trace_id="trace-approval",
            kind="decision",
            ref_id="approval-decision",
            label="ask",
        )
    )
    approval = store.create_approval(
        ApprovalRequest(
            approval_id="approval-service",
            trace_id="trace-approval",
            subject_id="action-approval",
            action_id="action-approval",
            action_name="code_exec",
            tool_call_id="action-approval",
            requesting_principal_id="adapter",
            tool="code_exec",
            resource="2 + 2",
            reason="需要人工确认",
            risk_score=72,
            severity="high",
            evidence={"decision": {"decision_id": "approval-decision"}},
        )
    )
    writer.update_approval(approval)
    service = ApprovalService(
        store=store,
        settings=GuardApiSettings(),
        provenance_writer=writer,
    )

    service.resolve_approval("approval-service", "allow_once")

    node = store.get_provenance_node("approval:approval-service")
    assert node is not None
    assert node.metadata["status"] == "resolved"
    assert node.metadata["decision"] == "allow_once"
    assert node.label == "allow_once"
    nodes, edges = store.list_provenance("trace-approval")
    assert len([item for item in nodes if item.kind == "approval"]) == 1
    assert [edge.relation for edge in edges] == ["requested_approval"]


def test_approval_update_rejects_a_decision_from_another_trace() -> None:
    store = MemoryControlPlaneStore()
    writer = ProvenanceWriter(store=store)
    store.add_provenance_node(
        ProvenanceNode(
            node_id="decision:foreign",
            trace_id="trace-foreign",
            kind="decision",
            ref_id="foreign",
            label="ask",
        )
    )
    approval = ApprovalRequest(
        approval_id="approval-cross-trace",
        trace_id="trace-local",
        subject_id="action-local",
        action_id="action-local",
        action_name="code_exec",
        tool_call_id="action-local",
        requesting_principal_id="adapter",
        tool="code_exec",
        resource="2 + 2",
        reason="需要人工确认",
        risk_score=72,
        severity="high",
        evidence={"decision": {"decision_id": "foreign"}},
    )

    with pytest.raises(ProvenanceConflictError):
        writer.update_approval(approval)


def test_edges_require_existing_endpoints_in_the_same_trace() -> None:
    store = MemoryControlPlaneStore()
    store.add_provenance_node(
        ProvenanceNode(
            node_id="action:a",
            trace_id="trace-edge",
            kind="action",
            ref_id="a",
            label="action",
        )
    )

    with pytest.raises(ProvenanceEndpointMissingError):
        store.add_provenance_edge(
            ProvenanceEdge(
                edge_id="edge:evaluated_to:action:a:decision:d",
                trace_id="trace-edge",
                source_node_id="action:a",
                target_node_id="decision:d",
                relation="evaluated_to",
            )
        )


def test_idempotent_audit_retry_repairs_partial_provenance() -> None:
    store = MemoryControlPlaneStore()
    service = AuditService(store=store)
    event = AuditEvent(
        audit_id="audit-repair",
        trace_id="trace-repair",
        summary="工具事件",
        decision="allow",
        risk_score=0,
        severity="low",
        blocked=False,
        reason="允许执行",
        links={"event_id": "event-repair"},
    )

    first = service.submit(event)
    store.provenance_nodes.pop("event:event-repair")
    store.provenance_edges.clear()
    replay = service.submit(event)

    assert first["created"] is True
    assert replay["idempotent_replay"] is True
    assert store.get_provenance_node("event:event-repair") is not None
    _, edges = store.list_provenance("trace-repair")
    assert [edge.relation for edge in edges] == ["recorded_as"]
