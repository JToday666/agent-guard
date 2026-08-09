"""Cross-component invariants for the frozen runtime-safety target fixture."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from agentguard_core import AuditEvent, ProvenanceEdge, ProvenanceNode
from guard_api.models import ApprovalRequest


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "runtime_safety_trace_v04.json"


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _walk(value: object) -> Iterator[tuple[str | None, object]]:
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key), nested
            yield from _walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield None, nested
            yield from _walk(nested)


def test_runtime_safety_fixture_validates_all_persisted_models() -> None:
    fixture = _fixture()
    facts = fixture["source_facts"]
    trace_id = facts["trace_id"]

    audits = [AuditEvent.model_validate(row) for row in facts["audit_events"]]
    approvals = [ApprovalRequest.model_validate(row) for row in facts["approvals"]]
    nodes = [
        ProvenanceNode.model_validate(row)
        for row in fixture["provenance_response"]["nodes"]
    ]
    edges = [
        ProvenanceEdge.model_validate(row)
        for row in fixture["provenance_response"]["edges"]
    ]

    assert all(
        item.trace_id == trace_id for item in [*audits, *approvals, *nodes, *edges]
    )
    assert len({item.audit_id for item in audits}) == len(audits)
    assert len({item.approval_id for item in approvals}) == len(approvals)
    assert len({item.node_id for item in nodes}) == len(nodes)
    assert len({item.edge_id for item in edges}) == len(edges)


def test_runtime_safety_fixture_has_complete_stable_cross_references() -> None:
    fixture = _fixture()
    facts = fixture["source_facts"]
    audits = {row["audit_id"]: row for row in facts["audit_events"]}
    approvals = {row["approval_id"]: row for row in facts["approvals"]}
    nodes = {row["node_id"]: row for row in fixture["provenance_response"]["nodes"]}
    edges = fixture["provenance_response"]["edges"]

    action_ids = {
        action["action_id"] for action in fixture["expected_projection"]["actions"]
    }
    for audit in audits.values():
        links = audit["links"]
        if policy_audit_id := links.get("policy_audit_id"):
            assert audits[policy_audit_id]["record_type"] == "policy_evaluation"
        if parent_audit_id := links.get("parent_audit_id"):
            assert parent_audit_id in audits
        if approval_id := links.get("approval_id"):
            assert approval_id in approvals
        if action_id := links.get("action_id"):
            assert action_id in action_ids

    for edge in edges:
        assert edge["source_node_id"] in nodes
        assert edge["target_node_id"] in nodes
        assert edge["edge_id"] == (
            f"edge:{edge['relation']}:{edge['source_node_id']}:{edge['target_node_id']}"
        )

    for action_id in action_ids:
        action_node = nodes[f"action:{action_id}"]
        assert action_node["kind"] == "action"
        assert action_node["ref_id"] == action_id


def test_runtime_safety_fixture_projection_snapshots_and_counts_are_consistent() -> (
    None
):
    fixture = _fixture()
    projection = fixture["expected_projection"]
    invariants = projection["invariants"]
    audits = fixture["source_facts"]["audit_events"]
    audit_ids = {row["audit_id"] for row in audits}

    assert len(projection["actions"]) == invariants["action_count"]
    assert len(fixture["source_facts"]["approvals"]) == invariants["approval_count"]
    for record_type, count_key in (
        ("policy_evaluation", "policy_evaluation_count"),
        ("runtime_outcome", "runtime_outcome_count"),
        ("runtime_observation", "runtime_observation_count"),
    ):
        assert (
            sum(row["record_type"] == record_type for row in audits)
            == invariants[count_key]
        )

    for snapshot in projection["snapshots"]:
        assert set(snapshot["included_audit_ids"]) <= audit_ids
    assert projection["trace_lifecycle"]["source_audit_id"] in audit_ids

    coordinate_keys = {
        key for key, _ in _walk(fixture) if key in {"x", "y", "position", "coordinates"}
    }
    assert coordinate_keys == set()
    assert invariants["frontend_coordinate_count"] == 0
    assert invariants["future_placeholder_count"] == 0
