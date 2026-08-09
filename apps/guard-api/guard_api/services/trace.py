"""Trace and provenance query service."""

from __future__ import annotations

import hashlib
import json

from agentguard_core import ProvenanceNode

from guard_api.models import ApprovalRequest
from guard_api.storage.base import (
    ControlPlaneStore,
)

from .audit_window import AuditWindowService

TRACE_AUDIT_LIMIT = 1000
TRACE_APPROVAL_LIMIT = 1000
PROVENANCE_NODE_LIMIT = 1000
PROVENANCE_EDGE_LIMIT = 2000


class TraceService:
    def __init__(
        self,
        *,
        store: ControlPlaneStore,
        audit_window_service: AuditWindowService | None = None,
    ) -> None:
        self.store = store
        self.audit_window_service = audit_window_service or AuditWindowService(
            store=store
        )

    def get_trace(
        self,
        trace_id: str,
        *,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, object]:
        effective_limit = limit
        if effective_limit is None and cursor is None:
            effective_limit = TRACE_AUDIT_LIMIT
        window = self.audit_window_service.get_window(
            limit=effective_limit,
            trace_id=trace_id,
            cursor=cursor,
        )
        scope = window["scope"]
        approvals = self.store.list_approvals(
            trace_id=trace_id,
            limit=TRACE_APPROVAL_LIMIT + 1,
        )
        approvals_have_more = len(approvals) > TRACE_APPROVAL_LIMIT
        approval_page = approvals[:TRACE_APPROVAL_LIMIT]
        return {
            "trace_id": trace_id,
            "audit_events": window["events"],
            "approvals": [
                approval.model_dump(mode="json") for approval in approval_page
            ],
            "audit_window": {
                "limit": scope["limit"],
                "returned_count": scope["returned_record_count"],
                "has_more": scope["has_more"],
                "next_cursor": scope["next_cursor"],
                "snapshot_id": scope["snapshot_id"],
            },
            "approval_window": {
                "limit": TRACE_APPROVAL_LIMIT,
                "returned_count": len(approval_page),
                "has_more": approvals_have_more,
            },
        }

    def get_provenance(self, trace_id: str) -> dict[str, object]:
        nodes, edges = self.store.list_provenance(
            trace_id,
            node_limit=PROVENANCE_NODE_LIMIT + 1,
            edge_limit=PROVENANCE_EDGE_LIMIT + 1,
        )
        nodes_have_more = len(nodes) > PROVENANCE_NODE_LIMIT
        node_page = nodes[:PROVENANCE_NODE_LIMIT]
        node_ids = {node.node_id for node in node_page}
        eligible_edges = [
            edge
            for edge in edges
            if edge.source_node_id in node_ids and edge.target_node_id in node_ids
        ]
        edges_have_more = (
            len(edges) > PROVENANCE_EDGE_LIMIT
            or len(eligible_edges) > PROVENANCE_EDGE_LIMIT
            or len(eligible_edges) != len(edges)
        )
        edge_page = eligible_edges[:PROVENANCE_EDGE_LIMIT]
        approvals = {
            approval.approval_id: approval
            for approval in self.store.list_approvals(
                trace_id=trace_id,
                limit=PROVENANCE_NODE_LIMIT + 1,
            )
        }
        return {
            "trace_id": trace_id,
            "nodes": [
                _with_current_approval_state(node, approvals).model_dump(mode="json")
                for node in node_page
            ],
            "edges": [edge.model_dump(mode="json") for edge in edge_page],
            "provenance_window": {
                "node_limit": PROVENANCE_NODE_LIMIT,
                "returned_node_count": len(node_page),
                "nodes_have_more": nodes_have_more,
                "edge_limit": PROVENANCE_EDGE_LIMIT,
                "returned_edge_count": len(edge_page),
                "edges_have_more": edges_have_more,
                "has_more": nodes_have_more or edges_have_more,
            },
        }


def _with_current_approval_state(
    node: ProvenanceNode,
    approvals: dict[str, ApprovalRequest],
) -> ProvenanceNode:
    if node.kind != "approval":
        return node
    approval = approvals.get(node.ref_id)
    if approval is None:
        return node
    label = (
        approval.decision
        if approval.status == "resolved" and approval.decision is not None
        else approval.status
    )
    return node.model_copy(
        update={
            "label": label,
            "metadata": {
                **node.metadata,
                "status": approval.status,
                "decision": approval.decision,
                "created_at": approval.created_at,
                "expires_at": approval.expires_at,
                "resolved_at": approval.resolved_at,
                "resolution_source": approval.resolution_source,
                "resolved_by": approval.resolved_by,
                "resolution_reason": approval.resolution_reason,
            },
        },
        deep=True,
    )


def encode_conditional_document(payload: dict[str, object]) -> tuple[bytes, str]:
    """Encode one stable HTTP representation and its opaque strong validator."""

    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    digest = hashlib.sha256(body).hexdigest()
    return body, f'"sha256:{digest}"'


def if_none_match_matches(header_value: str | None, etag: str) -> bool:
    """Apply weak comparison semantics required by HTTP If-None-Match."""

    if header_value is None:
        return False
    for candidate in header_value.split(","):
        normalized = candidate.strip()
        if normalized == "*":
            return True
        if normalized.startswith("W/"):
            normalized = normalized[2:].strip()
        if normalized == etag:
            return True
    return False
