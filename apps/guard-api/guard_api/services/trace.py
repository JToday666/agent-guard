"""Trace and provenance query service."""

from __future__ import annotations

import hashlib
import json

from agentguard_core import ProvenanceNode

from guard_api.models import ApprovalRequest
from guard_api.storage.base import (
    AuditWindowQuery,
    ControlPlaneStore,
)

TRACE_AUDIT_LIMIT = 1000


class TraceService:
    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def get_trace(self, trace_id: str) -> dict[str, object]:
        rows = self.store.read_audit_events_bounded(
            AuditWindowQuery(trace_id=trace_id, limit=TRACE_AUDIT_LIMIT + 1)
        )
        has_more = len(rows) > TRACE_AUDIT_LIMIT
        audit_events = rows[:TRACE_AUDIT_LIMIT]
        return {
            "trace_id": trace_id,
            "audit_events": [event.model_dump(mode="json") for event in audit_events],
            "approvals": [
                approval.model_dump(mode="json")
                for approval in self.store.list_approvals(trace_id=trace_id)
            ],
            "audit_window": {
                "limit": TRACE_AUDIT_LIMIT,
                "returned_count": len(audit_events),
                "has_more": has_more,
            },
        }

    def get_provenance(self, trace_id: str) -> dict[str, object]:
        nodes, edges = self.store.list_provenance(trace_id)
        approvals = {
            approval.approval_id: approval
            for approval in self.store.list_approvals(trace_id=trace_id)
        }
        return {
            "trace_id": trace_id,
            "nodes": [
                _with_current_approval_state(node, approvals).model_dump(mode="json")
                for node in nodes
            ],
            "edges": [edge.model_dump(mode="json") for edge in edges],
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
