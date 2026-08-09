"""Trace and provenance query service."""

from __future__ import annotations

import hashlib
import json

from guard_api.storage.base import (
    AuditWindowQuery,
    ControlPlaneStore,
    EvalMetricFilters,
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
            "metrics": self.store.eval_metrics(EvalMetricFilters(trace_id=trace_id)),
            "audit_window": {
                "limit": TRACE_AUDIT_LIMIT,
                "returned_count": len(audit_events),
                "has_more": has_more,
            },
        }

    def get_provenance(self, trace_id: str) -> dict[str, object]:
        nodes, edges = self.store.list_provenance(trace_id)
        return {
            "trace_id": trace_id,
            "nodes": [node.model_dump(mode="json") for node in nodes],
            "edges": [edge.model_dump(mode="json") for edge in edges],
        }


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
