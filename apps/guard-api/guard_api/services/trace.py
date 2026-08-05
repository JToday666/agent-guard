"""Trace and provenance query service."""

from __future__ import annotations

from guard_api.storage.base import (
    AuditEventFilters,
    ControlPlaneStore,
    EvalMetricFilters,
)


class TraceService:
    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def get_trace(self, trace_id: str) -> dict[str, object]:
        return {
            "trace_id": trace_id,
            "audit_events": [
                event.model_dump(mode="json")
                for event in self.store.list_audit_events(
                    AuditEventFilters(trace_id=trace_id, limit=1000)
                )
            ],
            "approvals": [
                approval.model_dump(mode="json")
                for approval in self.store.list_approvals(trace_id=trace_id)
            ],
            "metrics": self.store.eval_metrics(EvalMetricFilters(trace_id=trace_id)),
        }

    def get_provenance(self, trace_id: str) -> dict[str, object]:
        nodes, edges = self.store.list_provenance(trace_id)
        return {
            "trace_id": trace_id,
            "nodes": [node.model_dump(mode="json") for node in nodes],
            "edges": [edge.model_dump(mode="json") for edge in edges],
        }
