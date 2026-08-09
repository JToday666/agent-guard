"""Evaluation and runtime metrics service."""

from __future__ import annotations

from typing import Any

from guard_api.storage.base import (
    AuditEventFilters,
    ControlPlaneStore,
    EvalMetricFilters,
    EvalMetrics,
)

from .evidence import _event_hook_name
from .metric_rules import classify_record_type


class MetricService:
    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def eval_metrics(self, filters: EvalMetricFilters | None = None) -> EvalMetrics:
        return self.store.eval_metrics(filters)

    def runtime_metrics(
        self, *, runtime: str | None = None, limit: int = 1000
    ) -> dict[str, object]:
        events = self.store.list_audit_events(
            AuditEventFilters(runtime=runtime, limit=limit)
        )
        by_runtime: dict[str, dict[str, Any]] = {}
        hook_activity: dict[str, int] = {}
        for event in events:
            bucket = by_runtime.setdefault(
                event.runtime,
                {
                    "event_count": 0,
                    "allow_count": 0,
                    "deny_count": 0,
                    "ask_count": 0,
                    "blocked_count": 0,
                    "average_latency_ms": None,
                    "_latency_values": [],
                    "last_event_at": event.timestamp,
                },
            )
            bucket["event_count"] = int(bucket["event_count"]) + 1
            # §19.2/§19.3：allow/ask/deny/blocked 只统计策略判定记录。
            is_policy = classify_record_type(event) == "policy_evaluation"
            if is_policy and event.decision in {"allow", "deny", "ask"}:
                bucket[f"{event.decision}_count"] = (
                    int(bucket[f"{event.decision}_count"]) + 1
                )
            if is_policy and event.decision in {"deny", "ask"}:
                bucket["blocked_count"] = int(bucket["blocked_count"]) + 1
            if event.latency_ms is not None:
                bucket["_latency_values"].append(event.latency_ms)  # type: ignore[union-attr]
            if event.timestamp > str(bucket["last_event_at"]):
                bucket["last_event_at"] = event.timestamp
            hook_name = _event_hook_name(event)
            if hook_name is not None:
                hook_activity[hook_name] = hook_activity.get(hook_name, 0) + 1

        for bucket in by_runtime.values():
            latency_values = bucket.pop("_latency_values")
            bucket["average_latency_ms"] = (
                sum(latency_values) / len(latency_values) if latency_values else None
            )

        statuses = {
            adapter_id: status
            for adapter_id, status in self.store.list_adapter_statuses().items()
            if runtime is None or adapter_id == runtime
        }
        event_count = len(events)
        policy_events = [
            event
            for event in events
            if classify_record_type(event) == "policy_evaluation"
        ]
        blocked_count = sum(
            1 for event in policy_events if event.decision in {"deny", "ask"}
        )
        latency_values = [
            event.latency_ms for event in events if event.latency_ms is not None
        ]
        return {
            "runtime": runtime,
            "event_count": event_count,
            "allow_count": sum(
                1 for event in policy_events if event.decision == "allow"
            ),
            "deny_count": sum(1 for event in policy_events if event.decision == "deny"),
            "ask_count": sum(1 for event in policy_events if event.decision == "ask"),
            "blocked_count": blocked_count,
            "block_rate": (blocked_count / event_count) if event_count else None,
            "average_latency_ms": (
                (sum(latency_values) / len(latency_values)) if latency_values else None
            ),
            "by_runtime": by_runtime,
            "hook_activity": dict(sorted(hook_activity.items())),
            "adapters": statuses,
            "active_adapter_count": sum(
                1 for status in statuses.values() if status.get("loaded") is True
            ),
        }
