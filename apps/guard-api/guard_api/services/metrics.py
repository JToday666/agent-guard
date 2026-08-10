"""Evaluation and runtime metrics service."""

from __future__ import annotations

from datetime import datetime

from agentguard_core import AuditEvent

from guard_api.storage.base import (
    AuditEventFilters,
    ControlPlaneStore,
    classify_audit_record_type,
    parse_audit_timestamp,
)

from .evidence import _event_hook_name


class MetricService:
    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def runtime_metrics(
        self, *, runtime: str | None = None, limit: int = 1000
    ) -> dict[str, object]:
        events = self.store.list_audit_events(
            AuditEventFilters(runtime=runtime, limit=limit)
        )
        grouped_events: dict[str, list[AuditEvent]] = {}
        hook_activity: dict[str, int] = {}
        for event in events:
            grouped_events.setdefault(event.runtime, []).append(event)
            hook_name = _event_hook_name(event)
            if hook_name is not None:
                hook_activity[hook_name] = hook_activity.get(hook_name, 0) + 1

        by_runtime = {
            runtime_name: _aggregate_runtime_activity(runtime_events)
            for runtime_name, runtime_events in grouped_events.items()
        }

        statuses = {
            adapter_id: status
            for adapter_id, status in self.store.list_adapter_statuses().items()
            if runtime is None or adapter_id == runtime
        }
        aggregate = _aggregate_runtime_activity(events)
        return {
            "metric_version": "runtime_activity.v2",
            "scope": {
                "kind": "latest_runtime_activity",
                "runtime": runtime,
                "limit": limit,
                "returned_record_count": len(events),
            },
            **aggregate,
            "by_runtime": by_runtime,
            "hook_activity": dict(sorted(hook_activity.items())),
            "adapters": statuses,
            "active_adapter_count": sum(
                1 for status in statuses.values() if status.get("loaded") is True
            ),
        }


def _aggregate_runtime_activity(events: list[AuditEvent]) -> dict[str, object]:
    policy_events = [
        event
        for event in events
        if classify_audit_record_type(event) == "policy_evaluation"
    ]
    allow_count = sum(1 for event in policy_events if event.decision == "allow")
    deny_count = sum(1 for event in policy_events if event.decision == "deny")
    ask_count = sum(1 for event in policy_events if event.decision == "ask")
    intervention_count = deny_count + ask_count
    latency_values = [
        event.latency_ms for event in policy_events if event.latency_ms is not None
    ]
    last_event = _latest_event_timestamp(events)
    return {
        "record_count": len(events),
        "policy_evaluation_count": len(policy_events),
        "allow_count": allow_count,
        "deny_count": deny_count,
        "ask_count": ask_count,
        "intervention_count": intervention_count,
        "intervention_rate": (
            intervention_count / len(policy_events) if policy_events else None
        ),
        "average_decision_latency_ms": (
            sum(latency_values) / len(latency_values) if latency_values else None
        ),
        "latency_sample_count": len(latency_values),
        "last_event_at": last_event,
    }


def _latest_event_timestamp(events: list[AuditEvent]) -> str | None:
    latest: tuple[datetime, str] | None = None
    for event in events:
        try:
            candidate = (parse_audit_timestamp(event.timestamp), event.timestamp)
        except ValueError:
            continue
        if latest is None or candidate[0] > latest[0]:
            latest = candidate
    return latest[1] if latest is not None else None
