"""§19 指标分类、逻辑去重与聚合的共享纯函数。

Memory 与 PostgreSQL store 以及 runtime_metrics 必须经由同一套规则统计
policy_evaluation 指标，避免两套口径漂移（§19.1-§19.3）。
"""

from __future__ import annotations

from agentguard_core import AuditEvent

from guard_api.storage.base import EvalMetrics

_BLOCKING_DECISIONS = ("deny", "ask")


def classify_record_type(event: AuditEvent) -> str:
    """§19.2：record_type 缺失时的旧记录分类回退。

    event_type=config_audit → config_audit；
    event_type=runtime_observation → runtime_observation；
    其余 → policy_evaluation。
    """

    if event.record_type:
        return event.record_type
    if event.event_type == "config_audit":
        return "config_audit"
    if event.event_type == "runtime_observation":
        return "runtime_observation"
    return "policy_evaluation"


def logical_dedupe_key(event: AuditEvent) -> str:
    """§19.1：逻辑去重键 (links.event_id, links.decision_id)。

    任一缺失时回退 audit_id，保证无法配对的记录仍被单独统计。
    """

    event_id = event.links.get("event_id")
    decision_id = event.links.get("decision_id")
    if not event_id or not decision_id:
        return f"audit:{event.audit_id}"
    return f"policy:{event_id}:{decision_id}"


def aggregate_policy_metrics(events: list[AuditEvent]) -> EvalMetrics:
    """§19.3：只统计逻辑唯一的 policy_evaluation 记录。

    调用方必须按入链顺序（最旧 → 最新）传入事件；同一逻辑键重复时
    保留最早入链记录。blocked_count 口径为 decision in (deny, ask)。
    """

    seen: set[str] = set()
    unique: list[AuditEvent] = []
    for event in events:
        if classify_record_type(event) != "policy_evaluation":
            continue
        key = logical_dedupe_key(event)
        if key in seen:
            continue
        seen.add(key)
        unique.append(event)

    blocked = [event for event in unique if event.decision in _BLOCKING_DECISIONS]
    labeled_benign = [event for event in unique if event.is_malicious is False]
    labeled_malicious = [event for event in unique if event.is_malicious is True]
    false_positives = [
        event for event in labeled_benign if event.decision in _BLOCKING_DECISIONS
    ]
    false_negatives = [
        event
        for event in labeled_malicious
        if event.decision == "allow" and not event.blocked
    ]
    latency_values = [
        event.latency_ms for event in unique if event.latency_ms is not None
    ]
    return {
        "event_count": len(unique),
        "allow_count": sum(1 for event in unique if event.decision == "allow"),
        "deny_count": sum(1 for event in unique if event.decision == "deny"),
        "ask_count": sum(1 for event in unique if event.decision == "ask"),
        "blocked_count": len(blocked),
        "block_rate": (len(blocked) / len(unique)) if unique else None,
        "fpr": (len(false_positives) / len(labeled_benign)) if labeled_benign else None,
        "fnr": (
            (len(false_negatives) / len(labeled_malicious))
            if labeled_malicious
            else None
        ),
        "average_latency_ms": (
            (sum(latency_values) / len(latency_values)) if latency_values else None
        ),
    }
