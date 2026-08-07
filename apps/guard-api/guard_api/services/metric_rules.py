"""§19 指标分类、逻辑去重与聚合的共享纯函数。

Memory 与 PostgreSQL store 以及 runtime_metrics 必须经由同一套规则统计
policy_evaluation 指标，避免两套口径漂移（§19.1-§19.3）。
"""

from __future__ import annotations

from typing import Any

from agentguard_core import AuditEvent

from guard_api.storage.base import EvalMetrics
from guard_api.storage.integrity import read_audit_integrity

_BLOCKING_DECISIONS = ("deny", "ask")
_INTERVENTION_DECISIONS = ("ask", "deny")
_METRIC_VERSION_V2 = "policy_evaluation.v2"
_DEDUPLICATION_LABEL = "logical_policy_evaluation"


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


def aggregate_policy_metrics_v2(events: list[AuditEvent]) -> dict[str, Any]:
    """契约 §4/§5.3：policy_evaluation.v2 策略指标聚合。

    与旧口径物理分离；调用方传入窗口或 cohort 内的审计记录即可，
    聚合内部按 integrity.sequence 升序选择规范行（§5.4：重复逻辑键
    的规范行是 sequence 最小的一条）。规则：

    - decision=null 单独计入 unknown_decision_count，不并入 allow；
    - 同键异内容只计数上报（duplicate_policy_record_count），不静默合并；
    - 缺失关联 ID 的 legacy 记录回退 audit_id 去重并累计 legacy_fallback_count；
    - 分母为零时率返回 null，不得返回 0（§4.3）。
    """

    ordered = sorted(events, key=_audit_sequence_key)
    canonical: dict[str, AuditEvent] = {}
    duplicate_policy_record_count = 0
    legacy_fallback_count = 0
    for event in ordered:
        if classify_record_type(event) != "policy_evaluation":
            continue
        key = logical_dedupe_key(event)
        if key.startswith("audit:"):
            legacy_fallback_count += 1
        if key in canonical:
            duplicate_policy_record_count += 1
            continue
        canonical[key] = event
    unique = list(canonical.values())

    evaluation_count = len(unique)
    allow_count = sum(1 for event in unique if event.decision == "allow")
    ask_count = sum(1 for event in unique if event.decision == "ask")
    deny_count = sum(1 for event in unique if event.decision == "deny")
    unknown_decision_count = sum(1 for event in unique if event.decision is None)
    intervention_count = ask_count + deny_count

    known = [event for event in unique if event.decision is not None]
    benign_known = [
        event for event in known if event.is_malicious is False
    ]
    malicious_known = [
        event for event in known if event.is_malicious is True
    ]
    fpr_hits = sum(
        1 for event in benign_known if event.decision in _INTERVENTION_DECISIONS
    )
    fnr_hits = sum(1 for event in malicious_known if event.decision == "allow")
    latency_values = [
        event.latency_ms for event in unique if event.latency_ms is not None
    ]

    return {
        "metric_version": _METRIC_VERSION_V2,
        "evaluation_count": evaluation_count,
        "unknown_decision_count": unknown_decision_count,
        "allow_count": allow_count,
        "ask_count": ask_count,
        "deny_count": deny_count,
        "intervention_count": intervention_count,
        "intervention_rate": _rate(intervention_count, evaluation_count),
        "policy_deny_rate": _rate(deny_count, evaluation_count),
        "approval_trigger_rate": _rate(ask_count, evaluation_count),
        "policy_intervention_fpr": _rate(fpr_hits, len(benign_known)),
        "policy_intervention_fnr": _rate(fnr_hits, len(malicious_known)),
        "benign_label_count": len(benign_known),
        "malicious_label_count": len(malicious_known),
        "unlabeled_count": sum(1 for event in unique if event.is_malicious is None),
        "average_decision_latency_ms": (
            round(sum(latency_values) / len(latency_values), 6)
            if latency_values
            else None
        ),
        "latency_sample_count": len(latency_values),
        "duplicate_policy_record_count": duplicate_policy_record_count,
        "legacy_fallback_count": legacy_fallback_count,
        "deduplication": _DEDUPLICATION_LABEL,
    }


def _audit_sequence_key(event: AuditEvent) -> tuple[int, int, str]:
    metadata = read_audit_integrity(event)
    sequence = metadata.sequence if metadata is not None else 1 << 62
    return (0 if metadata is not None else 1, sequence, event.audit_id)


def _rate(numerator: int, denominator: int) -> float | None:
    # §4.3：分母为零返回 null，不得返回 0。
    if denominator <= 0:
        return None
    return round(numerator / denominator, 6)
