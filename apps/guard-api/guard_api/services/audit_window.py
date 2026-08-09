"""原子审计窗口与 policy_evaluation cohort 服务（契约 §5/§6）。"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agentguard_core import AuditEvent

from guard_api.storage.base import AuditWindowQuery, ControlPlaneStore
from guard_api.storage.integrity import canonical_sha256, read_audit_integrity

from .audit_window_cursor import (
    CursorExpiredError,
    decode_cursor,
    encode_cursor,
    filters_fingerprint,
    normalize_window_filters,
)
from .metric_rules import aggregate_policy_metrics_v2

# cohort 一次性读取上限；历史接口不提供无范围“全部历史”（契约 §6.2）。
_COHORT_READ_LIMIT = 10_000
_DEDUPLICATION_LABEL = "logical_policy_evaluation"


class AuditWindowRequestError(Exception):
    """审计窗口/cohort 请求级错误，由 Guard API 统一映射为结构化错误响应。"""

    def __init__(self, code: str, *, status_code: int) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(code)


class AuditWindowService:
    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def get_window(
        self,
        *,
        limit: int,
        trace_id: str | None = None,
        case_id: str | None = None,
        runtime: str | None = None,
        decision: str | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """契约 §5.2：捕获链头上界 → limit+1 读取 → scope/events/policy_metrics。"""

        filters = normalize_window_filters(
            trace_id=trace_id,
            case_id=case_id,
            runtime=runtime,
            decision=decision,
        )
        fingerprint = filters_fingerprint(filters)
        if cursor:
            try:
                state = decode_cursor(cursor)
            except CursorExpiredError:
                raise AuditWindowRequestError(
                    "CURSOR_EXPIRED", status_code=410
                ) from None
            # §5.2：客户端续页只提交 cursor；同时提交的 filters/limit
            # 必须与 cursor 绑定作用域一致，不得静默改变 cohort。
            if state["fingerprint"] != fingerprint or state["limit"] != limit:
                raise AuditWindowRequestError("CURSOR_SCOPE_MISMATCH", status_code=400)
            upper_sequence = int(state["upper_sequence"])
            after_sequence: int | None = int(state["after_sequence"])
        else:
            # 步骤 1：捕获当前审计链上界，快照固化后续读取。
            upper_sequence = self._capture_upper_sequence()
            after_sequence = None

        rows = self.store.read_audit_events_bounded(
            AuditWindowQuery(
                upper_sequence=upper_sequence,
                after_sequence=after_sequence,
                trace_id=filters["trace_id"],
                case_id=filters["case_id"],
                runtime=filters["runtime"],
                decision=filters["decision"],
                limit=limit + 1,
            )
        )
        has_more = len(rows) > limit
        page = rows[:limit]

        next_cursor: str | None = None
        if has_more and page:
            next_cursor = encode_cursor(
                upper_sequence=upper_sequence,
                after_sequence=_event_sequence(page[-1]),
                filters=filters,
                limit=limit,
            )

        sequences = [_event_sequence(event) for event in page]
        return {
            "scope": {
                "kind": "audit_window",
                "snapshot_id": snapshot_identifier(upper_sequence),
                "outcomes_as_of": _utc_now_iso_z(),
                "order": "audit_sequence",
                "limit": limit,
                "returned_record_count": len(page),
                "has_more": has_more,
                "next_cursor": next_cursor,
                "sequence_from": min(sequences) if sequences else None,
                "sequence_to": max(sequences) if sequences else None,
                "occurred_from": _occurred_bound(page, earliest=True),
                "occurred_to": _occurred_bound(page, earliest=False),
                "filters": dict(filters),
            },
            "events": [event.model_dump(mode="json") for event in page],
            "policy_metrics": aggregate_policy_metrics_v2(page),
        }

    def get_policy_cohort(
        self,
        *,
        evaluated_from: str | None,
        evaluated_to: str | None,
        outcomes_as_of: str | None = None,
        runtime: str | None = None,
        case_id: str | None = None,
    ) -> dict[str, Any]:
        """契约 §6：先捕获审计 sequence 快照，再按评估时间 cohort 读取。"""

        if evaluated_from is None or evaluated_to is None:
            raise AuditWindowRequestError("COHORT_RANGE_MISSING", status_code=400)
        normalized_from = _parse_rfc3339_utc(evaluated_from, field="evaluated_from")
        normalized_to = _parse_rfc3339_utc(evaluated_to, field="evaluated_to")
        if outcomes_as_of is None:
            normalized_as_of = _utc_now_iso_z()
        else:
            normalized_as_of = _parse_rfc3339_utc(
                outcomes_as_of, field="outcomes_as_of"
            )
        upper_sequence = self._capture_upper_sequence()
        runtime_filter = _optional_value(runtime)
        case_filter = _optional_value(case_id)
        events = self.store.read_audit_events_bounded(
            AuditWindowQuery(
                upper_sequence=upper_sequence,
                evaluated_from=normalized_from,
                evaluated_to=normalized_to,
                runtime=runtime_filter,
                case_id=case_filter,
                limit=_COHORT_READ_LIMIT,
            )
        )
        return {
            "scope": {
                "kind": "aggregate_history",
                "evaluated_from": normalized_from,
                "evaluated_to": normalized_to,
                "outcomes_as_of": normalized_as_of,
                "snapshot_id": snapshot_identifier(upper_sequence),
                "deduplication": _DEDUPLICATION_LABEL,
                "filters": {"runtime": runtime_filter, "case_id": case_filter},
            },
            "policy_metrics": aggregate_policy_metrics_v2(events),
        }

    def _capture_upper_sequence(self) -> int:
        rows = self.store.read_audit_events_bounded(AuditWindowQuery(limit=1))
        return _event_sequence(rows[0]) if rows else 0


def snapshot_identifier(upper_sequence: int) -> str:
    return canonical_sha256({"audit_window_snapshot": upper_sequence})


def _event_sequence(event: AuditEvent) -> int:
    metadata = read_audit_integrity(event)
    if metadata is None:
        raise AuditWindowRequestError("INTERNAL_ERROR", status_code=500)
    return metadata.sequence


def _optional_value(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _occurred_bound(events: list[AuditEvent], *, earliest: bool) -> str | None:
    best_value: datetime | None = None
    best_text: str | None = None
    for event in events:
        try:
            value = datetime.fromisoformat(event.timestamp)
        except ValueError:
            continue
        if best_value is None or (value < best_value) == earliest:
            best_value = value
            best_text = event.timestamp
    return best_text


def _parse_rfc3339_utc(value: str, *, field: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        raise AuditWindowRequestError("COHORT_RANGE_MISSING", status_code=400) from None
    if parsed.tzinfo is None:
        raise AuditWindowRequestError("COHORT_RANGE_MISSING", status_code=400)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
