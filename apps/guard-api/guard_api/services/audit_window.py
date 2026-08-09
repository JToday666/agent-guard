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
    normalize_window_filters,
)
from .metric_rules import aggregate_policy_metrics

# 历史 cohort 通过 sequence keyset 分页完整读取，不以固定总量静默截断。
_COHORT_PAGE_SIZE = 1000
_DEDUPLICATION_LABEL = "logical_policy_evaluation"
_DEFAULT_WINDOW_LIMIT = 500


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
        limit: int | None = None,
        trace_id: str | None = None,
        case_id: str | None = None,
        runtime: str | None = None,
        decision: str | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """契约 §5.2：捕获链头上界 → limit+1 读取 → scope/events/policy_metrics。"""

        requested_filters = normalize_window_filters(
            trace_id=trace_id,
            case_id=case_id,
            runtime=runtime,
            decision=decision,
        )
        if cursor:
            try:
                state = decode_cursor(cursor)
            except CursorExpiredError:
                raise AuditWindowRequestError(
                    "CURSOR_EXPIRED", status_code=410
                ) from None
            filters = state["filters"]
            supplied_filters = {
                key: value
                for key, value in requested_filters.items()
                if value is not None
            }
            if any(filters[key] != value for key, value in supplied_filters.items()):
                raise AuditWindowRequestError("CURSOR_SCOPE_MISMATCH", status_code=400)
            if limit is not None and state["limit"] != limit:
                raise AuditWindowRequestError("CURSOR_SCOPE_MISMATCH", status_code=400)
            effective_limit = int(state["limit"])
            upper_sequence = int(state["upper_sequence"])
            after_sequence: int | None = int(state["after_sequence"])
            snapshot_at = _parse_rfc3339_utc(
                str(state["snapshot_at"]), field="cursor.snapshot_at"
            )
        else:
            filters = requested_filters
            effective_limit = _DEFAULT_WINDOW_LIMIT if limit is None else limit
            # 单次存储快照同时捕获链上界与数据库/本地存储时钟。
            upper_sequence, snapshot_at = self.store.capture_audit_snapshot()
            after_sequence = None

        rows = self.store.read_audit_events_bounded(
            AuditWindowQuery(
                upper_sequence=upper_sequence,
                after_sequence=after_sequence,
                trace_id=filters["trace_id"],
                case_id=filters["case_id"],
                runtime=filters["runtime"],
                decision=filters["decision"],
                limit=effective_limit + 1,
            )
        )
        has_more = len(rows) > effective_limit
        page = rows[:effective_limit]

        next_cursor: str | None = None
        if has_more and page:
            next_cursor = encode_cursor(
                upper_sequence=upper_sequence,
                after_sequence=_event_sequence(page[-1]),
                filters=filters,
                limit=effective_limit,
                snapshot_at=_utc_iso_z(snapshot_at),
            )

        sequences = [_event_sequence(event) for event in page]
        return {
            "scope": {
                "kind": "audit_window",
                "snapshot_id": snapshot_identifier(upper_sequence),
                "outcomes_as_of": _utc_iso_z(snapshot_at),
                "order": "audit_sequence",
                "limit": effective_limit,
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
            "policy_metrics": aggregate_policy_metrics(page),
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
        cohort_from = _parse_rfc3339_utc(evaluated_from, field="evaluated_from")
        cohort_to = _parse_rfc3339_utc(evaluated_to, field="evaluated_to")
        if cohort_from >= cohort_to:
            raise AuditWindowRequestError("COHORT_RANGE_INVALID", status_code=400)
        upper_sequence, snapshot_at = self.store.capture_audit_snapshot()
        if outcomes_as_of is None:
            effective_as_of = snapshot_at
        else:
            requested_as_of = _parse_rfc3339_utc(outcomes_as_of, field="outcomes_as_of")
            # A sequence snapshot cannot make claims about future knowledge. Return
            # the effective cutoff actually represented by this response.
            effective_as_of = min(requested_as_of, snapshot_at)
        runtime_filter = _optional_value(runtime)
        case_filter = _optional_value(case_id)
        events = self._read_policy_cohort(
            upper_sequence=upper_sequence,
            evaluated_from=cohort_from,
            evaluated_to=cohort_to,
            ingested_as_of=effective_as_of,
            runtime=runtime_filter,
            case_id=case_filter,
        )
        return {
            "scope": {
                "kind": "aggregate_history",
                "evaluated_from": _utc_iso_z(cohort_from),
                "evaluated_to": _utc_iso_z(cohort_to),
                "outcomes_as_of": _utc_iso_z(effective_as_of),
                "snapshot_id": snapshot_identifier(upper_sequence),
                "deduplication": _DEDUPLICATION_LABEL,
                "filters": {"runtime": runtime_filter, "case_id": case_filter},
            },
            "policy_metrics": aggregate_policy_metrics(events),
        }

    def _read_policy_cohort(
        self,
        *,
        upper_sequence: int,
        evaluated_from: datetime,
        evaluated_to: datetime,
        ingested_as_of: datetime,
        runtime: str | None,
        case_id: str | None,
    ) -> list[AuditEvent]:
        events: list[AuditEvent] = []
        after_sequence: int | None = None
        while True:
            page = self.store.read_audit_events_bounded(
                AuditWindowQuery(
                    upper_sequence=upper_sequence,
                    after_sequence=after_sequence,
                    evaluated_from=evaluated_from,
                    evaluated_to=evaluated_to,
                    ingested_as_of=ingested_as_of,
                    record_type="policy_evaluation",
                    runtime=runtime,
                    case_id=case_id,
                    limit=_COHORT_PAGE_SIZE,
                )
            )
            if not page:
                break
            events.extend(page)
            if len(page) < _COHORT_PAGE_SIZE:
                break
            next_after = _event_sequence(page[-1])
            if next_after == after_sequence:
                raise AuditWindowRequestError("INTERNAL_ERROR", status_code=500)
            after_sequence = next_after
        return events


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


def _parse_rfc3339_utc(value: str, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        raise AuditWindowRequestError("COHORT_RANGE_INVALID", status_code=400) from None
    if parsed.tzinfo is None:
        raise AuditWindowRequestError("COHORT_RANGE_INVALID", status_code=400)
    return parsed.astimezone(timezone.utc)


def _utc_iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
