"""Direct contracts for bounded trace snapshots and HTTP validators."""

from __future__ import annotations

from agentguard_core import AuditEvent, ProvenanceNode
from guard_api.models import ApprovalRequest
from guard_api.routers.audit import _conditional_json_response
from guard_api.services.trace import (
    TRACE_AUDIT_LIMIT,
    TraceService,
    encode_conditional_document,
    if_none_match_matches,
)
from guard_api.storage.memory import MemoryControlPlaneStore


def _audit(index: int, *, trace_id: str = "trace-window") -> AuditEvent:
    return AuditEvent(
        audit_id=f"audit-{trace_id}-{index:04d}",
        trace_id=trace_id,
        timestamp=f"2026-08-08T00:{index // 60:02d}:{index % 60:02d}+00:00",
        summary=f"event {index}",
        decision="allow",
        risk_score=0,
        severity="low",
        blocked=False,
        reason="allowed",
    )


def test_trace_reports_a_bounded_window_without_guessing_from_result_length() -> None:
    store = MemoryControlPlaneStore()
    for index in range(TRACE_AUDIT_LIMIT + 1):
        store.add_audit_event(_audit(index))
    store.add_audit_event(_audit(0, trace_id="other-trace"))

    payload = TraceService(store=store).get_trace("trace-window")
    audit_events = payload["audit_events"]

    assert isinstance(audit_events, list)
    assert len(audit_events) == TRACE_AUDIT_LIMIT
    assert payload["audit_window"] == {
        "limit": TRACE_AUDIT_LIMIT,
        "returned_count": TRACE_AUDIT_LIMIT,
        "has_more": True,
    }
    assert audit_events[0]["audit_id"] == "audit-trace-window-1000"
    assert audit_events[-1]["audit_id"] == "audit-trace-window-0001"


def test_trace_reports_complete_windows_including_an_empty_trace() -> None:
    store = MemoryControlPlaneStore()
    service = TraceService(store=store)
    store.add_audit_event(_audit(0))

    assert service.get_trace("trace-window")["audit_window"] == {
        "limit": TRACE_AUDIT_LIMIT,
        "returned_count": 1,
        "has_more": False,
    }
    assert service.get_trace("missing")["audit_window"] == {
        "limit": TRACE_AUDIT_LIMIT,
        "returned_count": 0,
        "has_more": False,
    }


def test_trace_validator_changes_when_only_an_approval_changes() -> None:
    store = MemoryControlPlaneStore()
    service = TraceService(store=store)
    store.create_approval(
        ApprovalRequest(
            approval_id="approval-1",
            trace_id="trace-etag",
            subject_id="call-1",
            subject_type="tool_call",
            action_id="call-1",
            action_name="code_exec",
            requesting_principal_id="adapter",
            resource="2 + 2",
            reason="approval required",
            risk_score=72,
            severity="high",
            expires_at="2099-01-01T00:00:00+00:00",
        )
    )
    _, pending_etag = encode_conditional_document(service.get_trace("trace-etag"))

    store.resolve_approval("approval-1", "allow_once")
    _, resolved_etag = encode_conditional_document(service.get_trace("trace-etag"))

    assert resolved_etag != pending_etag


def test_provenance_projects_expired_approval_without_mutating_stored_node() -> None:
    store = MemoryControlPlaneStore()
    service = TraceService(store=store)
    approval = store.create_approval(
        ApprovalRequest(
            approval_id="approval-expired",
            trace_id="trace-expired",
            subject_id="call-expired",
            subject_type="tool_call",
            action_id="call-expired",
            action_name="code_exec",
            requesting_principal_id="adapter",
            resource="2 + 2",
            reason="approval required",
            risk_score=72,
            severity="high",
            created_at="2020-01-01T00:00:00+00:00",
            expires_at="2020-01-01T00:15:00+00:00",
        )
    )
    store.add_provenance_node(
        ProvenanceNode(
            node_id="approval:approval-expired",
            trace_id="trace-expired",
            kind="approval",
            ref_id="approval-expired",
            label="pending",
            metadata={"status": "pending"},
        )
    )

    graph = service.get_provenance("trace-expired")

    assert approval.status == "expired"
    assert graph["nodes"][0]["label"] == "expired"
    assert graph["nodes"][0]["metadata"]["status"] == "expired"
    assert graph["nodes"][0]["metadata"]["decision"] == "deny"
    stored = store.get_provenance_node("approval:approval-expired")
    assert stored is not None
    assert stored.label == "pending"
    assert stored.metadata["status"] == "pending"


def test_trace_and_provenance_have_independent_validators() -> None:
    store = MemoryControlPlaneStore()
    service = TraceService(store=store)
    trace_payload = service.get_trace("trace-independent")
    _, trace_etag = encode_conditional_document(trace_payload)

    store.add_provenance_node(
        ProvenanceNode(
            node_id="audit:audit-1",
            trace_id="trace-independent",
            kind="audit",
            ref_id="audit-1",
            label="audit",
        )
    )
    _, unchanged_trace_etag = encode_conditional_document(
        service.get_trace("trace-independent")
    )
    _, provenance_etag = encode_conditional_document(
        service.get_provenance("trace-independent")
    )

    assert unchanged_trace_etag == trace_etag
    assert provenance_etag != trace_etag


def test_conditional_response_supports_lists_wildcards_and_weak_tags() -> None:
    payload = {"trace_id": "trace-1", "audit_events": []}
    body, etag = encode_conditional_document(payload)

    assert if_none_match_matches(None, etag) is False
    assert if_none_match_matches(f'"other", {etag}', etag) is True
    assert if_none_match_matches(f"W/{etag}", etag) is True
    assert if_none_match_matches("*", etag) is True
    assert _conditional_json_response(payload, None).body == body
    not_modified = _conditional_json_response(payload, etag)
    assert not_modified.status_code == 304
    assert not_modified.body == b""
    assert not_modified.headers["etag"] == etag
    assert not_modified.headers["cache-control"] == "private, no-cache"
    assert not_modified.headers["vary"] == "Cookie, Authorization"
