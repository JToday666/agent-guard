"""Actual SDK/HTTP recovery; synthetic authority, no native Host qualification."""

import json
from pathlib import Path

import pytest
from concurrent.futures import ThreadPoolExecutor
import time

from tests.support.product_reconciliation_http import (
    ReconciliationHttpRig,
    reconciliation_http,
)

pytestmark = pytest.mark.e2e


def assert_rejected_then_reconciled(h: ReconciliationHttpRig, status: int):
    h.proxy.inject(
        "reject_409" if status == 409 else "reject_422", count=1, audit_id=h.audit_id
    )
    first = h.probe("prepare")
    assert first["delivered"]["status"] == "permanent_rejected", first
    assert first["auditId"] == h.audit_id
    assert h.http.store.get_audit_event(h.audit_id) is None
    assert len(h.proxy.exchanges) == 1
    original = h.proxy.exchanges[0]
    assert original.upstream_status is None
    assert original.forwarded_digest is None
    assert original.response_status == status
    assert original.request_digest == first["wireDigest"]
    h.assert_private_queue()
    before = len(h.http.requests)
    passive = h.probe("drain")
    assert passive["delivered"] == []
    assert passive["pid"] != first["pid"]
    assert len(h.proxy.exchanges) == 1
    assert h.http.requests[before:] == []
    recovered = h.probe("reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"])
    assert recovered["delivered"]["status"] == "recorded", recovered
    assert recovered["pid"] not in {first["pid"], passive["pid"]}
    assert len(h.proxy.exchanges) == 2
    replay = h.proxy.exchanges[-1]
    assert replay.request_body == original.request_body
    assert replay.forwarded_digest == original.request_digest
    assert replay.upstream_status == 200
    assert replay.upstream_body is not None
    assert json.loads(replay.upstream_body)["ok"] is True
    assert [item.path for item in h.http.requests[before:]] == ["/v1/audit/events"]
    assert all(item.activation_ack_header is None for item in h.http.requests[before:])
    h.assert_recorded(h.audit_id)
    again = h.probe("reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"])
    assert again["delivered"]["status"] == "recorded", again
    assert len(h.proxy.exchanges) == 2
    h.assert_private_queue()
    return first, recovered


@pytest.mark.parametrize("status", [409, 422])
def test_langgraph_original_rejected_wire_recovers_in_receipts_only_process(
    tmp_path, status
):
    with reconciliation_http(tmp_path / "langgraph", "langgraph") as h:
        first, recovered = assert_rejected_then_reconciled(h, status)
        assert recovered["status"]["pending_count"] == 0
        assert recovered["status"]["completed_count"] == 1
        assert recovered["status"]["breaker_open"] is True
        snapshot = recovered["snapshot"]
        assert snapshot["confirmed"] is True
        assert snapshot["requires_explicit_retry"] is False
        assert snapshot["original_rejection"]["http_status"] == status
        assert snapshot["wire_digest"] == first["wireDigest"]
        assert len(snapshot["attempts"]) == 1


def test_langgraph_recovery_rejects_replacement_endpoint_before_http(tmp_path):
    with reconciliation_http(tmp_path / "langgraph", "langgraph") as h:
        h.proxy.inject("reject_409", audit_id=h.audit_id)
        first = h.probe("prepare")
        assert first["delivered"]["status"] == "permanent_rejected"
        result = h.probe(
            "reconcile",
            auditId=h.audit_id,
            wireDigest=first["wireDigest"],
            baseUrlOverride=h.http.base_url,
            allowError=True,
        )
        assert "errorType" in result
        assert len(h.proxy.exchanges) == 1
        assert h.http.store.get_audit_event(h.audit_id) is None


def test_langgraph_recovery_wrong_digest_never_sends_or_replaces_original(tmp_path):
    with reconciliation_http(tmp_path / "langgraph", "langgraph") as h:
        h.proxy.inject("reject_422", audit_id=h.audit_id)
        first = h.probe("prepare")
        assert first["delivered"]["status"] == "permanent_rejected"
        result = h.probe(
            "reconcile", auditId=h.audit_id, wireDigest="0" * 64, allowError=True
        )
        assert "errorType" in result or result["delivered"]["status"] == "failed"
        assert len(h.proxy.exchanges) == 1
        assert (
            Path(h.probe_input["wirePath"]).read_bytes()
            == h.proxy.exchanges[0].request_body
        )


def test_langgraph_reconciliation_network_retry_remains_manual(tmp_path):
    with reconciliation_http(tmp_path / "langgraph", "langgraph") as h:
        h.proxy.inject("reject_409", audit_id=h.audit_id)
        first = h.probe("prepare")
        h.proxy.inject("disconnect_before", audit_id=h.audit_id)
        retry = h.probe("reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"])
        assert retry["delivered"]["status"] == "queued_durable", retry
        assert retry["snapshot"]["requires_explicit_retry"] is True
        assert len(h.proxy.exchanges) == 2
        h.proxy.inject("none")
        assert h.probe("drain")["delivered"] == []
        assert len(h.proxy.exchanges) == 2
        done = h.probe("reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"])
        assert done["delivered"]["status"] == "recorded", done
        assert len(done["snapshot"]["attempts"]) == 2
        assert all(
            item.request_body == h.proxy.exchanges[0].request_body
            for item in h.proxy.exchanges
        )


@pytest.mark.parametrize("fault", ["prepared_persist", "confirmation_persist"])
def test_langgraph_reconciliation_storage_failure_never_claims_confirmation(
    tmp_path, fault
):
    with reconciliation_http(tmp_path / "langgraph", "langgraph") as h:
        h.proxy.inject("reject_409", audit_id=h.audit_id)
        first = h.probe("prepare")
        h.proxy.inject("none")
        failed = h.probe(
            "reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"], fault=fault
        )
        assert failed["delivered"]["status"] == "failed", failed
        assert failed["faultCount"] > 0
        assert failed["snapshot"]["confirmed"] is False
        assert len(h.proxy.exchanges) == (1 if fault == "prepared_persist" else 2)
        assert (h.http.store.get_audit_event(h.audit_id) is not None) == (
            fault == "confirmation_persist"
        )
        done = h.probe("reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"])
        assert done["delivered"]["status"] == "recorded", done
        assert all(
            item.request_body == h.proxy.exchanges[0].request_body
            for item in h.proxy.exchanges
        )


def test_langgraph_real_ask_consumption_abort_reconciles_start_then_terminal(tmp_path):
    with reconciliation_http(
        tmp_path / "langgraph", "langgraph", decision_kind="ask"
    ) as h:
        start_id = f"audit_commit_{h.probe_input['event']['event_id']}"
        h.proxy.inject("reject_409", audit_id=start_id)
        first = h.probe("prepare")
        assert first["startAuditId"] == start_id
        assert first["nativeInvocations"] == 0
        assert (
            len(
                {
                    first[key]
                    for key in (
                        "evaluationAckDigest",
                        "consumptionAckDigest",
                        "refreshedAckDigest",
                    )
                }
            )
            == 3
        )
        assert first["originalAckDigest"] == first["consumptionAckDigest"]
        assert len(h.proxy.exchanges) == 1
        before = len(h.http.requests)
        h.proxy.inject("none")
        start = h.probe(
            "reconcile", auditId=start_id, wireDigest=first["startWireDigest"]
        )
        assert start["delivered"]["status"] == "recorded", start
        assert start["status"]["pending_count"] == 1
        assert h.probe("drain")["delivered"] == []
        assert len(h.proxy.exchanges) == 2
        terminal = h.probe(
            "reconcile", auditId=first["auditId"], wireDigest=first["wireDigest"]
        )
        assert terminal["delivered"]["status"] == "recorded", terminal
        assert terminal["status"]["pending_count"] == 0
        assert [request.path for request in h.http.requests[before:]] == [
            "/v1/audit/events",
            "/v1/audit/events",
        ]
        accepted = h.http.store.get_audit_event(first["auditId"])
        assert accepted is not None
        assert accepted.links["parent_audit_id"] == start_id
        assert accepted.links["lease_id"] == first["leaseId"]
        assert accepted.links["consumption_id"] == first["consumptionId"]
        assert accepted.evidence is not None
        assert accepted.evidence["execution"]["status"] == "not_invoked"


def assert_close_holds_owner_until_actual_http_finishes(h):
    h.proxy.inject("reject_409", audit_id=h.audit_id)
    first = h.probe("prepare")
    h.proxy.inject("none")
    gate = h.proxy.pause_response(h.audit_id)
    marker = h.root / "protected-recovery" / "close-state.json"
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            h.probe,
            "reconcile_close",
            auditId=h.audit_id,
            wireDigest=first["wireDigest"],
            closeMarker=str(marker),
        )
        try:
            assert gate.reached.wait(timeout=5)
            deadline = time.monotonic() + 2
            while not marker.exists():
                assert time.monotonic() < deadline
                time.sleep(0.005)
            peer = h.probe("status", allowError=True)
            assert "errorType" in peer
            assert len(h.proxy.exchanges) == 2
            h.assert_recorded(h.audit_id)
        finally:
            gate.release.set()
        closed = future.result(timeout=10)
    if h.runtime == "langgraph":
        # Python close deliberately retains the durable unknown attempt. A
        # received server response is not a locally persisted confirmation.
        assert closed["delivered"]["status"] == "failed", closed
        assert closed["delivered"]["error_code"] == "outbox_closed"
        pending = h.probe("status")
        assert pending["status"]["pending_count"] == 1
        done = h.probe("reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"])
        assert done["delivered"]["status"] == "recorded", done
        assert len(h.proxy.exchanges) == 3
        assert h.proxy.exchanges[-1].request_body == h.proxy.exchanges[0].request_body
        assert (
            json.loads(h.proxy.exchanges[-1].upstream_body)["idempotent_replay"] is True
        )
    else:
        assert closed["delivered"]["status"] == "recorded", closed
        assert len(h.proxy.exchanges) == 2
    idle = h.probe("status")
    assert (
        idle["status"]["pending_count" if h.runtime == "langgraph" else "pendingCount"]
        == 0
    )


def test_langgraph_close_retains_owner_through_actual_http_confirmation(tmp_path):
    with reconciliation_http(tmp_path / "langgraph", "langgraph") as h:
        assert_close_holds_owner_until_actual_http_finishes(h)


def assert_shipped_cli_recovers_original_http_receipt(h):
    h.proxy.inject("reject_422", audit_id=h.audit_id)
    first = h.probe("prepare")
    h.proxy.inject("none")
    before = len(h.http.requests)
    report = h.reconcile_cli(first)
    assert (
        report.get("product_active_started", report.get("product_active_enabled"))
        is False
    )
    assert [request.path for request in h.http.requests[before:]] == [
        "/v1/audit/events"
    ]
    assert h.proxy.exchanges[0].request_body == h.proxy.exchanges[1].request_body
    h.assert_recorded(first["auditId"])


def test_langgraph_shipped_cli_recovers_original_http_receipt(tmp_path):
    with reconciliation_http(tmp_path / "langgraph", "langgraph") as h:
        assert_shipped_cli_recovers_original_http_receipt(h)
