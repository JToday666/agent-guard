"""Actual Node SDK/HTTP recovery, explicit TEST package/authority, no Host."""

import pytest

from tests.support.product_reconciliation_http import reconciliation_http
from tests.test_langgraph_product_reconciliation_http import (
    assert_rejected_then_reconciled,
    assert_shipped_cli_recovers_original_http_receipt,
    assert_close_holds_owner_until_actual_http_finishes,
)
from tests.test_openclaw_product_activation_http import (
    _build_actual_openclaw_sdk as _build_actual_openclaw_sdk,
)

pytestmark = pytest.mark.contract


@pytest.mark.parametrize("status", [409, 422])
def test_openclaw_original_rejected_wire_recovers_in_receipts_only_process(
    tmp_path, status
):
    with reconciliation_http(tmp_path / "openclaw", "openclaw") as h:
        first, recovered = assert_rejected_then_reconciled(h, status)
        assert recovered["status"]["pendingCount"] == 0
        assert recovered["status"]["completedCount"] == 1
        assert recovered["status"]["breakerOpen"] is True
        rows = recovered["status"]["reconciliations"]
        assert len(rows) == 1
        assert rows[0]["completed"] is True
        assert rows[0]["originalHttpStatus"] == status
        assert rows[0]["wireDigest"] == first["wireDigest"]
        assert len(rows[0]["attempts"]) == 1


def test_openclaw_recovery_rejects_changed_endpoint_without_http(tmp_path):
    with reconciliation_http(tmp_path / "openclaw", "openclaw") as h:
        h.proxy.inject("reject_409", audit_id=h.audit_id)
        first = h.probe("prepare")
        assert first["delivered"]["status"] == "permanent_rejected"
        response = h.probe(
            "reconcile",
            auditId=h.audit_id,
            wireDigest=first["wireDigest"],
            baseUrlOverride=h.http.base_url,
            allowError=True,
        )
        assert "errorType" in response
        assert len(h.proxy.exchanges) == 1
        assert h.http.store.get_audit_event(h.audit_id) is None


def test_openclaw_reconciliation_network_retry_requires_explicit_retry(tmp_path):
    with reconciliation_http(tmp_path / "openclaw", "openclaw") as h:
        h.proxy.inject("reject_422", audit_id=h.audit_id)
        first = h.probe("prepare")
        h.proxy.inject("disconnect_before", audit_id=h.audit_id)
        retry = h.probe("reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"])
        assert retry["delivered"]["status"] == "queued_durable"
        assert retry["delivered"]["manualRetryRequired"] is True
        assert (
            retry["status"]["reconciliations"][0]["attempts"][-1]["status"]
            == "retryable"
        )
        assert len(h.proxy.exchanges) == 2
        h.proxy.inject("none")
        assert h.probe("drain")["delivered"] == []
        assert len(h.proxy.exchanges) == 2
        recovered = h.probe(
            "reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"]
        )
        assert recovered["delivered"]["status"] == "recorded"
        assert len(recovered["status"]["reconciliations"][0]["attempts"]) == 2
        assert all(
            item.request_body == h.proxy.exchanges[0].request_body
            for item in h.proxy.exchanges
        )


@pytest.mark.parametrize("fault", ["prepared_persist", "confirmation_persist"])
def test_openclaw_reconciliation_storage_failure_never_claims_confirmation(
    tmp_path, fault
):
    with reconciliation_http(tmp_path / "openclaw", "openclaw") as h:
        h.proxy.inject("reject_422", audit_id=h.audit_id)
        first = h.probe("prepare")
        h.proxy.inject("none")
        failed = h.probe(
            "reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"], fault=fault
        )
        assert failed["delivered"]["status"] == "failed", failed
        assert failed["faultCount"] > 0
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


def test_openclaw_real_ask_keeps_consumption_ack_through_receipts_only_recovery(
    tmp_path,
):
    with reconciliation_http(
        tmp_path / "openclaw", "openclaw", decision_kind="ask"
    ) as h:
        h.proxy.inject("reject_422", audit_id=h.audit_id)
        first = h.probe("prepare")
        assert first["delivered"]["status"] == "permanent_rejected", first
        assert first["approvalEvidence"]["hostInvocationCount"] == 0
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
        before = len(h.http.requests)
        h.proxy.inject("none")
        recovered = h.probe(
            "reconcile", auditId=first["auditId"], wireDigest=first["wireDigest"]
        )
        assert recovered["delivered"]["status"] == "recorded", recovered
        assert [request.path for request in h.http.requests[before:]] == [
            "/v1/audit/events"
        ]
        accepted = h.http.store.get_audit_event(first["auditId"])
        assert accepted is not None
        assert accepted.links["lease_id"] == first["leaseId"]
        assert accepted.links["consumption_id"] == first["consumptionId"]
        assert accepted.evidence is not None
        assert accepted.evidence["execution"]["status"] == "not_invoked"
        assert all(
            exchange.request_body == h.proxy.exchanges[0].request_body
            for exchange in h.proxy.exchanges
        )


def test_openclaw_close_retains_owner_through_actual_http_confirmation(tmp_path):
    with reconciliation_http(tmp_path / "openclaw", "openclaw") as h:
        assert_close_holds_owner_until_actual_http_finishes(h)


def test_openclaw_shipped_cli_recovers_original_http_receipt(tmp_path):
    with reconciliation_http(tmp_path / "openclaw", "openclaw") as h:
        assert_shipped_cli_recovers_original_http_receipt(h)
