"""Real SDK→localhost HTTP→PostgreSQL recovery, synthetic TEST authority only.

No Host or Provider is loaded. The observed denial receipts say not_invoked;
these checks do not qualify B12's executed-tool/native-host side effects.
"""

from datetime import datetime, timezone
import hashlib
import json
import time

import pytest
from sqlalchemy import create_engine, text

from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import get_test_database_url, reset_control_plane_schema
from tests.support.product_reconciliation_http import reconciliation_http
from tests.test_openclaw_product_activation_http import (
    _build_actual_openclaw_sdk as _build_actual_openclaw_sdk,
)

pytestmark = pytest.mark.postgres


@pytest.fixture
def reconciliation_postgres():
    url = get_test_database_url()
    reset_control_plane_schema(url)
    store = PostgresControlPlaneStore(url)
    store.initialize()
    engine = create_engine(url)
    try:
        yield store, engine
    finally:
        engine.dispose()
        reset_control_plane_schema(url)


def _row(engine, audit_id):
    with engine.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT audit_id, payload_json, sequence, event_hash FROM audit_events WHERE audit_id=:audit"
                ),
                {"audit": audit_id},
            )
            .mappings()
            .all()
        )
    assert len(rows) <= 1
    return dict(rows[0]) if rows else None


def _assert_original_pg_linkage(engine, h, original):
    row = _row(engine, original["auditId"])
    assert row is not None
    receipt = row["payload_json"]
    parent_row = _row(engine, original["policyAuditId"])
    assert parent_row is not None
    parent = parent_row["payload_json"]
    assert receipt["links"]["policy_audit_id"] == parent["audit_id"]
    assert receipt["links"]["event_id"] == h.probe_input["event"]["event_id"]
    assert receipt["evidence"]["execution"]["status"] == "not_invoked"
    with engine.connect() as connection:
        issuance = (
            connection.execute(
                text(
                    "SELECT token_digest, issued_at, expires_at, revoked_at, principal_id, runtime, agent_id, runtime_binding_id, profile_id, payload_json FROM product_activation_acks_v1 WHERE token_digest=:digest"
                ),
                {"digest": original["originalAckDigest"]},
            )
            .mappings()
            .one()
        )
        for table in ("execution_leases", "grant_consumptions", "approval_requests"):
            # A genuine deny creates no execution authority; recovery cannot
            # acquire any. Table names are fixed source constants, not input.
            assert (
                connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
                == 0
            )
    anchor = datetime.fromisoformat(
        parent["metadata"]["product_authority_initial_checked_at"].replace(
            "Z", "+00:00"
        )
    )
    assert issuance["issued_at"] <= anchor < issuance["expires_at"]
    assert issuance["revoked_at"] is None or anchor < issuance["revoked_at"]
    entry = h.http.fixture.bundle.runtime_entry(h.runtime)
    for name in (
        "runtime",
        "agent_id",
        "principal_id",
        "runtime_binding_id",
        "profile_id",
    ):
        assert issuance[name] == getattr(entry, name)
    original_wire = json.loads(h.proxy.exchanges[0].request_body)
    token = original_wire["metadata"]["activation_ack"]["ack_token"]
    assert token not in json.dumps(receipt)
    assert token not in json.dumps(dict(issuance), default=str)
    h.assert_recorded(original["auditId"])
    return row


def _assert_consumed_pg_linkage(engine, h, original):
    """Independent SQL binds the original consumed ACK to one lease/receipt."""
    row = _row(engine, original["auditId"])
    assert row is not None
    receipt = row["payload_json"]
    with engine.connect() as connection:
        approval = (
            connection.execute(
                text("SELECT * FROM approval_requests WHERE approval_id=:id"),
                {"id": original["approvalId"]},
            )
            .mappings()
            .one()
        )
        binding = (
            connection.execute(
                text("SELECT * FROM enforcement_bindings WHERE approval_id=:id"),
                {"id": original["approvalId"]},
            )
            .mappings()
            .one()
        )
        lease = (
            connection.execute(
                text("SELECT * FROM execution_leases WHERE lease_id=:id"),
                {"id": original["leaseId"]},
            )
            .mappings()
            .one()
        )
        consumption = (
            connection.execute(
                text("SELECT * FROM grant_consumptions WHERE consumption_id=:id"),
                {"id": original["consumptionId"]},
            )
            .mappings()
            .one()
        )
        issuance = (
            connection.execute(
                text(
                    "SELECT * FROM product_activation_acks_v1 WHERE token_digest=:digest"
                ),
                {"digest": original["consumptionAckDigest"]},
            )
            .mappings()
            .one()
        )
        grant = (
            connection.execute(
                text("SELECT * FROM capability_grant_runtime WHERE grant_id=:id"),
                {"id": binding["grant_id"]},
            )
            .mappings()
            .one()
        )
        for table in ("grant_consumptions", "execution_leases"):
            assert (
                connection.execute(
                    text(f"SELECT count(*) FROM {table} WHERE grant_id=:id"),
                    {"id": grant["grant_id"]},
                ).scalar_one()
                == 1
            )
    assert approval["decision"] == "allow_once"
    assert approval["resolved_at"] is not None
    assert binding["release_mode"] == (
        "strong_binding" if h.runtime == "langgraph" else "restricted_allow_once"
    )
    assert binding["policy_audit_id"] == original["policyAuditId"]
    assert binding["event_id"] == h.probe_input["event"]["event_id"]
    assert (
        binding["action_id"]
        == approval["action_id"]
        == lease["action_id"]
        == consumption["action_id"]
    )
    assert binding["grant_id"] == lease["grant_id"] == consumption["grant_id"]
    assert grant["remaining_uses"] == 0
    assert grant["scope_digest"] == binding["scope_digest"]
    assert (
        grant["authorization_fingerprint"]
        == binding["authorization_fingerprint"]
        == lease["authorization_fingerprint"]
        == consumption["authorization_fingerprint"]
    )
    assert lease["approval_id"] == approval["approval_id"]
    assert lease["consumption_id"] == consumption["consumption_id"]
    assert receipt["links"]["lease_id"] == lease["lease_id"]
    assert receipt["links"]["consumption_id"] == consumption["consumption_id"]
    assert receipt["links"]["policy_audit_id"] == binding["policy_audit_id"]
    assert receipt["evidence"]["execution"]["status"] == "not_invoked"
    consumed_at = datetime.fromisoformat(
        consumption["consumed_at"].replace("Z", "+00:00")
    )
    assert issuance["issued_at"] <= consumed_at < issuance["expires_at"]
    assert issuance["revoked_at"] is None or consumed_at < issuance["revoked_at"]
    entry = h.http.fixture.bundle.runtime_entry(h.runtime)
    for name in (
        "runtime",
        "agent_id",
        "principal_id",
        "runtime_binding_id",
        "profile_id",
    ):
        assert issuance[name] == getattr(entry, name)
    consumes = [
        request
        for request in h.http.requests
        if request.path
        == f"/v1/approvals/{original['approvalId']}/execution-leases/consume"
    ]
    assert len(consumes) == 1
    assert consumes[0].activation_ack_header is not None
    digest = (
        "sha256:"
        + hashlib.sha256(consumes[0].activation_ack_header.encode()).hexdigest()
    )
    assert digest == original["consumptionAckDigest"] == original["originalAckDigest"]
    wire = json.loads(
        (h.root / "protected-recovery" / "original-wire.json").read_bytes()
    )
    token = wire["metadata"]["activation_ack"]["ack_token"]
    assert token == consumes[0].activation_ack_header
    assert token not in json.dumps(receipt)
    assert token not in json.dumps(dict(issuance), default=str)
    if h.runtime == "langgraph":
        start = _row(engine, original["startAuditId"])
        assert start is not None
        assert receipt["links"]["parent_audit_id"] == start["audit_id"]
        assert start["sequence"] < row["sequence"]
    return row


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("http_status", [409, 422])
def test_postgres_explicit_reconciliation_commits_one_original_receipt(
    tmp_path, reconciliation_postgres, runtime, http_status
):
    store, engine = reconciliation_postgres
    with reconciliation_http(tmp_path / runtime, runtime, store=store) as h:
        h.proxy.inject(
            "reject_409" if http_status == 409 else "reject_422", audit_id=h.audit_id
        )
        first = h.probe("prepare")
        assert first["delivered"]["status"] == "permanent_rejected", first
        assert _row(engine, h.audit_id) is None
        assert h.proxy.exchanges[0].upstream_status is None
        before = len(h.http.requests)
        assert h.probe("drain")["delivered"] == []
        assert len(h.proxy.exchanges) == 1
        h.proxy.inject("none")
        recovered = h.probe(
            "reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"]
        )
        assert recovered["delivered"]["status"] == "recorded", recovered
        assert [request.path for request in h.http.requests[before:]] == [
            "/v1/audit/events"
        ]
        assert h.proxy.exchanges[0].request_body == h.proxy.exchanges[1].request_body
        row = _assert_original_pg_linkage(engine, h, first)
        again = h.probe("reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"])
        assert again["delivered"]["status"] == "recorded"
        assert len(h.proxy.exchanges) == 2
        assert _row(engine, h.audit_id) == row
        state = again["status"]
        assert state["pending_count" if runtime == "langgraph" else "pendingCount"] == 0
        assert (
            state["breaker_open" if runtime == "langgraph" else "breakerOpen"] is True
        )
        h.assert_private_queue()


def test_postgres_dual_sdk_reconciles_after_actual_original_ack_expiry(
    tmp_path, reconciliation_postgres
):
    store, engine = reconciliation_postgres
    with (
        reconciliation_http(
            tmp_path / "langgraph", "langgraph", store=store, decision_kind="ask"
        ) as lg,
        reconciliation_http(
            tmp_path / "openclaw",
            "openclaw",
            existing_http=lg.http,
            decision_kind="ask",
        ) as oc,
    ):
        prepared = []
        for h in (lg, oc):
            rejected_id = (
                f"audit_commit_{h.probe_input['event']['event_id']}"
                if h.runtime == "langgraph"
                else h.audit_id
            )
            h.proxy.inject("reject_409", audit_id=rejected_id)
            first = h.probe("prepare")
            assert first["delivered"]["status"] == "permanent_rejected"
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
            prepared.append((h, first))
        expires = max(
            datetime.fromisoformat(first["expiresAt"].replace("Z", "+00:00"))
            for _, first in prepared
        )
        deadline = time.monotonic() + 135
        # One shared real-wall-clock wait, no patched SDK/server/DB timestamps.
        while datetime.now(timezone.utc) <= expires:
            assert time.monotonic() < deadline
            time.sleep(0.1)
        before = len(lg.http.requests)
        for h, first in prepared:
            assert _row(engine, first["auditId"]) is None
            h.proxy.inject("none")
            if h.runtime == "langgraph":
                start = h.probe(
                    "reconcile",
                    auditId=first["startAuditId"],
                    wireDigest=first["startWireDigest"],
                )
                assert start["delivered"]["status"] == "recorded", start
                assert start["status"]["pending_count"] == 1
                assert h.probe("drain")["delivered"] == []
            recovered = h.probe(
                "reconcile", auditId=first["auditId"], wireDigest=first["wireDigest"]
            )
            assert recovered["delivered"]["status"] == "recorded", recovered
            assert recovered["pid"] != first["pid"]
            assert (
                h.proxy.exchanges[0].request_body == h.proxy.exchanges[1].request_body
            )
            row = _assert_consumed_pg_linkage(engine, h, first)
            again = h.probe(
                "reconcile", auditId=first["auditId"], wireDigest=first["wireDigest"]
            )
            assert again["delivered"]["status"] == "recorded"
            assert _row(engine, first["auditId"]) == row
        assert [request.path for request in lg.http.requests[before:]] == [
            "/v1/audit/events"
        ] * 3


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("fault", ["prepared_persist", "confirmation_persist"])
def test_postgres_receipt_confirmation_requires_local_persistence(
    tmp_path, reconciliation_postgres, runtime, fault
):
    store, engine = reconciliation_postgres
    with reconciliation_http(tmp_path / runtime, runtime, store=store) as h:
        h.proxy.inject("reject_409", audit_id=h.audit_id)
        first = h.probe("prepare")
        assert _row(engine, h.audit_id) is None
        h.proxy.inject("none")
        failed = h.probe(
            "reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"], fault=fault
        )
        assert failed["faultCount"] > 0
        assert failed["delivered"]["status"] == "failed"
        before = _row(engine, h.audit_id)
        assert (before is not None) == (fault == "confirmation_persist")
        done = h.probe("reconcile", auditId=h.audit_id, wireDigest=first["wireDigest"])
        assert done["delivered"]["status"] == "recorded", done
        after = _assert_original_pg_linkage(engine, h, first)
        if before is not None:
            assert after == before
            assert h.proxy.exchanges[-1].upstream_body is not None
            assert (
                json.loads(h.proxy.exchanges[-1].upstream_body)["idempotent_replay"]
                is True
            )
        assert all(
            exchange.request_body == h.proxy.exchanges[0].request_body
            for exchange in h.proxy.exchanges
        )
