"""Real Node SDK / local Core durable delivery, not native Product admission.

The actual built SDK is copied into a private package with synthetic TEST RC
metadata. Signed authority and inventory/artifact digests are TEST fixtures.
MemoryControlPlaneStore is not final PostgreSQL evidence. No provider or tool
is invoked; terminal receipts report a real policy denial and not_invoked.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

import httpx
import pytest

from guard_api.runtime_status import activation_ack_token_digest
from guard_api.security_state import SecurityStateService
from tests.support.product_delivery_http import DeliveryProxy, product_delivery_proxy
from tests.test_openclaw_product_activation_http import (
    ROOT,
    OpenClawHttpContract,
    _build_actual_openclaw_sdk as _build_actual_openclaw_sdk,
    transport_contract as transport_contract,
)
from tests.test_product_activation_http import _task_payload

pytestmark = pytest.mark.contract
PROBE = ROOT / "tests/support/openclaw-product-delivery-probe.mjs"


def _digest(value: bytes | str) -> str:
    return hashlib.sha256(
        value.encode() if isinstance(value, str) else value
    ).hexdigest()


@dataclass(slots=True)
class OpenClawDeliveryHttp:
    http: OpenClawHttpContract = field(repr=False)
    proxy: DeliveryProxy = field(repr=False)
    directory: Path
    key_path: Path = field(repr=False)
    namespace: dict[str, str] = field(repr=False)
    event: dict[str, Any] = field(repr=False)

    def probe(self, stage: str, scenario: str = "submit") -> dict[str, Any]:
        payload = {
            **self.http.probe_input,
            "baseUrl": self.proxy.base_url,
            "directory": str(self.directory),
            "keyPath": str(self.key_path),
            "namespace": self.namespace,
            "event": self.event,
            "stage": stage,
            "scenario": scenario,
            # Only the outbox retry scheduler uses this explicit TEST clock.
            "clockAdvanceMs": 60_000 if stage == "drain" else 0,
        }
        completed = subprocess.run(
            ["node", str(PROBE)],
            input=json.dumps(payload),
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=30,
        )
        # Check diagnostics before assertion rendering could expose a credential.
        tokens = [
            request.activation_ack_header
            for request in self.http.requests
            if request.activation_ack_header
        ]
        for token in tokens:
            assert token not in completed.stdout
            assert token not in completed.stderr
        assert completed.returncode == 0, completed.stdout
        result = json.loads(completed.stdout)
        assert result["ok"] is True
        return result

    def assert_private(self) -> None:
        records = list(self.directory.glob("*.agq"))
        assert records
        tokens = [
            request.activation_ack_header.encode()
            for request in self.http.requests
            if request.activation_ack_header
        ]
        for record in records:
            encrypted = record.read_bytes()
            assert all(token not in encrypted for token in tokens)
            assert record.stat().st_mode & 0o777 == 0o600
        assert self.directory.stat().st_mode & 0o777 == 0o700
        assert self.key_path.stat().st_mode & 0o777 == 0o600
        assert self.key_path.parent.stat().st_mode & 0o777 == 0o700
        assert self.directory not in self.key_path.parents

    def assert_recorded(self, result: dict[str, Any]) -> None:
        receipt = self.http.store.get_audit_event(result["auditId"])
        assert receipt is not None
        assert receipt.links["policy_audit_id"] == result["policyAuditId"]
        assert receipt.evidence is not None
        assert receipt.evidence["execution"]["status"] == "not_invoked"
        assert receipt.decision == "deny"
        for request in self.http.requests:
            if request.activation_ack_header:
                assert request.activation_ack_header not in receipt.model_dump_json()


@pytest.fixture
def delivery_http(
    transport_contract: OpenClawHttpContract, tmp_path: Path
) -> Iterator[OpenClawDeliveryHttp]:
    http = transport_contract
    # An actual constrained TaskFact produces a pure V2 denial. The command is
    # only evaluation JSON, and never enters an executable tool boundary.
    payload = _task_payload(
        "openclaw", http.fixture, trace_id=http.trace_id, session_id=http.session_id
    )
    payload["resource_constraints"] = [
        {"scheme": "file", "op": "exact", "values": ["/workspace/allowed.txt"]}
    ]
    with httpx.Client(
        base_url=http.probe_input["baseUrl"], timeout=3, trust_env=False
    ) as client:
        response = client.post(
            "/v1/tasks",
            headers={"Authorization": "Bearer control-secret"},
            json=payload,
        )
    assert response.status_code == 200
    task = response.json()
    assert task["status"] == "active"
    http.task_id = task["task_id"]
    SecurityStateService(http.store).ensure_ready(task["scope_digest"])
    event = http.event()
    # The public HTTP model defaults this field; the typed SDK builder expects
    # the explicit array before it creates a frozen complete receipt wire.
    event["security_context"]["derived_paths"] = []
    event["payload"] = {
        "tool": {"name": "exec", "call_id": "call:openclaw-durable-http-denied"},
        "arguments": {"command": "true"},
        "derived_resources": [],
    }
    entry = http.fixture.bundle.runtime_entry("openclaw")
    with product_delivery_proxy(http.probe_input["baseUrl"]) as proxy:
        yield OpenClawDeliveryHttp(
            http=http,
            proxy=proxy,
            directory=tmp_path / "encrypted-product-receipts",
            key_path=tmp_path / "private-product-keys" / "receipt.key",
            namespace={
                "runtime": "openclaw",
                "agentId": entry.agent_id,
                "principalId": entry.principal_id,
                "runtimeBindingId": entry.runtime_binding_id,
            },
            event=event,
        )


def test_openclaw_product_delivery_http_records_after_exact_ack(
    delivery_http: OpenClawDeliveryHttp,
) -> None:
    h = delivery_http
    result = h.probe("prepare")
    assert result["delivered"]["status"] == "recorded"
    assert result["delivered"]["auditId"] == result["auditId"]
    assert result["syntheticMetadata"] is True
    assert result["candidateAdmissionEvidence"] is False
    assert result["status"]["completedCount"] == 1
    assert result["status"]["pendingCount"] == 0
    assert len(h.proxy.exchanges) == 1
    exchange = h.proxy.exchanges[0]
    assert exchange.upstream_status == 200
    assert _digest(exchange.request_body) == result["wireHash"]
    ack = json.loads(exchange.request_body)["metadata"]["activation_ack"]
    assert _digest(ack["ack_token"]) == result["originalAckHash"]
    assert all(
        request.activation_ack_header is None
        for request in h.http.requests_for("/v1/audit/events")
    )
    h.assert_recorded(result)
    h.assert_private()


def test_openclaw_product_delivery_http_client_dispatches_through_encrypted_outbox(
    delivery_http: OpenClawDeliveryHttp,
) -> None:
    h = delivery_http
    result = h.probe("prepare", "client-dispatch")
    assert result["delivered"]["status"] == "recorded"
    assert result["status"]["completedCount"] == 1
    assert len(h.proxy.exchanges) == 1
    assert _digest(h.proxy.exchanges[0].request_body) == result["wireHash"]
    h.assert_recorded(result)
    h.assert_private()


def test_openclaw_product_delivery_http_client_missing_paths_makes_zero_requests(
    delivery_http: OpenClawDeliveryHttp,
) -> None:
    h = delivery_http
    result = h.probe("prepare", "client-missing-paths")
    assert result["delivered"]["status"] == "failed"
    assert h.proxy.exchanges == []
    assert h.http.store.get_audit_event(result["auditId"]) is None
    assert not h.directory.exists()


def test_openclaw_product_delivery_http_second_process_replays_original_historical_ack(
    delivery_http: OpenClawDeliveryHttp,
) -> None:
    h = delivery_http
    h.proxy.inject("disconnect_before")
    first = h.probe("prepare")
    assert first["delivered"]["status"] == "queued_durable"
    assert first["sessionClosed"] is True
    assert first["originalAckExpiredAtTestClock"] is True
    assert first["refreshedAckHash"] != first["originalAckHash"]
    assert h.http.store.get_audit_event(first["auditId"]) is None
    ack = json.loads(h.proxy.exchanges[0].request_body)["metadata"]["activation_ack"]
    issuance = h.http.store.get_product_activation_ack(
        activation_ack_token_digest(ack["ack_token"])
    )
    assert issuance is not None
    h.http.store.revoke_product_activation_acks(
        issuance.identity(), revoked_at=datetime.now(timezone.utc).isoformat()
    )
    # An unavailable current activation manifest must not prevent history drain.
    Path(h.http.probe_input["manifestPath"]).unlink()
    h.proxy.inject("none")
    before = len(h.http.requests)
    resumed = h.probe("drain")
    assert resumed["pid"] != first["pid"]
    assert resumed["sessionStarted"] is False
    assert [item["status"] for item in resumed["delivered"]] == ["recorded"]
    assert _digest(h.proxy.exchanges[-1].request_body) == first["wireHash"]
    assert [request.path for request in h.http.requests[before:]] == [
        "/v1/audit/events"
    ]
    assert resumed["status"]["completedCount"] == 1
    h.assert_recorded(first)
    h.assert_private()


def test_openclaw_product_delivery_http_lost_success_response_retries_idempotently(
    delivery_http: OpenClawDeliveryHttp,
) -> None:
    h = delivery_http
    h.proxy.inject("disconnect_after", count=1)
    first = h.probe("prepare")
    assert first["delivered"]["status"] == "queued_durable"
    assert h.proxy.exchanges[0].upstream_status == 200
    h.assert_recorded(first)
    resumed = h.probe("drain")
    assert [item["status"] for item in resumed["delivered"]] == ["recorded"]
    assert len(h.proxy.exchanges) == 2
    assert _digest(h.proxy.exchanges[-1].request_body) == first["wireHash"]
    body = h.proxy.exchanges[-1].upstream_body
    assert body is not None
    assert json.loads(body)["idempotent_replay"] is True
    h.assert_private()


@pytest.mark.parametrize(
    ("fault", "http_status"), [("tamper_parent", 409), ("tamper_ack", 422)]
)
def test_openclaw_product_delivery_http_permanent_rejection_survives_restart(
    delivery_http: OpenClawDeliveryHttp, fault: str, http_status: int
) -> None:
    h = delivery_http
    h.proxy.inject(fault)  # type: ignore[arg-type]
    first = h.probe("prepare")
    assert first["delivered"]["status"] == "permanent_rejected"
    assert h.proxy.exchanges[0].upstream_status == http_status
    assert h.http.store.get_audit_event(first["auditId"]) is None
    h.proxy.inject("none")
    resumed = h.probe("drain")
    assert resumed["status"]["breakerOpen"] is True
    assert resumed["readyRejected"] is True
    assert resumed["delivered"] == []
    assert len(h.proxy.exchanges) == 1
    h.assert_private()


def test_openclaw_product_delivery_http_wrong_ack_id_is_failed_and_retained(
    delivery_http: OpenClawDeliveryHttp,
) -> None:
    h = delivery_http
    h.proxy.inject("wrong_audit_id")
    first = h.probe("prepare")
    assert h.proxy.exchanges[0].upstream_status == 200
    assert first["delivered"]["status"] == "failed"
    assert first["status"]["breakerOpen"] is True
    assert first["status"]["completedCount"] == 0
    h.assert_recorded(first)  # Core received it; SDK did not obtain a valid ACK.
    h.proxy.inject("none")
    resumed = h.probe("drain")
    assert resumed["delivered"] == []
    assert resumed["status"]["breakerOpen"] is True
    assert len(h.proxy.exchanges) == 1
    h.assert_private()


def test_openclaw_product_delivery_http_disk_failure_prevents_direct_send(
    delivery_http: OpenClawDeliveryHttp,
) -> None:
    h = delivery_http
    result = h.probe("prepare", "disk-failure")
    assert result["delivered"]["status"] == "failed"
    assert result["status"]["breakerOpen"] is True
    assert h.proxy.exchanges == []
    assert h.http.store.get_audit_event(result["auditId"]) is None


@pytest.mark.parametrize("scenario", ["unknown-prepared", "unknown-released"])
def test_openclaw_product_delivery_http_unknown_action_cannot_resume_execution(
    delivery_http: OpenClawDeliveryHttp, scenario: str
) -> None:
    h = delivery_http
    first = h.probe("prepare", scenario)
    assert h.proxy.exchanges == []
    resumed = h.probe("drain")
    assert resumed["pid"] != first["pid"]
    assert resumed["before"]["unknownActionCount"] == 1
    assert resumed["status"]["breakerOpen"] is True
    assert resumed["readyRejected"] is True
    assert resumed["delivered"] == []
    assert h.proxy.exchanges == []
    h.assert_private()


def test_openclaw_product_delivery_http_terminal_outage_blocks_next_action_and_only_replays_receipt(
    delivery_http: OpenClawDeliveryHttp,
) -> None:
    h = delivery_http
    h.proxy.inject("disconnect_before")
    first = h.probe("prepare", "terminal-outage")
    assert first["delivered"]["status"] == "queued_durable"
    assert first["nextActionBlocked"] is True
    h.proxy.inject("none")
    before = len(h.http.requests)
    resumed = h.probe("drain")
    assert [item["status"] for item in resumed["delivered"]] == ["recorded"]
    assert resumed["status"]["unknownActionCount"] == 0
    assert _digest(h.proxy.exchanges[-1].request_body) == first["wireHash"]
    assert [request.path for request in h.http.requests[before:]] == [
        "/v1/audit/events"
    ]
    h.assert_recorded(first)
    h.assert_private()
