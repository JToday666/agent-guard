"""Real HTTP fault selection, using deliberately incomplete test receipts."""

from pathlib import Path

import httpx
import pytest

from tests.support.product_delivery_http import product_delivery_proxy
from tests.support.product_runtime_http import product_runtime_http

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("status", [409, 422])
def test_delivery_fault_only_consumes_selected_audit_without_forwarding(
    tmp_path: Path, status: int
) -> None:
    with (
        product_runtime_http(tmp_path) as http,
        product_delivery_proxy(http.base_url) as proxy,
        httpx.Client(base_url=proxy.base_url, trust_env=False, timeout=3) as client,
    ):
        target = "audit:selected-injected-rejection"
        proxy.inject(
            "reject_409" if status == 409 else "reject_422", count=1, audit_id=target
        )
        headers = {"Authorization": f"Bearer {http.runtime_tokens['langgraph']}"}
        # This malformed non-target must reach the real API and must not consume
        # the selected transport fault. No runtime outcome is being claimed.
        other = client.post(
            "/v1/audit/events", json={"audit_id": "audit:unrelated"}, headers=headers
        )
        assert other.status_code == 422
        before = len(http.requests_for("/v1/audit/events"))
        rejected = client.post(
            "/v1/audit/events", json={"audit_id": target}, headers=headers
        )
        assert rejected.status_code == status
        assert rejected.json()["error"]["code"] == "TEST_DELIVERY_FAULT"
        assert len(http.requests_for("/v1/audit/events")) == before
        exchange = proxy.exchanges[-1]
        assert exchange.audit_id == target
        assert exchange.upstream_status is None
        assert exchange.forwarded_digest is None
        assert exchange.response_status == status
        repeated = client.post(
            "/v1/audit/events", json={"audit_id": target}, headers=headers
        )
        assert repeated.status_code == 422
        assert len(http.requests_for("/v1/audit/events")) == before + 1
        assert proxy.exchanges[-1].fault == "none"
        assert proxy.exchanges[-1].request_digest == exchange.request_digest
        assert proxy.exchanges[-1].forwarded_digest == exchange.request_digest
