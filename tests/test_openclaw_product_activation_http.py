"""Real Node SDK / Guard API transport contracts, not native Product admission.

The source distribution is beta. Successful handshakes use its actual built
JavaScript copied into a private TEST package with synthetic RC metadata. The
signed authority, capabilities and artifact/inventory digests are test fixtures;
no host hook, external provider, or side effect is exercised or qualified here.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

import httpx
import pytest
from agentguard_core import PolicyBundle
from agentguard_core.actions.canonical_json import canonical_json, canonical_sha256
from agentguard_core.decisions.product import PRODUCT_EVENT_TYPES
from fastapi import Request

from guard_api.main import create_app
from guard_api.security_state import SecurityStateService
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.auth import add_adapter_credential
from tests.support.product_activation import (
    ProductActivationFixture,
    build_test_product_activation,
    product_runtime_status_for_activation,
    write_test_product_activation,
)
from tests.support.product_evaluation import product_replay_settings
from tests.support.product_runtime_http import CapturedProductRequest, _localhost_server
from tests.test_product_activation_http import _event_payload, _task_payload

# This layer verifies the HTTP/SDK protocol contract using real local sockets;
# it does not claim native Host execution. CI's contract job provisions Node.
pytestmark = pytest.mark.contract
ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "packages/agentguard-openclaw-plugin"
NODE_PROBE = ROOT / "tests/support/openclaw-product-http-probe.mjs"


@pytest.fixture(scope="module", autouse=True)
def _build_actual_openclaw_sdk() -> None:
    pnpm = shutil.which("pnpm")
    if pnpm is None or shutil.which("node") is None:
        pytest.fail("Node and pnpm are required for the OpenClaw HTTP transport tests")
    subprocess.run(
        [pnpm, "--filter", "@agentguard-ai/openclaw-plugin", "build"],
        cwd=ROOT,
        check=True,
        timeout=60,
    )


@dataclass(slots=True)
class OpenClawHttpContract:
    fixture: ProductActivationFixture = field(repr=False)
    store: MemoryControlPlaneStore = field(repr=False)
    requests: list[CapturedProductRequest] = field(repr=False)
    probe_input: dict[str, Any] = field(repr=False)
    task_id: str
    trace_id: str = "trace:openclaw-sdk-http-contract"
    session_id: str = "session:openclaw-sdk-http-contract"

    def event(self, event_type: str = "tool_call_proposed") -> dict[str, Any]:
        return _event_payload(
            "openclaw",
            event_type,
            self.task_id,
            trace_id=self.trace_id,
            session_id=self.session_id,
        )

    def requests_for(self, path: str) -> list[CapturedProductRequest]:
        return [request for request in self.requests if request.path == path]

    def probe(self, scenario: str, event: dict[str, Any]) -> dict[str, Any]:
        completed = subprocess.run(
            ["node", str(NODE_PROBE)],
            input=json.dumps(
                {**self.probe_input, "scenario": scenario, "event": event}
            ),
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stdout or completed.stderr
        result = json.loads(completed.stdout)
        assert result["ok"] is True
        for request in self.requests:
            if request.activation_ack_header:
                assert request.activation_ack_header not in completed.stdout
                assert request.activation_ack_header not in completed.stderr
        return result


@pytest.fixture
def transport_contract(tmp_path: Path) -> Iterator[OpenClawHttpContract]:
    policy = PolicyBundle()
    fixture = build_test_product_activation(
        now=datetime.now(timezone.utc),
        policy_digest=canonical_sha256(policy.model_dump(mode="json")),
    )
    settings = product_replay_settings(
        write_test_product_activation(
            tmp_path / "synthetic-signed-authority.json", fixture
        ),
        fixture,
    )
    settings.llm_approval_enabled = False
    settings.llm_approval_api_key = None
    settings.v21_semantic_enabled = False
    settings.v21_semantic_api_key = None
    store = MemoryControlPlaneStore()
    store.save_policy_snapshot(
        policy, expected_revision=0, updated_by="node-http-contract"
    )
    tokens = {
        "langgraph": "node-http-contract-langgraph-secret",
        "openclaw": "node-http-contract-openclaw-secret",
    }
    for runtime in ("langgraph", "openclaw"):
        entry = fixture.bundle.runtime_entry(runtime)
        add_adapter_credential(
            store,
            token=tokens[runtime],
            runtime=runtime,
            agent_id=entry.agent_id,
            principal_id=entry.principal_id,
        )
    entry = fixture.bundle.runtime_entry("openclaw")
    manifest_directory = tmp_path / "protected-manifest"
    manifest_directory.mkdir(mode=0o700)
    manifest_path = manifest_directory / "manifest.json"
    fields = (
        "runtime",
        "runtime_version",
        "plugin_version",
        "principal_id",
        "agent_id",
        "runtime_binding_id",
        "profile_id",
        "profile_digest",
        "adapter_artifact_digest",
        "capability_report_digest",
        "host_inventory_digest",
        "plugin_inventory_digest",
        "plugin_order_inventory_digest",
        "tool_inventory_digest",
    )
    manifest = {name: getattr(entry, name) for name in fields}
    manifest.update(
        schema_version="1.0", activation_ref_digest=fixture.bundle.activation_ref_digest
    )
    manifest_path.write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    manifest_path.chmod(0o600)
    observed_fields = (
        "runtime",
        "runtime_version",
        "plugin_version",
        "adapter_artifact_digest",
        "host_inventory_digest",
        "plugin_inventory_digest",
        "plugin_order_inventory_digest",
        "tool_inventory_digest",
    )
    observation = {
        **{name: getattr(entry, name) for name in observed_fields},
        "loaded": True,
        "enforcement_mode": "enforce",
        "capability_report": fixture.openclaw_capability.model_dump(mode="json"),
    }
    peer_heartbeat = product_runtime_status_for_activation(
        fixture, "langgraph"
    ).model_dump(mode="json", exclude={"runtime", "principal_id", "last_heartbeat_at"})
    requests: list[CapturedProductRequest] = []
    app = create_app(store=store, settings=settings)

    @app.middleware("http")
    async def capture_request(request: Request, call_next):
        raw = await request.body()
        capture = CapturedProductRequest(
            path=request.url.path,
            activation_ack_header=request.headers.get("X-AgentGuard-Activation-Ack"),
            body=json.loads(raw) if raw else {},
        )
        requests.append(capture)
        response = await call_next(request)
        capture.status_code = response.status_code
        return response

    with _localhost_server(app) as base_url:
        with httpx.Client(base_url=base_url, timeout=3, trust_env=False) as client:
            peer = client.post(
                "/v1/adapters/langgraph/heartbeat",
                headers={"Authorization": f"Bearer {tokens['langgraph']}"},
                json=peer_heartbeat,
            )
            assert peer.status_code == 200, peer.text
            assert peer.headers["cache-control"] == "no-store"
            harness = OpenClawHttpContract(
                fixture=fixture,
                store=store,
                requests=requests,
                task_id="",
                probe_input={
                    "baseUrl": base_url,
                    "sourcePackageRoot": str(PLUGIN_ROOT),
                    "packageDirectory": str(tmp_path / "synthetic-rc-sdk"),
                    "manifestPath": str(manifest_path),
                    "profileDigest": entry.profile_digest,
                    "observation": observation,
                    "token": tokens["openclaw"],
                    "peerToken": tokens["langgraph"],
                    "peerHeartbeat": peer_heartbeat,
                },
            )
            task = client.post(
                "/v1/tasks",
                headers={"Authorization": "Bearer control-secret"},
                json=_task_payload(
                    "openclaw",
                    fixture,
                    trace_id=harness.trace_id,
                    session_id=harness.session_id,
                ),
            )
            assert task.status_code == 200, task.text
            task_body = task.json()
            assert task_body["status"] == "active"
            harness.task_id = task_body["task_id"]
            # TaskFact creation was real HTTP. Its internal online-state anchor
            # has no public mutation route, matching the existing Product tests.
            SecurityStateService(store).ensure_ready(task_body["scope_digest"])
            yield harness


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("event_type", PRODUCT_EVENT_TYPES)
def test_openclaw_sdk_http_contract_seven_events_have_original_ack_and_authority(
    transport_contract: OpenClawHttpContract,
    event_type: str,
) -> None:
    harness = transport_contract
    event = harness.event(event_type)
    result = harness.probe("evaluate", event)
    assert result["syntheticPackageMetadata"] is True
    assert result["assumedVersion"] == "0.1.0-rc.1"
    assert result["actualHostVersion"] == "2026.7.1-2"
    assert result["decisionId"].startswith("dec:v21-product:")
    assert (
        result["authority"]["activation_ref_digest"]
        == harness.fixture.bundle.activation_ref_digest
    )
    assert result["authority"]["legacy_floor_applied"] is False
    assert result["authority"]["matched_path_ids"] == []
    assert (
        result["directive"]["capability_digest"]
        == harness.fixture.openclaw_capability.report_digest
    )
    heartbeats = harness.requests_for("/v1/adapters/openclaw/heartbeat")
    assert len(heartbeats) == 1
    assert heartbeats[0].status_code == 200
    assert heartbeats[0].body["plugin_version"] == "0.1.0-rc.1"
    assert (
        heartbeats[0].body["capability_report"]["c3_atomic_replace_and_seal"] is False
    )
    requests = harness.requests_for("/v1/guard/evaluate")
    assert len(requests) == 1
    assert requests[0].status_code == 200
    assert requests[0].activation_ack_header is not None
    assert _hash_token(requests[0].activation_ack_header) == result["originalAckHash"]
    parent = harness.store.get_policy_evaluation_by_event_id(event["event_id"])
    assert parent is not None
    assert parent.audit_id == result["policyAuditId"]
    assert parent.metadata["product_authority_digest"].startswith("sha256:")


@pytest.mark.parametrize("scenario", ["beta-rejected", "unstarted", "missing-manifest"])
def test_openclaw_sdk_http_contract_invalid_start_makes_zero_requests(
    transport_contract: OpenClawHttpContract,
    scenario: str,
) -> None:
    harness = transport_contract
    count = len(harness.requests)
    result = harness.probe(scenario, harness.event())
    assert result["rejected"] is True
    assert len(harness.requests) == count
    if scenario == "beta-rejected":
        assert result["syntheticPackageMetadata"] is False
        assert result["errorType"] == "OpenClawProductActivationError"
        assert result["errorCode"] == "version_mismatch"
        assert (
            json.loads((PLUGIN_ROOT / "package.json").read_text())["version"]
            == "0.1.0-beta.1"
        )


def test_openclaw_sdk_http_contract_peer_drift_blocks_without_policy_write(
    transport_contract: OpenClawHttpContract,
) -> None:
    harness = transport_contract
    event = harness.event()
    result = harness.probe("peer-drift", event)
    assert result["rejected"] is True
    requests = harness.requests_for("/v1/guard/evaluate")
    assert len(requests) == 1
    assert requests[0].status_code == 503
    assert requests[0].activation_ack_header is not None
    assert _hash_token(requests[0].activation_ack_header) == result["originalAckHash"]
    assert harness.store.get_policy_evaluation_by_event_id(event["event_id"]) is None


def test_openclaw_sdk_http_contract_original_ack_receipt_survives_refresh_and_close(
    transport_contract: OpenClawHttpContract,
) -> None:
    harness = transport_contract
    # Narrow the actual TaskFact to a file resource. The proposed high-impact
    # process action violates explicit V2 scope without relying on a legacy rule.
    task_payload = _task_payload(
        "openclaw",
        harness.fixture,
        trace_id=harness.trace_id,
        session_id=harness.session_id,
    )
    task_payload["resource_constraints"] = [
        {"scheme": "file", "op": "exact", "values": ["/workspace/allowed.txt"]}
    ]
    with httpx.Client(
        base_url=harness.probe_input["baseUrl"], timeout=3, trust_env=False
    ) as client:
        response = client.post(
            "/v1/tasks",
            headers={"Authorization": "Bearer control-secret"},
            json=task_payload,
        )
    assert response.status_code == 200, response.text
    task = response.json()
    assert task["status"] == "active"
    harness.task_id = task["task_id"]
    SecurityStateService(harness.store).ensure_ready(task["scope_digest"])
    event = harness.event()
    # This command is JSON evidence submitted to evaluation; no exec tool runs.
    event["payload"] = {
        "tool": {"name": "exec", "call_id": "call:node-http-denied"},
        "arguments": {"command": "true"},
        "derived_resources": [],
    }
    result = harness.probe("historical-receipt", event)
    assert result["decision"] == "deny"
    assert result["authority"]["legacy_floor_applied"] is False
    assert result["receiptRecorded"] is True
    assert result["sessionClosedBeforeReceipt"] is True
    assert result["freshAckHash"] != result["originalAckHash"]
    receipts = harness.requests_for("/v1/audit/events")
    assert len(receipts) == 1
    assert receipts[0].status_code == 200
    assert receipts[0].activation_ack_header is None
    body = receipts[0].body
    assert (
        _hash_token(body["metadata"]["activation_ack"]["ack_token"])
        == result["originalAckHash"]
    )
    assert body["evidence"]["execution"]["status"] == "not_invoked"
    persisted = harness.store.get_audit_event(result["receiptAuditId"])
    assert persisted is not None
    assert persisted.links["policy_audit_id"] == result["policyAuditId"]
    assert (
        body["metadata"]["activation_ack"]["ack_token"]
        not in persisted.model_dump_json()
    )


def test_openclaw_sdk_http_contract_conservative_floor_deny_never_releases(
    transport_contract: OpenClawHttpContract,
) -> None:
    harness = transport_contract
    event = harness.event()
    # Retain the original B03 negative input. B07 accepts its conservative
    # Product DENY without claiming a pure V2 ALLOW or invoking any tool.
    event["payload"] = {
        "tool": {"name": "exec", "call_id": "call:node-http-legacy-floor"},
        "arguments": {"command": "rm -rf /"},
        "derived_resources": [],
    }
    result = harness.probe("conservative-floor-deny", event)
    assert result["decision"] == "deny"
    assert result["directive"]["mode"] == "not_applicable"
    assert result["authority"]["legacy_floor_applied"] is True
    evaluations = harness.requests_for("/v1/guard/evaluate")
    assert len(evaluations) == 1
    assert evaluations[0].status_code == 200
    audit = harness.store.get_policy_evaluation_by_event_id(event["event_id"])
    assert audit is not None
    authority = audit.model_dump(mode="json")["decision_authority"]
    assert authority["source"] == "v21"
    assert authority["legacy_floor_applied"] is True
    assert harness.requests_for("/v1/audit/events") == []
