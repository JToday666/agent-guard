"""Real HTTP and SDK recovery, with synthetic TEST identity and no Host/Provider.

The caller owns an optional PostgreSQL store and its isolated schema lifecycle.
No fixture receipt claims a tool invocation: preparation observes a real deny.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Literal

from agentguard_core import PolicyBundle
from agentguard_core.policies import RuleOverride
from guard_api.security_state import SecurityStateService
from guard_api.services.competition import parse_decision_authority_evidence_payload
from guard_api.storage.base import ControlPlaneStore
from tests.support.product_activation import product_runtime_status_for_activation
from tests.support.product_delivery_http import DeliveryProxy, product_delivery_proxy
from tests.support.product_runtime_http import (
    ProductRuntimeHttpHarness,
    product_runtime_http,
)
from tests.test_product_activation_http import _event_payload, _task_payload

ROOT = Path(__file__).resolve().parents[2]


def write_private_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        path.chmod(0o600)
        json.dump(
            value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )


@dataclass(slots=True)
class ReconciliationHttpRig:
    runtime: Literal["langgraph", "openclaw"]
    root: Path
    http: ProductRuntimeHttpHarness = field(repr=False)
    proxy: DeliveryProxy = field(repr=False)
    probe_input: dict[str, Any] = field(repr=False)
    config_file: Path = field(repr=False)

    @property
    def audit_id(self) -> str:
        return (
            f"audit_outcome_{self.probe_input['event']['event_id']}_pre_execution_deny"
        )

    @property
    def directory(self) -> Path:
        return self.root / "queue"

    def probe(self, stage: str, **changes: Any) -> dict[str, Any]:
        payload = {**self.probe_input, "stage": stage, **changes}
        script = (
            "langgraph-product-reconciliation-probe.py"
            if self.runtime == "langgraph"
            else "openclaw-product-reconciliation-probe.mjs"
        )
        command = [sys.executable if self.runtime == "langgraph" else "node"]
        command.append(str(ROOT / "tests" / "support" / script))
        completed = subprocess.run(
            command,
            input=json.dumps(payload),
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=40,
        )
        # Check secrets before reporting any child diagnostics in assertions.
        secrets = list(self.http.runtime_tokens.values())
        for request in self.http.requests:
            if request.activation_ack_header:
                secrets.append(request.activation_ack_header)
            ack = request.body.get("metadata", {}).get("activation_ack")
            if isinstance(ack, dict) and isinstance(ack.get("ack_token"), str):
                secrets.append(ack["ack_token"])
        assert all(
            secret not in completed.stdout and secret not in completed.stderr
            for secret in secrets
        ), "Recovery child leaked a private credential/carrier"
        assert completed.returncode == 0, completed.stdout
        result = json.loads(completed.stdout)
        assert result["syntheticTestEvidence"] is True
        assert result["nativeHostEvidence"] is False
        if not changes.get("allowError", False):
            assert "errorType" not in result, result
        return result

    def assert_recorded(self, audit_id: str) -> None:
        event = self.http.store.get_audit_event(audit_id)
        assert event is not None
        assert event.record_type == "runtime_outcome"
        assert event.decision == "deny"
        assert event.evidence is not None
        assert event.evidence["execution"]["status"] == "not_invoked"
        policy = self.http.store.get_audit_event(event.links["policy_audit_id"])
        assert policy is not None and policy.evidence is not None
        parsed_authority = parse_decision_authority_evidence_payload(
            {"decision_authority": policy.evidence["decision_authority"]}
        )
        authority = parsed_authority.decision_authority.model_dump(mode="json")
        assert {
            key: authority[key] for key in ("source", "mode", "selection_basis")
        } == {"source": "v21", "mode": "active", "selection_basis": "profile_all"}
        for exchange in self.proxy.exchanges:
            ack = (
                json.loads(exchange.request_body)
                .get("metadata", {})
                .get("activation_ack")
            )
            if isinstance(ack, dict):
                assert ack["ack_token"] not in event.model_dump_json()

    def reconcile_cli(self, original: dict[str, Any]) -> dict[str, Any]:
        """Run the shipped command with private config and actual HTTP."""
        environment = os.environ.copy()
        if self.runtime == "langgraph":
            command = [
                sys.executable,
                str(ROOT / "scripts/product-runtime-receipts.py"),
                "reconcile",
                "--config-file",
                str(self.config_file),
            ]
            report_path = None
        else:
            config_path = self.root / "protected-recovery" / "node-cli-config.json"
            report_path = self.root / "protected-recovery" / "node-cli-report.json"
            environment["AGENTGUARD_TEST_RECEIPT_TOKEN"] = self.probe_input["token"]
            write_private_json(
                config_path,
                {
                    "guardApiBaseUrl": self.probe_input["baseUrl"],
                    "adapterTokenEnv": "AGENTGUARD_TEST_RECEIPT_TOKEN",
                    "agentId": self.probe_input["agentId"],
                    "principalId": self.probe_input["principalId"],
                    "runtimeBindingId": self.probe_input["runtimeBindingId"],
                    "productReceiptDirectory": self.probe_input["directory"],
                    "productReceiptKeyPath": self.probe_input["keyPath"],
                    "requestTimeoutMs": 3000,
                },
            )
            command = [
                "node",
                str(ROOT / "scripts/product-runtime-reconcile-openclaw.mjs"),
                "--package-root",
                self.probe_input["packageDirectory"],
                "--config",
                str(config_path),
                "--report",
                str(report_path),
            ]
        command.extend(
            [
                "--audit-id",
                original["auditId"],
                "--expected-wire-digest",
                original["wireDigest"],
            ]
        )
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=15,
        )
        wire = json.loads(
            (self.root / "protected-recovery" / "original-wire.json").read_bytes()
        )
        secrets = [
            *self.http.runtime_tokens.values(),
            wire["metadata"]["activation_ack"]["ack_token"],
        ]
        assert all(
            secret not in completed.stdout and secret not in completed.stderr
            for secret in secrets
        )
        assert completed.returncode == 0, completed.stdout
        report = json.loads(completed.stdout)
        assert report["exit_code"] == 0
        assert report["selected_confirmed"] is True
        if report_path is not None:
            assert json.loads(report_path.read_bytes()) == report
            assert report_path.stat().st_mode & 0o777 == 0o600
        return report

    def assert_private_queue(self) -> None:
        records = list(self.directory.glob("*.agq"))
        assert records
        assert self.directory.stat().st_mode & 0o777 == 0o700
        tokens = {
            json.loads(item.request_body)
            .get("metadata", {})
            .get("activation_ack", {})
            .get("ack_token")
            for item in self.proxy.exchanges
        } - {None}
        for record in records:
            assert record.stat().st_mode & 0o777 == 0o600
            assert all(token.encode() not in record.read_bytes() for token in tokens)


@contextmanager
def reconciliation_http(
    root: Path,
    runtime: Literal["langgraph", "openclaw"],
    *,
    store: ControlPlaneStore | None = None,
    existing_http: ProductRuntimeHttpHarness | None = None,
    decision_kind: str = "deny",
) -> Iterator[ReconciliationHttpRig]:
    root.mkdir(mode=0o700, parents=True)
    # Freeze the TEST review policy before constructing/signing authority; the
    # real Core still computes ASK and its release eligibility from the event.
    policy = (
        PolicyBundle(
            sensitive_resource_markers=["transport-review.txt"],
            rule_overrides={
                "P001_sensitive_file_access": RuleOverride(
                    decision="ask", risk_score=50, severity="medium"
                )
            },
        )
        if decision_kind == "ask"
        else None
    )
    with (
        (
            nullcontext(existing_http)
            if existing_http is not None
            else product_runtime_http(root, store=store, policy=policy)
        ) as http,
        product_delivery_proxy(http.base_url) as proxy,
    ):
        entry = http.fixture.bundle.runtime_entry(runtime)
        if runtime == "openclaw":
            peer = product_runtime_status_for_activation(http.fixture, "langgraph")
            response = http.client.post(
                "/v1/adapters/langgraph/heartbeat",
                headers={"Authorization": f"Bearer {http.runtime_tokens['langgraph']}"},
                json=peer.model_dump(
                    mode="json",
                    exclude={"runtime", "principal_id", "last_heartbeat_at"},
                ),
            )
            assert response.status_code == 200
        task_payload = _task_payload(
            runtime, http.fixture, trace_id=http.trace_id, session_id=http.session_id
        )
        if decision_kind == "deny":
            task_payload["resource_constraints"] = [
                {"scheme": "file", "op": "exact", "values": ["/workspace/allowed.txt"]}
            ]
        response = http.client.post(
            "/v1/tasks",
            headers={"Authorization": "Bearer control-secret"},
            json=task_payload,
        )
        assert response.status_code == 200
        task = response.json()
        SecurityStateService(http.store).ensure_ready(task["scope_digest"])
        event = _event_payload(
            runtime,
            "tool_call_proposed",
            task["task_id"],
            trace_id=http.trace_id,
            session_id=http.session_id,
        )
        event["event_id"] = f"evt:reconcile:{runtime}"
        event["security_context"]["derived_paths"] = []
        if decision_kind == "deny":
            event["payload"] = {
                "tool": {"name": "exec", "call_id": f"call:reconcile:{runtime}"},
                "arguments": {"command": "true"},
                "derived_resources": [],
            }
        else:
            event["payload"] = {
                "tool": {"name": "read_file", "call_id": f"call:reconcile:{runtime}"},
                "arguments": {"path": "/workspace/transport-review.txt"},
                "derived_resources": [],
            }
        config: dict[str, Any] = {
            "runtime": runtime,
            "api_mode": "guard-api-v0.3",
            "fail_closed": True,
            "defense_enabled": True,
            "core_base_url": proxy.base_url,
            "token": http.runtime_tokens[runtime],
            "timeout": 3.0,
            "agent_id": entry.agent_id,
            "runtime_binding_id": entry.runtime_binding_id,
            "product_manifest_path": str(http.manifest_path),
            "context_isolation_mode": "required",
            "runtime_receipt_mode": "required",
            "product_receipt_directory": str(root / "queue"),
            "product_receipt_key_path": str(root / "keys" / "receipt.key"),
            "product_execution_enabled": False,
        }
        config_file = root / "protected-recovery" / "config.json"
        if runtime == "langgraph":
            write_private_json(
                config_file,
                {
                    "schema_version": "agentguard-product-receipt-recovery/1",
                    "runtime": runtime,
                    "config": config,
                },
            )
        manifest_path = root / "protected-recovery" / "openclaw-manifest.json"
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
        observed = None
        if runtime == "openclaw":
            manifest = {name: getattr(entry, name) for name in fields}
            manifest.update(
                schema_version="1.0",
                activation_ref_digest=http.fixture.bundle.activation_ref_digest,
            )
            write_private_json(manifest_path, manifest)
            observed = {
                name: manifest[name]
                for name in (
                    "runtime",
                    "runtime_version",
                    "plugin_version",
                    "adapter_artifact_digest",
                    "host_inventory_digest",
                    "plugin_inventory_digest",
                    "plugin_order_inventory_digest",
                    "tool_inventory_digest",
                )
            }
            observed.update(
                loaded=True,
                enforcement_mode="enforce",
                capability_report=http.fixture.openclaw_capability.model_dump(
                    mode="json"
                ),
            )
        probe_input = {
            "runtime": runtime,
            "decisionKind": decision_kind,
            "controlToken": "control-secret",
            "event": event,
            "config": config,
            "configFile": str(config_file),
            "baseUrl": proxy.base_url,
            "token": http.runtime_tokens[runtime],
            "agentId": entry.agent_id,
            "principalId": entry.principal_id,
            "runtimeBindingId": entry.runtime_binding_id,
            "manifestPath": str(manifest_path),
            "profileDigest": entry.profile_digest,
            "observation": observed or http.observation.model_dump(mode="json"),
            "packageDirectory": str(root / "synthetic-sdk"),
            "sourcePackageRoot": str(ROOT / "packages/agentguard-openclaw-plugin"),
            "directory": str(root / "queue"),
            "keyPath": str(root / "keys" / "receipt.key"),
            "wirePath": str(root / "protected-recovery" / "original-wire.json"),
        }
        yield ReconciliationHttpRig(
            runtime, root, http, proxy, probe_input, config_file
        )


def raw_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
