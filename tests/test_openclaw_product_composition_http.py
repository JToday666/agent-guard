"""Public installed-byte Product factory, real Host/API, controlled local model.

The npm archive contains explicitly synthetic RC metadata and admission is signed
by test keys. The API uses MemoryControlPlaneStore. These integration results are
not final candidate qualification or PostgreSQL evidence; external requests = 0.
"""

from contextlib import contextmanager
import asyncio
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Thread
import time
from types import SimpleNamespace

import httpx
from jsonschema import Draft7Validator
import pytest
from agentguard_core import (
    PolicyBundle,
    RuntimeActivationEntryV1,
    RuntimeOutcomeReceipt,
    build_product_activation_bundle,
)
from agentguard_core.actions.canonical_json import canonical_json, canonical_sha256
from agentguard_core.actions.product_tools import PRODUCT_INBOX_TARGET
from agentguard_core.policies import RuleOverride
from fastapi import Request

from guard_api.main import create_app
from guard_api.security_state import SecurityStateService
from guard_api.services.context_manifest import (
    ContextManifestEnvelope,
    context_manifest_anchor_from_policy,
    context_manifest_record_digest,
    validate_context_manifest_audit_event,
)
from guard_api.services.ct_projection import decode_ct_transient_facts
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.auth import add_adapter_credential
from tests.support.product_activation import (
    product_runtime_status_for_activation,
    write_test_product_activation,
)
from tests.support.product_evaluation import product_replay_settings
from tests.support.product_runtime_http import CapturedProductRequest, _localhost_server
from tests.support.product_tool_catalog import catalog_fixture, resign_catalog_document
from tests.test_openclaw_product_activation_http import (
    ROOT,
    _build_actual_openclaw_sdk as _build_actual_openclaw_sdk,
)
from tests.test_product_activation_http import _task_payload
from tests.test_langgraph_native_graph_http import _automated_test_operator

pytestmark = pytest.mark.e2e
PROBE = ROOT / "tests/support/openclaw-product-composition.mjs"
MODEL = "controlled-product-composition"
TOOLS = (
    ("read", {"path": "fixture.txt"}),
    ("write", {"path": "created.txt", "content": "composition-written\n"}),
    (
        "edit",
        {
            "path": "created.txt",
            "edits": [
                {"oldText": "composition-written", "newText": "composition-edited"}
            ],
        },
    ),
    ("exec", {"command": "node marker.mjs"}),
    ("process", {"action": "list"}),
    ("agentguard_memory_write", {"key": "fixture", "value": "composition-memory"}),
    ("agentguard_memory_read", {"key": "fixture"}),
    (
        "message",
        {
            "action": "send",
            "channel": "agentguard-fixture",
            "target": PRODUCT_INBOX_TARGET,
            "message": "composition-message",
        },
    ),
)
TASK = (
    "In this isolated workspace, read fixture.txt, write created.txt with "
    "composition-written, edit that text to composition-edited, run the approved "
    "node marker.mjs command, list processes, store the new SQLite memory key "
    "fixture with value composition-memory, read that key, and send "
    f"composition-message to the local {PRODUCT_INBOX_TARGET} channel."
)


@contextmanager
def _model_server(root, program):
    """Local controlled SSE and test inbox; received messages stay in this fixture."""
    calls, deliveries, ready_observations = [], [], []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 1024 * 1024:
                self.send_error(413)
                return
            body = json.loads(self.rfile.read(size))
            if self.path == "/inbox":
                deliveries.append(body)
                response = b'{"ok":true,"messageId":"fixture:00000000-0000-4000-8000-000000000001"}'
                self.send_response(201)
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
                return
            if self.path != "/v1/chat/completions":
                self.send_error(400)
                return
            ready_file = root / "composition-ready.json"
            ready_observations.append(
                json.loads(ready_file.read_text()) if ready_file.exists() else None
            )
            calls.append(body)
            # Count surplus/hidden retry requests even when the fixture rejects
            # them; an extra request must fail the exact call-count assertion.
            if len(calls) > len(program) + 1:
                self.send_error(400)
                return
            if (
                self.headers.get("Authorization")
                != "Bearer synthetic-local-model-token"
            ):
                self.send_error(401)
                return
            if body.get("model") != MODEL or body.get("stream") is not True:
                self.send_error(400)
                return
            tool_index = len(calls) - 1
            has_tool = tool_index < len(program)
            if has_tool:
                name, arguments = program[tool_index]
                delta = {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": f"composition-call-{tool_index}",
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": json.dumps(arguments),
                            },
                        }
                    ],
                }
            else:
                delta = {"role": "assistant", "content": "The isolated task is done."}
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            for value, finish in (
                (delta, None),
                ({}, "tool_calls" if has_tool else "stop"),
            ):
                chunk = {
                    "id": f"composition-{len(calls)}",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": MODEL,
                    "choices": [{"index": 0, "delta": value, "finish_reason": finish}],
                }
                self.wfile.write(("data: " + json.dumps(chunk) + "\n\n").encode())
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield (
            f"http://127.0.0.1:{server.server_port}",
            calls,
            deliveries,
            ready_observations,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _probe(payload):
    result = subprocess.run(
        ["node", str(PROBE)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=ROOT,
        # The full fixture performs eight Host invocations and their complete
        # checkpoints; keep a finite bound without applying the one-tool limit.
        timeout=360 if payload.get("captureRunOutcome") else 180,
        check=False,
    )
    if result.stderr:
        stderr_path = Path(payload["root"]) / "composition-stderr.log"
        stderr_path.write_text(result.stderr[: 1024 * 1024])
        stderr_path.chmod(0o600)
    if result.returncode:
        pytest.fail(f"public Product composition failed: {payload['phase']}")
    output = json.loads(result.stdout)
    assert output["outputLimitExceeded"] is False
    return output


def _receipt_public_body(request):
    # pytest can expand intermediate subscriptions. Only use this projection
    # in assertions; original ACKs are compared by hashes outside assertions.
    return {
        **request.body,
        "metadata": {
            "outcome_kind": request.body["metadata"]["outcome_kind"],
            "agent_id": request.body["metadata"].get("agent_id"),
        },
    }


def _is_original_task_message(message):
    return message.get("role") == "user" and message.get("content") in (
        TASK,
        [{"type": "text", "text": TASK}],
    )


def _memory_proof_diagnostic(policy):
    evidence = policy.evidence or {}
    proof = evidence.get("product_action_data", {})
    decoded = decode_ct_transient_facts(policy)
    return {
        "coverage": evidence.get("decision_v21", {}).get("payload", {}).get("coverage"),
        "proof_taints": proof.get("taints"),
        "first_write_memory_ref": proof.get("first_write_memory_ref"),
        "facts": [
            {
                "memory_id": fact.memory_id,
                "trust_state": fact.trust_state,
                "taints": fact.taints,
                "source_refs": fact.source_refs,
            }
            for fact in (decoded.bundle.memory_facts if decoded.bundle else ())
        ],
    }


def _context_plan_diagnostic(policy, store):
    anchor = context_manifest_anchor_from_policy(policy)
    if anchor is None:
        return {"status": "missing_anchor"}
    record = store.get_audit_event(anchor.audit_id)
    if record is None:
        return {"status": "missing_record"}
    validated = validate_context_manifest_audit_event(record)
    manifest = validated.evidence.context_manifest
    return {
        "plan_id": manifest.plan_id,
        "reason_codes": manifest.reason_codes,
        "excluded_chunk_ids": manifest.excluded_chunk_ids,
        "chunks": [
            chunk.model_dump(
                mode="json",
                include={
                    "chunk_id",
                    "source_ref",
                    "source_type",
                    "compartment",
                    "trust",
                    "fact_authority",
                    "taints",
                    "transform_state",
                    "sequence",
                    "evidence_refs",
                },
            )
            for chunk in manifest.chunks
        ],
    }


@contextmanager
def _synthetic_peer_refresh(base_url, token, payload):
    """Keep the explicitly synthetic LG peer fresh during this OC-only test.

    Final qualification must instead keep the real LG process/session running.
    Neither the server freshness window nor the received ACK is modified here.
    """
    stop = Event()
    failures = []

    def refresh():
        with httpx.Client(base_url=base_url, timeout=10, trust_env=False) as client:
            while not stop.wait(30):
                try:
                    status = client.post(
                        "/v1/adapters/langgraph/heartbeat",
                        headers={"Authorization": f"Bearer {token}"},
                        json=payload,
                    ).status_code
                    if status != 200:
                        failures.append("peer_heartbeat_rejected")
                        return
                except Exception:
                    failures.append("peer_heartbeat_unavailable")
                    return

    thread = Thread(target=refresh, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=12)
        assert not thread.is_alive()
        assert failures == []


@contextmanager
def _workspace(tmp_path):
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    with TemporaryDirectory(prefix="product-composition-", dir=reports) as directory:
        root = Path(directory).resolve()
        try:
            yield root
        except BaseException:
            for name in (
                "composition-host.log",
                "composition-stderr.log",
                "composition-private-error.log",
                "composition-registry.json",
                "composition-api-evidence.json",
                "composition-result.json",
            ):
                source = root / name
                if source.is_file():
                    shutil.copy2(source, tmp_path / name)
            raise


def _replace_candidate_digest(catalog, digest):
    values = catalog.bundle.digest_projection()
    entries = [entry.model_dump(mode="json") for entry in catalog.bundle.runtimes]
    next(entry for entry in entries if entry["runtime"] == "openclaw")[
        "adapter_artifact_digest"
    ] = digest
    values["runtimes"] = [RuntimeActivationEntryV1.model_validate(e) for e in entries]
    values["rollout_admission_record"] = catalog.bundle.rollout_admission_record
    values["residual_risk_acceptance"] = catalog.bundle.residual_risk_acceptance
    catalog.bundle = build_product_activation_bundle(
        server_secret=catalog.fixture.server_secret, **values
    )


@pytest.mark.parametrize(
    "scenario",
    [
        "read",
        "all-eight",
        "concurrent-run",
        "close-during-start",
        "memory-after-untrusted",
        "message-allow",
        "message-ask",
        "message-deny",
    ],
)
def test_public_product_factory_runs_real_host_tools_after_ack(tmp_path, scenario):
    all_tools = scenario == "all-eight"
    tainted_memory = scenario == "memory-after-untrusted"
    message_decision = (
        scenario.removeprefix("message-") if scenario.startswith("message-") else None
    )
    policy_bundle = PolicyBundle()
    if message_decision == "allow":
        policy_bundle = PolicyBundle(
            allowed_email_domains=[
                *policy_bundle.allowed_email_domains,
                "agentguard.invalid",
            ]
        )
    elif message_decision == "deny":
        policy_bundle = PolicyBundle(
            rule_overrides={"P005_external_send": RuleOverride(decision="deny")}
        )
    # The independent write has only the authorized task as model input. A
    # separate real Host case below proves that persisting later UNTRUSTED
    # tool ancestry is still blocked. Neither proof nor trust is rewritten.
    program = (
        TOOLS[5:6] + TOOLS[:5] + TOOLS[7:] + TOOLS[6:7]
        if all_tools
        else (
            TOOLS[:1] + TOOLS[5:6]
            if tainted_memory
            else TOOLS[7:] if message_decision else TOOLS[:1]
        )
    )
    with _workspace(tmp_path) as root:
        with _model_server(root, program) as (model_url, calls, deliveries, ready):
            prepared = _probe(
                {
                    "phase": "prepare",
                    "root": str(root),
                    "modelBaseUrl": model_url + "/v1",
                    "modelId": MODEL,
                    "inboxUrl": model_url + "/inbox",
                }
            )
            inspected = prepared["inspected"]
            assert inspected["active"] is False
            assert calls == [] and deliveries == []
            fixture_schema_errors = [
                f"{name}:{error.json_path}:{error.validator}"
                for name, arguments in TOOLS
                for error in Draft7Validator(
                    inspected["inventory"]["input_schemas"][name]
                ).iter_errors(arguments)
            ]
            assert fixture_schema_errors == []
            catalog = catalog_fixture(
                tmp_path,
                policy_digest=canonical_sha256(policy_bundle.model_dump(mode="json")),
            )
            catalog.document["runtimes"][1] = {
                "runtime": "openclaw",
                "inventory": inspected["inventory"],
                "execution": inspected["execution"],
            }
            _replace_candidate_digest(catalog, inspected["artifactDigest"])
            resign_catalog_document(catalog)
            fixture = replace(catalog.fixture, bundle=catalog.bundle)
            entry = fixture.bundle.runtime_entry("openclaw")
            activation = write_test_product_activation(
                root / "test-authority.json", fixture
            )
            settings = product_replay_settings(activation, fixture)
            settings.v21_product_tool_catalog_path = str(catalog.path)
            settings.context_builder_enabled = True
            settings.ct_fact_projection_enabled = True
            settings.llm_approval_enabled = False
            settings.v21_semantic_enabled = False
            store = MemoryControlPlaneStore()
            store.save_policy_snapshot(
                policy_bundle, expected_revision=0, updated_by="composition-test"
            )
            tokens = {
                runtime: f"test-composition-{runtime}"
                for runtime in ("langgraph", "openclaw")
            }
            for runtime, token in tokens.items():
                identity = fixture.bundle.runtime_entry(runtime)
                add_adapter_credential(
                    store,
                    token=token,
                    runtime=runtime,
                    agent_id=identity.agent_id,
                    principal_id=identity.principal_id,
                )
            app = create_app(store=store, settings=settings)
            requests = []

            @app.middleware("http")
            async def capture(request: Request, call_next):
                raw = await request.body()
                item = CapturedProductRequest(
                    request.url.path,
                    request.headers.get("X-AgentGuard-Activation-Ack"),
                    json.loads(raw) if raw else {},
                )
                requests.append(item)
                response = await call_next(request)
                item.status_code = response.status_code
                if (
                    scenario == "close-during-start"
                    and request.url.path == "/v1/adapters/openclaw/heartbeat"
                ):
                    held = root / "composition-ack-held"
                    held.write_text("held\n")
                    held.chmod(0o600)
                    deadline = time.monotonic() + 15
                    while not (root / "composition-ack-release").exists():
                        if time.monotonic() >= deadline:
                            raise RuntimeError("test_heartbeat_release_missing")
                        await asyncio.sleep(0.01)
                return response

            manifest = {
                key: getattr(entry, key)
                for key in (
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
            }
            manifest.update(
                schema_version="1.0",
                activation_ref_digest=fixture.bundle.activation_ref_digest,
            )
            manifest_path = root / "activation-manifest.json"
            manifest_path.write_text(canonical_json(manifest) + "\n")
            manifest_path.chmod(0o600)
            with _localhost_server(app) as base_url:
                with httpx.Client(
                    base_url=base_url, timeout=5, trust_env=False
                ) as client:
                    peer = product_runtime_status_for_activation(
                        fixture, "langgraph"
                    ).model_dump(
                        mode="json",
                        exclude={"runtime", "principal_id", "last_heartbeat_at"},
                    )
                    peer_status = client.post(
                        "/v1/adapters/langgraph/heartbeat",
                        headers={"Authorization": f"Bearer {tokens['langgraph']}"},
                        json=peer,
                    ).status_code
                    assert peer_status == 200
                    payload = _task_payload(
                        "openclaw",
                        fixture,
                        trace_id="trace:composition",
                        session_id=prepared["profile"]["sessionKey"],
                    )
                    payload["task_text"] = TASK
                    response = client.post(
                        "/v1/tasks",
                        headers={"Authorization": "Bearer control-secret"},
                        json=payload,
                    )
                    assert response.status_code == 200
                    task = response.json()
                    assert task["status"] == "active"
                    SecurityStateService(store).ensure_ready(task["scope_digest"])
                    try:
                        # Automated HTTP test operator uses launch/session/CSRF;
                        # actual browser UI qualification remains a B12 check.
                        with (
                            _synthetic_peer_refresh(
                                base_url, tokens["langgraph"], peer
                            ),
                            _automated_test_operator(
                                SimpleNamespace(
                                    base_url=base_url, trace_id="trace:composition"
                                )
                            ) as resolutions,
                        ):
                            result = _probe(
                                {
                                    "phase": "run",
                                    "root": str(root),
                                    "baseUrl": base_url,
                                    "token": tokens["openclaw"],
                                    "manifestPath": str(manifest_path),
                                    "taskId": task["task_id"],
                                    "scopeDigest": task["scope_digest"],
                                    "taskText": TASK,
                                    "traceId": "trace:composition",
                                    "concurrentRun": scenario == "concurrent-run",
                                    "captureRunOutcome": all_tools
                                    or tainted_memory
                                    or message_decision is not None,
                                    "closeDuringStart": scenario
                                    == "close-during-start",
                                }
                            )
                        result_path = root / "composition-result.json"
                        result_path.write_text(json.dumps(result))
                        result_path.chmod(0o600)
                    finally:
                        # Deliberately exclude all ACK/token material and raw request bodies.
                        evidence = {
                            "requests": [
                                {
                                    "path": r.path,
                                    "status": r.status_code,
                                    "event_type": r.body.get("event_type"),
                                }
                                for r in requests
                            ],
                            "model_calls": len(calls),
                            "inbox_deliveries": len(deliveries),
                            "memory_proofs": [
                                _memory_proof_diagnostic(p)
                                for p in store.audit_events
                                if p.record_type == "policy_evaluation"
                                and p.event_type == "memory_write_proposed"
                            ],
                            "context_plans": [
                                _context_plan_diagnostic(p, store)
                                for p in store.audit_events
                                if p.record_type == "policy_evaluation"
                                and p.event_type == "context_assembled"
                            ],
                            "receipts": [
                                {
                                    "stage": r.body.get("stage"),
                                    "event_id": r.body.get("links", {}).get("event_id"),
                                    "outcome_kind": r.body.get("metadata", {}).get(
                                        "outcome_kind"
                                    ),
                                    "execution": r.body.get("evidence", {}).get(
                                        "execution"
                                    ),
                                }
                                for r in requests
                                if r.path == "/v1/audit/events"
                            ],
                            "policy": [
                                {
                                    "event_type": p.event_type,
                                    "decision": p.decision,
                                    "audit_id": p.audit_id,
                                    "rule_hits": p.rule_hits,
                                    "reason": p.reason,
                                }
                                for p in store.audit_events
                                if p.record_type == "policy_evaluation"
                            ],
                        }
                        evidence_path = root / "composition-api-evidence.json"
                        evidence_path.write_text(json.dumps(evidence))
                        evidence_path.chmod(0o600)

            if scenario == "close-during-start":
                assert calls == deliveries == ready == []
                assert result["runOutcomes"] == ["rejected"]
                assert all(
                    s["state"] == "closed" and not s["ready"] and not s["active"]
                    for s in result["snapshots"][1:]
                )
                assert not any(r.path == "/v1/guard/evaluate" for r in requests)
                assert any(
                    r.path == "/v1/adapters/openclaw/heartbeat" and r.status_code == 200
                    for r in requests
                )
                return
            assert result["activeInspectionOutcomes"] == ["rejected", "rejected"]
            if message_decision == "deny":
                assert len(calls) == 1
                assert resolutions == deliveries == []
                assert result["runOutcomes"] == ["rejected"]
                policies = [
                    p
                    for p in store.audit_events
                    if p.record_type == "policy_evaluation"
                ]
                message_policies = [
                    p for p in policies if p.event_type == "message_send_proposed"
                ]
                assert len(message_policies) == 1
                policy = message_policies[0]
                assert policy.decision == "deny"
                assert all(p.decision == "allow" for p in policies if p is not policy)
                assert not any(
                    r.path.endswith("/execution-leases/consume") for r in requests
                )
                assert ready and all(s and s["ready"] and s["active"] for s in ready)
                for p in policies:
                    authority = p.evidence["decision_authority"]["payload"][
                        "decision_authority"
                    ]
                    assert (
                        authority["source"],
                        authority["mode"],
                        authority["selection_basis"],
                    ) == ("v21", "active", "profile_all")
                terminals = [
                    r
                    for r in requests
                    if r.path == "/v1/audit/events"
                    and r.body.get("links", {}).get("policy_audit_id")
                    == policy.audit_id
                ]
                assert len(terminals) == 1
                terminal = _receipt_public_body(terminals[0])
                assert terminals[0].status_code == 200
                assert terminal["metadata"]["outcome_kind"] == "pre_execution_deny"
                assert terminal["evidence"]["execution"]["status"] == "not_invoked"
                assert terminal["evidence"]["execution"]["invoked_at"] is None
                original = next(
                    r
                    for r in requests
                    if r.path == "/v1/guard/evaluate"
                    and r.body["event_id"] == policy.links["event_id"]
                )
                assert original.body["payload"]["recipient"] == PRODUCT_INBOX_TARGET
                assert original.body["payload"]["channel"] == "agentguard-fixture"
                actual_hash = canonical_sha256(
                    terminals[0].body["metadata"]["activation_ack"]["ack_token"]
                )
                expected_hash = canonical_sha256(original.activation_ack_header)
                assert actual_hash == expected_hash
                saved = store.get_audit_event(terminal["audit_id"])
                assert saved is not None and saved.links == terminal["links"]
                assert not any(
                    r.body.get("metadata", {}).get("outcome_kind") == "approval_release"
                    for r in requests
                    if r.path == "/v1/audit/events"
                )
                return
            if tainted_memory:
                assert len(calls) == 2
                assert resolutions == deliveries == []
                assert result["runOutcomes"] == ["rejected"]
                assert [s["state"] for s in result["snapshots"]] == [
                    "created",
                    "ready",
                    "blocked",
                    "closed",
                ]
                assert not (
                    Path(prepared["profile"]["workspaceDir"]) / "memory.sqlite"
                ).exists()
                writes = [
                    p
                    for p in store.audit_events
                    if p.record_type == "policy_evaluation"
                    and p.event_type == "memory_write_proposed"
                ]
                assert len(writes) == 1
                policy = writes[0]
                assert policy.decision == "ask"
                proof = _memory_proof_diagnostic(policy)
                assert "UNTRUSTED" in proof["proof_taints"]
                assert "PERSISTENT_UNTRUSTED" not in proof["proof_taints"]
                assert len(proof["facts"]) == 1
                fact = proof["facts"][0]
                assert fact["memory_id"] == proof["first_write_memory_ref"]
                assert {"UNTRUSTED", "PERSISTENT_UNTRUSTED"} <= set(fact["taints"])
                assert fact["trust_state"] == "tainted"
                for domain in ("dataflow", "memory"):
                    assert proof["coverage"][domain]["status"] == "partial"
                    assert any(
                        "dependency_closure_mismatch" in reason
                        for reason in proof["coverage"][domain]["reason_codes"]
                    )
                change = store.get_memory_change(policy.links["memory_change_id"])
                assert change is not None and change.status == "quarantined"
                for p in store.audit_events:
                    if p.record_type != "policy_evaluation":
                        continue
                    authority = p.evidence["decision_authority"]["payload"][
                        "decision_authority"
                    ]
                    assert (
                        authority["source"],
                        authority["mode"],
                        authority["selection_basis"],
                    ) == ("v21", "active", "profile_all")
                terminals = [
                    r
                    for r in requests
                    if r.path == "/v1/audit/events"
                    and r.body.get("links", {}).get("policy_audit_id")
                    == policy.audit_id
                ]
                assert len(terminals) == 1
                terminal = _receipt_public_body(terminals[0])
                assert terminals[0].status_code == 200
                assert terminal["metadata"]["outcome_kind"] == "pre_execution_deny"
                assert terminal["evidence"]["execution"]["status"] == "not_invoked"
                assert terminal["evidence"]["execution"]["invoked_at"] is None
                original = next(
                    r
                    for r in requests
                    if r.path == "/v1/guard/evaluate"
                    and r.body["event_id"] == policy.links["event_id"]
                )
                actual_hash = canonical_sha256(
                    terminals[0].body["metadata"]["activation_ack"]["ack_token"]
                )
                expected_hash = canonical_sha256(original.activation_ack_header)
                assert actual_hash == expected_hash
                saved = store.get_audit_event(terminal["audit_id"])
                assert saved is not None and saved.links == terminal["links"]
                return
            if scenario == "concurrent-run":
                assert sorted(result["runOutcomes"]) == ["fulfilled", "rejected"]
            assert len(calls) == len(program) + 1
            assert ready and all(s and s["ready"] and s["active"] for s in ready)
            assert [s["state"] for s in result["snapshots"]] == [
                "created",
                "ready",
                "completed",
                "closed",
            ]
            assert all(
                s["c3AtomicReplaceAndSeal"] is False for s in result["snapshots"]
            )
            runtime_files = [
                path
                for path in Path(prepared["profile"]["stateDir"]).rglob("*")
                if path.is_file()
            ]
            private_values = (
                b"synthetic-local-model-token",
                b"synthetic-local-gateway-token",
                tokens["openclaw"].encode(),
            )
            leaked_paths = [
                str(path.relative_to(prepared["profile"]["stateDir"]))
                for path in runtime_files
                if any(value in path.read_bytes() for value in private_values)
            ]
            assert leaked_paths == []
            assert result["snapshots"][1]["modelAttempts"] == 0
            delivered = result["snapshots"][2]["delivery"]
            assert delivered["pendingCount"] == delivered["unknownActionCount"] == 0
            assert delivered["breakerOpen"] is False
            expected_names = {name for name, _ in TOOLS}
            assert all(
                {tool["function"]["name"] for tool in call["tools"]} == expected_names
                for call in calls
            )
            expected_tools = sorted(
                inspected["modelVisibleTools"], key=lambda tool: tool["name"]
            )
            assert all(
                sorted(
                    [tool["function"] for tool in call["tools"]],
                    key=lambda tool: tool["name"],
                )
                == expected_tools
                for call in calls
            )
            evaluations = [r for r in requests if r.path == "/v1/guard/evaluate"]
            heartbeats = [
                r for r in requests if r.path == "/v1/adapters/openclaw/heartbeat"
            ]
            assert heartbeats and all(r.status_code == 200 for r in heartbeats)
            assert requests.index(heartbeats[0]) < requests.index(evaluations[0])
            assert evaluations and all(r.status_code == 200 for r in evaluations)
            policies = [
                p for p in store.audit_events if p.record_type == "policy_evaluation"
            ]
            for policy in policies:
                assert policy.evidence is not None
                authority = policy.evidence["decision_authority"]["payload"][
                    "decision_authority"
                ]
                assert (
                    authority["source"],
                    authority["mode"],
                    authority["selection_basis"],
                ) == ("v21", "active", "profile_all")
            if all_tools:
                assert resolutions
                assert {p.event_type for p in policies} == {
                    "context_assembled",
                    "model_input_prepared",
                    "model_output_produced",
                    "tool_call_proposed",
                    "tool_result_produced",
                    "memory_write_proposed",
                    "message_send_proposed",
                }
                workspace = Path(prepared["profile"]["workspaceDir"])
                assert (workspace / "created.txt").read_text() == "composition-edited\n"
                assert (
                    workspace / "command-marker.txt"
                ).read_text() == "isolated command executed\n"
                with sqlite3.connect(
                    f"file:{workspace / 'memory.sqlite'}?mode=ro", uri=True
                ) as database:
                    assert database.execute(
                        "SELECT key, value FROM memory"
                    ).fetchall() == [("fixture", "composition-memory")]
                assert len(deliveries) == 1
                assert "composition-message" in json.dumps(deliveries[0])
                writes = [
                    policy
                    for policy in policies
                    if policy.event_type == "memory_write_proposed"
                ]
                assert len(writes) == 1
                memory_policy = writes[0]
                change = store.get_memory_change(
                    memory_policy.links["memory_change_id"]
                )
                assert change is not None
                assert change.status == "committed"
                assert change.source_trust == "unknown"
                original = decode_ct_transient_facts(memory_policy)
                assert original.kind == "full" and original.bundle is not None
                assert original.bundle.scope_digest == task["scope_digest"]
                memory_proof = memory_policy.evidence["product_action_data"]
                memory_id = memory_proof["first_write_memory_ref"]
                original_facts = [
                    fact
                    for fact in original.bundle.memory_facts
                    if fact.memory_id == memory_id
                ]
                assert len(original_facts) == 1
                original_fact = original_facts[0]
                assert original_fact.trust_state == "unknown"
                state = store.get_security_state(task["scope_digest"])
                assert state is not None
                assert state.dirty is False and state.dirty_domains == []
                facts = [
                    fact
                    for fact in state.canonical_payload["memory_index"]
                    if fact["memory_id"] == memory_id
                    and fact["change_id"] == change.change_id
                ]
                assert len(facts) == 1
                fact = facts[0]
                assert fact["change_status"] == "committed"
                assert fact["trust_state"] in {"unknown", "quarantined"}
                assert set(original_fact.taints) <= set(fact["taints"])
                assert set(original_fact.source_refs) <= set(fact["source_refs"])
                assert (
                    f"action:{memory_policy.links['action_id']}" in fact["source_refs"]
                )
                model_source_ref = memory_proof["model_source_ref"]
                assert model_source_ref in original_fact.source_refs
                model_sources = [
                    source
                    for source in state.canonical_payload["source_index"]
                    if source["source_id"] == model_source_ref
                ]
                assert len(model_sources) == 1
                assert model_sources[0]["scope_digest"] == task["scope_digest"]
                assert model_sources[0]["source_type"] == "model"
                assert model_sources[0]["trust"] == "unknown"
                assert set(model_sources[0]["taints"]) <= set(fact["taints"])

                # A committed write remains untrusted. Inspect the actual later
                # context plans without assuming where this run isolates its read.
                observed_memory_sources = 0
                observed_excluded_memory = 0
                for context_policy in policies:
                    if context_policy.event_type != "context_assembled":
                        continue
                    context_requests = [
                        item.body
                        for item in evaluations
                        if item.body["event_id"] == context_policy.links["event_id"]
                    ]
                    assert len(context_requests) == 1
                    memory_sources = [
                        source
                        for source in context_requests[0]["payload"]["sources"]
                        if source["source_type"] == "memory"
                        and source["source_id"] == memory_id
                    ]
                    if not memory_sources:
                        continue
                    observed_memory_sources += 1
                    assert len(memory_sources) == 1
                    source = memory_sources[0]
                    assert source["source_trust"] == "untrusted"
                    assert json.loads(source["summary"]) == {
                        "key": change.key,
                        "value": change.value_preview,
                    }
                    anchor = context_manifest_anchor_from_policy(context_policy)
                    assert anchor is not None
                    manifest_record = store.get_audit_event(anchor.audit_id)
                    assert manifest_record is not None
                    validated = validate_context_manifest_audit_event(manifest_record)
                    manifest_digest = context_manifest_record_digest(validated)
                    assert manifest_digest == anchor.manifest_digest
                    manifest = validated.evidence.context_manifest
                    assert isinstance(manifest, ContextManifestEnvelope)
                    assert manifest.completeness.status == "complete"
                    assert manifest.completeness.truncated is False
                    assert manifest.scope_digest == task["scope_digest"]
                    chunks = [
                        chunk
                        for chunk in manifest.chunks
                        if chunk.sequence is not None
                        and chunk.sequence.value == source["sequence_index"]
                    ]
                    assert len(chunks) == 1
                    chunk = chunks[0]
                    assert chunk.source_type == "memory"
                    assert chunk.compartment == "memory_context"
                    assert chunk.content_digest == source["content_digest"]
                    if chunk.transform_state != "excluded":
                        continue
                    observed_excluded_memory += 1
                    assert chunk.chunk_id in manifest.excluded_chunk_ids
                    assert chunk.trust != "trusted"
                    assert "MEMORY_NOT_ACTIVE_TRACE_SAFE" in manifest.reason_codes
                    model_inputs = [
                        item.body
                        for item in evaluations
                        if item.body["event_type"] == "model_input_prepared"
                        and item.body["payload"].get("context_plan_id")
                        == manifest.plan_id
                    ]
                    assert model_inputs
                    for model_input in model_inputs:
                        assert (
                            chunk.source_ref
                            not in model_input["payload"]["visible_source_refs"]
                        )
                        assert (
                            chunk.source_ref
                            not in model_input["security_context"][
                                "visible_source_refs"
                            ]
                        )
                        projection = json.loads(
                            model_input["payload"]["content_preview"]
                        )
                        non_task = [
                            message
                            for message in projection["messages"]
                            if not _is_original_task_message(message)
                        ]
                        assert change.value_preview not in json.dumps(non_task)
                assert observed_memory_sources > 0
                assert observed_excluded_memory > 0
                # TASK itself authorizes this exact value. Remove only that
                # exact original message, never a substring in tool evidence.
                for call in calls:
                    non_task = [
                        message
                        for message in call["messages"]
                        if not _is_original_task_message(message)
                    ]
                    assert change.value_preview not in json.dumps(non_task)
            elif message_decision:
                assert len(deliveries) == 1
                assert deliveries[0]["target"] == PRODUCT_INBOX_TARGET
                assert deliveries[0]["text"] == "composition-message"
                message_policies = [
                    p for p in policies if p.event_type == "message_send_proposed"
                ]
                assert len(message_policies) == 1
                assert message_policies[0].decision == message_decision
                assert len(resolutions) == (1 if message_decision == "ask" else 0)
                assert sum(
                    r.path.endswith("/execution-leases/consume") for r in requests
                ) == len(resolutions)
            else:
                assert deliveries == []
            transcripts = list(
                Path(prepared["profile"]["stateDir"]).rglob(
                    prepared["profile"]["sessionId"] + ".jsonl"
                )
            )
            assert len(transcripts) == 1
            messages = [
                json.loads(line).get("message", {})
                for line in transcripts[0].read_text().splitlines()
                if line.strip()
            ]
            results = [m for m in messages if m.get("role") == "toolResult"]
            assert [m["toolName"] for m in results] == [name for name, _ in program]
            assert all(m.get("isError") is not True for m in results)
            if any(name == "read" for name, _ in program):
                assert "composition-safe" in json.dumps(
                    next(m for m in results if m["toolName"] == "read")["content"]
                )
            if all_tools:
                by_name = {message["toolName"]: message for message in results}
                process_result = by_name["process"]
                assert process_result["content"] == [
                    {"type": "text", "text": "No running or recent sessions."}
                ]
                assert process_result["details"]["status"] == "completed"
                assert process_result["details"]["sessions"] == []
            all_receipts = [
                r
                for r in requests
                if r.path == "/v1/audit/events"
                and r.body.get("record_type") == "runtime_outcome"
            ]
            assert all(r.status_code == 200 for r in all_receipts)
            receipts = [
                r
                for r in all_receipts
                if r.body["metadata"]["outcome_kind"] != "approval_release"
            ]
            releases = [
                r
                for r in all_receipts
                if r.body["metadata"]["outcome_kind"] == "approval_release"
            ]
            assert len(releases) == len(resolutions)
            for release in releases:
                release_body = _receipt_public_body(release)
                assert release_body["stage"] == "product_gate_released"
                assert release_body["evidence"]["execution"]["status"] == "unknown"
                assert release_body["evidence"]["execution"]["invoked_at"] is None
                saved = store.get_audit_event(release_body["audit_id"])
                assert saved is not None and saved.links == release_body["links"]
                approval_id = release_body["links"]["approval_id"]
                consumed = [
                    r
                    for r in requests
                    if r.path == f"/v1/approvals/{approval_id}/execution-leases/consume"
                    and r.status_code == 200
                ]
                consume_count = len(consumed)
                assert consume_count == 1
                assert consumed[0].body["mode"] == "restricted_allow_once"
                assert store.approval_execution_was_consumed(approval_id)
                enforcement = release_body["evidence"]["enforcement"]
                assert enforcement["release_mode"] == "restricted_allow_once"
                assert enforcement["binding_check_status"] == "not_performed"
                assert enforcement["lease_consume_outcome"] == "consumed"
                actual_hash = canonical_sha256(
                    release.body["metadata"]["activation_ack"]["ack_token"]
                )
                expected_hash = canonical_sha256(consumed[0].activation_ack_header)
                assert actual_hash == expected_hash
                try:
                    normalized_evidence = RuntimeOutcomeReceipt.model_validate(
                        release.body
                    ).evidence.model_dump(mode="json")
                except Exception:
                    pytest.fail("invalid Product release receipt evidence")
                assert saved.evidence == normalized_evidence
            assert len(receipts) == len(policies)
            for policy in policies:
                matching = [
                    r
                    for r in receipts
                    if r.body["links"]["policy_audit_id"] == policy.audit_id
                ]
                count = len(matching)
                assert count == 1
                receipt = matching[0]
                receipt_body = _receipt_public_body(receipt)
                assert receipt.status_code == 200
                assert receipt_body["metadata"]["outcome_kind"] == "execution_completed"
                assert receipt_body["evidence"]["execution"]["status"] == "executed"
                assert receipt_body["evidence"]["execution"]["invoked_at"] is None
                expected_stage = (
                    "native_model_terminal"
                    if policy.event_type == "model_input_prepared"
                    else (
                        "native_tool_result_middleware"
                        if policy.event_type
                        in {
                            "tool_call_proposed",
                            "memory_write_proposed",
                            "message_send_proposed",
                        }
                        else f"product_{policy.event_type}"
                    )
                )
                assert receipt_body["stage"] == expected_stage
                stored = store.get_audit_event(receipt_body["audit_id"])
                assert stored is not None
                assert stored.links == receipt_body["links"]
                try:
                    normalized_evidence = RuntimeOutcomeReceipt.model_validate(
                        receipt.body
                    ).evidence.model_dump(mode="json")
                except Exception:
                    pytest.fail("invalid Product runtime receipt evidence")
                assert stored.evidence == normalized_evidence
                assert (
                    receipt_body["links"]["decision_id"] == policy.links["decision_id"]
                )
                original = next(
                    r
                    for r in evaluations
                    if r.body["event_id"] == receipt_body["links"]["event_id"]
                )
                approval_id = receipt_body["links"].get("approval_id")
                if approval_id is not None:
                    consumed = [
                        r
                        for r in requests
                        if r.path
                        == f"/v1/approvals/{approval_id}/execution-leases/consume"
                        and r.status_code == 200
                    ]
                    consume_count = len(consumed)
                    assert consume_count == 1
                    original = consumed[0]
                    assert original.body["mode"] == "restricted_allow_once"
                    assert store.approval_execution_was_consumed(approval_id)
                    enforcement = receipt_body["evidence"]["enforcement"]
                    assert enforcement["release_mode"] == "restricted_allow_once"
                    assert enforcement["binding_check_status"] == "not_performed"
                    assert enforcement["lease_consume_outcome"] == "consumed"
                actual_hash = canonical_sha256(
                    receipt.body["metadata"]["activation_ack"]["ack_token"]
                )
                expected_hash = canonical_sha256(original.activation_ack_header)
                assert actual_hash == expected_hash
