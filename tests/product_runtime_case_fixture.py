"""Synthetic unit protocol observations, never a Host conformance runner.

This module writes ephemeral inputs for the complete admission validator test.
Production tools must not import it or publish its records as qualification.
"""

from __future__ import annotations

from copy import deepcopy
import base64
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions.models import RuntimeOutcomeReceipt
from agentguard_core.events import GuardEvent
from agentguard_core.events.payloads import (
    ContextBuildPayload,
    MemoryEventPayload,
    MessageSendPayload,
    ModelCallPayload,
    ToolCallPayload,
    ToolResultPayload,
)
from scripts.product_runtime.requirements import (
    COMPOSITION_COMPONENTS,
    NEGATIVE_REASONS,
    Requirement,
)
from tests.test_product_runtime_admission import receipt_frames


def _reference(root: Path, path: Path) -> dict[str, Any]:
    body = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "size": len(body),
        "raw_sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
    }


def _sqlite(table: str, rows: list[tuple]) -> bytes:
    connection = sqlite3.connect(":memory:")
    try:
        if table == "memory":
            connection.execute(
                "CREATE TABLE memory(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
            )
            connection.executemany("INSERT INTO memory VALUES (?,?)", rows)
        else:
            connection.execute(
                "CREATE TABLE messages(sequence INTEGER PRIMARY KEY,message_id TEXT,target TEXT,text TEXT)"
            )
            connection.executemany("INSERT INTO messages VALUES (?,?,?,?)", rows)
        connection.commit()
        return connection.serialize()
    finally:
        connection.close()


def build_case_fixture(
    root: Path,
    requirement: Requirement,
    observation: dict[str, Any],
    *,
    baseline_material: dict[str, Any],
    ack: dict[str, Any],
    capability: dict[str, Any],
) -> dict[str, Any]:
    """Return a full CaseResult and write its original referenced observations."""
    if requirement.policy_group is not None:
        raise ValueError("policy cases require the actual Core replay fixture")
    runtime = observation["runtime"]
    directory = root / "unit-case-evidence" / runtime / requirement.id
    directory.mkdir(parents=True, mode=0o700)
    serial = 0

    def artifact(value: Any, *, raw: bool = False) -> dict[str, Any]:
        nonlocal serial
        serial += 1
        body = (
            value
            if raw
            else json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )
        path = directory / f"{serial}.bin"
        path.write_bytes(body)
        path.chmod(0o600)
        return _reference(root, path)

    frames: list[dict[str, Any]] = []

    def add(actor: str, event: str, data: Any, attachments: list | None = None) -> None:
        frames.append(
            {
                "sequence": len(frames),
                "actor": actor,
                "event": event,
                "data": data,
                "attachments": attachments or [],
            }
        )

    receipt_disposition = "not_applicable"
    model_kind = "none"
    subject = requirement.subject
    if requirement.validator == "native_invocation":
        model_kind = "controlled_local"
        name = subject
        recipient = (
            "fixture-inbox@agentguard.invalid"
            if runtime == "langgraph"
            else "fixture-inbox"
        )
        args = {
            "read": {"path": "fixture.txt"},
            "write": {"path": "output.txt", "content": "written fixture\n"},
            "edit": {
                "path": "fixture.txt",
                "edits": [{"oldText": "original", "newText": "edited"}],
            },
            "exec": {
                "command": (
                    "python marker.py" if runtime == "langgraph" else "node marker.mjs"
                )
            },
            "process": {"action": "list"},
            "agentguard_memory_read": {"key": "fixture"},
            "agentguard_memory_write": {"key": "fixture", "value": "unit memory"},
            "message": {
                "action": "send",
                "channel": "agentguard-fixture",
                "target": recipient,
                "message": "unit local text",
            },
        }[name]
        before = b"original fixture\n"
        after = before
        result: Any = {"ok": True, "path": args.get("path")}
        kind = "file"
        if name == "write":
            after = args["content"].encode()
        elif name == "edit":
            after = b"edited fixture\n"
        elif name == "read":
            result = before
        elif name == "exec":
            kind, after = "command", before + b"isolated command executed\n"
            result = {"exit_code": 0, "execution": 1, "stdout": "unit marker output"}
        elif name == "process":
            kind = "process_result"
            if runtime == "langgraph":
                before = after = b'[{"sequence":1,"exit_code":0}]'
                result = {"processes": [{"sequence": 1, "exit_code": 0}]}
            else:
                before = after = (
                    b'{"commands":[],"host_list_text":"No running or recent sessions."}'
                )
                result = b"No running or recent sessions."
        elif name.startswith("agentguard_memory_"):
            kind = "memory"
            before = _sqlite(
                "memory", [("fixture", "unit memory")] if name.endswith("read") else []
            )
            after = _sqlite("memory", [("fixture", "unit memory")])
            result = (
                {"key": "fixture", "value": "unit memory"}
                if name.endswith("read")
                else {"ok": True, "key": "fixture"}
            )
        elif name == "message":
            kind = "message"
            before = _sqlite("messages", [])
            after = _sqlite(
                "messages", [(1, "fixture:unit", recipient, "unit local text")]
            )
            result = {"ok": True, "messageId": "fixture:unit"}
        response = (
            result
            if type(result) is bytes
            else json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        )
        before_ref, after_ref, result_ref = (
            artifact(value, raw=True) for value in (before, after, response)
        )
        effect = {
            "kind": kind,
            "phase": "before",
            "target": "unit-fixture",
            "count": 0,
            "content_digest": before_ref["raw_sha256"],
            "invocation_id": "unit-invocation",
        }
        add("effect", "snapshot", effect, [before_ref])
        call = {
            "tool_name": name,
            "invocation_id": "unit-invocation",
            "arguments": args,
        }
        add("model", "tool_call_requested", call)
        add("host", "tool_invocation", call)
        add(
            "host",
            "tool_result",
            {
                "invocation_id": "unit-invocation",
                "is_error": False,
                "result_digest": result_ref["raw_sha256"],
            },
            [result_ref],
        )
        add(
            "effect",
            "snapshot",
            effect
            | {"phase": "after", "count": 1, "content_digest": after_ref["raw_sha256"]},
            [after_ref],
        )
        observation["entrypoint"] = (
            "StateGraph.ToolNode" if runtime == "langgraph" else "openclaw.agentCommand"
        )
    elif requirement.validator == "baseline_material":
        add("consumer", "baseline_material", baseline_material)
    elif requirement.validator == "event_consumer":
        payload = {
            "context_assembled": {
                "sources": [],
                "will_enter_context": True,
                "sanitized": False,
            },
            "model_input_prepared": {
                "phase": "input",
                "content_preview": "unit context",
            },
            "model_output_produced": {
                "phase": "output",
                "content_preview": "unit output",
            },
            "tool_call_proposed": {
                "tool": {"name": "read", "call_id": "unit-action"},
                "arguments": {"path": "fixture.txt"},
            },
            "tool_result_produced": {
                "tool": {"name": "read", "call_id": "unit-action"},
                "result": {"content_preview": "unit result"},
            },
            "memory_write_proposed": {
                "memory": {
                    "namespace": "unit-memory",
                    "key": "fixture",
                    "value_preview": "unit value",
                }
            },
            "message_send_proposed": {
                "channel": "agentguard-fixture",
                "recipient": "fixture-inbox@agentguard.invalid",
                "content_preview": "unit message",
            },
        }[subject]
        payload_type = {
            "context_assembled": ContextBuildPayload,
            "model_input_prepared": ModelCallPayload,
            "model_output_produced": ModelCallPayload,
            "tool_call_proposed": ToolCallPayload,
            "tool_result_produced": ToolResultPayload,
            "memory_write_proposed": MemoryEventPayload,
            "message_send_proposed": MessageSendPayload,
        }[subject]
        if subject == "context_assembled":
            payload["sources"] = [
                {
                    "source_id": "unit-source",
                    "source_type": "tool_result",
                    "source_trust": "untrusted",
                    "summary": "UNIT_RESTRICTED_SENTINEL",
                }
            ]
        elif subject in {"model_input_prepared", "model_output_produced"}:
            payload["content_preview"] = "UNIT_RESTRICTED_SENTINEL"
        elif subject == "tool_result_produced":
            payload["result"]["content_preview"] = "UNIT_RESTRICTED_SENTINEL"
        payload = payload_type.model_validate(payload).model_dump(mode="json")
        event = GuardEvent.model_validate(
            {
                "event_id": "unit-event",
                "trace_id": "unit-trace",
                "runtime": runtime,
                "event_type": subject,
                "stage": "unit",
                "security_context": {"agent_id": ack["agent_id"]},
                "payload": payload,
            }
        ).model_dump(mode="json")
        add(
            "consumer",
            "event_evaluated",
            {
                "event": event,
                "event_digest": canonical_sha256(event),
                "policy_audit_id": "unit-policy",
            },
        )
        add("postgres", "event_receipt", {"policy_audit_id": "unit-policy"})
        if subject in {
            "context_assembled",
            "model_input_prepared",
            "model_output_produced",
            "tool_result_produced",
        }:
            request = {"messages": [{"role": "user", "content": "clean unit context"}]}
            add(
                "consumer",
                "quarantined_content",
                {
                    "original": "UNIT_RESTRICTED_SENTINEL",
                    "original_request_id": "unit-original",
                    "next_model_input": request,
                    "memory_values": [],
                    "inbox_values": [],
                    "memory_snapshot": artifact([]),
                    "inbox_snapshot": artifact([]),
                    "disposition": "isolated",
                },
            )
            add(
                "model",
                "next_request",
                {"request_id": "unit-next", "body": artifact(request)},
            )
            model_kind = "controlled_local"
    elif subject in {
        "receipt.network_queue",
        "receipt.restart_drain_only",
        "receipt.permanent_409",
        "receipt.permanent_422",
        "receipt.disk_failure",
        "ack.historical_receipt",
    }:
        status = int(subject[-3:]) if "permanent_" in subject else 409
        rows = deepcopy(receipt_frames(status))
        payload = json.loads(rows[0][2]["wire"])
        payload.update(runtime=runtime)
        payload["metadata"].update(agent_id=ack["agent_id"], activation_ack=ack)
        RuntimeOutcomeReceipt.model_validate(payload, strict=True)
        wire = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        wire_digest = hashlib.sha256(wire.encode()).hexdigest()
        ack_digest = canonical_sha256(ack)
        for actor, event, data in rows:
            if "wire" in data:
                data.update(
                    wire=wire,
                    wire_digest=wire_digest,
                    activation_ack=ack,
                    ack_digest=ack_digest,
                )
            elif "wire_digest" in data:
                data["wire_digest"] = wire_digest
            if "ack_digest" in data:
                data["ack_digest"] = ack_digest
            if "expected_wire_digest" in data:
                data["expected_wire_digest"] = wire_digest
            if "headers" in data:
                data["headers"] = {"content-type": "application/json"}
            if event == "receipts_only_worker":
                data["process_id"] = observation["process_id"] + 1
            add(actor, event, data)
        if subject == "receipt.network_queue":
            add("journal", "queued_durable", {"server_confirmed": False})
        if subject == "ack.historical_receipt":
            final_exchange = [
                row
                for row in frames
                if row["actor"] == "http" and row["event"] == "receipt_exchange"
            ][-1]
            final_exchange["data"]["observed_at"] = ack["expires_at"]
            add(
                "http",
                "historical_window",
                {
                    "issued_at": ack["issued_at"],
                    "evaluation_at": ack["issued_at"],
                    "ack_expires_at": ack["expires_at"],
                    "delivery_at": ack["expires_at"],
                },
            )
        if subject == "receipt.disk_failure":
            add(
                "journal",
                "disk_failure",
                {
                    "stage": "pre_action",
                    "new_invocations": 0,
                    "evaluation_started": False,
                    "errno": "EACCES",
                },
            )
            add(
                "journal",
                "disk_failure",
                {
                    "stage": "confirmation_persist",
                    "terminal_durable": True,
                    "server_confirmed": True,
                    "errno": "EACCES",
                },
            )
        receipt_disposition = "confirmed"
    elif subject in NEGATIVE_REASONS:
        reason = NEGATIVE_REASONS[subject][0]
        values: dict[str, Any] = {}
        if subject == "ack.identity":
            fields = {
                "runtime",
                "runtime_version",
                "plugin_version",
                "agent_id",
                "runtime_binding_id",
                "profile_id",
                "activation_ref_digest",
                "capability_digest",
                "host_inventory_digest",
                "plugin_inventory_digest",
                "plugin_order_inventory_digest",
                "tool_inventory_digest",
            }
            expected = {key: ack[key] for key in fields}
            expected["agent_id"] += "-different"
            values = {"activation_ack": ack, "expected_identity": expected}
        elif subject == "ack.expiry":
            values = {"activation_ack": ack, "now": ack["expires_at"]}
        elif subject == "config.incomplete_blocked":
            values = {
                "required_components": list(COMPOSITION_COMPONENTS),
                "configured_components": list(COMPOSITION_COMPONENTS[:-1]),
            }
        elif subject == "inventory.drift_blocked":
            values = {"before": {"unit": "original"}, "after": {"unit": "changed"}}
        elif subject == "approval.timeout":
            values = {
                "resolution": None,
                "requested_at": "2026-09-01T00:00:00+00:00",
                "expires_at": "2026-09-01T00:01:00+00:00",
                "observed_at": "2026-09-01T00:02:00+00:00",
            }
        elif subject == "approval.invalid_release":
            values = {"release_mode": "forbidden", "requested_resolution": "allow_once"}
        elif subject == "receipt.payload_conflict":
            values = {
                "original_wire": '{"audit_id":"unit","x":1}',
                "attempted_wire": '{"audit_id":"unit","x":2}',
            }
        elif subject == "receipt.decrypt_failure":
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            key, nonce = b"s" * 32, b"n" * 12
            header = {
                "format": "agentguard.product-envelope.v1",
                "algorithm": "AES-256-GCM",
                "namespace": canonical_sha256({"unit": runtime}),
                "record_id": "unit-receipt",
                "kind": "receipt",
                "revision": 1,
            }
            ciphertext = AESGCM(key).encrypt(
                nonce,
                b'{"unit":"encrypted journal payload"}',
                json.dumps(header, sort_keys=True, separators=(",", ":")).encode(),
            )
            changed = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
            envelope = header | {
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            }
            corrupt = envelope | {"ciphertext": base64.b64encode(changed).decode()}
            values = {
                "original_envelope": artifact(envelope),
                "corrupted_envelope": artifact(corrupt),
                "synthetic_spool_key": artifact(key, raw=True),
                "failure_stage": "aes_gcm_authentication",
            }
        elif subject == "receipt.pending_blocks_side_effect":
            values = {"pending_count": 1, "terminal_confirmed": False}
        elif subject in {
            "receipt.start_confirmation_required",
            "release.confirmation_required",
        }:
            values = {
                "server_confirmed": False,
                "delivery_disposition": "queued_durable",
                "stage": (
                    "invocation_start" if runtime == "langgraph" else "gate_release"
                ),
            }
        elif subject.startswith("binding."):
            values = {
                "original_action": {"unit": "original"},
                "attempted_action": {"unit": "changed"},
            }
        add("consumer", "fault_input", {"case": subject, "input": values})
        add("consumer", "rejected", {"reason_code": reason, "new_invocations": 0})
        if subject.startswith("receipt.") or subject == "release.confirmation_required":
            add("journal", "breaker", {"open": True})
        if subject.startswith("binding."):
            add(
                "consumer",
                "binding_proof",
                {
                    "mode": (
                        "strong_binding"
                        if runtime == "langgraph"
                        else "restricted_allow_once"
                    ),
                    "original_action_digest": canonical_sha256(
                        values["original_action"]
                    ),
                    "attempted_action_digest": canonical_sha256(
                        values["attempted_action"]
                    ),
                },
            )
    elif subject == "ack.single_flight":
        add(
            "http",
            "heartbeat_concurrency",
            {
                "concurrent_callers": 2,
                "request_count": 1,
                "maximum_inflight": 1,
                "returned_ack_digests": [canonical_sha256(ack)] * 2,
                "returned_acks": [artifact(ack), artifact(ack)],
            },
        )
        add(
            "http",
            "heartbeat_exchange",
            {"status": 200, "response": {"activation_ack": ack}},
        )
    elif subject in {"ack.immutable_action_snapshot", "ack.consume_retry_fixed"}:
        event = (
            "consume_exchange"
            if subject.endswith("consume_retry_fixed")
            else "action_exchange"
        )
        if subject.endswith("consume_retry_fixed"):
            request = (
                {
                    "action_id": "unit-action",
                    "authorization_fingerprint": "hmac-sha256:" + "b" * 64,
                }
                if runtime == "langgraph"
                else {"mode": "restricted_allow_once", "action_id": "unit-action"}
            )
        else:
            payload = ToolCallPayload.model_validate(
                {
                    "tool": {"name": "read", "call_id": "unit-action"},
                    "arguments": {"path": "fixture.txt"},
                }
            ).model_dump(mode="json")
            request = GuardEvent.model_validate(
                {
                    "event_id": "unit-event",
                    "trace_id": "unit-trace",
                    "runtime": runtime,
                    "event_type": "tool_call_proposed",
                    "stage": "unit",
                    "security_context": {"agent_id": ack["agent_id"]},
                    "payload": payload,
                }
            ).model_dump(mode="json")
        for _ in range(2):
            add(
                "http",
                event,
                {
                    "request": request,
                    "request_wire": json.dumps(
                        request, sort_keys=True, separators=(",", ":")
                    ),
                    "activation_ack": ack,
                    "headers": {"x-agentguard-activation-ack": ack["ack_token"]},
                    "observed_at": ack["issued_at"],
                },
            )
        changed = {**ack, "ack_token": "hmac-sha256:" + "a" * 64}
        add("http", "refreshed_ack", {"activation_ack": changed})
    elif subject == "duplicate_action":
        add("host", "tool_invocation", {"invocation_id": "unit-invocation"})
        add(
            "consumer",
            "duplicate_action",
            {
                "attempts": 2,
                "additional_invocations": 0,
                "action_ids": ["unit-action"] * 2,
            },
        )
    elif subject == "unknown_no_reexecution":
        add(
            "journal",
            "unknown",
            {
                "terminal_observed": False,
                "intent_durable": True,
                "breaker": True,
                "additional_invocations": 0,
                "drain_posts": 0,
            },
        )
        add("postgres", "release_gate", {"row_count": 1})
        receipt_disposition = "unknown_retained"
    elif subject == "residual_boundaries":
        add(
            "consumer",
            "capability_observed",
            {
                "c3_atomic_replace_and_seal": False,
                "cf_13": "NOT_SUPPORTED",
                "residual_boundaries": capability["residual_boundaries"],
            },
        )
    else:
        raise ValueError("unit fixture case not implemented")
    observation = deepcopy(observation)
    observation["frames"] = frames
    path = directory / "observation.json"
    path.write_text(json.dumps(observation, sort_keys=True, separators=(",", ":")))
    path.chmod(0o600)
    baseline = requirement.id.startswith("baseline.")
    return {
        "id": requirement.id,
        "status": "PASS",
        "evidence_kind": "native_baseline" if baseline else "deterministic_contract",
        "model_kind": model_kind,
        "authority_kind": "none" if baseline else "synthetic_contract_fixture",
        "execution_scope": (
            "native_baseline" if baseline else "isolated_contract_fixture"
        ),
        "scope_id": observation["scope_id"],
        "policy_group": None,
        "policy_digest": None,
        "invocation_count": sum(
            row["actor"] == "host" and row["event"] == "tool_invocation"
            for row in frames
        ),
        "effects": [
            canonical_sha256(row["data"])
            for row in frames
            if row["actor"] == "effect" and row["event"] == "snapshot"
        ],
        "receipt_disposition": receipt_disposition,
        "hashed_evidence": [_reference(root, path)],
    }
