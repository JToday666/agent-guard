"""Actual JS receipt builder -> Core C1 memory terminal selector.

The parent policies are explicitly selection-only fixtures, as in the existing
memory selector tests. No fake MemoryFact, lifecycle commit or native admission
is asserted. ACKs and restricted lease records come from actual API services.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from agentguard_core import RuntimeOutcomeReceipt
from guard_api.services.product_memory import is_product_memory_completion
from tests.test_openclaw_product_activation_http import (
    ROOT,
    _build_actual_openclaw_sdk as _build_actual_openclaw_sdk,
)
from tests.test_product_activation_ack_receipt import _rig
from tests.test_restricted_product_memory_receipt import _memory_parent
from tests.test_restricted_product_receipt_api import restricted_rig  # noqa: F401

pytestmark = pytest.mark.contract

_SCRIPT = """
import {readFileSync} from 'node:fs';
import {readOpenClawActivationAckHandle} from './packages/agentguard-openclaw-plugin/dist/runtime/activation-ack-handle.js';
import {bindEvaluationActivationAck,bindConsumptionActivationAck,runtimeOutcomeToWire} from './packages/agentguard-openclaw-plugin/dist/runtime/product-authority-context.js';
import {buildProductActionReceipt} from './packages/agentguard-openclaw-plugin/dist/mapping/product-receipts.js';
try {
 const input=JSON.parse(readFileSync(0,'utf8'));
 const {schema_version,runtime,issued_at,expires_at,ack_token,...identity}=input.ack;
 const handle=readOpenClawActivationAckHandle(input.ack,identity,{nowMs:Date.parse(issued_at)+1});
 bindEvaluationActivationAck(input.evaluation,handle);
 if(input.options.lease)bindConsumptionActivationAck(input.evaluation,handle);
 const receipt=buildProductActionReceipt(input.event,input.evaluation,input.options);
 process.stdout.write(JSON.stringify(runtimeOutcomeToWire(receipt)));
} catch { process.stderr.write('native_receipt_contract_failed');process.exitCode=1; }
"""


def _build(parent, payload, *, persisted=True, kind="execution_completed"):
    approval_id = payload["links"].get("approval_id")
    options = {
        "kind": kind,
        "persisted": persisted,
        "timestamp": payload["timestamp"],
    }
    if approval_id:
        options.update(
            approval={"status": "allowed", "decision": "allow_once"},
            lease={
                "leaseId": payload["links"]["lease_id"],
                "consumptionId": payload["links"]["consumption_id"],
                "expiresAt": payload["timestamp"],
            },
        )
    body = {
        "ack": payload["metadata"]["activation_ack"],
        "event": {
            "event_id": payload["links"]["event_id"],
            "event_type": "memory_write_proposed",
            "trace_id": parent.trace_id,
            "security_context": {
                "agent_id": payload["metadata"]["agent_id"],
                "derived_paths": [],
            },
            "payload": {"action_id": payload["links"]["action_id"]},
        },
        "evaluation": {
            "decision": {
                "decision_id": payload["links"]["decision_id"],
                "decision": parent.decision,
                "risk_score": parent.risk_score,
                "severity": parent.severity,
            },
            "policy_audit_id": parent.audit_id,
            "approval": {"approval_id": approval_id} if approval_id else None,
            "approval_release_directive": {
                "mode": "restricted_allow_once" if approval_id else "not_applicable"
            },
        },
        "options": options,
    }
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", _SCRIPT],
        input=json.dumps(body),
        text=True,
        capture_output=True,
        cwd=ROOT,
        timeout=30,
    )
    # Never render subprocess credential-bearing output on assertion failure.
    assert completed.returncode == 0, "native receipt builder failed"
    assert completed.stderr == ""
    try:
        return RuntimeOutcomeReceipt.model_validate_json(completed.stdout)
    except ValueError:
        pytest.fail("native receipt failed the Core contract", pytrace=False)


def _assert_memory_contract(parent, payload):
    parent = _memory_parent(parent)
    receipt = _build(parent, payload)
    assert receipt.evidence.result.disposition == "passed_through"
    assert receipt.evidence.execution.tool_result_entered_context is None
    assert receipt.evidence.execution.invoked_at is None
    assert is_product_memory_completion(receipt, parent)
    for kwargs in ({"persisted": False}, {"kind": "execution_failed"}):
        assert not is_product_memory_completion(
            _build(parent, payload, **kwargs), parent
        )
    if payload["links"].get("lease_id"):
        assert not is_product_memory_completion(
            _build(parent, payload, kind="approval_release"), parent
        )


def test_actual_js_allow_memory_terminal_matches_core_selector(tmp_path):
    _, parent, payload, _ = _rig(tmp_path, runtime="openclaw")
    _assert_memory_contract(parent, payload)


def test_actual_js_restricted_memory_terminal_matches_core_selector(
    restricted_rig,  # noqa: F811
):
    _, parent, payload, _, _, _ = restricted_rig
    _assert_memory_contract(parent, payload)
