"""Actual JS content receipt -> signed historical ACK and AuditService contract.

Parent policies are explicitly synthetic projection fixtures. No Host execution,
Provider call, model output admission or Product qualification is asserted.
"""

from __future__ import annotations

import json
import subprocess
from copy import deepcopy

import pytest

from agentguard_core import RuntimeOutcomeReceipt
from guard_api.services.audit import RuntimeOutcomeReceiptError
from tests.test_openclaw_product_activation_http import (
    ROOT,
    _build_actual_openclaw_sdk as _build_actual_openclaw_sdk,
)
from tests.test_product_model_content import _fixture

pytestmark = pytest.mark.contract

_SCRIPT = """
import {readFileSync} from 'node:fs';
import {readOpenClawActivationAckHandle} from './packages/agentguard-openclaw-plugin/dist/runtime/activation-ack-handle.js';
import {bindEvaluationActivationAck,runtimeOutcomeToWire} from './packages/agentguard-openclaw-plugin/dist/runtime/product-authority-context.js';
import {buildProductContentReceipt} from './packages/agentguard-openclaw-plugin/dist/mapping/product-content-receipts.js';
try {
 const input=JSON.parse(readFileSync(0,'utf8'));
 const {schema_version,runtime,issued_at,expires_at,ack_token,...identity}=input.ack;
 const handle=readOpenClawActivationAckHandle(input.ack,identity,{nowMs:Date.parse(issued_at)+1});
 bindEvaluationActivationAck(input.evaluation,handle);
 const receipt=buildProductContentReceipt(input.event,input.evaluation,input.options);
 process.stdout.write(JSON.stringify(runtimeOutcomeToWire(receipt)));
} catch { process.stderr.write('native_content_receipt_contract_failed');process.exitCode=1; }
"""


def _receipt(rig, status):
    event_type = (
        "model_input_prepared" if status == "failed" else "model_output_produced"
    )
    event_id = f"content-{status}"
    parent = rig.parent_builder(event_id, event_type, [], [])
    parent.links["action_id"] = f"act_{event_id}"
    parent.case_id = "case:original-policy"
    parent.is_malicious = False
    parent.rule_hits = ["policy:matched"]
    assert parent.decision == "allow" and parent.blocked is False
    assert rig.harness.store.add_audit_event(parent)
    ack = rig.receipt_wire["metadata"]["activation_ack"]
    event = {
        "event_id": event_id,
        "event_type": event_type,
        "trace_id": parent.trace_id,
        "case_id": parent.case_id,
        "is_malicious": parent.is_malicious,
        "security_context": {"agent_id": parent.metadata["agent_id"]},
    }
    payload = {
        "ack": ack,
        "event": event,
        "evaluation": {
            "decision": {
                "decision_id": parent.links["decision_id"],
                "decision": parent.decision,
                "risk_score": parent.risk_score,
                "severity": parent.severity,
                "rule_hits": [{"rule_id": key} for key in parent.rule_hits],
            },
            "policy_audit_id": parent.audit_id,
            "decision_authority": {
                "source": "v21",
                "mode": "active",
                "selection_basis": "profile_all",
                "legacy_floor_applied": False,
                "activation_ref_digest": ack["activation_ref_digest"],
            },
            "approval_release_directive": {"mode": "not_applicable"},
        },
        "options": {
            "accepted": False,
            "status": status,
            "modelTerminal": status == "failed",
        },
    }
    result = subprocess.run(
        ["node", "--input-type=module", "-e", _SCRIPT],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=ROOT,
        timeout=30,
    )
    # Do not display credential-bearing stdout or raw diagnostic text.
    assert result.returncode == 0, "actual JS content receipt builder failed"
    assert result.stderr == ""
    try:
        return parent, RuntimeOutcomeReceipt.model_validate_json(result.stdout)
    except ValueError:
        pytest.fail("content receipt failed Core validation", pytrace=False)


@pytest.mark.parametrize("status", ["failed", "executed"])
def test_runtime_failure_or_quarantine_preserves_allow_parent_projection(
    tmp_path, status
):
    rig = _fixture(tmp_path, runtime="openclaw")
    parent, receipt = _receipt(rig, status)
    assert receipt.blocked is False
    assert receipt.rule_hits == parent.rule_hits
    assert receipt.evidence.execution.status == status
    assert receipt.evidence.intervention.type == "content_isolation"
    assert receipt.evidence.result.disposition == (
        "not_applicable" if status == "failed" else "quarantined"
    )
    for field, value in (
        ("blocked", True),
        ("rule_hits", []),
        ("case_id", "case:changed"),
        ("is_malicious", True),
    ):
        changed = deepcopy(receipt.model_dump(mode="json"))
        changed[field] = value
        with pytest.raises(RuntimeOutcomeReceiptError) as caught:
            rig.service.submit(
                RuntimeOutcomeReceipt.model_validate(changed),
                auth_context=rig.harness.auth_context,
            )
        assert caught.value.code == "RUNTIME_OUTCOME_PARENT_MISMATCH"
        assert rig.harness.store.get_audit_event(receipt.audit_id) is None
    accepted = rig.service.submit(receipt, auth_context=rig.harness.auth_context)
    assert accepted["ok"] is True and accepted["created"] is True
    replay = rig.service.submit(receipt, auth_context=rig.harness.auth_context)
    assert replay["idempotent_replay"] is True
