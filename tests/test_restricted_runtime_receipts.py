"""Shared C1 receipt contracts; synthetic fixtures make no host execution claim."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from agentguard_core import ActivationAckV1, RuntimeOutcomeReceipt
from agentguard_langgraph_adapter.event_models import (
    RuntimeOutcomeReceipt as AdapterReceipt,
    RuntimeEnforcementEvidence as AdapterEnforcement,
)

ROOT = Path(__file__).resolve().parents[1]
MARKER = "v21:restricted_allow_once"


def restricted_receipt():
    return json.loads(
        (
            ROOT / "tests/fixtures/runtime_enforcement/restricted_approval_release.json"
        ).read_text()
    )


def _accept(payload):
    RuntimeOutcomeReceipt.model_validate(payload)
    AdapterEnforcement.model_validate(payload["evidence"]["enforcement"])
    Draft202012Validator(
        json.loads((ROOT / "schemas/runtime_outcome_receipt.schema.json").read_text())
    ).validate(payload)


def _reject(payload):
    for model in (RuntimeOutcomeReceipt, AdapterReceipt):
        with pytest.raises(ValidationError):
            model.model_validate(payload)
    assert list(
        Draft202012Validator(
            json.loads(
                (ROOT / "schemas/runtime_outcome_receipt.schema.json").read_text()
            )
        ).iter_errors(payload)
    )


def test_restricted_release_is_c1_historical_and_not_invocation():
    payload = restricted_receipt()
    _accept(payload)
    # Current expiry is deliberately irrelevant to historical carrier parsing.
    assert (
        RuntimeOutcomeReceipt.model_validate(payload).evidence.execution.invoked_at
        is None
    )


@pytest.mark.parametrize(
    "gate,reason",
    [
        ("binding_failed", "v21:restricted_host_mismatch"),
        ("binding_failed", "rte-05:lease_expired"),
        ("binding_failed", "rte-05:lease_response_invalid"),
        ("timed_out", "rte-05:lease_consume_timed_out"),
    ],
)
def test_restricted_consumed_denial_retains_authority(gate, reason):
    payload = restricted_receipt()
    payload["metadata"]["outcome_kind"] = "pre_execution_deny"
    payload["audit_id"] = (
        f"audit_outcome_{payload['links']['event_id']}_pre_execution_deny"
    )
    payload["evidence"]["execution"]["status"] = "not_invoked"
    payload["evidence"]["result"]["disposition"] = "not_applicable"
    enforcement = payload["evidence"]["enforcement"]
    enforcement["gate_state"] = gate
    enforcement["reason_codes"].append(reason)
    _accept(payload)
    enforcement["reason_codes"].remove("rte-05:lease_consumed")
    _reject(payload)


@pytest.mark.parametrize(
    "mutation",
    [
        "passed",
        "failed",
        "binding_exact",
        "missing_marker",
        "missing_mode",
        "null_mode",
        "strong_mode",
        "invocation",
        "missing_ack",
        "langgraph",
        "missing_lease",
        "missing_action",
        "missing_approval",
        "not_consumed",
        "not_human_shape",
        "unknown_field",
        "wrong_released_reason",
    ],
)
def test_restricted_cannot_claim_strong_binding_or_drop_consumption(mutation):
    payload = restricted_receipt()
    enforcement = payload["evidence"]["enforcement"]
    if mutation in {"passed", "failed"}:
        enforcement["binding_check_status"] = mutation
    elif mutation == "binding_exact":
        enforcement["reason_codes"].append("rte-05:binding_exact")
    elif mutation == "missing_marker":
        enforcement["reason_codes"].remove(MARKER)
    elif mutation == "missing_mode":
        del enforcement["release_mode"]
    elif mutation == "null_mode":
        enforcement["release_mode"] = None
    elif mutation == "strong_mode":
        enforcement["release_mode"] = "strong_binding"
    elif mutation == "invocation":
        payload["evidence"]["execution"]["invoked_at"] = payload["timestamp"]
    elif mutation == "missing_ack":
        del payload["metadata"]["activation_ack"]
    elif mutation == "langgraph":
        payload["runtime"] = "langgraph"
        ack = payload["metadata"]["activation_ack"]
        ack.update(
            runtime="langgraph",
            runtime_version="1.2.7",
            plugin_version="0.1.0rc1",
            profile_id="agentguard-langgraph-v2",
            plugin_inventory_digest=None,
            plugin_order_inventory_digest=None,
        )
        ActivationAckV1.model_validate(ack)  # Valid LG ACK still cannot authorize C1.
    elif mutation in {"missing_lease", "missing_action", "missing_approval"}:
        del payload["links"][
            {
                "missing_lease": "lease_id",
                "missing_action": "action_id",
                "missing_approval": "approval_id",
            }[mutation]
        ]
    elif mutation == "not_consumed":
        enforcement["lease_consume_outcome"] = "not_attempted"
    elif mutation == "not_human_shape":
        payload["evidence"]["approval"].update(status="denied", decision="deny")
    elif mutation == "unknown_field":
        enforcement["C3"] = True
    elif mutation == "wrong_released_reason":
        enforcement["reason_codes"].append("rte-05:lease_expired")
    _reject(payload)


def test_old_strong_wire_omits_new_default_and_preserves_receipt():
    payload = restricted_receipt()
    payload["evidence"]["enforcement"] = {
        "gate_state": "approval_released",
        "binding_check_status": "passed",
        "lease_consume_outcome": "consumed",
        "reason_codes": ["rte-05:binding_exact", "rte-05:lease_consumed"],
    }
    payload["runtime"] = "langgraph"
    del payload["metadata"]["activation_ack"]
    _accept(payload)
    for model in (RuntimeOutcomeReceipt, AdapterReceipt):
        parsed = model.model_validate(payload)
        assert (
            parsed.evidence.enforcement.model_dump(mode="json")
            == payload["evidence"]["enforcement"]
        )
        explicit = deepcopy(payload)
        explicit["evidence"]["enforcement"]["release_mode"] = "strong_binding"
        assert (
            model.model_validate(explicit).evidence.enforcement.model_dump(mode="json")
            == payload["evidence"]["enforcement"]
        )


@pytest.mark.parametrize(
    "kind,status", [("execution_completed", "executed"), ("execution_failed", "failed")]
)
def test_restricted_actual_after_terminal_has_no_authoritative_start(kind, status):
    payload = restricted_receipt()
    payload["metadata"]["outcome_kind"] = kind
    payload["audit_id"] = f"audit_outcome_{payload['links']['event_id']}_{kind}"
    payload["evidence"]["execution"].update(
        status=status, error="host_failure" if status == "failed" else None
    )
    payload["evidence"]["result"]["disposition"] = (
        "passed_through" if status == "executed" else "unknown"
    )
    _accept(payload)
    # The LG receipt/session transport deliberately remains LangGraph only.
    with pytest.raises(ValidationError):
        AdapterReceipt.model_validate(payload)
