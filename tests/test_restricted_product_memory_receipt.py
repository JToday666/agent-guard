"""C1 memory terminal selection; synthetic policies never create clean facts."""

from __future__ import annotations

from copy import deepcopy

import pytest

from agentguard_core import RuntimeOutcomeReceipt
from guard_api.services.product_memory import is_product_memory_completion
from tests.test_product_activation_ack_receipt import _rig
from tests.test_restricted_product_receipt_api import restricted_rig  # noqa: F401

pytestmark = pytest.mark.integration


def _memory_parent(parent):
    # Selection-only fixture. No memory change/proof is invented or committed.
    parent = parent.model_copy(deep=True)
    parent.event_type = "memory_write_proposed"
    parent.evidence["decision_authority"]["payload"]["event_type"] = "memory_write_proposed"
    return parent


def _completed(payload):
    payload = deepcopy(payload)
    payload["metadata"]["outcome_kind"] = "execution_completed"
    payload["audit_id"] = (
        f"audit_outcome_{payload['links']['event_id']}_execution_completed"
    )
    payload["evidence"]["execution"].update(
        status="executed", invoked_at=None, persisted=True
    )
    payload["evidence"]["result"]["disposition"] = "passed_through"
    return payload


def test_openclaw_allow_after_hook_is_eligible_without_fabricated_lease(tmp_path):
    _, parent, payload, _ = _rig(tmp_path, runtime="openclaw")
    receipt = RuntimeOutcomeReceipt.model_validate(_completed(payload))
    assert receipt.evidence.enforcement is None and receipt.links.lease_id is None
    assert is_product_memory_completion(receipt, _memory_parent(parent))


def test_restricted_consumed_after_hook_is_eligible_but_release_is_not(restricted_rig):  # noqa: F811
    _, parent, payload, _, _, _ = restricted_rig
    parent = _memory_parent(parent)
    assert not is_product_memory_completion(
        RuntimeOutcomeReceipt.model_validate(payload), parent
    )
    assert is_product_memory_completion(
        RuntimeOutcomeReceipt.model_validate(_completed(payload)), parent
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "failed",
        "quarantined",
        "not_persisted",
        "unknown_persisted",
        "fake_invocation",
        "missing_ack",
        "wrong_runtime",
    ],
)
def test_openclaw_ambiguous_or_unpersisted_after_does_not_commit(tmp_path, mutation):
    _, parent, payload, _ = _rig(tmp_path, runtime="openclaw")
    payload = _completed(payload)
    if mutation == "failed":
        payload["metadata"]["outcome_kind"] = "execution_failed"
        payload["audit_id"] = (
            f"audit_outcome_{payload['links']['event_id']}_execution_failed"
        )
        payload["evidence"]["execution"].update(
            status="failed", error="fixture_failure"
        )
    elif mutation == "quarantined":
        payload["evidence"]["result"]["disposition"] = "quarantined"
    elif mutation in {"not_persisted", "unknown_persisted"}:
        payload["evidence"]["execution"]["persisted"] = (
            False if mutation == "not_persisted" else None
        )
    elif mutation == "fake_invocation":
        payload["evidence"]["execution"]["invoked_at"] = payload["timestamp"]
    elif mutation == "missing_ack":
        payload["metadata"].pop("activation_ack")
    elif mutation == "wrong_runtime":
        parent.runtime = "langgraph"
    assert not is_product_memory_completion(
        RuntimeOutcomeReceipt.model_validate(payload), _memory_parent(parent)
    )
