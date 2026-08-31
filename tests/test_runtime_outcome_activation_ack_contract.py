"""Contract parity for activation ACK evidence carried by runtime receipts."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from agentguard_core import RuntimeOutcomeReceipt, build_activation_ack

pytestmark = pytest.mark.contract

ROOT = Path(__file__).resolve().parents[1]
SECRET = b"runtime-receipt-ack-secret-32bytes"
DIGESTS = {character: f"sha256:{character * 64}" for character in "123456"}


def _json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _receipt_payload() -> dict[str, Any]:
    return _json(ROOT / "tests/fixtures/runtime_enforcement/execution_completed.json")


def _ack(
    *,
    runtime: str = "langgraph",
    agent_id: str = "agent_rte_fixture",
    issued_at: str = "2026-08-15T08:09:00+00:00",
    expires_at: str = "2026-08-15T08:11:00+00:00",
) -> dict[str, Any]:
    openclaw = runtime == "openclaw"
    return build_activation_ack(
        server_secret=SECRET,
        runtime=runtime,  # type: ignore[arg-type]
        runtime_version="2026.7.1-2" if openclaw else "1.2.7",
        plugin_version="0.1.0-rc.1" if openclaw else "0.1.0rc1",
        agent_id=agent_id,
        runtime_binding_id=f"binding:{runtime}:receipt",
        profile_id=(
            "agentguard-openclaw-v2-restricted"
            if openclaw
            else "agentguard-langgraph-v2"
        ),
        activation_ref_digest=DIGESTS["1"],
        capability_digest=DIGESTS["2"],
        host_inventory_digest=DIGESTS["3"],
        plugin_inventory_digest=DIGESTS["4"] if openclaw else None,
        plugin_order_inventory_digest=DIGESTS["5"] if openclaw else None,
        tool_inventory_digest=DIGESTS["6"],
        issued_at=issued_at,
        expires_at=expires_at,
    ).model_dump(mode="json")


def _receipt_schema() -> dict[str, Any]:
    return _json(ROOT / "schemas/runtime_outcome_receipt.schema.json")


def test_legacy_receipt_without_activation_ack_remains_compatible() -> None:
    receipt = RuntimeOutcomeReceipt.model_validate(_receipt_payload())
    dumped = receipt.model_dump(mode="json")

    assert "activation_ack" not in dumped["metadata"]
    assert Draft202012Validator(_receipt_schema()).is_valid(dumped)


def test_explicit_null_activation_ack_is_rejected_by_model_and_schema() -> None:
    payload = _receipt_payload()
    payload["metadata"]["activation_ack"] = None

    with pytest.raises(ValidationError, match="must be omitted instead of null"):
        RuntimeOutcomeReceipt.model_validate(payload)
    assert not Draft202012Validator(_receipt_schema()).is_valid(payload)


def test_receipt_accepts_only_a_strict_identity_bound_activation_ack() -> None:
    payload = _receipt_payload()
    payload["metadata"]["activation_ack"] = _ack()

    receipt = RuntimeOutcomeReceipt.model_validate(payload)
    dumped = receipt.model_dump(mode="json")

    assert dumped["metadata"]["activation_ack"]["ack_token"].startswith("hmac-sha256:")
    assert Draft202012Validator(_receipt_schema()).is_valid(dumped)

    wrong_runtime = copy.deepcopy(payload)
    wrong_runtime["metadata"]["activation_ack"] = _ack(runtime="openclaw")
    with pytest.raises(ValidationError, match="runtime must match"):
        RuntimeOutcomeReceipt.model_validate(wrong_runtime)

    wrong_agent = copy.deepcopy(payload)
    wrong_agent["metadata"]["activation_ack"] = _ack(agent_id="other-agent")
    with pytest.raises(ValidationError, match="agent must match"):
        RuntimeOutcomeReceipt.model_validate(wrong_agent)

    future_ack = copy.deepcopy(payload)
    future_ack["metadata"]["activation_ack"] = _ack(
        issued_at="2026-08-15T08:10:04+00:00",
        expires_at="2026-08-15T08:12:04+00:00",
    )
    with pytest.raises(ValidationError, match="issued after receipt"):
        RuntimeOutcomeReceipt.model_validate(future_ack)


def test_receipt_ack_schema_reuses_the_standalone_authority_schema() -> None:
    receipt_schema = _receipt_schema()
    standalone = _json(ROOT / "schemas/activation_ack_v1.schema.json")
    expected = {
        key: value for key, value in standalone.items() if key not in {"$id", "$schema"}
    }

    Draft202012Validator.check_schema(receipt_schema)
    assert receipt_schema["$defs"]["ActivationAckV1"] == expected
    assert receipt_schema["properties"]["metadata"]["properties"]["activation_ack"] == {
        "$ref": "#/$defs/ActivationAckV1"
    }


@pytest.mark.parametrize(
    "mutation",
    [
        {"profile_id": "wrong-profile"},
        {"runtime_version": "latest"},
        {"ack_token": "not-a-token"},
        {"unexpected": True},
    ],
)
def test_invalid_activation_ack_is_rejected_by_model_and_schema(
    mutation: dict[str, Any],
) -> None:
    payload = _receipt_payload()
    payload["metadata"]["activation_ack"] = {**_ack(), **mutation}

    with pytest.raises(ValidationError):
        RuntimeOutcomeReceipt.model_validate(payload)
    assert not Draft202012Validator(_receipt_schema()).is_valid(payload)


def test_secret_scan_exempts_only_the_typed_ack_token_leaf() -> None:
    payload = _receipt_payload()
    payload["metadata"]["activation_ack"] = _ack()
    RuntimeOutcomeReceipt.model_validate(payload)

    smuggled = copy.deepcopy(payload)
    smuggled["links"]["action_id"] = f"hmac-sha256:{'a' * 64}"
    with pytest.raises(ValidationError, match="cannot contain strong-binding secret"):
        RuntimeOutcomeReceipt.model_validate(smuggled)

    nested_smuggle = copy.deepcopy(payload)
    secret_agent = f"hmac-sha256:{'b' * 64}"
    nested_smuggle["metadata"]["agent_id"] = secret_agent
    nested_smuggle["metadata"]["activation_ack"] = _ack(agent_id=secret_agent)
    with pytest.raises(ValidationError, match="cannot contain strong-binding secret"):
        RuntimeOutcomeReceipt.model_validate(nested_smuggle)
