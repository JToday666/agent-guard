"""PostgreSQL parity for delayed and invalid Product ACK receipts."""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from agentguard_core import RuntimeOutcomeReceipt
from agentguard_core.actions import ActionConstraint
from guard_api.runtime_status import activation_ack_token_digest
from guard_api.services.audit import RuntimeOutcomeReceiptError
from tests.support.product_evaluation_postgres import (
    create_product_postgres_evaluation_harness,
)
from tests.test_product_activation_ack_receipt import _rig

pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("revoked_before_anchor", [False, True])
def test_postgres_historical_ack_receipt_and_replay(
    tmp_path: Path,
    revoked_before_anchor: bool,
) -> None:
    with create_product_postgres_evaluation_harness(
        tmp_path,
        action_constraints=[ActionConstraint(action_types=["tool_call"])],
    ) as harness:
        _, parent, payload, service = _rig(tmp_path, harness=harness)
        record = harness.store.get_product_activation_ack(
            activation_ack_token_digest(harness.activation_ack_token)
        )
        assert record is not None
        anchor = datetime.fromisoformat(
            parent.metadata["product_authority_initial_checked_at"]
        )
        harness.writer.revoke_product_activation_acks(
            record.identity(),
            revoked_at=(
                anchor if revoked_before_anchor else anchor + timedelta(seconds=1)
            ).isoformat(),
        )
        receipt = RuntimeOutcomeReceipt.model_validate(payload)
        if revoked_before_anchor:
            with pytest.raises(RuntimeOutcomeReceiptError) as raised:
                service.submit(receipt, auth_context=harness.auth_context)
            assert raised.value.code == "RUNTIME_OUTCOME_INVALID"
            assert harness.store.get_audit_event(receipt.audit_id) is None
        else:
            assert (
                service.submit(receipt, auth_context=harness.auth_context)["created"]
                is True
            )
            assert (
                service.submit(receipt, auth_context=harness.auth_context)[
                    "idempotent_replay"
                ]
                is True
            )
            persisted = harness.writer.get_audit_event(receipt.audit_id)
            assert persisted is not None
            assert harness.activation_ack_token not in persisted.model_dump_json()
