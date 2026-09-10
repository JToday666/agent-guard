"""One real SDK process; synthetic TEST authority, no native Host or Provider."""

from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import sys
import traceback
import time


def run(data):
    from agentguard_langgraph_adapter.product_receipt_recovery import (
        load_product_recovery_config,
        open_product_receipt_recovery,
    )

    config = load_product_recovery_config(data["configFile"])
    if "baseUrlOverride" in data:
        config = replace(config, core_base_url=data["baseUrlOverride"])
    result = {
        "pid": os.getpid(),
        "syntheticTestEvidence": True,
        "nativeHostEvidence": False,
    }
    if data["stage"] != "prepare":
        from agentguard_langgraph_adapter.product_envelope_store import (
            ProductEnvelopeStore,
            ProductEnvelopeStoreError,
        )

        original_replace = ProductEnvelopeStore.replace
        faults = []

        def faulted_replace(self, record_id, payload, **kwargs):
            record = json.loads(payload)
            selected = (
                data.get("fault") == "confirmation_persist"
                and record.get("record_type") == "tombstone"
            ) or (
                data.get("fault") == "prepared_persist"
                and record.get("phase") == "reconcile_pending"
                and record.get("reconciliation") is not None
            )
            if selected:
                faults.append(True)
                raise ProductEnvelopeStoreError("write_failed")
            return original_replace(self, record_id, payload, **kwargs)

        # Process-local, explicitly synthetic storage fault. No journal bytes
        # are replaced or edited by this probe; normal persistence does all I/O.
        if data.get("fault"):
            ProductEnvelopeStore.replace = faulted_replace
        with open_product_receipt_recovery(config) as recovery:
            result["before"] = asdict(recovery.status())
            if data["stage"] == "reconcile_close":
                from concurrent.futures import ThreadPoolExecutor

                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(
                        recovery.reconcile_rejected_receipt,
                        data["auditId"],
                        data["wireDigest"],
                    )
                    deadline = time.monotonic() + 5
                    while True:
                        snapshot = recovery.reconciliation_snapshot(
                            data["auditId"], data["wireDigest"]
                        )
                        if (
                            snapshot.attempts
                            and snapshot.attempts[-1].outcome == "prepared"
                        ):
                            break
                        assert time.monotonic() < deadline
                        time.sleep(0.005)
                    result["closeDuringSend"] = asdict(recovery.close())
                    assert result["closeDuringSend"]["closing"] is True
                    with Path(data["closeMarker"]).open("x") as marker:
                        Path(data["closeMarker"]).chmod(0o600)
                        json.dump({"closing": True}, marker)
                    result["delivered"] = asdict(future.result(timeout=10))
            elif data["stage"] == "reconcile":
                delivered = recovery.reconcile_rejected_receipt(
                    data["auditId"], data["wireDigest"]
                )
                result["delivered"] = asdict(delivered)
                result["snapshot"] = asdict(
                    recovery.reconciliation_snapshot(
                        data["auditId"], data["wireDigest"]
                    )
                )
            elif data["stage"] == "drain":
                result["delivered"] = [asdict(item) for item in recovery.drain_once()]
            elif data["stage"] != "status":
                raise ValueError("Unknown recovery stage")
            result["status"] = asdict(recovery.status())
            result["faultCount"] = len(faults)
        ProductEnvelopeStore.replace = original_replace
        return result

    # These imports and the session exist only in the initial owner process.
    from agentguard_langgraph_adapter.core_client import AgentGuardCoreClient
    from agentguard_langgraph_adapter.langgraph_adapter import LangGraphAdapter
    from agentguard_langgraph_adapter.product_envelope_store import (
        ProductEnvelopeStore,
        ProductStoreNamespace,
    )
    from agentguard_langgraph_adapter.product_manifest import ProductRuntimeObservation
    from agentguard_langgraph_adapter.product_outbox import (
        ProductReceiptOutbox,
        _encode,
    )
    from agentguard_langgraph_adapter.runtime_receipts import build_runtime_outcome

    adapter = LangGraphAdapter(
        config=replace(
            config, product_receipt_directory=None, product_receipt_key_path=None
        )
    )
    outbox = None
    try:
        ack = adapter.start_product_session(
            observe=lambda: ProductRuntimeObservation.model_validate(
                data["observation"]
            )
        )
        decision = adapter.evaluate_guard_event(data["event"])
        assert decision.decision == data.get("decisionKind", "deny")
        authority = decision.decision_authority
        assert authority is not None
        assert authority.source == "v21"
        assert authority.mode == "active"
        assert authority.selection_basis == "profile_all"
        assert config.product_receipt_directory is not None
        assert config.product_receipt_key_path is not None
        assert config.runtime_binding_id is not None
        assert isinstance(adapter.core_client, AgentGuardCoreClient)
        store = ProductEnvelopeStore(
            config.product_receipt_directory,
            config.product_receipt_key_path,
            namespace=ProductStoreNamespace(
                runtime="langgraph",
                agent_id=config.agent_id,
                principal_id=data["principalId"],
                runtime_binding_id=config.runtime_binding_id,
            ),
        )
        outbox = ProductReceiptOutbox(
            store,
            send_receipt=adapter.core_client.submit_product_receipt_wire,
            transport_binding_digest=adapter.core_client.product_receipt_transport_binding_digest,
            retry_base_seconds=0.001,
            retry_max_seconds=0.001,
        )
        if data.get("decisionKind") == "ask":
            from langgraph_reconciliation_approval import prepare_strong_ask_abort

            receipt, fields = prepare_strong_ask_abort(adapter, outbox, data, decision)
            result.update(fields)
        else:
            receipt = build_runtime_outcome(
                data["event"], decision, execution_status="not_invoked"
            )
            result["delivered"] = asdict(outbox.submit(receipt))
        wire = _encode(receipt.to_wire())
        path = Path(data["wirePath"])
        with path.open("xb") as stream:
            path.chmod(0o600)
            stream.write(wire)
        refreshed = adapter.refresh_product_ack()
        assert refreshed.header_value() != ack.header_value()
        receipt_ack = decision._consumption_activation_ack or ack
        assert refreshed.header_value() != receipt_ack.header_value()
        result.update(
            auditId=receipt.audit_id,
            policyAuditId=receipt.links.policy_audit_id,
            wireDigest=hashlib.sha256(wire).hexdigest(),
            originalAckDigest="sha256:"
            + hashlib.sha256(receipt_ack.header_value().encode()).hexdigest(),
            evaluationAckDigest="sha256:"
            + hashlib.sha256(ack.header_value().encode()).hexdigest(),
            refreshedAckDigest="sha256:"
            + hashlib.sha256(refreshed.header_value().encode()).hexdigest(),
            expiresAt=receipt_ack.expires_at,
            status=asdict(outbox.status()),
        )
        return result
    finally:
        if outbox is not None:
            outbox.close()
        adapter.close_product_session()


try:
    result = run(json.load(sys.stdin))
except Exception as error:
    # Never serialize exception text, config, raw wire or private carrier.
    result = {
        "syntheticTestEvidence": True,
        "nativeHostEvidence": False,
        "errorType": type(error).__name__,
        "errorCode": getattr(error, "code", None),
        "errorLocations": [
            [Path(frame.filename).name, frame.lineno]
            for frame in traceback.extract_tb(error.__traceback__)[-4:]
        ],
    }
print(json.dumps(result, separators=(",", ":")))
