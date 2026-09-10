#!/usr/bin/env python
"""Inspect or deliver existing LangGraph receipts, without starting a runtime."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from agentguard_langgraph_adapter.activation_ack import ProductActivationError
from agentguard_langgraph_adapter.product_receipt_recovery import (
    load_product_recovery_config,
    open_product_receipt_recovery,
)

_REJECTED_CODES = {
    "receipt_reconciliation_worker_required",
    "receipt_reconciliation_selector_invalid",
    "receipt_reconciliation_not_found",
    "receipt_reconciliation_digest_mismatch",
    "receipt_reconciliation_order_invalid",
    "receipt_reconciliation_ineligible",
    "receipt_reconciliation_limit",
    "outbox_transport_binding_missing",
    "outbox_transport_binding_mismatch",
    "outbox_control_missing",
    "outbox_receipt_conflict",
    "receipt_recovery_binding_missing",
    "receipt_recovery_config_invalid",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("status", "drain", "reconcile"))
    parser.add_argument("--config-file", required=True, type=Path)
    parser.add_argument("--audit-id")
    parser.add_argument("--expected-wire-digest")
    args = parser.parse_args(argv)
    if args.command == "reconcile":
        if not args.audit_id or not args.expected_wire_digest:
            parser.error("reconcile requires --audit-id and --expected-wire-digest")
    elif args.audit_id is not None or args.expected_wire_digest is not None:
        parser.error("receipt selector is only valid for reconcile")
    try:
        config = load_product_recovery_config(args.config_file)
        with open_product_receipt_recovery(config) as recovery:
            deliveries = []
            snapshot = None
            if args.command == "reconcile":
                assert isinstance(args.audit_id, str)
                assert isinstance(args.expected_wire_digest, str)
                deliveries = [
                    recovery.reconcile_rejected_receipt(
                        args.audit_id, args.expected_wire_digest
                    )
                ]
                snapshot = recovery.reconciliation_snapshot(
                    args.audit_id, args.expected_wire_digest
                )
            elif args.command == "drain":
                deliveries = list(recovery.drain_once())
            status = recovery.status()
            closed = recovery.close()
            readable = status.error_code not in {
                "outbox_storage_failed",
                "outbox_recovery_failed",
                "outbox_closed",
                "outbox_closing",
            }
            selected_confirmed = (
                snapshot is not None
                and snapshot.confirmed
                and len(deliveries) == 1
                and deliveries[0].status == "recorded"
                and not closed.closing
                and readable
            )
            all_confirmed = (
                status.pending_count == 0
                and status.unknown_action_count == 0
                and status.completed_count > 0
                and not closed.closing
                and readable
            )
            payload = {
                "schema_version": "agentguard-product-receipt-recovery-result/1",
                "runtime": "langgraph",
                "command": args.command,
                "selected_confirmed": selected_confirmed,
                "all_receipts_confirmed": all_confirmed,
                "deliveries": [asdict(item) for item in deliveries],
                "reconciliation": asdict(snapshot) if snapshot is not None else None,
                "status": asdict(status),
                "close_status": asdict(closed),
                "product_active_started": False,
            }
            if args.command == "status":
                exit_code = 0 if not closed.closing and readable else 2
            elif selected_confirmed or args.command == "drain" and all_confirmed:
                exit_code = 0
            elif any(item.status == "permanent_rejected" for item in deliveries):
                exit_code = 1
            elif any(
                item.status == "failed" and item.error_code in _REJECTED_CODES
                for item in deliveries
            ):
                exit_code = 1
            else:
                exit_code = 2
            payload["exit_code"] = exit_code
            print(json.dumps(payload, sort_keys=True))
            return exit_code
    except ProductActivationError as error:
        exit_code = 1 if error.code in _REJECTED_CODES else 2
        print(
            json.dumps(
                {
                    "error": error.code,
                    "product_active_started": False,
                    "exit_code": exit_code,
                },
                sort_keys=True,
            )
        )
        return exit_code
    except Exception:
        print(
            '{"error":"receipt_recovery_unavailable",'
            '"product_active_started":false,"exit_code":2}'
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
