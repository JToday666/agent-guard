"""Versioned, closed pre-activation case set shared by runners and signer."""

from __future__ import annotations

from dataclasses import dataclass

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions.product import PRODUCT_EVENT_TYPES

REQUIREMENTS_VERSION = "agentguard-product-pre-activation/1"
POLICY_GROUPS = ("allow", "ask", "deny")
RUNTIMES = ("langgraph", "openclaw")
TOOLS = {
    "read": "read",
    "write": "write",
    "edit": "edit",
    "exec": "exec",
    "process": "process",
    "memory_read": "agentguard_memory_read",
    "memory_write": "agentguard_memory_write",
    "message": "message",
}

# Fixed failure contracts. A report cannot invent the set of accepted errors.
NEGATIVE_REASONS = {
    "ack.identity": (
        "ack_identity_mismatch",
        "identity_mismatch",
        "heartbeat_identity_mismatch",
    ),
    "ack.expiry": ("ack_expired", "ack_too_old", "expired", "too_old"),
    "config.incomplete_blocked": (
        "product_execution_unavailable",
        "product_registration_incomplete",
        "product_composition_unavailable",
    ),
    "inventory.drift_blocked": (
        "product_inventory_changed",
        "product_composition_drift",
        "product_profile_drift",
        "observation_drift",
    ),
    "approval.invalid_release": (
        "rte-05:lease_response_invalid",
        "rte-05:binding_mismatch",
        "v21:restricted_host_mismatch",
        "approval_release_forbidden",
    ),
    "approval.timeout": (
        "rte-05:lease_consume_timed_out",
        "approval_timeout",
        "approval_expired",
    ),
    "receipt.decrypt_failure": ("outbox_recovery_failed", "outbox_storage_failed"),
    "receipt.payload_conflict": ("outbox_receipt_conflict",),
    "receipt.pending_blocks_side_effect": (
        "outbox_pending_receipts",
        "outbox_barrier_open",
        "product_delivery_blocked",
        "product_delivery_unavailable",
    ),
    "receipt.start_confirmation_required": (
        "receipt_retry_pending",
        "receipt_transport_failed",
        "receipt_acknowledgement_invalid",
        "outbox_barrier_open",
    ),
    "release.confirmation_required": (
        "receipt_retry_pending",
        "receipt_transport_failed",
        "receipt_acknowledgement_invalid",
        "outbox_barrier_open",
        "product_delivery_blocked",
    ),
    "binding.strong": (
        "rte-05:binding_mismatch",
        "action_ticket_invalid",
        "action_identity_invalid",
    ),
    "binding.restricted": (
        "v21:restricted_host_mismatch",
        "action_ticket_invalid",
        "action_identity_invalid",
    ),
}
COMPOSITION_COMPONENTS = (
    "activation_session",
    "tool_catalog",
    "receipt_delivery",
    "action_barrier",
    "seven_event_consumers",
)


@dataclass(frozen=True)
class Requirement:
    id: str
    validator: str
    subject: str
    policy_group: str | None = None

    def to_wire(self) -> dict:
        return {
            "id": self.id,
            "validator": self.validator,
            "subject": self.subject,
            "policy_group": self.policy_group,
        }


def requirements_for(runtime: str) -> tuple[Requirement, ...]:
    if runtime not in RUNTIMES:
        raise ValueError("unknown_product_runtime")
    rows = [
        Requirement(f"baseline.tool.{label}", "native_invocation", name)
        for label, name in TOOLS.items()
    ]
    rows.extend(
        Requirement(f"baseline.{name}", "baseline_material", name)
        for name in (
            "inventory_exact",
            "runtime_pin",
            "actual_candidate_install",
            "product_disabled",
        )
    )
    rows.extend(
        Requirement(f"contract.event.{event}", "event_consumer", event)
        for event in PRODUCT_EVENT_TYPES
    )
    for group, subjects in (
        (
            "ack",
            (
                "identity",
                "expiry",
                "single_flight",
                "immutable_action_snapshot",
                "consume_retry_fixed",
                "historical_receipt",
            ),
        ),
        ("config", ("incomplete_blocked",)),
        ("inventory", ("drift_blocked",)),
        ("approval", ("invalid_release", "timeout")),
        (
            "receipt",
            (
                "network_queue",
                "restart_drain_only",
                "permanent_409",
                "permanent_422",
                "disk_failure",
                "decrypt_failure",
                "payload_conflict",
                "pending_blocks_side_effect",
            ),
        ),
    ):
        rows.extend(
            Requirement(f"contract.{group}.{subject}", "protocol", f"{group}.{subject}")
            for subject in subjects
        )
    rows.append(
        Requirement("contract.duplicate_action", "protocol", "duplicate_action")
    )
    extras = (
        ("receipt.start_confirmation_required", "binding.strong")
        if runtime == "langgraph"
        else (
            "release.confirmation_required",
            "binding.restricted",
            "unknown_no_reexecution",
            "residual_boundaries",
        )
    )
    rows.extend(
        Requirement(f"contract.{subject}", "protocol", subject) for subject in extras
    )
    rows.extend(
        Requirement(
            f"contract.policy.{group}.{category}", "policy_chain", category, group
        )
        for group in POLICY_GROUPS
        for category in ("file", "command", "memory", "message")
    )
    return tuple(sorted(rows, key=lambda row: row.id))


def requirements_document() -> dict:
    return {
        "schema_version": REQUIREMENTS_VERSION,
        "runtimes": {
            runtime: [row.to_wire() for row in requirements_for(runtime)]
            for runtime in RUNTIMES
        },
        "permanent_receipt_recovery": "explicit_original_wire_reconcile_after_cause_removed",
        "disk_failure_stages": ["pre_action", "confirmation_persist"],
        "unknown_scope": "no_observed_host_terminal",
        "negative_reason_codes": {
            key: list(value) for key, value in NEGATIVE_REASONS.items()
        },
        "composition_components": list(COMPOSITION_COMPONENTS),
        "post_activation_additional_required_cases": [
            {"id": "active.ack.revoked", "phase": "product_active", "expected_new_invocations": 0},
            {"id": "active.approval.rejected", "phase": "product_active", "expected_new_invocations": 0},
        ],
    }


def requirements_digest() -> str:
    return canonical_sha256(requirements_document())
