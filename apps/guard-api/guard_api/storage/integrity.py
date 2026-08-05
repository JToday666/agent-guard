"""Audit hash-chain helpers shared by Control Plane stores."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from agentguard_core import AuditEvent, AuditIntegrityMetadata

from guard_api.storage.base import AuditIntegrityStatus

CANONICALIZATION = "json:v1"


def attach_audit_integrity(
    event: AuditEvent,
    *,
    sequence: int,
    prev_hash: str | None,
) -> AuditEvent:
    metadata = AuditIntegrityMetadata(
        sequence=sequence,
        prev_hash=prev_hash,
        event_hash=compute_audit_event_hash(
            event, sequence=sequence, prev_hash=prev_hash
        ),
        canonicalization=CANONICALIZATION,
    )
    return event.model_copy(update={"integrity": metadata})


def compute_audit_event_hash(
    event: AuditEvent,
    *,
    sequence: int,
    prev_hash: str | None,
) -> str:
    payload = {
        "sequence": sequence,
        "prev_hash": prev_hash,
        "event": event.model_dump(mode="json", exclude={"integrity"}),
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def read_audit_integrity(event: AuditEvent) -> AuditIntegrityMetadata | None:
    value = None
    if event.model_extra:
        value = event.model_extra.get("integrity")
    if value is None:
        return None
    if isinstance(value, AuditIntegrityMetadata):
        return value
    return AuditIntegrityMetadata.model_validate(value)


def verify_audit_chain(events: Iterable[AuditEvent]) -> AuditIntegrityStatus:
    ordered_events = list(events)
    total_count = len(ordered_events)
    prev_hash: str | None = None
    count = 0
    head_hash: str | None = None
    for event in ordered_events:
        count += 1
        metadata = read_audit_integrity(event)
        if metadata is None:
            return AuditIntegrityStatus(
                valid=False,
                event_count=total_count,
                head_hash=head_hash,
                first_broken_audit_id=event.audit_id,
            )
        expected_hash = compute_audit_event_hash(
            event, sequence=metadata.sequence, prev_hash=prev_hash
        )
        if (
            metadata.sequence != count
            or metadata.prev_hash != prev_hash
            or metadata.event_hash != expected_hash
        ):
            return AuditIntegrityStatus(
                valid=False,
                event_count=total_count,
                head_hash=head_hash,
                first_broken_audit_id=event.audit_id,
            )
        prev_hash = metadata.event_hash
        head_hash = metadata.event_hash
    return AuditIntegrityStatus(
        valid=True,
        event_count=total_count,
        head_hash=head_hash,
        first_broken_audit_id=None,
    )
