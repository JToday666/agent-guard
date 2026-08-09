"""rehash the audit chain with RFC 8785 JCS

Revision ID: 0013_jcs_audit_chain
Revises: 0012_operational_columns
Create Date: 2026-08-10
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any, NoReturn

from alembic import op
import rfc8785
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0013_jcs_audit_chain"
down_revision = "0012_operational_columns"
branch_labels = None
depends_on = None

JCS_CANONICALIZATION = "jcs:rfc8785"
LEGACY_CANONICALIZATION = "json:v1"
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_INTEGRITY_FIELDS = {
    "sequence",
    "prev_hash",
    "event_hash",
    "canonicalization",
}


def upgrade() -> None:
    _rehash_audit_chains(rfc8785.dumps, JCS_CANONICALIZATION)


def downgrade() -> None:
    _rehash_audit_chains(_legacy_json_bytes, LEGACY_CANONICALIZATION)


def _rehash_audit_chains(
    serializer: Callable[[Any], bytes],
    canonicalization: str,
) -> None:
    connection = op.get_bind()
    # This migration changes every chain hash. Serialize it against runtime
    # writers and refuse to turn an already-broken chain into a valid one.
    connection.execute(sa.text("LOCK TABLE audit_events IN ACCESS EXCLUSIVE MODE"))
    connection.execute(
        sa.text("LOCK TABLE audit_integrity_heads IN ACCESS EXCLUSIVE MODE")
    )
    _validate_existing_audit_chains(connection)

    rows = connection.execute(sa.text("""
            SELECT chain_id, audit_id, sequence, payload_json
            FROM audit_events
            ORDER BY chain_id ASC, sequence ASC, audit_id ASC
            """)).mappings()
    update_event = sa.text("""
        UPDATE audit_events
        SET payload_json = :payload_json,
            prev_hash = :prev_hash,
            event_hash = :event_hash
        WHERE chain_id = :chain_id AND audit_id = :audit_id
        """).bindparams(sa.bindparam("payload_json", type_=JSONB))

    heads: dict[str, tuple[int, str]] = {}
    previous_by_chain: dict[str, str | None] = {}
    for row in rows:
        chain_id = str(row["chain_id"])
        audit_id = str(row["audit_id"])
        sequence = int(row["sequence"])
        previous = previous_by_chain.get(chain_id)
        event_payload = dict(row["payload_json"])
        event_payload.pop("integrity", None)
        hash_payload = {
            "sequence": sequence,
            "prev_hash": previous,
            "event": event_payload,
        }
        event_hash = hashlib.sha256(serializer(hash_payload)).hexdigest()
        event_payload["integrity"] = {
            "sequence": sequence,
            "prev_hash": previous,
            "event_hash": event_hash,
            "canonicalization": canonicalization,
        }
        connection.execute(
            update_event,
            {
                "payload_json": event_payload,
                "prev_hash": previous,
                "event_hash": event_hash,
                "chain_id": chain_id,
                "audit_id": audit_id,
            },
        )
        previous_by_chain[chain_id] = event_hash
        heads[chain_id] = (sequence, event_hash)

    connection.execute(sa.text("DELETE FROM audit_integrity_heads"))
    for chain_id, (sequence, event_hash) in heads.items():
        connection.execute(
            sa.text("""
                INSERT INTO audit_integrity_heads (
                    chain_id, sequence, event_hash, updated_at
                ) VALUES (
                    :chain_id, :sequence, :event_hash, statement_timestamp()
                )
                """),
            {
                "chain_id": chain_id,
                "sequence": sequence,
                "event_hash": event_hash,
            },
        )


def _validate_existing_audit_chains(connection: Any) -> None:
    rows = connection.execute(sa.text("""
            SELECT chain_id, audit_id, sequence, prev_hash, event_hash, payload_json
            FROM audit_events
            ORDER BY chain_id ASC, sequence ASC, audit_id ASC
            """)).mappings()
    previous_by_chain: dict[str, str | None] = {}
    sequence_by_chain: dict[str, int] = {}
    expected_heads: dict[str, tuple[int, str]] = {}

    for row in rows:
        chain_id = str(row["chain_id"])
        audit_id = str(row["audit_id"])
        sequence = int(row["sequence"])
        expected_sequence = sequence_by_chain.get(chain_id, 0) + 1
        if sequence != expected_sequence:
            _invalid_chain(audit_id, "non-contiguous sequence")

        payload = dict(row["payload_json"])
        if payload.get("audit_id") != audit_id:
            _invalid_chain(audit_id, "payload audit_id mismatch")
        integrity = payload.get("integrity")
        if not isinstance(integrity, dict) or set(integrity) != _INTEGRITY_FIELDS:
            _invalid_chain(audit_id, "missing or malformed integrity metadata")

        metadata_sequence = integrity.get("sequence")
        previous = previous_by_chain.get(chain_id)
        metadata_previous = integrity.get("prev_hash")
        event_hash = integrity.get("event_hash")
        canonicalization = integrity.get("canonicalization")
        if type(metadata_sequence) is not int or metadata_sequence != sequence:
            _invalid_chain(audit_id, "integrity sequence mismatch")
        if metadata_previous != previous or row["prev_hash"] != previous:
            _invalid_chain(audit_id, "previous hash mismatch")
        if (
            not isinstance(event_hash, str)
            or not _HASH_PATTERN.fullmatch(event_hash)
            or row["event_hash"] != event_hash
        ):
            _invalid_chain(audit_id, "event hash mismatch")

        source_serializer = _serializer_for(canonicalization, audit_id)
        payload.pop("integrity")
        hash_payload = {
            "sequence": sequence,
            "prev_hash": previous,
            "event": payload,
        }
        try:
            expected_hash = hashlib.sha256(source_serializer(hash_payload)).hexdigest()
        except Exception as exc:
            raise RuntimeError(
                f"cannot canonicalize existing audit event {audit_id!r}"
            ) from exc
        if event_hash != expected_hash:
            _invalid_chain(audit_id, "content hash mismatch")

        previous_by_chain[chain_id] = event_hash
        sequence_by_chain[chain_id] = sequence
        expected_heads[chain_id] = (sequence, event_hash)

    _validate_existing_heads(connection, expected_heads)


def _validate_existing_heads(
    connection: Any,
    expected_heads: dict[str, tuple[int, str]],
) -> None:
    rows = connection.execute(sa.text("""
            SELECT chain_id, sequence, event_hash
            FROM audit_integrity_heads
            ORDER BY chain_id ASC
            """)).mappings()
    actual_heads = {
        str(row["chain_id"]): (int(row["sequence"]), row["event_hash"]) for row in rows
    }
    for chain_id, expected in expected_heads.items():
        if actual_heads.pop(chain_id, None) != expected:
            raise RuntimeError(
                f"refusing to rehash audit chain {chain_id!r}: head mismatch"
            )
    for chain_id, actual in actual_heads.items():
        if actual != (0, None):
            raise RuntimeError(
                f"refusing to rehash audit chain {chain_id!r}: orphaned head"
            )


def _serializer_for(
    canonicalization: object,
    audit_id: str,
) -> Callable[[Any], bytes]:
    if canonicalization == JCS_CANONICALIZATION:
        return rfc8785.dumps
    if canonicalization == LEGACY_CANONICALIZATION:
        return _legacy_json_bytes
    _invalid_chain(audit_id, "unsupported canonicalization")


def _invalid_chain(audit_id: str, reason: str) -> NoReturn:
    raise RuntimeError(
        f"refusing to rehash invalid audit chain at {audit_id!r}: {reason}"
    )


def _legacy_json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
