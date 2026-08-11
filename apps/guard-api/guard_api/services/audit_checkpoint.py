"""Database-external authenticated checkpoints for the audit hash chain."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Callable, Iterator, Literal

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

from guard_api.storage.base import (
    AuditCanonicalizationError,
    AuditIntegrityStatus,
    AuditWindowQuery,
    ControlPlaneStore,
)
from guard_api.storage.integrity import (
    CANONICALIZATION,
    canonical_json_bytes,
    read_audit_integrity,
)

CHECKPOINT_SCHEMA_VERSION = "agentguard.audit-checkpoint.v1"
CHECKPOINT_CHAIN_ID = "default"
CHECKPOINT_SIGNATURE_ALGORITHM = "hmac-sha256"
MAX_CHECKPOINT_FILE_BYTES = 256 * 1024 * 1024

_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_BODY_FIELDS = {
    "schema_version",
    "chain_id",
    "sequence",
    "head_hash",
    "canonicalization",
    "checkpointed_at",
    "previous_checkpoint_hash",
}
_SIGNED_FIELDS = _BODY_FIELDS | {"checkpoint_hash"}
_RECORD_FIELDS = _SIGNED_FIELDS | {"signature"}

AuditAnchorState = Literal[
    "disabled",
    "empty",
    "current",
    "stale",
    "invalid",
    "error",
]


class AuditCheckpointError(RuntimeError):
    """Base error for an enabled external checkpoint sink."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AuditCheckpointIntegrityError(AuditCheckpointError):
    """Raised when the checkpoint log or its database binding is invalid."""


class AuditCheckpointIoError(AuditCheckpointError):
    """Raised when the checkpoint sink cannot be read or durably appended."""


@contextmanager
def _locked_file_descriptor(
    descriptor: int,
    *,
    exclusive: bool,
) -> Iterator[None]:
    """Hold the checkpoint file lock without masking a primary operation error."""

    acquired = False
    active_error: BaseException | None = None
    try:
        _acquire_file_lock(descriptor, exclusive=exclusive)
        acquired = True
        yield
    except BaseException as exc:
        active_error = exc
        raise
    finally:
        if acquired:
            try:
                _release_file_lock(descriptor)
            except AuditCheckpointIoError as exc:
                if active_error is None:
                    raise
                active_error.add_note(exc.code)


def _acquire_file_lock(descriptor: int, *, exclusive: bool) -> None:
    try:
        if sys.platform == "win32":
            # ``msvcrt`` has no dependable cross-process shared-lock behavior for
            # this use case. Serialize reads and writes on Windows instead.
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        else:
            mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            fcntl.flock(descriptor, mode)
    except OSError as exc:
        raise AuditCheckpointIoError("AUDIT_CHECKPOINT_LOCK_FAILED") from exc


def _release_file_lock(descriptor: int) -> None:
    try:
        if sys.platform == "win32":
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError as exc:
        raise AuditCheckpointIoError("AUDIT_CHECKPOINT_UNLOCK_FAILED") from exc


@dataclass(frozen=True, slots=True)
class AuditAnchorStatus:
    enabled: bool
    status: AuditAnchorState
    checkpoint_sequence: int | None = None
    checkpoint_head_hash: str | None = None
    checkpoint_hash: str | None = None
    checkpointed_at: str | None = None
    lag: int | None = None
    key_id: str | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class _CheckpointRecord:
    sequence: int
    head_hash: str
    checkpoint_hash: str
    checkpointed_at: str
    key_id: str


def disabled_audit_anchor_status() -> AuditAnchorStatus:
    return AuditAnchorStatus(enabled=False, status="disabled")


class AuditCheckpointService:
    """Maintain a signed append-only JSONL checkpoint outside PostgreSQL.

    The database hash chain remains the primary integrity mechanism. This log
    authenticates selected chain heads with a secret that is not stored in the
    database, allowing database-only rewrites and rollbacks to be detected.
    """

    def __init__(
        self,
        *,
        store: ControlPlaneStore,
        path: Path,
        signing_key: bytes,
        key_id: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("audit checkpoint signing key must contain 32 bytes")
        self.store = store
        self.path = path
        self.signing_key = signing_key
        self.key_id = key_id
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._file_identity: tuple[int, int] | None = None
        self._loaded_size = 0
        self._loaded_mtime_ns = 0
        self._loaded_ctime_ns = 0
        self._latest: _CheckpointRecord | None = None

    def initialize(self) -> AuditAnchorStatus:
        """Validate the sink and immediately anchor the current valid head."""

        if not self.path.parent.is_dir():
            raise AuditCheckpointIoError("AUDIT_CHECKPOINT_PARENT_MISSING")
        return self.checkpoint()

    def checkpoint(self) -> AuditAnchorStatus:
        """Append one checkpoint when the verified database head has advanced."""

        chain_status = self.store.verify_audit_integrity()
        if not chain_status.valid:
            raise AuditCheckpointIntegrityError("AUDIT_CHAIN_INVALID")

        with self._lock:
            descriptor = self._open(create=True)
            try:
                with _locked_file_descriptor(descriptor, exclusive=True):
                    latest = self._synchronize(descriptor)
                    status = self._status_for(latest, chain_status)
                    if status.status == "invalid":
                        raise AuditCheckpointIntegrityError(
                            status.error_code or "AUDIT_CHECKPOINT_INVALID"
                        )
                    if chain_status.event_count == 0 or status.status == "current":
                        return status
                    if chain_status.head_hash is None:
                        raise AuditCheckpointIntegrityError("AUDIT_CHAIN_HEAD_MISSING")

                    record_payload = self._build_record(
                        sequence=chain_status.event_count,
                        head_hash=chain_status.head_hash,
                        previous_checkpoint_hash=(
                            latest.checkpoint_hash if latest is not None else None
                        ),
                    )
                    line = canonical_json_bytes(record_payload) + b"\n"
                    current_size = os.fstat(descriptor).st_size
                    if current_size + len(line) > MAX_CHECKPOINT_FILE_BYTES:
                        raise AuditCheckpointIoError("AUDIT_CHECKPOINT_FILE_TOO_LARGE")
                    try:
                        remaining = memoryview(line)
                        while remaining:
                            written = os.write(descriptor, remaining)
                            if written <= 0:
                                raise OSError("checkpoint append made no progress")
                            remaining = remaining[written:]
                        os.fsync(descriptor)
                    except OSError as exc:
                        raise AuditCheckpointIoError(
                            "AUDIT_CHECKPOINT_APPEND_FAILED"
                        ) from exc
                    self._refresh_cache_after_append(descriptor, record_payload)
                    return self._status_for(self._latest, chain_status)
            finally:
                os.close(descriptor)

    def inspect(self, chain_status: AuditIntegrityStatus) -> AuditAnchorStatus:
        """Verify the external log and compare its latest head with the database."""

        if not chain_status.valid:
            return AuditAnchorStatus(
                enabled=True,
                status="invalid",
                key_id=self.key_id,
                error_code="AUDIT_CHAIN_INVALID",
            )
        try:
            with self._lock:
                descriptor = self._open(create=False)
                try:
                    with _locked_file_descriptor(descriptor, exclusive=False):
                        latest = self._synchronize(descriptor)
                finally:
                    os.close(descriptor)
            return self._status_for(latest, chain_status)
        except AuditCheckpointIntegrityError as exc:
            return AuditAnchorStatus(
                enabled=True,
                status="invalid",
                key_id=self.key_id,
                error_code=exc.code,
            )
        except (AuditCheckpointIoError, AuditCanonicalizationError) as exc:
            code = (
                exc.code
                if isinstance(exc, AuditCheckpointError)
                else "AUDIT_CHECKPOINT_CANONICALIZATION_FAILED"
            )
            return AuditAnchorStatus(
                enabled=True,
                status="error",
                key_id=self.key_id,
                error_code=code,
            )

    def _open(self, *, create: bool) -> int:
        if self.path.is_symlink():
            raise AuditCheckpointIoError("AUDIT_CHECKPOINT_SYMLINK_FORBIDDEN")
        flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
        if create:
            flags |= os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileNotFoundError as exc:
            raise AuditCheckpointIoError("AUDIT_CHECKPOINT_FILE_MISSING") from exc
        except OSError as exc:
            raise AuditCheckpointIoError("AUDIT_CHECKPOINT_OPEN_FAILED") from exc
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise AuditCheckpointIoError("AUDIT_CHECKPOINT_NOT_REGULAR_FILE")
        return descriptor

    def _synchronize(self, descriptor: int) -> _CheckpointRecord | None:
        file_status = os.fstat(descriptor)
        identity = (file_status.st_dev, file_status.st_ino)
        if file_status.st_size > MAX_CHECKPOINT_FILE_BYTES:
            raise AuditCheckpointIoError("AUDIT_CHECKPOINT_FILE_TOO_LARGE")

        if self._file_identity is None:
            latest = self._read_records(descriptor, offset=0, previous=None)
        elif identity != self._file_identity or file_status.st_size < self._loaded_size:
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_REPLACED")
        elif file_status.st_size == self._loaded_size:
            if (
                file_status.st_mtime_ns != self._loaded_mtime_ns
                or file_status.st_ctime_ns != self._loaded_ctime_ns
            ):
                raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_MUTATED")
            return self._latest
        else:
            latest = self._read_records(
                descriptor,
                offset=self._loaded_size,
                previous=self._latest,
            )

        refreshed = os.fstat(descriptor)
        self._file_identity = (refreshed.st_dev, refreshed.st_ino)
        self._loaded_size = refreshed.st_size
        self._loaded_mtime_ns = refreshed.st_mtime_ns
        self._loaded_ctime_ns = refreshed.st_ctime_ns
        self._latest = latest
        return latest

    def _read_records(
        self,
        descriptor: int,
        *,
        offset: int,
        previous: _CheckpointRecord | None,
    ) -> _CheckpointRecord | None:
        try:
            os.lseek(descriptor, offset, os.SEEK_SET)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
        except OSError as exc:
            raise AuditCheckpointIoError("AUDIT_CHECKPOINT_READ_FAILED") from exc
        data = b"".join(chunks)
        if not data:
            return previous
        if not data.endswith(b"\n"):
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_TRUNCATED")
        for line in data.splitlines():
            if not line:
                raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_INVALID_RECORD")
            record_payload = self._parse_json_record(line)
            previous = self._verify_record(record_payload, previous)
        return previous

    def _parse_json_record(self, line: bytes) -> dict[str, object]:
        try:
            decoded = line.decode("utf-8")
            value = json.loads(
                decoded,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise AuditCheckpointIntegrityError(
                "AUDIT_CHECKPOINT_INVALID_JSON"
            ) from exc
        if not isinstance(value, dict):
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_INVALID_RECORD")
        try:
            canonical_line = canonical_json_bytes(value)
        except AuditCanonicalizationError as exc:
            raise AuditCheckpointIntegrityError(
                "AUDIT_CHECKPOINT_INVALID_RECORD"
            ) from exc
        if not hmac.compare_digest(line, canonical_line):
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_NON_CANONICAL")
        return value

    def _verify_record(
        self,
        record: dict[str, object],
        previous: _CheckpointRecord | None,
    ) -> _CheckpointRecord:
        if set(record) != _RECORD_FIELDS:
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_INVALID_RECORD")
        if record.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_SCHEMA_MISMATCH")
        if record.get("chain_id") != CHECKPOINT_CHAIN_ID:
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_CHAIN_MISMATCH")
        if record.get("canonicalization") != CANONICALIZATION:
            raise AuditCheckpointIntegrityError(
                "AUDIT_CHECKPOINT_CANONICALIZATION_MISMATCH"
            )

        sequence = record.get("sequence")
        head_hash = record.get("head_hash")
        checkpoint_hash = record.get("checkpoint_hash")
        checkpointed_at = record.get("checkpointed_at")
        previous_hash = record.get("previous_checkpoint_hash")
        if type(sequence) is not int or sequence < 1:
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_INVALID_SEQUENCE")
        if not isinstance(head_hash, str) or not _HASH_PATTERN.fullmatch(head_hash):
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_INVALID_HEAD_HASH")
        if not isinstance(checkpoint_hash, str) or not _HASH_PATTERN.fullmatch(
            checkpoint_hash
        ):
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_INVALID_HASH")
        if previous_hash is not None and (
            not isinstance(previous_hash, str)
            or not _HASH_PATTERN.fullmatch(previous_hash)
        ):
            raise AuditCheckpointIntegrityError(
                "AUDIT_CHECKPOINT_INVALID_PREVIOUS_HASH"
            )
        if not isinstance(checkpointed_at, str):
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_INVALID_TIMESTAMP")
        _parse_checkpoint_timestamp(checkpointed_at)

        expected_previous = previous.checkpoint_hash if previous is not None else None
        if previous_hash != expected_previous:
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_CHAIN_BROKEN")
        if previous is not None and sequence <= previous.sequence:
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_SEQUENCE_REUSED")

        body = {field: record[field] for field in _BODY_FIELDS}
        expected_hash = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
        if not hmac.compare_digest(checkpoint_hash, expected_hash):
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_HASH_MISMATCH")

        signature = record.get("signature")
        if not isinstance(signature, dict) or set(signature) != {
            "algorithm",
            "key_id",
            "value",
        }:
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_INVALID_SIGNATURE")
        if signature.get("algorithm") != CHECKPOINT_SIGNATURE_ALGORITHM:
            raise AuditCheckpointIntegrityError(
                "AUDIT_CHECKPOINT_SIGNATURE_ALGORITHM_MISMATCH"
            )
        if signature.get("key_id") != self.key_id:
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_KEY_MISMATCH")
        signature_value = signature.get("value")
        if not isinstance(signature_value, str) or not _SIGNATURE_PATTERN.fullmatch(
            signature_value
        ):
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_INVALID_SIGNATURE")
        signed_payload = {field: record[field] for field in _SIGNED_FIELDS}
        expected_signature = self._sign(signed_payload)
        if not hmac.compare_digest(signature_value, expected_signature):
            raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_SIGNATURE_MISMATCH")

        return _CheckpointRecord(
            sequence=sequence,
            head_hash=head_hash,
            checkpoint_hash=checkpoint_hash,
            checkpointed_at=checkpointed_at,
            key_id=self.key_id,
        )

    def _build_record(
        self,
        *,
        sequence: int,
        head_hash: str,
        previous_checkpoint_hash: str | None,
    ) -> dict[str, object]:
        checkpointed_at = _format_checkpoint_timestamp(self.clock())
        body: dict[str, object] = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "chain_id": CHECKPOINT_CHAIN_ID,
            "sequence": sequence,
            "head_hash": head_hash,
            "canonicalization": CANONICALIZATION,
            "checkpointed_at": checkpointed_at,
            "previous_checkpoint_hash": previous_checkpoint_hash,
        }
        checkpoint_hash = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
        signed_payload = {**body, "checkpoint_hash": checkpoint_hash}
        return {
            **signed_payload,
            "signature": {
                "algorithm": CHECKPOINT_SIGNATURE_ALGORITHM,
                "key_id": self.key_id,
                "value": self._sign(signed_payload),
            },
        }

    def _sign(self, payload: dict[str, object]) -> str:
        signature_payload = {
            "domain": "agentguard/audit-checkpoint-signature/v1",
            "algorithm": CHECKPOINT_SIGNATURE_ALGORITHM,
            "key_id": self.key_id,
            "checkpoint": payload,
        }
        digest = hmac.new(
            self.signing_key,
            canonical_json_bytes(signature_payload),
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def _refresh_cache_after_append(
        self,
        descriptor: int,
        record_payload: dict[str, object],
    ) -> None:
        latest = self._verify_record(record_payload, self._latest)
        file_status = os.fstat(descriptor)
        self._file_identity = (file_status.st_dev, file_status.st_ino)
        self._loaded_size = file_status.st_size
        self._loaded_mtime_ns = file_status.st_mtime_ns
        self._loaded_ctime_ns = file_status.st_ctime_ns
        self._latest = latest

    def _status_for(
        self,
        latest: _CheckpointRecord | None,
        chain_status: AuditIntegrityStatus,
    ) -> AuditAnchorStatus:
        if latest is None:
            return AuditAnchorStatus(
                enabled=True,
                status="empty",
                lag=chain_status.event_count,
                key_id=self.key_id,
            )
        if latest.sequence > chain_status.event_count:
            return self._invalid_status(latest, "AUDIT_CHECKPOINT_AHEAD_OF_DATABASE")

        anchored_event_hash = self._database_event_hash(latest.sequence)
        if anchored_event_hash != latest.head_hash:
            return self._invalid_status(latest, "AUDIT_CHECKPOINT_DATABASE_MISMATCH")

        lag = chain_status.event_count - latest.sequence
        if lag == 0 and chain_status.head_hash != latest.head_hash:
            return self._invalid_status(latest, "AUDIT_CHECKPOINT_DATABASE_MISMATCH")
        return AuditAnchorStatus(
            enabled=True,
            status="current" if lag == 0 else "stale",
            checkpoint_sequence=latest.sequence,
            checkpoint_head_hash=latest.head_hash,
            checkpoint_hash=latest.checkpoint_hash,
            checkpointed_at=latest.checkpointed_at,
            lag=lag,
            key_id=latest.key_id,
        )

    def _invalid_status(
        self,
        latest: _CheckpointRecord,
        code: str,
    ) -> AuditAnchorStatus:
        return AuditAnchorStatus(
            enabled=True,
            status="invalid",
            checkpoint_sequence=latest.sequence,
            checkpoint_head_hash=latest.head_hash,
            checkpoint_hash=latest.checkpoint_hash,
            checkpointed_at=latest.checkpointed_at,
            key_id=latest.key_id,
            error_code=code,
        )

    def _database_event_hash(self, sequence: int) -> str | None:
        rows = self.store.read_audit_events_bounded(
            AuditWindowQuery(
                upper_sequence=sequence,
                after_sequence=sequence + 1,
                limit=1,
            )
        )
        if len(rows) != 1:
            return None
        integrity = read_audit_integrity(rows[0])
        if integrity is None or integrity.sequence != sequence:
            return None
        return integrity.event_hash


def _format_checkpoint_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise AuditCheckpointIoError("AUDIT_CHECKPOINT_CLOCK_INVALID")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _parse_checkpoint_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise AuditCheckpointIntegrityError(
            "AUDIT_CHECKPOINT_INVALID_TIMESTAMP"
        ) from None
    if parsed.tzinfo is None:
        raise AuditCheckpointIntegrityError("AUDIT_CHECKPOINT_INVALID_TIMESTAMP")
    return parsed
