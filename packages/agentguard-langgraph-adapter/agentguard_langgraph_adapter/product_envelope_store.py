"""Private, bounded AES-GCM records; no HTTP, execution, or activation policy."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
from typing import Any, Literal
import uuid

MAX_RECORDS = 10_000
MAX_RECORD_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
_FORMAT = "agentguard.product-envelope.v1"
_ALGORITHM = "AES-256-GCM"
_RECORD_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_FILENAME = re.compile(r"[0-9a-f]{64}\.agq\Z")
_KINDS = frozenset({"action", "receipt", "tombstone", "breaker"})
_HEADER_FIELDS = frozenset(
    {"format", "algorithm", "namespace", "record_id", "kind", "revision"}
)
_ENVELOPE_FIELDS = _HEADER_FIELDS | {"nonce", "ciphertext"}
_ERROR_CODES = frozenset(
    {
        "invalid_configuration",
        "unsupported_platform",
        "crypto_unavailable",
        "store_closed",
        "store_locked",
        "permission_denied",
        "key_missing",
        "key_invalid",
        "namespace_mismatch",
        "record_invalid",
        "record_conflict",
        "record_missing",
        "decryption_failed",
        "capacity_exceeded",
        "orphan_temporary",
        "read_failed",
        "write_failed",
        "store_failed",
    }
)
RecordKind = Literal["action", "receipt", "tombstone", "breaker"]


class ProductEnvelopeStoreError(Exception):
    """Fixed diagnostics never retain filesystem paths, payloads, or credentials."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _ERROR_CODES else "store_failed"
        super().__init__(f"Product envelope store unavailable: {self.code}")


@dataclass(frozen=True, slots=True, repr=False)
class ProductStoreNamespace:
    runtime: str
    agent_id: str
    principal_id: str
    runtime_binding_id: str

    def __post_init__(self) -> None:
        values = (
            self.runtime,
            self.agent_id,
            self.principal_id,
            self.runtime_binding_id,
        )
        if self.runtime != "langgraph" or any(
            not isinstance(value, str) or not value or len(value) > 256
            for value in values
        ):
            raise ProductEnvelopeStoreError("invalid_configuration")
        try:
            for value in values:
                value.encode("utf-8", errors="strict")
        except UnicodeError:
            raise ProductEnvelopeStoreError("invalid_configuration") from None

    def __repr__(self) -> str:
        return "ProductStoreNamespace(<private>)"


@dataclass(frozen=True, slots=True)
class StoredEnvelope:
    record_id: str = field(repr=False)
    kind: RecordKind
    revision: int
    payload: bytes = field(repr=False)
    stored_bytes: int


@dataclass(frozen=True, slots=True)
class StoreUsage:
    record_count: int
    stored_bytes: int


class ProductEnvelopeStore:
    """One owning process and atomic CAS replacement of independently encrypted records.

    Every record kind, including completed tombstones, consumes the same quota.
    One maximum-size record of the total budget is reserved for atomic replacement.
    Successful writes include fsync of both the new file and its containing directory.
    No delete or implicit repair operation can erase uncertain execution evidence.
    """

    def __init__(
        self,
        directory: str | Path,
        key_path: str | Path,
        *,
        namespace: ProductStoreNamespace,
        max_records: int = MAX_RECORDS,
        max_record_bytes: int = MAX_RECORD_BYTES,
        max_total_bytes: int = MAX_TOTAL_BYTES,
    ) -> None:
        self._mutex = threading.RLock()
        self._directory_fd = -1
        self._key_directory_fd = -1
        self._lock_fd = -1
        self._cipher: Any = None
        self._closed = True
        self._owner_pid = os.getpid()
        self._records: dict[str, StoredEnvelope] = {}
        if not isinstance(namespace, ProductStoreNamespace):
            raise ProductEnvelopeStoreError("invalid_configuration")
        for value, upper in (
            (max_records, MAX_RECORDS),
            (max_record_bytes, MAX_RECORD_BYTES),
            (max_total_bytes, MAX_TOTAL_BYTES),
        ):
            if type(value) is not int or value < 1 or value > upper:
                raise ProductEnvelopeStoreError("invalid_configuration")
        if max_total_bytes <= max_record_bytes:
            raise ProductEnvelopeStoreError("invalid_configuration")
        self._max_records = max_records
        self._max_record_bytes = max_record_bytes
        self._max_total_bytes = max_total_bytes
        self._committed_byte_limit = max_total_bytes - max_record_bytes
        self._identity = namespace
        self._namespace = hashlib.sha256(
            _canonical(
                {
                    "runtime": namespace.runtime,
                    "agent_id": namespace.agent_id,
                    "principal_id": namespace.principal_id,
                    "runtime_binding_id": namespace.runtime_binding_id,
                }
            )
        ).hexdigest()
        directory_path = _absolute_path(directory)
        secret_path = _absolute_path(key_path)
        if (
            secret_path.parent == directory_path
            or directory_path in secret_path.parents
            or secret_path in directory_path.parents
        ):
            raise ProductEnvelopeStoreError("invalid_configuration")
        if not all(
            hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")
        ):
            raise ProductEnvelopeStoreError("unsupported_platform")
        try:
            import fcntl
        except ImportError:
            raise ProductEnvelopeStoreError("unsupported_platform") from None
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ProductEnvelopeStoreError("crypto_unavailable") from None
        try:
            self._directory_fd = _open_private_directory(directory_path)
            self._lock_fd = os.open(
                ".lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=self._directory_fd,
            )
            _check_private_file(os.fstat(self._lock_fd))
            if os.fstat(self._lock_fd).st_size != 0:
                raise ProductEnvelopeStoreError("record_invalid")
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ProductEnvelopeStoreError("store_locked") from None
            self._key_directory_fd = _open_private_directory(secret_path.parent)
            self._key_name = secret_path.name
            key = self._load_or_create_key(secret_path.name)
            self._key_digest = hashlib.sha256(key).digest()
            self._cipher = AESGCM(key)
            self._closed = False
            self._scan()
        except ProductEnvelopeStoreError:
            self.close()
            raise
        except OSError:
            self.close()
            raise ProductEnvelopeStoreError("read_failed") from None
        except Exception:
            self.close()
            raise ProductEnvelopeStoreError("store_failed") from None

    def __repr__(self) -> str:
        return f"ProductEnvelopeStore(closed={self._closed})"

    @property
    def namespace(self) -> ProductStoreNamespace:
        return self._identity

    def __enter__(self) -> ProductEnvelopeStore:
        self._assert_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        with self._mutex:
            self._closed = True
            self._cipher = None
            self._records.clear()
            for attribute in ("_key_directory_fd", "_lock_fd", "_directory_fd"):
                descriptor = getattr(self, attribute)
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    setattr(self, attribute, -1)

    def get(self, record_id: str) -> StoredEnvelope | None:
        _check_record_id(record_id)
        with self._mutex:
            self._scan()
            return self._records.get(record_id)

    def records(self) -> tuple[StoredEnvelope, ...]:
        with self._mutex:
            self._scan()
            return tuple(self._records[key] for key in sorted(self._records))

    def usage(self) -> StoreUsage:
        with self._mutex:
            self._scan()
            return self._usage()

    def create(
        self, record_id: str, payload: bytes, *, kind: RecordKind = "action"
    ) -> StoredEnvelope:
        _check_record_input(record_id, payload, kind)
        with self._mutex:
            self._scan()
            previous = self._records.get(record_id)
            if previous is not None:
                if previous.kind != kind or previous.payload != payload:
                    raise ProductEnvelopeStoreError("record_conflict")
                return previous
            return self._persist(record_id, kind, 1, payload, previous=None)

    def replace(
        self,
        record_id: str,
        payload: bytes,
        *,
        expected_revision: int,
        kind: RecordKind,
    ) -> StoredEnvelope:
        _check_record_input(record_id, payload, kind)
        if type(expected_revision) is not int or expected_revision < 1:
            raise ProductEnvelopeStoreError("record_conflict")
        with self._mutex:
            self._scan()
            previous = self._records.get(record_id)
            if previous is None:
                raise ProductEnvelopeStoreError("record_missing")
            if previous.revision != expected_revision:
                raise ProductEnvelopeStoreError("record_conflict")
            if previous.kind == kind and previous.payload == payload:
                return previous
            return self._persist(
                record_id, kind, previous.revision + 1, payload, previous=previous
            )

    def _assert_open(self) -> None:
        if self._closed:
            raise ProductEnvelopeStoreError("store_closed")
        if self._owner_pid != os.getpid():
            raise ProductEnvelopeStoreError("store_locked")

    def _usage(self) -> StoreUsage:
        return StoreUsage(
            record_count=len(self._records),
            stored_bytes=sum(record.stored_bytes for record in self._records.values()),
        )

    def _load_or_create_key(self, name: str) -> bytes:
        try:
            return _read_private_file(self._key_directory_fd, name, 32, key=True)
        except FileNotFoundError:
            with os.scandir(self._directory_fd) as entries:
                if any(entry.name != ".lock" for entry in entries):
                    raise ProductEnvelopeStoreError("key_missing") from None
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=self._key_directory_fd,
            )
            key = os.urandom(32)
            _write_all(descriptor, key)
            os.fsync(descriptor)
            os.fsync(self._key_directory_fd)
            return key
        except FileExistsError:
            # Another independent store may provision the shared key concurrently.
            return _read_private_file(self._key_directory_fd, name, 32, key=True)
        except OSError:
            raise ProductEnvelopeStoreError("write_failed") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _scan(self) -> None:
        self._assert_open()
        try:
            _check_private_directory(os.fstat(self._directory_fd))
            _check_private_directory(os.fstat(self._key_directory_fd))
            lock_metadata = os.fstat(self._lock_fd)
            _check_private_file(lock_metadata)
            named_lock = os.stat(
                ".lock", dir_fd=self._directory_fd, follow_symlinks=False
            )
            if (named_lock.st_dev, named_lock.st_ino) != (
                lock_metadata.st_dev,
                lock_metadata.st_ino,
            ):
                raise ProductEnvelopeStoreError("store_locked")
            key = _read_private_file(
                self._key_directory_fd, self._key_name, 32, key=True
            )
            if hashlib.sha256(key).digest() != self._key_digest:
                raise ProductEnvelopeStoreError("key_invalid")
            records: dict[str, StoredEnvelope] = {}
            total = 0
            with os.scandir(self._directory_fd) as entries:
                for entry in entries:
                    name = entry.name
                    if name == ".lock":
                        continue
                    if name.startswith(".tmp-"):
                        raise ProductEnvelopeStoreError("orphan_temporary")
                    if not _FILENAME.fullmatch(name):
                        raise ProductEnvelopeStoreError("record_invalid")
                    if len(records) >= self._max_records:
                        raise ProductEnvelopeStoreError("capacity_exceeded")
                    serialized = _read_private_file(
                        self._directory_fd, name, self._max_record_bytes
                    )
                    total += len(serialized)
                    if total > self._committed_byte_limit:
                        raise ProductEnvelopeStoreError("capacity_exceeded")
                    record = self._decode(name, serialized)
                    prior = self._records.get(record.record_id)
                    if record.record_id in records or (
                        prior is not None
                        and (
                            record.revision < prior.revision
                            or (record.revision == prior.revision and record != prior)
                        )
                    ):
                        raise ProductEnvelopeStoreError("record_conflict")
                    records[record.record_id] = record
            # A record disappearing while this process owns the store is never a
            # successful deletion. Across process lifetimes the server remains the ledger.
            if set(self._records) - set(records):
                raise ProductEnvelopeStoreError("record_missing")
            self._records = records
        except ProductEnvelopeStoreError:
            raise
        except OSError:
            raise ProductEnvelopeStoreError("read_failed") from None

    def _decode(self, filename: str, serialized: bytes) -> StoredEnvelope:
        try:
            value = json.loads(serialized)
            if (
                not isinstance(value, dict)
                or set(value) != _ENVELOPE_FIELDS
                or _canonical(value) != serialized
                or value["format"] != _FORMAT
                or value["algorithm"] != _ALGORITHM
                or value["kind"] not in _KINDS
                or type(value["revision"]) is not int
                or not 1 <= value["revision"] <= 2**53 - 1
            ):
                raise ProductEnvelopeStoreError("record_invalid")
            _check_record_id(value["record_id"])
            if _filename(value["record_id"]) != filename:
                raise ProductEnvelopeStoreError("record_invalid")
            if value["namespace"] != self._namespace:
                raise ProductEnvelopeStoreError("namespace_mismatch")
            nonce = base64.b64decode(value["nonce"], validate=True)
            ciphertext = base64.b64decode(value["ciphertext"], validate=True)
            if len(nonce) != 12 or len(ciphertext) < 16:
                raise ProductEnvelopeStoreError("record_invalid")
            header = {key: value[key] for key in _HEADER_FIELDS}
        except ProductEnvelopeStoreError:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise ProductEnvelopeStoreError("record_invalid") from None
        try:
            payload = self._cipher.decrypt(nonce, ciphertext, _canonical(header))
        except Exception:
            raise ProductEnvelopeStoreError("decryption_failed") from None
        return StoredEnvelope(
            record_id=value["record_id"],
            kind=value["kind"],
            revision=value["revision"],
            payload=payload,
            stored_bytes=len(serialized),
        )

    def _persist(
        self,
        record_id: str,
        kind: RecordKind,
        revision: int,
        payload: bytes,
        *,
        previous: StoredEnvelope | None,
    ) -> StoredEnvelope:
        if len(payload) > self._max_record_bytes or revision > 2**53 - 1:
            raise ProductEnvelopeStoreError("capacity_exceeded")
        header = {
            "format": _FORMAT,
            "algorithm": _ALGORITHM,
            "namespace": self._namespace,
            "record_id": record_id,
            "kind": kind,
            "revision": revision,
        }
        try:
            nonce = os.urandom(12)
            ciphertext = self._cipher.encrypt(nonce, payload, _canonical(header))
            serialized = _canonical(
                {
                    **header,
                    "nonce": base64.b64encode(nonce).decode("ascii"),
                    "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                }
            )
        except Exception:
            raise ProductEnvelopeStoreError("write_failed") from None
        usage = self._usage()
        if (
            len(serialized) > self._max_record_bytes
            or usage.record_count + (previous is None) > self._max_records
            or usage.stored_bytes
            - (previous.stored_bytes if previous else 0)
            + len(serialized)
            > self._committed_byte_limit
            or usage.stored_bytes + len(serialized) > self._max_total_bytes
        ):
            raise ProductEnvelopeStoreError("capacity_exceeded")
        self._atomic_write(_filename(record_id), serialized)
        record = StoredEnvelope(record_id, kind, revision, payload, len(serialized))
        self._records[record_id] = record
        return record

    def _atomic_write(self, target: str, serialized: bytes) -> None:
        temporary = f".tmp-{uuid.uuid4().hex}"
        descriptor = -1
        created = False
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=self._directory_fd,
            )
            created = True
            _write_all(descriptor, serialized)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary,
                target,
                src_dir_fd=self._directory_fd,
                dst_dir_fd=self._directory_fd,
            )
            os.fsync(self._directory_fd)
        except OSError:
            raise ProductEnvelopeStoreError("write_failed") from None
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    raise ProductEnvelopeStoreError("write_failed") from None
            if created:
                try:
                    os.unlink(temporary, dir_fd=self._directory_fd)
                    os.fsync(self._directory_fd)
                except OSError:
                    # Never remove the committed record, including uncertain fsync.
                    pass


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _absolute_path(value: str | Path) -> Path:
    try:
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
            raise ProductEnvelopeStoreError("invalid_configuration")
        return path
    except (TypeError, ValueError):
        raise ProductEnvelopeStoreError("invalid_configuration") from None


def _open_private_directory(path: Path) -> int:
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            created = False
            try:
                next_descriptor = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                created = True
                next_descriptor = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            if created:
                try:
                    os.fsync(descriptor)
                except OSError:
                    os.close(next_descriptor)
                    raise
            os.close(descriptor)
            descriptor = next_descriptor
        _check_private_directory(os.fstat(descriptor))
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _check_private_directory(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ProductEnvelopeStoreError("permission_denied")


def _check_private_file(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ProductEnvelopeStoreError("permission_denied")


def _read_private_file(
    directory_fd: int, name: str, limit: int, *, key: bool = False
) -> bytes:
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd
    )
    try:
        before = os.fstat(descriptor)
        _check_private_file(before)
        if before.st_size > limit or (key and before.st_size != 32):
            raise ProductEnvelopeStoreError(
                "key_invalid" if key else "capacity_exceeded"
            )
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        _check_private_file(after)
        value = b"".join(chunks)
        if (
            before.st_size != len(value)
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise ProductEnvelopeStoreError("read_failed")
        return value
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, value: bytes) -> None:
    remaining = memoryview(value)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("write failed")
        remaining = remaining[written:]


def _filename(record_id: str) -> str:
    return f"{hashlib.sha256(record_id.encode('ascii')).hexdigest()}.agq"


def _check_record_id(value: str) -> None:
    if not isinstance(value, str) or not _RECORD_ID.fullmatch(value):
        raise ProductEnvelopeStoreError("record_invalid")


def _check_record_input(record_id: str, payload: bytes, kind: str) -> None:
    _check_record_id(record_id)
    if type(payload) is not bytes or not isinstance(kind, str) or kind not in _KINDS:
        raise ProductEnvelopeStoreError("record_invalid")
