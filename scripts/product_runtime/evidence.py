"""Bounded, immutable evidence reads without following filesystem links."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping

from agentguard_core.actions.canonical_json import canonical_sha256

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024


class EvidenceError(ValueError):
    """A stable error code, without evidence contents or credentials."""


@dataclass(frozen=True)
class VerifiedFile:
    path: Path
    relative_path: str
    size: int
    raw_sha256: str
    content: bytes = field(repr=False)

    def reference(self) -> dict[str, Any]:
        return {
            "path": self.relative_path,
            "size": self.size,
            "raw_sha256": self.raw_sha256,
        }


@dataclass(frozen=True)
class VerifiedDocument:
    file: VerifiedFile
    data: Any = field(repr=False)
    canonical_digest: str


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def object_fields(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise EvidenceError(code)
    return value


def reference(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) and callable(getattr(value, "model_dump", None)):
        value = value.model_dump(mode="json")
    value = dict(value) if isinstance(value, Mapping) else value
    object_fields(value, {"path", "size", "raw_sha256"}, "evidence_reference_invalid")
    relative_path(value["path"])
    if (
        type(value["size"]) is not int
        or value["size"] < 0
        or type(value["raw_sha256"]) is not str
        or not _DIGEST.fullmatch(value["raw_sha256"])
    ):
        raise EvidenceError("evidence_reference_invalid")
    return value


def relative_path(value: Any) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > 4096
        or "\\" in value
        or "\0" in value
        or value.startswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or PurePosixPath(value).as_posix() != value
    ):
        raise EvidenceError("evidence_path_invalid")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("evidence_json_duplicate_key")
        result[key] = value
    return result


def strict_json(content: bytes) -> Any:
    def nonfinite(_value: str) -> Any:
        raise EvidenceError("evidence_json_nonfinite")

    try:
        parsed = json.loads(
            content.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=nonfinite
        )
        pending = [(parsed, 0)]
        count = 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if depth > 64 or count > 250_000:
                raise EvidenceError("evidence_json_limit")
            if type(value) is dict:
                pending.extend((item, depth + 1) for item in value.values())
            elif type(value) is list:
                pending.extend((item, depth + 1) for item in value)
        canonical_sha256(parsed)  # Reject non-finite numbers and invalid Unicode.
        return parsed
    except EvidenceError:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError, TypeError):
        raise EvidenceError("evidence_json_invalid") from None


def _identity(value: os.stat_result, *, directory: bool = False) -> tuple[int, ...]:
    base = (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)
    return (
        base
        if directory
        else base
        + (
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
    )


class EvidenceStore:
    """Pin each directory/file identity; shared identical refs are read once.

    Every read and final recheck opens all path components with O_NOFOLLOW.
    Directory entry creation is allowed, while parent replacement is rejected.
    """

    def __init__(self, root: str | Path, *, max_total_bytes: int = MAX_TOTAL_BYTES):
        supplied = os.fspath(root)
        if not os.path.isabs(supplied) or os.path.normpath(supplied) != supplied:
            raise EvidenceError("evidence_root_invalid")
        self.root = Path(supplied)
        self.max_total_bytes = max_total_bytes
        self._total_bytes = 0
        self._trees: dict[tuple[str, frozenset[str]], frozenset[str]] = {}
        self._listings: dict[str, frozenset[str]] = {}
        self._directories: dict[str, tuple[int, ...]] = {}
        self._files: dict[
            str, tuple[dict[str, Any], tuple[int, ...], VerifiedFile]
        ] = {}
        descriptor = self._open_directory(self.root)
        os.close(descriptor)

    def _open_directory(self, path: Path) -> int:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        current = Path("/")
        try:
            for part in path.parts[1:]:
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
                current /= part
                identity = _identity(os.fstat(descriptor), directory=True)
                previous = self._directories.setdefault(str(current), identity)
                if previous != identity:
                    raise EvidenceError("evidence_directory_changed")
            return descriptor
        except EvidenceError:
            os.close(descriptor)
            raise
        except OSError:
            os.close(descriptor)
            raise EvidenceError("evidence_directory_unavailable") from None

    def relative(self, path: str | Path) -> str:
        """Convert an explicitly supplied installation path, without resolving links."""
        try:
            candidate = Path(path)
            if not candidate.is_absolute() or str(candidate) != os.fspath(path):
                raise ValueError
            return relative_path(candidate.relative_to(self.root).as_posix())
        except (ValueError, TypeError):
            raise EvidenceError("evidence_path_outside_root") from None

    def _read(self, name: str, max_bytes: int) -> tuple[bytes, tuple[int, ...]]:
        name = relative_path(name)
        parent = self.root / PurePosixPath(name).parent
        directory = self._open_directory(parent)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                PurePosixPath(name).name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory,
            )
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise EvidenceError("evidence_file_not_regular")
            if before.st_size > max_bytes:
                raise EvidenceError("evidence_file_limit")
            chunks = bytearray()
            while True:
                chunk = os.read(
                    descriptor, min(1024 * 1024, max_bytes + 1 - len(chunks))
                )
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > max_bytes:
                    raise EvidenceError("evidence_file_limit")
            after = os.fstat(descriptor)
            visible = os.stat(
                PurePosixPath(name).name, dir_fd=directory, follow_symlinks=False
            )
            identity = _identity(before)
            if (
                identity != _identity(after)
                or identity != _identity(visible)
                or len(chunks) != before.st_size
            ):
                raise EvidenceError("evidence_file_changed")
            # Detect replacement of a parent while its old directory fd was open.
            checked = self._open_directory(parent)
            os.close(checked)
            return bytes(chunks), identity
        except EvidenceError:
            raise
        except OSError:
            raise EvidenceError("evidence_file_unavailable") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)

    def capture(self, name: str, *, max_bytes: int = MAX_FILE_BYTES) -> VerifiedFile:
        """Read actual evidence to construct a reference; never trust a supplied hash."""
        content, identity = self._read(name, max_bytes)
        value = VerifiedFile(
            self.root / name, name, len(content), sha256(content), content
        )
        expected = value.reference()
        previous = self._files.get(name)
        if previous is not None:
            if previous[0] != expected or previous[1] != identity:
                raise EvidenceError("evidence_file_changed")
            return previous[2]
        if self._total_bytes + value.size > self.max_total_bytes:
            raise EvidenceError("evidence_total_limit")
        self._total_bytes += value.size
        self._files[name] = (expected, identity, value)
        return value

    def tree(
        self, name: str, *, skip_root: frozenset[str] = frozenset()
    ) -> dict[str, VerifiedFile]:
        """Inventory actual package files, including unreported additions."""
        base = relative_path(name)
        pending = [base]
        result: dict[str, VerifiedFile] = {}
        count = 0
        while pending:
            current = pending.pop()
            descriptor = self._open_directory(self.root / current)
            try:
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        count += 1
                        if count > 20_000:
                            raise EvidenceError("evidence_tree_limit")
                        if current == base and entry.name in skip_root:
                            continue
                        path = current + "/" + entry.name
                        mode = entry.stat(follow_symlinks=False).st_mode
                        if stat.S_ISDIR(mode):
                            pending.append(path)
                        elif stat.S_ISREG(mode):
                            file = self.capture(path, max_bytes=32 * 1024 * 1024)
                            result[
                                file.path.relative_to(self.root / base).as_posix()
                            ] = file
                        else:
                            raise EvidenceError("evidence_file_not_regular")
            except OSError:
                raise EvidenceError("evidence_directory_unavailable") from None
            finally:
                os.close(descriptor)
        paths = frozenset(result)
        if self._trees.setdefault((base, skip_root), paths) != paths:
            raise EvidenceError("evidence_tree_changed")
        return result

    def require_protected(self, file: VerifiedFile) -> None:
        """Check the permissions captured with these exact file bytes."""
        observed = self._files.get(file.relative_path)
        if observed is None or observed[2] is not file or observed[1][2] & 0o022:
            raise EvidenceError("evidence_installed_file_writable")

    def directory_names(self, name: str) -> frozenset[str]:
        """Pin bounded directory membership without following any child entries."""
        name = relative_path(name)
        descriptor = self._open_directory(self.root / name)
        try:
            names = set()
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    names.add(entry.name)
                    if len(names) > 20_000:
                        raise EvidenceError("evidence_tree_limit")
            result = frozenset(names)
            if self._listings.setdefault(name, result) != result:
                raise EvidenceError("evidence_tree_changed")
            return result
        finally:
            os.close(descriptor)

    def require_protected_tree(self, name: str | None = None) -> None:
        base = self.root if name is None else self.root / relative_path(name)
        for path, identity in self._directories.items():
            if Path(path).is_relative_to(base) and identity[2] & 0o022:
                raise EvidenceError("evidence_installed_directory_writable")

    def read_file(self, ref: Any, *, max_bytes: int = MAX_FILE_BYTES) -> VerifiedFile:
        expected = reference(ref)
        if expected["size"] > max_bytes:
            raise EvidenceError("evidence_file_limit")
        previous = self._files.get(expected["path"])
        if previous is not None and previous[0] != expected:
            raise EvidenceError("evidence_reference_conflict")
        actual = self.capture(expected["path"], max_bytes=max_bytes)
        if actual.reference() != expected:
            raise EvidenceError("evidence_digest_mismatch")
        return actual

    def read_json(self, ref: Any) -> VerifiedDocument:
        file = self.read_file(ref, max_bytes=MAX_JSON_BYTES)
        data = strict_json(file.content)
        return VerifiedDocument(file, data, canonical_sha256(data))

    def recheck_reads(self) -> None:
        for name, (expected, identity, _value) in tuple(self._files.items()):
            content, current = self._read(name, expected["size"])
            if current != identity or sha256(content) != expected["raw_sha256"]:
                raise EvidenceError("evidence_file_changed")
        for (name, skip), _paths in tuple(self._trees.items()):
            self.tree(name, skip_root=skip)
        for name in tuple(self._listings):
            self.directory_names(name)
