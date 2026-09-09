"""Verify a signed wheel against the actual, non-editable imported installation."""

from __future__ import annotations

import base64
import csv
import contextlib
import dataclasses
from dataclasses import dataclass, field
from email.parser import BytesParser
import hashlib
from importlib import metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import types
import weakref
from typing import Iterator
from zipfile import ZipFile

from .activation_ack import ProductActivationError

_PACKAGE = "agentguard_langgraph_adapter"
_DISTRIBUTION = "agentguard-langgraph-adapter"
_VERSION = "0.1.0rc1"
_MAX_WHEEL = 32 * 1024 * 1024
_MAX_INSTALLED = 64 * 1024 * 1024
_ISSUED: weakref.WeakKeyDictionary[InstalledProductArtifact, tuple[object, ...]] = (
    weakref.WeakKeyDictionary()
)


def _fail() -> ProductActivationError:
    return ProductActivationError("installed_artifact_invalid")


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read(path: Path, *, private: bool = False, limit: int = _MAX_WHEEL) -> bytes:
    """Traverse without following symlinks and reject changing/nonregular files."""
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise _fail()
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    descriptor = None
    ancestors: list[tuple[Path, tuple[int, ...]]] = []
    current = Path("/")
    try:
        for part in path.parts[1:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            os.close(directory)
            directory = child
            current = current / part
            ancestors.append((current, _fingerprint(os.fstat(child))))
        parent = os.fstat(directory)
        if private and (
            parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise _fail()
        descriptor = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or before.st_mode & 0o022
            or not 0 <= before.st_size <= limit
            or (private and stat.S_IMODE(before.st_mode) != 0o600)
        ):
            raise _fail()
        chunks: list[bytes] = []
        size = 0
        while data := os.read(descriptor, min(65536, limit + 1 - size)):
            size += len(data)
            if size > limit:
                raise _fail()
            chunks.append(data)
        if _fingerprint(before) != _fingerprint(os.fstat(descriptor)):
            raise _fail()
        if _fingerprint(before) != _fingerprint(
            os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        ):
            raise _fail()
        for ancestor, identity in ancestors:
            observed = os.stat(ancestor, follow_symlinks=False)
            if _fingerprint(observed)[:5] != identity[:5]:
                raise _fail()
        return b"".join(chunks)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def _record(data: bytes) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for row in csv.reader(io.StringIO(data.decode("utf-8"))):
        if len(row) != 3 or row[0] in result:
            raise _fail()
        name = row[0]
        if (
            PurePosixPath(name).is_absolute()
            or ".." in PurePosixPath(name).parts
            or "\\" in name
            or str(PurePosixPath(name)) != name
        ):
            raise _fail()
        result[name] = (row[1], row[2])
    return result


def _hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(
        hashlib.sha256(data).digest()
    ).decode().rstrip("=")


@dataclass(frozen=True, eq=False)
class InstalledProductArtifact:
    """Only a freshly verified digest is public; paths/RECORD remain private."""

    digest: str
    _wheel: Path = field(repr=False)
    _package_root: Path = field(repr=False)
    _files: tuple[tuple[Path, str], ...] = field(repr=False)
    _package_files: frozenset[str] = field(repr=False)

    def assert_current(self) -> None:
        try:
            if _ISSUED.get(self) != (
                self.digest,
                self._wheel,
                self._package_root,
                self._files,
                self._package_files,
            ):
                raise _fail()
            if metadata.version(_DISTRIBUTION) != _VERSION:
                raise _fail()
            if (
                "sha256:" + hashlib.sha256(_read(self._wheel, private=True)).hexdigest()
                != self.digest
            ):
                raise _fail()
            for path, digest in self._files:
                if hashlib.sha256(_read(path)).hexdigest() != digest:
                    raise _fail()
            _check_package(self._package_root, self._package_files)
        except Exception:
            raise ProductActivationError("installed_artifact_drift") from None


def _check_package(root: Path, expected: frozenset[str]) -> None:
    if sys.dont_write_bytecode is not True:
        raise _fail()
    actual: set[str] = set()
    for directory, subdirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        if any((base / name).is_symlink() for name in (*subdirs, *files)):
            raise _fail()
        for name in files:
            relative = (base / name).relative_to(root).as_posix()
            # Product candidates use --no-compile and PYTHONDONTWRITEBYTECODE=1.
            # Never accept an unverified cache that importlib could execute.
            if name.endswith((".pyc", ".pyo")):
                raise _fail()
            actual.add(relative)
    if actual != expected:
        raise _fail()
    for name, module in tuple(sys.modules.items()):
        if name == _PACKAGE or name.startswith(_PACKAGE + "."):
            origin = getattr(module, "__file__", None)
            if not isinstance(origin, str):
                raise _fail()
            path = Path(origin)
            if not path.is_absolute() or path.resolve() != path:
                raise _fail()
            relative = path.relative_to(root).as_posix()
            if relative not in expected:
                raise _fail()
            _verify_loaded_code(module, _read(path))


def _code_identity(code: types.CodeType) -> types.CodeType:
    # Relocation changes only co_filename; all executable instructions,
    # constants, nested code and line metadata must match candidate source.
    normalized = code.replace(
        co_filename="",
        co_consts=tuple(
            _code_identity(item) if isinstance(item, types.CodeType) else item
            for item in code.co_consts
        ),
    )
    return normalized


def _verify_loaded_code(module: types.ModuleType, source: bytes) -> None:
    expected: set[types.CodeType] = set()
    names: set[str] = set()

    def empty_context() -> Iterator[None]:
        yield None

    wrappers = {
        contextlib.contextmanager(empty_context).__code__,
        getattr(dataclasses, "_recursive_repr")(lambda: None).__code__,
    }

    def collect(code: types.CodeType) -> None:
        expected.add(_code_identity(code))
        names.add(getattr(code, "co_qualname", code.co_name))
        for child in code.co_consts:
            if isinstance(child, types.CodeType):
                collect(child)

    collect(compile(source, module.__file__ or "", "exec", dont_inherit=True))
    visited: set[int] = set()

    def verify(value: object, *, generated: bool = False) -> None:
        if id(value) in visited:
            return
        visited.add(id(value))
        if isinstance(value, (staticmethod, classmethod)):
            verify(value.__func__)
        elif isinstance(value, property):
            for method in (value.fget, value.fset, value.fdel):
                if method is not None:
                    verify(method)
        elif (
            isinstance(value, types.FunctionType)
            and value.__module__ == module.__name__
        ):
            code = value.__code__
            # Generated dataclass methods have no source counterpart and are
            # checked through their owning installed class and instance graph.
            if (
                generated
                and code.co_filename == "<string>"
                and code.co_name
                in {
                    "__init__",
                    "__repr__",
                    "__eq__",
                    "__hash__",
                    "__setattr__",
                    "__delattr__",
                }
                and value.__qualname__ not in names
            ):
                return
            if code in wrappers:
                wrapped = getattr(value, "__wrapped__", None)
                if not isinstance(wrapped, types.FunctionType):
                    raise _fail()
                verify(wrapped, generated=generated)
                return
            if _code_identity(code) not in expected:
                raise _fail()
            wrapped = getattr(value, "__wrapped__", None)
            if wrapped is not None:
                verify(wrapped)
        elif isinstance(value, type) and value.__module__ == module.__name__:
            for member in vars(value).values():
                verify(member, generated=dataclasses.is_dataclass(value))

    for value in vars(module).values():
        verify(value)


def verify_installed_product_artifact(
    wheel_path: str, *, expected_digest: str
) -> InstalledProductArtifact:
    """No version override, editable installation, or manifest-derived observation."""
    try:
        wheel = Path(wheel_path)
        data = _read(wheel, private=True)
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if digest != expected_digest:
            raise _fail()
        distribution = metadata.distribution(_DISTRIBUTION)
        if distribution.version != _VERSION:
            raise _fail()
        direct = distribution.read_text("direct_url.json")
        if direct and json.loads(direct).get("dir_info", {}).get("editable"):
            raise _fail()
        files: dict[str, bytes] = {}
        with ZipFile(io.BytesIO(data)) as archive:
            total = 0
            for item in archive.infolist():
                name = item.filename
                total += item.file_size
                if (
                    name in files
                    or item.is_dir()
                    or total > _MAX_INSTALLED
                    or item.file_size > 8 * 1024 * 1024
                    or item.flag_bits & 1
                    or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG)
                    or "\\" in name
                    or PurePosixPath(name).is_absolute()
                    or ".." in PurePosixPath(name).parts
                    or str(PurePosixPath(name)) != name
                ):
                    raise _fail()
                files[name] = archive.read(item)
        dist_info = f"{_PACKAGE}-{_VERSION}.dist-info"
        if any(
            not name.startswith((_PACKAGE + "/", dist_info + "/")) for name in files
        ):
            raise _fail()
        meta = BytesParser().parsebytes(files[dist_info + "/METADATA"])
        if meta["Name"] != _DISTRIBUTION or meta["Version"] != _VERSION:
            raise _fail()
        record_name = dist_info + "/RECORD"
        record = _record(files[record_name])
        if set(record) != set(files) or record[record_name] != ("", ""):
            raise _fail()
        installed_record_path = Path(
            os.path.abspath(str(distribution.locate_file(record_name)))
        )
        installed_record = _record(_read(installed_record_path))
        verified: list[tuple[Path, str]] = []
        for name, body in files.items():
            if name == record_name:
                continue  # Installers append their own RECORD entries.
            if (
                record[name] != (_hash(body), str(len(body)))
                or installed_record.get(name) != record[name]
            ):
                raise _fail()
            location = Path(os.path.abspath(str(distribution.locate_file(name))))
            if _read(location) != body:
                raise _fail()
            verified.append((location, hashlib.sha256(body).hexdigest()))
        verified.append(
            (
                installed_record_path,
                hashlib.sha256(_read(installed_record_path)).hexdigest(),
            )
        )
        root = Path(os.path.abspath(str(distribution.locate_file(_PACKAGE))))
        expected = frozenset(
            name[len(_PACKAGE) + 1 :]
            for name in files
            if name.startswith(_PACKAGE + "/")
        )
        _check_package(root, expected)
        result = InstalledProductArtifact(
            digest, wheel, root, tuple(verified), expected
        )
        _ISSUED[result] = (
            result.digest,
            result._wheel,
            result._package_root,
            result._files,
            result._package_files,
        )
        result.assert_current()
        return result
    except Exception:
        raise _fail() from None
