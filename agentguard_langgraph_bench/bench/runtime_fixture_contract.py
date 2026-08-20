"""Frozen runtime-input identity for the LangGraph competition runner.

The 70-case dataset manifest identifies task records.  A live case also consumes
materialized sandbox files and repository-backed browser/MCP/RAG resources.  This
module gives those inputs one path-independent, binary-safe identity without
including runtime outputs such as receipts or Outbox records.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .config import BENCH_ROOT
from .environment import is_volatile_sandbox_path


RUNTIME_FIXTURE_SCHEMA_VERSION = "competition-runtime-fixtures/1.0"
RUNTIME_FIXTURE_RUN_SCHEMA_VERSION = "competition-runtime-fixture-run/1.0"
RUNTIME_FIXTURE_CONTRACT_NAME = "runtime_fixture_bundle"
RUNTIME_FIXTURE_ROOT_IDS = (
    "environment_manifest",
    "instrumentation",
    "materialized_sandbox",
    "mcpsafety",
    "poisonedrag",
    "shared_sandbox_files",
    "shared_sandbox_mcp",
)


class RuntimeFixtureContractError(ValueError):
    """A runtime fixture bundle is unreadable, unsafe, or not frozen."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class RuntimeFixtureEntry:
    root_id: str
    relative_path: str
    size: int
    sha256: str

    def digest_projection(self) -> dict[str, Any]:
        return {
            "root_id": self.root_id,
            "relative_path": self.relative_path,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class RuntimeFixtureRootSummary:
    root_id: str
    file_count: int
    byte_count: int
    root_digest: str

    def public_dump(self) -> dict[str, Any]:
        return {
            "root_id": self.root_id,
            "file_count": self.file_count,
            "byte_count": self.byte_count,
            "root_digest": self.root_digest,
        }


@dataclass(frozen=True, slots=True)
class RuntimeFixtureSnapshot:
    bundle_digest: str
    file_count: int
    byte_count: int
    roots: tuple[RuntimeFixtureRootSummary, ...]
    entries: tuple[RuntimeFixtureEntry, ...]

    def public_dump(self) -> dict[str, Any]:
        """Return a display-safe projection with no host paths or file names."""

        return {
            "schema_version": RUNTIME_FIXTURE_SCHEMA_VERSION,
            "bundle_digest": self.bundle_digest,
            "file_count": self.file_count,
            "byte_count": self.byte_count,
            "roots": [root.public_dump() for root in self.roots],
        }


@dataclass(frozen=True, slots=True)
class _SourceRoot:
    root_id: str
    path: Path
    sandbox_prefix: str | None = None


def default_runtime_fixture_sources(
    *, bench_root: Path = BENCH_ROOT
) -> tuple[_SourceRoot, ...]:
    """Return repository-backed inputs that can be consumed outside scratch."""

    return (
        _SourceRoot(
            "environment_manifest",
            bench_root / "datasets/environment_manifest.json",
        ),
        _SourceRoot("instrumentation", bench_root / "datasets/instrumentation"),
        _SourceRoot("mcpsafety", bench_root / "datasets/mcpsafety"),
        _SourceRoot("poisonedrag", bench_root / "datasets/poisonedrag"),
        _SourceRoot(
            "shared_sandbox_files",
            bench_root / "sandbox/files",
            sandbox_prefix="files",
        ),
        _SourceRoot(
            "shared_sandbox_mcp",
            bench_root / "sandbox/mcp",
            sandbox_prefix="mcp",
        ),
    )


def build_runtime_fixture_snapshot(
    sandbox_dir: Path,
    *,
    source_roots: Mapping[str, Path] | None = None,
) -> RuntimeFixtureSnapshot:
    """Hash one already-materialized, pristine competition fixture bundle.

    ``source_roots`` is a test seam.  Production callers omit it and receive the
    frozen repository roots above.
    """

    sandbox = sandbox_dir.resolve()
    _require_empty_outbox(sandbox / "outbox")
    sources: Sequence[_SourceRoot]
    if source_roots is None:
        sources = default_runtime_fixture_sources()
    else:
        sources = tuple(
            _SourceRoot(str(root_id), Path(path))
            for root_id, path in sorted(source_roots.items())
        )

    materialized_entries = list(
        _collect_root(
            _SourceRoot(
                "materialized_sandbox",
                sandbox,
                sandbox_prefix="",
            )
        )
    )
    entries = list(materialized_entries)
    materialized_paths = {
        item.relative_path for item in materialized_entries
    }
    for source in sources:
        source_entries = _collect_root(source)
        if source.sandbox_prefix is not None:
            # The live resolver prefers the arm-local materialized sandbox.
            # Hash only shared fallback files that are not already shadowed by
            # that canonical snapshot; ignored/generated copies in the
            # repository must not make an otherwise identical run drift.
            source_entries = [
                item
                for item in source_entries
                if "/".join((source.sandbox_prefix, item.relative_path))
                not in materialized_paths
            ]
        entries.extend(source_entries)
    entries.sort(key=lambda item: (item.root_id, item.relative_path))

    roots: list[RuntimeFixtureRootSummary] = []
    root_ids = sorted(
        {item.root_id for item in entries}
        | {source.root_id for source in sources}
        | {"materialized_sandbox"}
    )
    for root_id in root_ids:
        selected = [item for item in entries if item.root_id == root_id]
        roots.append(
            RuntimeFixtureRootSummary(
                root_id=root_id,
                file_count=len(selected),
                byte_count=sum(item.size for item in selected),
                root_digest=_canonical_sha256(
                    {
                        "root_id": root_id,
                        "files": [item.digest_projection() for item in selected],
                    }
                ),
            )
        )

    projection = {
        "schema_version": RUNTIME_FIXTURE_SCHEMA_VERSION,
        "files": [item.digest_projection() for item in entries],
    }
    return RuntimeFixtureSnapshot(
        bundle_digest=_canonical_sha256(projection),
        file_count=len(entries),
        byte_count=sum(item.size for item in entries),
        roots=tuple(roots),
        entries=tuple(entries),
    )


def validate_runtime_fixture_bundle(
    sandbox_dir: Path,
    *,
    expected_digest: str,
    source_roots: Mapping[str, Path] | None = None,
) -> RuntimeFixtureSnapshot:
    snapshot = build_runtime_fixture_snapshot(
        sandbox_dir,
        source_roots=source_roots,
    )
    if snapshot.bundle_digest != expected_digest:
        raise RuntimeFixtureContractError(
            "runtime_fixture_identity_mismatch",
            "runtime fixture bundle does not match the packaged competition profile",
        )
    return snapshot


def _collect_root(source: _SourceRoot) -> list[RuntimeFixtureEntry]:
    path = source.path
    try:
        root_stat = path.lstat()
    except OSError as exc:
        raise RuntimeFixtureContractError(
            "runtime_fixture_unreadable",
            f"runtime fixture root is unavailable: {source.root_id}",
        ) from exc
    if stat.S_ISLNK(root_stat.st_mode):
        raise RuntimeFixtureContractError(
            "runtime_fixture_unsafe_file",
            f"runtime fixture root is a symbolic link: {source.root_id}",
        )
    if stat.S_ISREG(root_stat.st_mode):
        return [_entry_for_file(source.root_id, path.name, path, root_stat.st_size)]
    if not stat.S_ISDIR(root_stat.st_mode):
        raise RuntimeFixtureContractError(
            "runtime_fixture_unsafe_file",
            f"runtime fixture root is not a regular file or directory: {source.root_id}",
        )

    entries: list[RuntimeFixtureEntry] = []
    for relative_path, file_path, size in _walk_regular_files(path):
        sandbox_relative = (
            relative_path
            if source.sandbox_prefix is None
            else "/".join(
                item for item in (source.sandbox_prefix, relative_path) if item
            )
        )
        if source.sandbox_prefix is not None and is_volatile_sandbox_path(
            sandbox_relative
        ):
            continue
        entries.append(_entry_for_file(source.root_id, relative_path, file_path, size))
    return entries


def _walk_regular_files(root: Path) -> list[tuple[str, Path, int]]:
    rows: list[tuple[str, Path, int]] = []

    def walk(directory: Path) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise RuntimeFixtureContractError(
                "runtime_fixture_unreadable",
                "runtime fixture directory cannot be read",
            ) from exc
        for child in children:
            child_path = Path(child.path)
            try:
                child_stat = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimeFixtureContractError(
                    "runtime_fixture_unreadable",
                    "runtime fixture entry cannot be inspected",
                ) from exc
            if stat.S_ISLNK(child_stat.st_mode):
                raise RuntimeFixtureContractError(
                    "runtime_fixture_unsafe_file",
                    "runtime fixture bundle contains a symbolic link",
                )
            if stat.S_ISDIR(child_stat.st_mode):
                walk(child_path)
                continue
            if not stat.S_ISREG(child_stat.st_mode):
                raise RuntimeFixtureContractError(
                    "runtime_fixture_unsafe_file",
                    "runtime fixture bundle contains a non-regular file",
                )
            rows.append(
                (
                    child_path.relative_to(root).as_posix(),
                    child_path,
                    child_stat.st_size,
                )
            )

    walk(root)
    return rows


def _entry_for_file(
    root_id: str,
    relative_path: str,
    path: Path,
    expected_size: int,
) -> RuntimeFixtureEntry:
    digest = hashlib.sha256()
    observed_size = 0
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                observed_size += len(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise RuntimeFixtureContractError(
            "runtime_fixture_unreadable",
            "runtime fixture file cannot be read",
        ) from exc
    if observed_size != expected_size:
        raise RuntimeFixtureContractError(
            "runtime_fixture_changed_during_read",
            "runtime fixture file changed while its identity was computed",
        )
    return RuntimeFixtureEntry(
        root_id=root_id,
        relative_path=relative_path,
        size=observed_size,
        sha256=f"sha256:{digest.hexdigest()}",
    )


def _require_empty_outbox(outbox: Path) -> None:
    try:
        outbox_stat = outbox.lstat()
    except OSError as exc:
        raise RuntimeFixtureContractError(
            "runtime_fixture_outbox_invalid",
            "competition Outbox is unavailable before execution",
        ) from exc
    if stat.S_ISLNK(outbox_stat.st_mode) or not stat.S_ISDIR(outbox_stat.st_mode):
        raise RuntimeFixtureContractError(
            "runtime_fixture_outbox_invalid",
            "competition Outbox is not a real directory",
        )
    try:
        has_entries = next(os.scandir(outbox), None) is not None
    except OSError as exc:
        raise RuntimeFixtureContractError(
            "runtime_fixture_outbox_invalid",
            "competition Outbox cannot be inspected",
        ) from exc
    if has_entries:
        raise RuntimeFixtureContractError(
            "runtime_fixture_outbox_not_empty",
            "competition Outbox must be empty before execution",
        )


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"
