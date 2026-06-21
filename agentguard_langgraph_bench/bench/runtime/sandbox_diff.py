"""Per-case sandbox snapshot and diff helpers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class SandboxFile:
    relative_path: str
    absolute_path: str
    size: int
    sha256: str
    mtime_ns: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "path": self.relative_path,
            "absolute_path": self.absolute_path,
            "size": self.size,
            "sha256": self.sha256,
            "mtime_ns": self.mtime_ns,
        }


def snapshot_sandbox(root: Path) -> dict[str, SandboxFile]:
    root = root.expanduser().resolve()
    snapshot: dict[str, SandboxFile] = {}
    if not root.exists():
        return snapshot
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        resolved = path.resolve()
        relative = resolved.relative_to(root).as_posix()
        stat = resolved.stat()
        snapshot[relative] = SandboxFile(
            relative_path=relative,
            absolute_path=str(resolved),
            size=stat.st_size,
            sha256=_sha256(resolved),
            mtime_ns=stat.st_mtime_ns,
        )
    return snapshot


def diff_snapshots(before: dict[str, SandboxFile], after: dict[str, SandboxFile], *, root: Path) -> dict[str, Any]:
    added = [after[path].as_dict() for path in sorted(set(after) - set(before))]
    deleted = [before[path].as_dict() for path in sorted(set(before) - set(after))]
    modified = [
        {
            "relative_path": path,
            "path": path,
            "before": before[path].as_dict(),
            "after": after[path].as_dict(),
            "size": after[path].size,
            "sha256": after[path].sha256,
        }
        for path in sorted(set(before) & set(after))
        if before[path].sha256 != after[path].sha256 or before[path].size != after[path].size
    ]
    outside_paths = [
        item["absolute_path"]
        for group in (added, deleted)
        for item in group
        if not _is_under(Path(item["absolute_path"]), root)
    ]
    outside_paths.extend(
        item["after"]["absolute_path"]
        for item in modified
        if not _is_under(Path(item["after"]["absolute_path"]), root)
    )
    return {
        "schema_version": "1.0",
        "root": str(root.expanduser().resolve()),
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "outside_sandbox_paths": sorted(set(outside_paths)),
        "empty": not added and not modified and not deleted and not outside_paths,
    }


def diff_sandbox(root: Path, before: dict[str, SandboxFile]) -> dict[str, Any]:
    return diff_snapshots(before, snapshot_sandbox(root), root=root)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(root.expanduser().resolve())
        return True
    except ValueError:
        return False
