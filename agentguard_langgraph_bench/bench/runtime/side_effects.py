"""Filesystem side-effect helpers shared by sandbox tool runtimes."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def snapshot_tree(root: Path) -> dict[str, tuple[int, int]]:
    snapshot: dict[str, tuple[int, int]] = {}
    if not root.exists():
        return snapshot
    for file_path in root.rglob("*"):
        if file_path.is_file():
            stat = file_path.stat()
            snapshot[str(file_path.resolve())] = (stat.st_size, stat.st_mtime_ns)
    return snapshot


def diff_snapshot(root: Path, before: dict[str, tuple[int, int]]) -> list[dict[str, Any]]:
    effects: list[dict[str, Any]] = []
    after = snapshot_tree(root)
    for path in sorted(set(before) | set(after)):
        old_size, old_mtime = before.get(path, (0, 0))
        new_size, new_mtime = after.get(path, (0, 0))
        if new_size == old_size and new_mtime == old_mtime:
            continue
        effects.append({"path": path, "bytes_delta": new_size - old_size})
    return effects
