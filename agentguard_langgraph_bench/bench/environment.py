"""Archive and reset the benchmark sandbox evaluation state."""

from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .config import DEFAULT_RESULTS_DIR, DEFAULT_SANDBOX_DIR, ensure_sandbox


VOLATILE_DIR_PREFIXES = (
    "api/downloads",
    "browser/replay_artifacts",
    "browser/screenshots",
    "downloads",
    "files/home",
    "files/reports",
    "mcp/github/repositories",
)
VOLATILE_FILE_GLOBS = (
    "api/*.jsonl",
    "browser/*.jsonl",
    "mcp/*.jsonl",
    "memory/*.jsonl",
    "outbox/*.jsonl",
    "rag/*.jsonl",
)
VOLATILE_FILES = {
    "api/lead_security_controls.json",
}
PERSISTENT_FIXTURE_FILES = {
    "files/reports/misinformation_post.txt",
    "files/reports/README.md",
    "files/reports/redaction_policy.md",
    "files/reports/allowed_report_template.md",
    "files/reports/monthly_controls_summary.md",
    "files/reports/redacted_dlp_drill_example.md",
}


@dataclass(slots=True)
class SandboxSnapshot:
    files: dict[str, bytes]
    dirs: set[str]


@dataclass(slots=True)
class SandboxResetReport:
    sandbox_dir: str
    restored_files: int
    removed_files: int
    removed_dirs: int

    def as_dict(self) -> dict[str, int | str]:
        return {
            "sandbox_dir": self.sandbox_dir,
            "restored_files": self.restored_files,
            "removed_files": self.removed_files,
            "removed_dirs": self.removed_dirs,
        }


@dataclass(slots=True)
class SandboxArchiveReport:
    sandbox_dir: str
    artifact_dir: str
    manifest_path: str
    added_files: int
    modified_files: int
    deleted_fixture_files: int
    copied_files: int

    def as_dict(self) -> dict[str, int | str]:
        return {
            "sandbox_dir": self.sandbox_dir,
            "artifact_dir": self.artifact_dir,
            "manifest_path": self.manifest_path,
            "added_files": self.added_files,
            "modified_files": self.modified_files,
            "deleted_fixture_files": self.deleted_fixture_files,
            "copied_files": self.copied_files,
        }


def archive_sandbox_effects(
    sandbox_dir: Path = DEFAULT_SANDBOX_DIR,
    results_dir: Path = DEFAULT_RESULTS_DIR,
    *,
    run_id: str | None = None,
) -> SandboxArchiveReport:
    """Copy sandbox changes into results before the live sandbox is reset."""

    sandbox = sandbox_dir.resolve()
    results = results_dir.resolve()
    _assert_safe_sandbox_target(sandbox)
    _assert_results_outside_sandbox(sandbox, results)
    sandbox.mkdir(parents=True, exist_ok=True)

    snapshot = build_initial_sandbox_snapshot()
    run_stamp = _safe_run_id(run_id or _utc_stamp())
    artifact_dir = (results / "sandbox_artifacts" / f"sandbox_{run_stamp}").resolve()
    artifact_sandbox = artifact_dir / "sandbox"
    manifest_path = artifact_dir / "manifest.json"

    current_files = {relative: sandbox / relative for relative in _current_relative_files(sandbox)}
    added: list[str] = []
    modified: list[str] = []
    copied_entries: list[dict[str, int | str]] = []

    for relative, path in sorted(current_files.items()):
        if PurePosixPath(relative).name == ".gitkeep":
            continue
        category: str | None = None
        if relative not in snapshot.files:
            category = "added"
            added.append(relative)
        elif _file_content_changed(path, snapshot.files[relative]):
            category = "modified"
            modified.append(relative)
        if category is None:
            continue
        destination = artifact_sandbox / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination, follow_symlinks=False)
        copied_entries.append(
            {
                "path": relative,
                "category": category,
                "size_bytes": path.lstat().st_size,
            }
        )

    deleted = sorted(relative for relative in snapshot.files if relative not in current_files)
    manifest = {
        "schema_version": "0.1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_stamp,
        "sandbox_dir": str(sandbox),
        "artifact_dir": str(artifact_dir),
        "copied_files": copied_entries,
        "deleted_fixture_files": deleted,
    }
    artifact_dir.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

    return SandboxArchiveReport(
        sandbox_dir=str(sandbox),
        artifact_dir=str(artifact_dir),
        manifest_path=str(manifest_path),
        added_files=len(added),
        modified_files=len(modified),
        deleted_fixture_files=len(deleted),
        copied_files=len(copied_entries),
    )


def restore_initial_sandbox(sandbox_dir: Path = DEFAULT_SANDBOX_DIR) -> SandboxResetReport:
    """Rebuild the sandbox from the reproducible initial fixture snapshot."""

    sandbox = sandbox_dir.resolve()
    _assert_safe_sandbox_target(sandbox)
    snapshot = build_initial_sandbox_snapshot()
    sandbox.mkdir(parents=True, exist_ok=True)
    _preserve_marker_files(sandbox, snapshot)

    removed_files = 0
    for path in sorted(_iter_files(sandbox), key=lambda item: len(item.parts), reverse=True):
        relative = _relative_posix(path, sandbox)
        if relative not in snapshot.files:
            path.unlink()
            removed_files += 1

    restored_files = 0
    for relative, content in snapshot.files.items():
        target = sandbox / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or target.read_bytes() != content:
            target.write_bytes(content)
            restored_files += 1

    removed_dirs = 0
    for path in sorted(_iter_dirs(sandbox), key=lambda item: len(item.parts), reverse=True):
        relative = _relative_posix(path, sandbox)
        if relative in snapshot.dirs:
            continue
        try:
            path.rmdir()
            removed_dirs += 1
        except OSError:
            continue

    for relative in sorted(snapshot.dirs):
        (sandbox / relative).mkdir(parents=True, exist_ok=True)
    ensure_sandbox(sandbox)

    return SandboxResetReport(
        sandbox_dir=str(sandbox),
        restored_files=restored_files,
        removed_files=removed_files,
        removed_dirs=removed_dirs,
    )


def build_initial_sandbox_snapshot() -> SandboxSnapshot:
    """Create the canonical initial sandbox state without using the live sandbox."""

    with tempfile.TemporaryDirectory(prefix="agentguard-bench-sandbox-") as temp_dir:
        sandbox = Path(temp_dir) / "sandbox"
        ensure_sandbox(sandbox)
        return _snapshot_sandbox(sandbox)


def is_volatile_sandbox_path(relative_path: str | PurePosixPath) -> bool:
    rel = PurePosixPath(relative_path)
    if rel.name == ".gitkeep":
        return False
    rel_text = rel.as_posix()
    if rel_text in PERSISTENT_FIXTURE_FILES:
        return False
    if rel_text in VOLATILE_FILES:
        return True
    if any(rel_text == prefix or rel_text.startswith(prefix + "/") for prefix in VOLATILE_DIR_PREFIXES):
        return True
    return any(rel.match(pattern) for pattern in VOLATILE_FILE_GLOBS)


def _snapshot_sandbox(sandbox: Path) -> SandboxSnapshot:
    files: dict[str, bytes] = {}
    dirs: set[str] = set()
    if not sandbox.exists():
        return SandboxSnapshot(files=files, dirs=dirs)
    for path in _iter_dirs(sandbox):
        relative = _relative_posix(path, sandbox)
        if not is_volatile_sandbox_path(relative):
            dirs.add(relative)
    for path in _iter_files(sandbox):
        relative = _relative_posix(path, sandbox)
        if not is_volatile_sandbox_path(relative):
            files[relative] = path.read_bytes()
            dirs.add(PurePosixPath(relative).parent.as_posix())
    dirs.discard(".")
    return SandboxSnapshot(files=files, dirs=dirs)


def _preserve_marker_files(sandbox: Path, snapshot: SandboxSnapshot) -> None:
    if not sandbox.exists():
        return
    for path in sandbox.rglob(".gitkeep"):
        if not path.is_file():
            continue
        relative = _relative_posix(path, sandbox)
        snapshot.files[relative] = path.read_bytes()
        parent = PurePosixPath(relative).parent.as_posix()
        if parent != ".":
            snapshot.dirs.add(parent)


def _assert_safe_sandbox_target(sandbox: Path) -> None:
    if sandbox == Path("/"):
        raise ValueError("refusing to reset filesystem root")
    if sandbox == sandbox.parent:
        raise ValueError(f"refusing to reset invalid sandbox path: {sandbox}")
    default = DEFAULT_SANDBOX_DIR.resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    allowed = sandbox == default or default in sandbox.parents or temp_root in sandbox.parents
    if not allowed and sandbox.name != "sandbox":
        raise ValueError(f"refusing to reset path that is not a benchmark sandbox: {sandbox}")


def _assert_results_outside_sandbox(sandbox: Path, results: Path) -> None:
    if results == sandbox or sandbox in results.parents:
        raise ValueError(f"results directory must not be inside sandbox: {results}")


def _iter_files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*") if path.is_file() or path.is_symlink()]


def _iter_dirs(root: Path) -> list[Path]:
    return [path for path in root.rglob("*") if path.is_dir() and not path.is_symlink()]


def _relative_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _current_relative_files(sandbox: Path) -> list[str]:
    return [_relative_posix(path, sandbox) for path in _iter_files(sandbox)]


def _file_content_changed(path: Path, expected: bytes) -> bool:
    if path.is_symlink():
        return True
    return path.read_bytes() != expected


def _safe_run_id(run_id: str) -> str:
    safe = "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in run_id.strip())
    return safe or _utc_stamp()


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
