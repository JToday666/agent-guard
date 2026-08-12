"""Inspect AgentGuard release archives for expected files and local-data leaks."""

from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

EXPECTED_ARCHIVES = {
    "aegis_agentguard_core-0.1.0b1-py3-none-any.whl",
    "aegis_agentguard_core-0.1.0b1.tar.gz",
    "aegis_agentguard_api-0.1.0b1-py3-none-any.whl",
    "aegis_agentguard_api-0.1.0b1.tar.gz",
    "aegis_agentguard_cli-0.1.0b1-py3-none-any.whl",
    "aegis_agentguard_cli-0.1.0b1.tar.gz",
    "agentguard-ai-openclaw-plugin-0.1.0-beta.1.tgz",
}

FORBIDDEN_NAME_PARTS = {
    ".env",
    ".pytest_cache",
    ".ruff_cache",
    "benchmark",
    "dashboard",
    "langgraph",
    "node_modules",
    "test-results",
    "tests",
}

FORBIDDEN_CONTENT = (
    b"D:\\Dev\\agent-guard",
    b"D:/Dev/agent-guard",
    b"/home/runner/work/",
)


def _members(path: Path) -> Iterator[tuple[str, bytes]]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if not info.is_dir():
                    yield info.filename, archive.read(info)
        return
    with tarfile.open(path, "r:*") as archive:
        for info in archive.getmembers():
            if info.isfile():
                extracted = archive.extractfile(info)
                assert extracted is not None
                yield info.name, extracted.read()


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    archive_paths = sorted(
        (
            path
        for path in root.rglob("*")
        if path.is_file()
        and (path.suffix in {".whl", ".tgz"} or path.name.endswith(".tar.gz"))
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    archives: dict[str, list[Path]] = defaultdict(list)
    for path in archive_paths:
        archives[path.name].append(path)

    archive_names = set(archives)
    missing = EXPECTED_ARCHIVES - archive_names
    unexpected = archive_names - EXPECTED_ARCHIVES
    if missing:
        errors.append(f"missing archives: {', '.join(sorted(missing))}")
    if unexpected:
        errors.append(f"unexpected archives: {', '.join(sorted(unexpected))}")
    for archive_name, paths in sorted(archives.items()):
        if len(paths) > 1:
            relative_paths = ", ".join(
                path.relative_to(root).as_posix() for path in paths
            )
            errors.append(f"duplicate archive {archive_name}: {relative_paths}")

    for archive_path in archive_paths:
        archive_name = archive_path.name
        archive_label = archive_path.relative_to(root).as_posix()
        member_names: list[str] = []
        for member_name, content in _members(archive_path):
            member_names.append(member_name)
            parts = {part.lower() for part in PurePosixPath(member_name).parts}
            forbidden = sorted(parts & FORBIDDEN_NAME_PARTS)
            if forbidden:
                errors.append(
                    f"{archive_label}: forbidden member {member_name!r} ({forbidden[0]})"
                )
            for marker in FORBIDDEN_CONTENT:
                if marker in content:
                    errors.append(
                        f"{archive_label}: local build path found in {member_name!r}"
                    )
        if not any(name.lower().endswith("license") for name in member_names):
            errors.append(f"{archive_label}: LICENSE is missing")
        if archive_name.endswith(".tgz") and not any(
            name == "package/dist/index.js" for name in member_names
        ):
            errors.append(f"{archive_label}: compiled plugin entry is missing")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, help="Directory containing release archives")
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"release artifact scan: {len(EXPECTED_ARCHIVES)} archives passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
