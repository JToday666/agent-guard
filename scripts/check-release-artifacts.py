"""Inspect AgentGuard release archives for expected files and local-data leaks."""

from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
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
    archives = {
        path.name: path
        for path in root.rglob("*")
        if path.is_file()
        and (path.suffix in {".whl", ".tgz"} or path.name.endswith(".tar.gz"))
    }
    missing = EXPECTED_ARCHIVES - archives.keys()
    unexpected = archives.keys() - EXPECTED_ARCHIVES
    if missing:
        errors.append(f"missing archives: {', '.join(sorted(missing))}")
    if unexpected:
        errors.append(f"unexpected archives: {', '.join(sorted(unexpected))}")

    for archive_name, archive_path in archives.items():
        member_names: list[str] = []
        for member_name, content in _members(archive_path):
            member_names.append(member_name)
            parts = {part.lower() for part in PurePosixPath(member_name).parts}
            forbidden = sorted(parts & FORBIDDEN_NAME_PARTS)
            if forbidden:
                errors.append(
                    f"{archive_name}: forbidden member {member_name!r} ({forbidden[0]})"
                )
            for marker in FORBIDDEN_CONTENT:
                if marker in content:
                    errors.append(
                        f"{archive_name}: local build path found in {member_name!r}"
                    )
        if not any(name.lower().endswith("license") for name in member_names):
            errors.append(f"{archive_name}: LICENSE is missing")
        if archive_name.endswith(".tgz") and not any(
            name == "package/dist/index.js" for name in member_names
        ):
            errors.append(f"{archive_name}: compiled plugin entry is missing")
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
