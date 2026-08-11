#!/usr/bin/env python
"""Create or verify a content-addressed manifest for release archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
DEFAULT_MANIFEST_NAME = "release-artifact-manifest.json"


class ReleaseManifestError(ValueError):
    """Raised when release artifacts do not have one immutable identity."""


def build_manifest(root: Path) -> dict[str, Any]:
    root = root.resolve()
    archives = _archives(root)
    _reject_duplicate_names(archives, root)
    artifacts = [
        {
            "name": path.name,
            "relative_path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for path in archives
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }


def write_manifest(root: Path, output: Path) -> dict[str, Any]:
    manifest = build_manifest(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def verify_manifest(root: Path, manifest_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"manifest is unreadable: {type(exc).__name__}"]
    if not isinstance(expected, dict) or expected.get("schema_version") != SCHEMA_VERSION:
        return [f"manifest schema_version must be {SCHEMA_VERSION}"]
    try:
        actual = build_manifest(root)
    except ReleaseManifestError as exc:
        return [str(exc)]

    expected_artifacts = expected.get("artifacts")
    if not isinstance(expected_artifacts, list):
        return ["manifest artifacts must be an array"]
    if expected.get("artifact_count") != len(expected_artifacts):
        errors.append("manifest artifact_count does not match its records")

    expected_by_path: dict[str, dict[str, Any]] = {}
    for item in expected_artifacts:
        if not isinstance(item, dict) or not isinstance(item.get("relative_path"), str):
            errors.append("manifest contains an invalid artifact record")
            continue
        relative_path = item["relative_path"]
        if relative_path in expected_by_path:
            errors.append(f"manifest contains duplicate path: {relative_path}")
            continue
        expected_by_path[relative_path] = item
    actual_by_path = {item["relative_path"]: item for item in actual["artifacts"]}

    missing = sorted(set(expected_by_path) - set(actual_by_path))
    unexpected = sorted(set(actual_by_path) - set(expected_by_path))
    if missing:
        errors.append(f"manifest artifacts missing from disk: {', '.join(missing)}")
    if unexpected:
        errors.append(f"unmanifested artifacts on disk: {', '.join(unexpected)}")
    for relative_path in sorted(set(expected_by_path) & set(actual_by_path)):
        expected_item = expected_by_path[relative_path]
        actual_item = actual_by_path[relative_path]
        for field in ("name", "size", "sha256"):
            if expected_item.get(field) != actual_item.get(field):
                errors.append(f"artifact {relative_path} {field} mismatch")
    return errors


def _archives(root: Path) -> list[Path]:
    return sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file()
            and (
                path.suffix in {".whl", ".tgz"}
                or path.name.endswith(".tar.gz")
            )
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def _reject_duplicate_names(archives: list[Path], root: Path) -> None:
    by_name: dict[str, list[str]] = {}
    for path in archives:
        by_name.setdefault(path.name, []).append(path.relative_to(root).as_posix())
    duplicates = {
        name: paths for name, paths in sorted(by_name.items()) if len(paths) > 1
    }
    if duplicates:
        details = "; ".join(
            f"{name}: {', '.join(paths)}" for name, paths in duplicates.items()
        )
        raise ReleaseManifestError(f"duplicate release archive names: {details}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("root", type=Path)
    create.add_argument("--output", type=Path)
    verify = subparsers.add_parser("verify")
    verify.add_argument("root", type=Path)
    verify.add_argument("--manifest", type=Path)
    args = parser.parse_args(argv)

    root = args.root.resolve()
    manifest_path = (args.output if args.command == "create" else args.manifest) or (
        root / DEFAULT_MANIFEST_NAME
    )
    if args.command == "create":
        try:
            manifest = write_manifest(root, manifest_path.resolve())
        except ReleaseManifestError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(manifest, ensure_ascii=False, sort_keys=True))
        return 0

    errors = verify_manifest(root, manifest_path.resolve())
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"release artifact manifest: {manifest_path} verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
