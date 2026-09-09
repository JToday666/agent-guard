#!/usr/bin/env python
"""Create/verify a strict Product candidate; does not sign or activate it."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import uuid

from product_runtime.candidate import (
    ARCHIVE_LIMIT,
    CANDIDATE_SCHEMA,
    NPM_DISTRIBUTION,
    PYTHON_PROJECTS,
    _verify_build,
    _verify_node_install,
    _verify_python_install,
    archive_name,
    bounded_command,
    safe_archive_members,
    source_archive_bytes,
    verify_candidate,
    verify_artifacts,
    verify_checkout,
)
from product_runtime.evidence import EvidenceError, EvidenceStore


def _directory(path: Path) -> int:
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise EvidenceError("candidate_output_path_invalid")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=directory)
            except FileExistsError:
                pass
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            os.close(directory)
            directory = child
        return directory
    except BaseException:
        os.close(directory)
        raise


def _write(path: Path, content: bytes) -> None:
    """Publish a complete file without overwrites or following parent links."""
    directory = _directory(path)
    temporary = ".candidate-" + uuid.uuid4().hex
    descriptor = None
    created = False
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        created = True
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(
            temporary,
            path.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        os.unlink(temporary, dir_fd=directory)
        created = False
        os.fsync(directory)
    finally:
        if created:
            os.unlink(temporary, dir_fd=directory)
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def _json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
        + "\n"
    ).encode()


def _artifact_refs(store: EvidenceStore, artifact_root: Path) -> list[dict]:
    pending = [store.relative(artifact_root)]
    paths = []
    count = 0
    while pending:
        directory = pending.pop()
        for name in store.directory_names(directory):
            count += 1
            if count > 100:
                raise EvidenceError("candidate_artifact_tree_limit")
            path = store.root / directory / name
            if path.is_symlink():
                raise EvidenceError("candidate_artifact_path_invalid")
            if path.is_dir():
                pending.append(store.relative(path))
            elif path.suffix in {".whl", ".tgz"} or path.name.endswith(".tar.gz"):
                paths.append(path)
            elif (
                path.name == ".gitignore"
                and path.parent.parent == artifact_root
                and path.parent.name in PYTHON_PROJECTS
                and store.capture(store.relative(path)).content == b"*"
            ):
                pass  # Fixed uv build sentinel, never a tenth candidate archive.
            else:
                raise EvidenceError("candidate_artifact_unexpected_file")
    expected = [
        (name, kind) for name in PYTHON_PROJECTS for kind in ("wheel", "sdist")
    ] + [(NPM_DISTRIBUTION, "npm_tgz")]
    if len(paths) != 9 or {path.name for path in paths} != {
        archive_name(*item) for item in expected
    }:
        raise EvidenceError("candidate_artifact_set_invalid")
    return [
        {
            "distribution": name,
            "kind": kind,
            "file": store.capture(
                store.relative(
                    next(
                        path for path in paths if path.name == archive_name(name, kind)
                    )
                ),
                max_bytes=ARCHIVE_LIMIT,
            ).reference(),
        }
        for name, kind in expected
    ]


def _build(args: argparse.Namespace, store: EvidenceStore, checkout: Path) -> dict:
    """Record actual fixed build subprocesses; failed commands never yield complete=true."""
    artifact_root = args.artifacts_root
    if artifact_root.exists():
        raise EvidenceError("candidate_build_directory_exists")
    store.relative(artifact_root)
    source_bytes = source_archive_bytes(checkout, args.expected_source_revision)
    _require_build_source(checkout, source_bytes)
    directory = _directory(artifact_root / ".placeholder")
    os.close(directory)
    source_path = store.root / "source" / "source.tar"
    _write(source_path, source_bytes)
    source = store.capture(store.relative(source_path), max_bytes=ARCHIVE_LIMIT)
    commands = []
    for name, (project, _module) in PYTHON_PROJECTS.items():
        output = artifact_root / name
        output.mkdir(mode=0o700, parents=True)
        commands.append(["uv", "build", project, "--out-dir", str(output)])
    npm = artifact_root / "npm"
    npm.mkdir(mode=0o700)
    commands.extend(
        [
            ["pnpm", "--filter", NPM_DISTRIBUTION, "build"],
            [
                "pnpm",
                "--filter",
                NPM_DISTRIBUTION,
                "pack",
                "--pack-destination",
                str(npm),
            ],
        ]
    )
    versions = {}
    for name, argv in {
        "python": [sys.executable, "--version"],
        "uv": ["uv", "--version"],
        "node": ["node", "--version"],
        "pnpm": ["pnpm", "--version"],
    }.items():
        status, stdout, _stderr = bounded_command(argv, cwd=checkout, limit=4096)
        if status:
            raise EvidenceError("candidate_build_tool_unavailable")
        versions[name] = stdout.decode().strip()
    records = []
    for index, argv in enumerate(commands):
        status, stdout, stderr = bounded_command(
            argv, cwd=checkout, timeout=600, limit=16 * 1024 * 1024
        )
        paths = [
            store.root / "build" / f"{index:02d}.{suffix}.log"
            for suffix in ("stdout", "stderr")
        ]
        for path, content in zip(paths, (stdout, stderr), strict=True):
            _write(path, content)
        records.append(
            {
                "argv": argv,
                "cwd": str(checkout),
                "exit_code": status,
                "stdout": store.capture(store.relative(paths[0])).reference(),
                "stderr": store.capture(store.relative(paths[1])).reference(),
            }
        )
        if status:
            raise EvidenceError("candidate_build_command_failed")
    verify_checkout(checkout, args.expected_source_revision)
    artifacts = _artifact_refs(store, artifact_root)
    report = {
        "schema_version": "agentguard-product-build/1",
        "source_revision": args.expected_source_revision,
        "source_archive_raw_sha256": source.raw_sha256,
        "commands": records,
        "tool_versions": versions,
        "artifacts": [item["file"] for item in artifacts],
        "complete": True,
        "exit_code": 0,
    }
    output = store.root / "build" / "build-evidence.json"
    _write(output, _json(report))
    return {
        "source_archive": source.reference(),
        "build_evidence": store.capture(store.relative(output)).reference(),
        "artifact_count": len(artifacts),
    }


def _require_build_source(checkout: Path, content: bytes) -> None:
    source = EvidenceStore(checkout)
    for name, expected in safe_archive_members(content, wheel=False).items():
        file = source.capture(name, max_bytes=ARCHIVE_LIMIT)
        if file.content != expected:
            raise EvidenceError("candidate_build_source_mismatch")
        source.require_protected(file)
    source.require_protected_tree()
    source.recheck_reads()


def _install(args: argparse.Namespace, store: EvidenceStore, checkout: Path) -> dict:
    """Run the two actual retained-environment verifiers, then read their evidence."""
    source_path = args.source_archive or store.root / "source/source.tar"
    build_path = args.build_evidence or store.root / "build/build-evidence.json"
    source = store.capture(store.relative(source_path), max_bytes=ARCHIVE_LIMIT)
    if source.content != source_archive_bytes(checkout, args.expected_source_revision):
        raise EvidenceError("candidate_source_archive_mismatch")
    artifacts = verify_artifacts(
        store,
        _artifact_refs(store, args.artifacts_root),
        safe_archive_members(source.content, wheel=False),
    )
    build = store.read_json(store.capture(store.relative(build_path)).reference())
    _verify_build(
        store, build, artifacts, args.expected_source_revision, source, checkout
    )
    root = store.root / "installation"
    if root.exists():
        raise EvidenceError("candidate_installation_directory_exists")
    directory = _directory(root / ".placeholder")
    os.close(directory)
    python_report = root / "python.json"
    node_report = root / "openclaw.json"
    python_argv = [
        sys.executable,
        str(checkout / "scripts/verify-wheel-install.py"),
        str(args.artifacts_root),
        "--environment-root",
        str(root / "python-environment"),
        "--report",
        str(python_report),
        "--source-revision",
        args.expected_source_revision,
    ]
    if args.dependency_wheelhouse is not None:
        python_argv.extend(["--dependency-wheelhouse", str(args.dependency_wheelhouse)])
    npm = next(artifact for artifact in artifacts if artifact.kind == "npm_tgz")
    node_argv = [
        "node",
        str(checkout / "scripts/verify-npm-tarball.mjs"),
        str(npm.path),
        "--environment-root",
        str(root / "openclaw-environments"),
        "--report",
        str(node_report),
        "--source-revision",
        args.expected_source_revision,
    ]
    for name, argv in (("python", python_argv), ("openclaw", node_argv)):
        status, stdout, stderr = bounded_command(
            argv, cwd=checkout, timeout=900, limit=16 * 1024 * 1024
        )
        _write(root / (name + ".stdout.log"), stdout)
        _write(root / (name + ".stderr.log"), stderr)
        if status:
            raise EvidenceError("candidate_installation_command_failed")
    python = store.read_json(store.capture(store.relative(python_report)).reference())
    node = store.read_json(store.capture(store.relative(node_report)).reference())
    _verify_python_install(store, python, artifacts, args.expected_source_revision)
    _verify_node_install(store, node, npm, args.expected_source_revision)
    verify_checkout(checkout, args.expected_source_revision)
    store.recheck_reads()
    report = {
        "schema_version": "agentguard-product-installation/1",
        "source_revision": args.expected_source_revision,
        "python": python.file.reference(),
        "openclaw": node.file.reference(),
    }
    output = root / "installation-evidence.json"
    _write(output, _json(report))
    return {
        "installation_evidence": store.capture(store.relative(output)).reference(),
        "verified": True,
        "product_active_enabled": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "install", "create", "verify"))
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--expected-source-revision", required=True)
    parser.add_argument("--artifacts-root", type=Path)
    parser.add_argument("--source-archive", type=Path)
    parser.add_argument("--build-evidence", type=Path)
    parser.add_argument("--installation-evidence", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--dependency-wheelhouse", type=Path)
    args = parser.parse_args(argv)
    try:
        store = EvidenceStore(args.evidence_root)
        checkout = verify_checkout(args.checkout, args.expected_source_revision)
        if args.command in {"build", "install"}:
            if args.artifacts_root is None:
                parser.error("build/install requires --artifacts-root")
            summary = (_build if args.command == "build" else _install)(
                args, store, checkout
            )
        else:
            if args.command == "create":
                if any(
                    getattr(args, name) is None
                    for name in (
                        "artifacts_root",
                        "source_archive",
                        "build_evidence",
                        "installation_evidence",
                        "output",
                    )
                ):
                    parser.error(
                        "create requires artifacts, source, build, installation and output paths"
                    )
                store.relative(args.output)
                if args.output.exists():
                    raise EvidenceError("candidate_output_exists")
                manifest = {
                    "schema_version": CANDIDATE_SCHEMA,
                    "source_revision": args.expected_source_revision,
                    "source_archive": store.capture(
                        store.relative(args.source_archive), max_bytes=ARCHIVE_LIMIT
                    ).reference(),
                    "artifacts": _artifact_refs(store, args.artifacts_root),
                    "build_evidence": store.capture(
                        store.relative(args.build_evidence)
                    ).reference(),
                    "installation_evidence": store.capture(
                        store.relative(args.installation_evidence)
                    ).reference(),
                }
                temporary = args.output.with_name(args.output.name + ".unverified")
                _write(temporary, _json(manifest))
                try:
                    verified = verify_candidate(
                        store.capture(store.relative(temporary)).reference(),
                        store,
                        checkout,
                        args.expected_source_revision,
                    )
                    _write(args.output, _json(manifest))
                finally:
                    temporary.unlink(missing_ok=True)
            else:
                if args.manifest is None:
                    parser.error("verify requires --manifest")
                verified = verify_candidate(
                    store.capture(store.relative(args.manifest)).reference(),
                    store,
                    checkout,
                    args.expected_source_revision,
                )
            summary = {
                "schema_version": CANDIDATE_SCHEMA,
                "source_revision": args.expected_source_revision,
                "candidate_manifest_digest": verified.canonical_digest,
                "artifact_count": len(verified.artifacts),
                "verified": True,
                "product_active_enabled": False,
            }
        print(json.dumps(summary, sort_keys=True))
        return 0
    except EvidenceError as error:
        print(json.dumps({"error": str(error), "verified": False}), file=sys.stderr)
        return (
            2 if any(word in str(error) for word in ("unavailable", "timeout")) else 1
        )
    except (OSError, ValueError, TypeError):
        print(
            '{"error":"candidate_environment_invalid","verified":false}',
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
