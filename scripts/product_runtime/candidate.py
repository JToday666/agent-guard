"""Strict candidate archives and source/install evidence, without signing."""

from __future__ import annotations

from dataclasses import dataclass, field
import base64
import csv
import gzip
from email.parser import BytesParser
from email.policy import default as email_policy
import io
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import time
from typing import Any
import zipfile

from agentguard_core.actions.canonical_json import canonical_sha256

from .evidence import (
    EvidenceError,
    EvidenceStore,
    VerifiedDocument,
    VerifiedFile,
    object_fields,
    reference,
    relative_path,
    strict_json,
)

CANDIDATE_SCHEMA = "agentguard-product-candidate/1"
PYTHON_VERSION = "0.1.0rc1"
NPM_VERSION = "0.1.0-rc.1"
NPM_DISTRIBUTION = "@agentguard-ai/openclaw-plugin"
PYTHON_PROJECTS = {
    "aegis-agentguard-core": ("packages/agentguard-core", "agentguard_core"),
    "aegis-agentguard-api": ("apps/guard-api", "guard_api"),
    "aegis-agentguard-cli": ("apps/cli", "agentguard_cli"),
    "agentguard-langgraph-adapter": (
        "packages/agentguard-langgraph-adapter",
        "agentguard_langgraph_adapter",
    ),
}
ARCHIVE_LIMIT = 128 * 1024 * 1024
MEMBER_LIMIT = 32 * 1024 * 1024
UNPACKED_LIMIT = 256 * 1024 * 1024
MEMBER_COUNT_LIMIT = 20_000
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_NATIVE_PINS = {
    "langgraph": "1.2.7",
    "langgraph-prebuilt": "1.1.0",
    "langchain-core": "1.4.8",
}


class CandidateError(EvidenceError):
    """Stable rejection code; candidate verification never prints source contents."""


@dataclass(frozen=True)
class VerifiedArtifact:
    distribution: str
    kind: str
    version: str
    file: VerifiedFile = field(repr=False)
    members: dict[str, bytes] = field(repr=False)

    @property
    def path(self) -> Path:
        return self.file.path

    @property
    def raw_sha256(self) -> str:
        return self.file.raw_sha256

    @property
    def size(self) -> int:
        return self.file.size


@dataclass(frozen=True)
class VerifiedCandidate:
    manifest: dict[str, Any] = field(repr=False)
    canonical_digest: str
    artifacts: tuple[VerifiedArtifact, ...] = field(repr=False)
    source_archive: VerifiedFile = field(repr=False)
    build_evidence: VerifiedDocument = field(repr=False)
    installation_evidence: VerifiedDocument = field(repr=False)
    installation_reports: dict[str, VerifiedDocument] = field(repr=False)


def archive_name(distribution: str, kind: str) -> str:
    if distribution in PYTHON_PROJECTS and kind in {"wheel", "sdist"}:
        base = distribution.replace("-", "_") + "-" + PYTHON_VERSION
        return base + ("-py3-none-any.whl" if kind == "wheel" else ".tar.gz")
    if distribution == NPM_DISTRIBUTION and kind == "npm_tgz":
        return "agentguard-ai-openclaw-plugin-" + NPM_VERSION + ".tgz"
    raise CandidateError("candidate_artifact_identity_invalid")


def safe_archive_members(content: bytes, *, wheel: bool) -> dict[str, bytes]:
    """Read bounded regular members; never extract, follow or silently overwrite."""
    result: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0

    def accept(name: str, size: int, directory: bool) -> str:
        nonlocal total
        canonical = relative_path(name.rstrip("/") if directory else name)
        if canonical in seen or len(seen) >= MEMBER_COUNT_LIMIT:
            raise CandidateError("candidate_archive_duplicate_or_limit")
        seen.add(canonical)
        if size < 0 or size > MEMBER_LIMIT or total + size > UNPACKED_LIMIT:
            raise CandidateError("candidate_archive_size_limit")
        total += size
        return canonical

    try:
        if wheel:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                for member in archive.infolist():
                    mode = member.external_attr >> 16
                    directory = member.is_dir()
                    if member.flag_bits & 1 or (
                        stat.S_IFMT(mode)
                        and not (stat.S_ISREG(mode) or directory and stat.S_ISDIR(mode))
                    ):
                        raise CandidateError("candidate_archive_member_type")
                    name = accept(member.filename, member.file_size, directory)
                    if not directory:
                        result[name] = archive.read(member)
        else:
            if content.startswith(b"\x1f\x8b"):
                with gzip.GzipFile(fileobj=io.BytesIO(content)) as compressed:
                    content = compressed.read(UNPACKED_LIMIT + 1)
            if len(content) > UNPACKED_LIMIT:
                raise CandidateError("candidate_archive_size_limit")
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
                for member in archive:
                    if not (member.isfile() or member.isdir()):
                        raise CandidateError("candidate_archive_member_type")
                    if member.sparse is not None:
                        raise CandidateError("candidate_archive_member_type")
                    name = accept(member.name, member.size, member.isdir())
                    if member.isfile():
                        reader = archive.extractfile(member)
                        if reader is None:
                            raise CandidateError("candidate_archive_member_type")
                        data = reader.read(MEMBER_LIMIT + 1)
                        if len(data) != member.size:
                            raise CandidateError("candidate_archive_member_size")
                        result[name] = data
        # A file cannot simultaneously be the parent of another member.
        if any(
            str(parent) in result
            for name in seen
            for parent in PurePosixPath(name).parents
            if str(parent) != "."
        ):
            raise CandidateError("candidate_archive_parent_conflict")
        return result
    except EvidenceError:
        raise
    except (
        OSError,
        ValueError,
        EOFError,
        tarfile.TarError,
        zipfile.BadZipFile,
        RuntimeError,
    ):
        raise CandidateError("candidate_archive_invalid") from None


def _metadata(content: bytes, distribution: str, version: str) -> Any:
    try:
        metadata = BytesParser(policy=email_policy).parsebytes(content)
        if metadata.defects or any(
            len(metadata.get_all(key, [])) != 1 for key in ("Name", "Version")
        ):
            raise ValueError
        normalized = re.sub(r"[-_.]+", "-", str(metadata["Name"])).lower()
        if normalized != distribution or str(metadata["Version"]) != version:
            raise ValueError
        return metadata
    except (ValueError, TypeError):
        raise CandidateError("candidate_metadata_mismatch") from None


def _python_metadata(members: dict[str, bytes], distribution: str, kind: str) -> None:
    stem = distribution.replace("-", "_") + "-" + PYTHON_VERSION
    expected = stem + (".dist-info/METADATA" if kind == "wheel" else "/PKG-INFO")
    matches = [
        name
        for name in members
        if (
            name.endswith(".dist-info/METADATA")
            if kind == "wheel"
            else name.count("/") == 1 and name.endswith("/PKG-INFO")
        )
    ]
    if matches != [expected]:
        raise CandidateError("candidate_metadata_count")
    metadata = _metadata(members[expected], distribution, PYTHON_VERSION)
    dependencies = metadata.get_all("Requires-Dist", [])
    if distribution == "aegis-agentguard-api" and not any(
        re.fullmatch(r"aegis-agentguard-core\s*==\s*0\.1\.0rc1", str(item))
        for item in dependencies
    ):
        raise CandidateError("candidate_api_core_dependency")
    if distribution == "agentguard-langgraph-adapter":
        if "native" not in metadata.get_all("Provides-Extra", []):
            raise CandidateError("candidate_native_extra_missing")
        if any(
            re.match(
                r"(?:aegis-agentguard-core|agentguard-langgraph-bench)\b", str(item)
            )
            for item in dependencies
        ):
            raise CandidateError("candidate_adapter_dependency_isolation")
        for name, version in _NATIVE_PINS.items():
            if not any(
                re.fullmatch(
                    re.escape(name)
                    + r"\s*==\s*"
                    + re.escape(version)
                    + r"\s*;\s*extra\s*==\s*[\"']native[\"']",
                    str(item),
                )
                for item in dependencies
            ):
                raise CandidateError("candidate_native_pin_mismatch")
    if not any(PurePosixPath(name).name == "LICENSE" for name in members):
        raise CandidateError("candidate_license_missing")


def _npm_metadata(members: dict[str, bytes]) -> None:
    for name, expected_name in (
        ("package/package.json", NPM_DISTRIBUTION),
        (
            "package/product-runtime/product/package.json",
            "@agentguard-ai/openclaw-product-runtime",
        ),
    ):
        if name not in members:
            raise CandidateError("candidate_npm_metadata_missing")
        value = strict_json(members[name])
        if (
            type(value) is not dict
            or value.get("name") != expected_name
            or value.get("version") != NPM_VERSION
        ):
            raise CandidateError("candidate_npm_metadata_mismatch")
    for name, expected_id in (
        ("package/openclaw.plugin.json", "agentguard-security"),
        (
            "package/product-runtime/product/openclaw.plugin.json",
            "agentguard-product-runtime-fixture",
        ),
    ):
        value = strict_json(members.get(name, b"null"))
        if (
            type(value) is not dict
            or value.get("id") != expected_id
            or value.get("version") != NPM_VERSION
        ):
            raise CandidateError("candidate_npm_manifest_mismatch")
    if (
        "package/dist/index.js" not in members
        or "package/product-runtime/product/index.mjs" not in members
        or "package/LICENSE" not in members
    ):
        raise CandidateError("candidate_npm_entry_missing")


def bounded_command(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: float = 60,
    limit: int = ARCHIVE_LIMIT,
) -> tuple[int, bytes, bytes]:
    """Bound both live pipes, elapsed time and descendant lifetime."""
    process = None
    completed = False
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            umask=0o022,
        )
        assert process.stdout is not None and process.stderr is not None
        outputs = {
            process.stdout.fileno(): bytearray(),
            process.stderr.fileno(): bytearray(),
        }
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise CandidateError("candidate_command_timeout")
                for key, _event in selector.select(
                    min(0.2, max(0, deadline - time.monotonic()))
                ):
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    outputs[key.fd].extend(chunk)
                    if len(outputs[key.fd]) > limit:
                        raise CandidateError("candidate_command_output_limit")
        status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        completed = True
        return (
            status,
            bytes(outputs[process.stdout.fileno()]),
            bytes(outputs[process.stderr.fileno()]),
        )
    except (OSError, subprocess.TimeoutExpired):
        raise CandidateError("candidate_command_unavailable") from None
    finally:
        if process is not None:
            if not completed or process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


def _git(checkout: Path, arguments: list[str], *, limit: int = ARCHIVE_LIMIT) -> bytes:
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    env.update(
        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0"
    )
    try:
        status, stdout, stderr = bounded_command(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=" + os.devnull,
                *arguments,
            ],
            cwd=checkout,
            env=env,
            timeout=60,
            limit=limit,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise CandidateError("candidate_git_unavailable") from None
    if status or len(stderr) > 1024 * 1024:
        raise CandidateError("candidate_git_failed")
    return stdout


def verify_checkout(checkout: str | Path, source_revision: str) -> Path:
    if type(source_revision) is not str or not _SHA.fullmatch(source_revision):
        raise CandidateError("candidate_source_revision_invalid")
    path = Path(checkout)
    if not path.is_absolute() or path.resolve() != path:
        raise CandidateError("candidate_checkout_invalid")
    if _git(path, ["rev-parse", "--show-toplevel"]).decode().strip() != str(path):
        raise CandidateError("candidate_checkout_invalid")
    if (
        _git(path, ["rev-parse", "--verify", "HEAD"]).decode().strip()
        != source_revision
    ):
        raise CandidateError("candidate_source_revision_mismatch")
    if _git(path, ["status", "--porcelain=v1", "--untracked-files=all"]):
        raise CandidateError("candidate_checkout_dirty")
    return path


def source_archive_bytes(checkout: Path, source_revision: str) -> bytes:
    return _git(
        checkout, ["-c", "tar.umask=0002", "archive", "--format=tar", source_revision]
    )


def _check_source(artifact: VerifiedArtifact, source: dict[str, bytes]) -> None:
    if artifact.distribution in PYTHON_PROJECTS:
        project, module = PYTHON_PROJECTS[artifact.distribution]
        prefix = (
            ""
            if artifact.kind == "wheel"
            else artifact.distribution.replace("-", "_") + "-" + PYTHON_VERSION + "/"
        )
        checked = 0
        for name, content in artifact.members.items():
            local = name.removeprefix(prefix)
            if (
                local.startswith(module + "/")
                or artifact.kind == "sdist"
                and local in {"pyproject.toml", "README.md", "LICENSE"}
            ):
                if source.get(project + "/" + local) != content:
                    raise CandidateError("candidate_source_member_mismatch")
                checked += 1
        if not checked:
            raise CandidateError("candidate_source_members_missing")
        expected = {
            name.removeprefix(project + "/")
            for name in source
            if name.startswith(project + "/" + module + "/")
        }
        actual = {
            name.removeprefix(prefix)
            for name in artifact.members
            if name.removeprefix(prefix).startswith(module + "/")
        }
        if expected != actual:
            raise CandidateError("candidate_source_members_missing")
    else:
        for name, content in artifact.members.items():
            if not name.startswith("package/"):
                raise CandidateError("candidate_npm_member_root")
            local = name.removeprefix("package/")
            if local == "package.json":
                # Pinned pnpm pack moves scripts to the end and removes the
                # trailing newline. Preserve archive/source raw hashes while
                # comparing every metadata value with strict JSON types.
                original = source.get(
                    "packages/agentguard-openclaw-plugin/package.json"
                )
                if original is None:
                    raise CandidateError("candidate_source_member_mismatch")
                expected, packed = strict_json(original), strict_json(content)
                if (
                    type(expected) is not dict
                    or type(packed) is not dict
                    or canonical_sha256(expected) != canonical_sha256(packed)
                ):
                    raise CandidateError("candidate_source_member_mismatch")
                continue
            if (
                not local.startswith("dist/")
                and source.get("packages/agentguard-openclaw-plugin/" + local)
                != content
            ):
                raise CandidateError("candidate_source_member_mismatch")


def _success_report(value: Any, kind: str, source_revision: str) -> dict[str, Any]:
    if (
        type(value) is not dict
        or value.get("schema_version") != "1.0"
        or value.get("kind") != kind
        or value.get("source_revision") != source_revision
    ):
        raise CandidateError("candidate_installation_identity")
    if (
        value.get("product_active_enabled") is not False
        or type(value.get("external_provider_requests")) is not int
        or value["external_provider_requests"] != 0
        or value.get("complete") is not True
        or type(value.get("exit_code")) is not int
        or value["exit_code"] != 0
    ):
        raise CandidateError("candidate_installation_incomplete")
    return value


def _absolute_file(
    store: EvidenceStore, item: Any, *, limit: int = MEMBER_LIMIT
) -> VerifiedFile:
    object_fields(
        item, {"path", "size", "raw_sha256"}, "candidate_installed_file_invalid"
    )
    file = store.read_file(
        {**item, "path": store.relative(item["path"])}, max_bytes=limit
    )
    store.require_protected(file)
    return file


def _installed_files(
    store: EvidenceStore, values: Any, root: Path
) -> dict[str, VerifiedFile]:
    if type(values) is not list or not values or len(values) > MEMBER_COUNT_LIMIT:
        raise CandidateError("candidate_installed_files_invalid")
    result = {}
    for item in values:
        file = _absolute_file(store, item)
        try:
            name = relative_path(file.path.relative_to(root).as_posix())
        except ValueError:
            raise CandidateError("candidate_installation_path_mismatch") from None
        if name in result:
            raise CandidateError("candidate_installed_file_duplicate")
        if "__pycache__" in PurePosixPath(name).parts or name.endswith(
            (".pyc", ".pyo", ".pth")
        ):
            raise CandidateError("candidate_installation_not_clean")
        result[name] = file
    return result


def _match_archive(item: Any, artifact: VerifiedArtifact) -> None:
    object_fields(
        item, {"path", "size", "raw_sha256"}, "candidate_install_archive_invalid"
    )
    if item != {
        "path": str(artifact.path),
        "size": artifact.size,
        "raw_sha256": artifact.raw_sha256,
    }:
        raise CandidateError("candidate_install_archive_mismatch")


def _verify_python_install(
    store: EvidenceStore,
    document: VerifiedDocument,
    artifacts: tuple[VerifiedArtifact, ...],
    revision: str,
) -> None:
    report = _success_report(document.data, "python_candidate_installation", revision)
    object_fields(
        report,
        {
            "schema_version",
            "kind",
            "source_revision",
            "environment_root",
            "python_executable",
            "python_version",
            "packages",
            "runtime_versions",
            "product_active_enabled",
            "external_provider_requests",
            "complete",
            "exit_code",
        },
        "candidate_python_report_fields",
    )
    environment = store.root / store.relative(report["environment_root"])
    executable = store.root / store.relative(report["python_executable"])
    if (
        not executable.is_relative_to(environment)
        or not re.fullmatch(r"3\.12\.\d+", str(report["python_version"]))
        or report["runtime_versions"] != _NATIVE_PINS
    ):
        raise CandidateError("candidate_python_runtime_mismatch")
    store.require_protected(
        store.capture(store.relative(executable), max_bytes=ARCHIVE_LIMIT)
    )
    packages = report["packages"]
    if (
        type(packages) is not list
        or len(packages) != 4
        or any(
            type(p) is not dict or type(p.get("distribution")) is not str
            for p in packages
        )
        or {p["distribution"] for p in packages} != set(PYTHON_PROJECTS)
    ):
        raise CandidateError("candidate_installed_packages_mismatch")
    package_roots = set()
    for package in packages:
        object_fields(
            package,
            {
                "distribution",
                "version",
                "artifact",
                "metadata_path",
                "module_file",
                "files",
            },
            "candidate_python_package_fields",
        )
        name = package["distribution"]
        artifact = next(
            a for a in artifacts if a.distribution == name and a.kind == "wheel"
        )
        _match_archive(package["artifact"], artifact)
        if package["version"] != PYTHON_VERSION:
            raise CandidateError("candidate_installed_version_mismatch")
        metadata_path = store.root / store.relative(package["metadata_path"])
        package_root = metadata_path.parent.parent
        package_roots.add(package_root)
        module_file = store.root / store.relative(package["module_file"])
        if (
            not package_root.is_relative_to(environment)
            or module_file != package_root / PYTHON_PROJECTS[name][1] / "__init__.py"
        ):
            raise CandidateError("candidate_installation_path_mismatch")
        files = _installed_files(store, package["files"], package_root)
        expected_metadata = (
            name.replace("-", "_") + "-" + PYTHON_VERSION + ".dist-info/METADATA"
        )
        if metadata_path != package_root / expected_metadata:
            raise CandidateError("candidate_installed_metadata_path")
        actual_files = {}
        for directory in (
            PYTHON_PROJECTS[name][1],
            str(PurePosixPath(expected_metadata).parent),
        ):
            actual_files.update(
                {
                    directory + "/" + local: value
                    for local, value in store.tree(
                        store.relative(package_root / directory)
                    ).items()
                }
            )
        if set(actual_files) != set(files):
            raise CandidateError("candidate_installed_file_manifest_mismatch")
        for directory in (
            PYTHON_PROJECTS[name][1],
            str(PurePosixPath(expected_metadata).parent),
        ):
            store.require_protected_tree(store.relative(package_root / directory))
        for member, content in artifact.members.items():
            if member.endswith(".dist-info/RECORD"):
                continue  # Installer rewrites RECORD; all other bytes stay exact.
            if member not in files or files[member].content != content:
                raise CandidateError("candidate_installed_member_mismatch")
        dist_info = str(PurePosixPath(expected_metadata).parent)
        extras = set(files) - set(artifact.members)
        if extras - {
            dist_info + "/direct_url.json",
            dist_info + "/INSTALLER",
            dist_info + "/REQUESTED",
            dist_info + "/uv_cache.json",
        }:
            raise CandidateError("candidate_installed_extra_member")
        direct = files.get(dist_info + "/direct_url.json")
        if direct is None:
            raise CandidateError("candidate_installed_origin_missing")
        origin = strict_json(direct.content)
        if (
            type(origin) is not dict
            or set(origin) != {"url", "archive_info"}
            or origin.get("url") != artifact.path.as_uri()
        ):
            raise CandidateError("candidate_installed_origin_mismatch")
        # uv records local wheel origins with an empty archive_info. The exact
        # archive raw hash and all installed wheel bytes were checked above;
        # never invent a hash purportedly supplied by the installer.
        expected_hashes = {
            "hashes": {"sha256": artifact.raw_sha256.removeprefix("sha256:")}
        }
        if origin["archive_info"] not in ({}, expected_hashes):
            raise CandidateError("candidate_installed_origin_mismatch")
        cache_file = files.get(dist_info + "/uv_cache.json")
        if cache_file is not None:
            cache = strict_json(cache_file.content)
            object_fields(
                cache,
                {"timestamp", "commit", "tags", "env", "directories"},
                "candidate_installed_cache_invalid",
            )
            timestamp = object_fields(
                cache["timestamp"],
                {"secs_since_epoch", "nanos_since_epoch"},
                "candidate_installed_cache_invalid",
            )
            installer = files.get(dist_info + "/INSTALLER")
            if (
                installer is None
                or installer.content not in (b"uv", b"uv\n")
                or cache["commit"] is not None
                or cache["tags"] is not None
                or cache["env"] != {}
                or cache["directories"] != {}
                or any(type(v) is not int or v < 0 for v in timestamp.values())
                or timestamp["nanos_since_epoch"] >= 1_000_000_000
            ):
                raise CandidateError("candidate_installed_cache_invalid")
        record_name = dist_info + "/RECORD"
        record = files.get(record_name)
        if record is None:
            raise CandidateError("candidate_installed_record_missing")
        try:
            rows = list(csv.reader(io.StringIO(record.content.decode("utf-8"))))
            records = {}
            for row in rows:
                if len(row) != 3 or row[0] in records:
                    raise ValueError
                records[row[0]] = row[1:]
            for local, file in files.items():
                if local == record_name:
                    if records.get(local) != ["", ""]:
                        raise ValueError
                    continue
                expected_hash = "sha256=" + base64.urlsafe_b64encode(
                    bytes.fromhex(file.raw_sha256[7:])
                ).decode().rstrip("=")
                if records.get(local) != [expected_hash, str(file.size)]:
                    raise ValueError
        except (ValueError, UnicodeError, csv.Error):
            raise CandidateError("candidate_installed_record_mismatch") from None
    if len(package_roots) != 1:
        raise CandidateError("candidate_python_environment_mismatch")
    site = package_roots.pop()
    entries = store.directory_names(store.relative(site))
    for name, version in _NATIVE_PINS.items():
        matches = [
            entry
            for entry in entries
            if entry.endswith(".dist-info")
            and re.sub(r"[-_.]+", "-", entry[:-10].rsplit("-", 1)[0]).lower() == name
        ]
        expected_directory = name.replace("-", "_") + "-" + version + ".dist-info"
        if matches != [expected_directory]:
            raise CandidateError("candidate_python_native_metadata_mismatch")
        metadata = store.capture(store.relative(site / expected_directory / "METADATA"))
        store.require_protected(metadata)
        _metadata(metadata.content, name, version)
    store.require_protected_tree(store.relative(environment))


def _verify_node_install(
    store: EvidenceStore,
    document: VerifiedDocument,
    artifact: VerifiedArtifact,
    revision: str,
) -> None:
    report = _success_report(document.data, "openclaw_candidate_installation", revision)
    object_fields(
        report,
        {
            "schema_version",
            "kind",
            "source_revision",
            "artifact",
            "package_version",
            "lanes",
            "environment_root",
            "product_active_enabled",
            "external_provider_requests",
            "complete",
            "exit_code",
        },
        "candidate_node_report_fields",
    )
    _match_archive(report["artifact"], artifact)
    if (
        report["package_version"] != NPM_VERSION
        or type(report["lanes"]) is not list
        or len(report["lanes"]) != 2
    ):
        raise CandidateError("candidate_node_lanes_invalid")
    environment = store.root / store.relative(report["environment_root"])
    for lane, expected_lane, version in zip(
        report["lanes"], ("legacy", "product"), ("2026.6.6", "2026.7.1-2"), strict=True
    ):
        object_fields(
            lane,
            {
                "lane",
                "runtime_version",
                "package_version",
                "installation_root",
                "plugin_root",
                "runtime_root",
                "artifact_digest",
                "files",
                "compatibility_import",
                "product_inspection",
                "product_active_enabled",
                "evidence_file",
            },
            "candidate_node_lane_fields",
        )
        if (
            lane["lane"] != expected_lane
            or lane["runtime_version"] != version
            or lane["package_version"] != NPM_VERSION
            or lane["artifact_digest"] != artifact.raw_sha256
            or lane["compatibility_import"] is not True
            or lane["product_active_enabled"] is not False
        ):
            raise CandidateError("candidate_node_lane_mismatch")
        root = store.root / store.relative(lane["installation_root"])
        plugin = store.root / store.relative(lane["plugin_root"])
        runtime = store.root / store.relative(lane["runtime_root"])
        if (
            not root.is_relative_to(environment)
            or not plugin.is_relative_to(root)
            or not runtime.is_relative_to(root)
        ):
            raise CandidateError("candidate_installation_path_mismatch")
        files = _installed_files(store, lane["files"], plugin)
        actual_files = store.tree(
            store.relative(plugin), skip_root=frozenset({"node_modules"})
        )
        if set(actual_files) != set(files):
            raise CandidateError("candidate_installed_file_manifest_mismatch")
        store.require_protected_tree(store.relative(plugin))
        expected = {
            name.removeprefix("package/"): value
            for name, value in artifact.members.items()
        }
        if set(files) != set(expected) or any(
            files[name].content != content for name, content in expected.items()
        ):
            raise CandidateError("candidate_installed_member_mismatch")
        host_file = store.capture(store.relative(runtime / "package.json"))
        store.require_protected(host_file)
        host = strict_json(host_file.content)
        if (
            type(host) is not dict
            or host.get("name") != "openclaw"
            or host.get("version") != version
        ):
            raise CandidateError("candidate_node_runtime_mismatch")
        worker_file = _absolute_file(store, lane["evidence_file"])
        worker = strict_json(worker_file.content)
        if worker != {
            key: value
            for key, value in lane.items()
            if key not in {"lane", "evidence_file"}
        }:
            raise CandidateError("candidate_node_worker_evidence_mismatch")
        inspection = lane["product_inspection"]
        if expected_lane == "product":
            if (
                type(inspection) is not dict
                or inspection.get("active") is not False
                or inspection.get("artifactDigest") != artifact.raw_sha256
                or inspection.get("runtimeVersion") != version
                or inspection.get("packageVersion") != NPM_VERSION
            ):
                raise CandidateError("candidate_product_inspection_invalid")
        elif inspection is not None:
            raise CandidateError("candidate_legacy_inspection_invalid")
    store.require_protected_tree(store.relative(environment))


def _verify_build(
    store: EvidenceStore,
    document: VerifiedDocument,
    artifacts: tuple[VerifiedArtifact, ...],
    revision: str,
    source: VerifiedFile,
    checkout: Path,
) -> None:
    value = document.data
    object_fields(
        value,
        {
            "schema_version",
            "source_revision",
            "source_archive_raw_sha256",
            "commands",
            "tool_versions",
            "artifacts",
            "complete",
            "exit_code",
        },
        "candidate_build_fields",
    )
    if (
        value["schema_version"] != "agentguard-product-build/1"
        or value["source_revision"] != revision
        or value["source_archive_raw_sha256"] != source.raw_sha256
        or value["complete"] is not True
        or type(value["exit_code"]) is not int
        or value["exit_code"] != 0
    ):
        raise CandidateError("candidate_build_incomplete")
    object_fields(
        value["tool_versions"],
        {"python", "uv", "node", "pnpm"},
        "candidate_build_tools_invalid",
    )
    if any(
        type(v) is not str or not v.strip() or len(v) > 128
        for v in value["tool_versions"].values()
    ):
        raise CandidateError("candidate_build_tools_invalid")
    if type(value["commands"]) is not list or len(value["commands"]) != 6:
        raise CandidateError("candidate_build_commands_invalid")
    expected_commands = []
    for name, (project, _module) in PYTHON_PROJECTS.items():
        artifact = next(
            a for a in artifacts if a.distribution == name and a.kind == "wheel"
        )
        expected_commands.append(
            ["uv", "build", project, "--out-dir", str(artifact.path.parent)]
        )
    npm = next(a for a in artifacts if a.kind == "npm_tgz")
    expected_commands.extend(
        [
            ["pnpm", "--filter", NPM_DISTRIBUTION, "build"],
            [
                "pnpm",
                "--filter",
                NPM_DISTRIBUTION,
                "pack",
                "--pack-destination",
                str(npm.path.parent),
            ],
        ]
    )
    for command, expected in zip(value["commands"], expected_commands, strict=True):
        object_fields(
            command,
            {"argv", "cwd", "exit_code", "stdout", "stderr"},
            "candidate_build_command_fields",
        )
        if (
            command["argv"] != expected
            or command["cwd"] != str(checkout)
            or type(command["exit_code"]) is not int
            or command["exit_code"] != 0
        ):
            raise CandidateError("candidate_build_command_mismatch")
        store.read_file(command["stdout"])
        store.read_file(command["stderr"])
    expected_refs = [a.file.reference() for a in artifacts]
    if value["artifacts"] != expected_refs:
        raise CandidateError("candidate_build_artifacts_mismatch")


def verify_artifacts(
    store: EvidenceStore, items: Any, source_members: dict[str, bytes]
) -> tuple[VerifiedArtifact, ...]:
    """Check all nine archives before installing or trusting their contents."""
    expected = {
        (name, kind) for name in PYTHON_PROJECTS for kind in ("wheel", "sdist")
    } | {(NPM_DISTRIBUTION, "npm_tgz")}
    if type(items) is not list or len(items) != 9:
        raise CandidateError("candidate_artifact_set_invalid")
    artifacts: list[VerifiedArtifact] = []
    unpacked_bytes = sum(len(content) for content in source_members.values())
    seen: set[tuple[str, str]] = set()
    paths: set[str] = set()
    for item in items:
        object_fields(
            item, {"distribution", "kind", "file"}, "candidate_artifact_fields"
        )
        identity = (item["distribution"], item["kind"])
        if (
            any(type(v) is not str for v in identity)
            or identity not in expected
            or identity in seen
        ):
            raise CandidateError("candidate_artifact_set_invalid")
        seen.add(identity)
        ref = reference(item["file"])
        if ref["path"] in paths or PurePosixPath(ref["path"]).name != archive_name(
            *identity
        ):
            raise CandidateError("candidate_artifact_path_invalid")
        paths.add(ref["path"])
        file = store.read_file(ref, max_bytes=ARCHIVE_LIMIT)
        members = safe_archive_members(file.content, wheel=identity[1] == "wheel")
        unpacked_bytes += sum(len(content) for content in members.values())
        if unpacked_bytes > UNPACKED_LIMIT:
            raise CandidateError("candidate_archive_size_limit")
        if any(
            set(PurePosixPath(name).parts)
            & {
                ".git",
                ".env",
                ".venv",
                "__pycache__",
                "node_modules",
                "tests",
                "benchmark",
            }
            for name in members
        ):
            raise CandidateError("candidate_archive_local_data")
        if identity[1] == "npm_tgz":
            _npm_metadata(members)
        else:
            _python_metadata(members, *identity)
        artifact = VerifiedArtifact(
            *identity,
            NPM_VERSION if identity[1] == "npm_tgz" else PYTHON_VERSION,
            file,
            members,
        )
        _check_source(artifact, source_members)
        artifacts.append(artifact)
    return tuple(artifacts)


def verify_candidate(
    manifest_ref: Any,
    store: EvidenceStore,
    checkout: str | Path,
    expected_source_revision: str,
) -> VerifiedCandidate:
    path = verify_checkout(checkout, expected_source_revision)
    document = store.read_json(manifest_ref)
    manifest = object_fields(
        document.data,
        {
            "schema_version",
            "source_revision",
            "source_archive",
            "artifacts",
            "build_evidence",
            "installation_evidence",
        },
        "candidate_manifest_fields",
    )
    if (
        manifest["schema_version"] != CANDIDATE_SCHEMA
        or manifest["source_revision"] != expected_source_revision
    ):
        raise CandidateError("candidate_manifest_identity")
    source = store.read_file(manifest["source_archive"], max_bytes=ARCHIVE_LIMIT)
    if source.content != source_archive_bytes(path, expected_source_revision):
        raise CandidateError("candidate_source_archive_mismatch")
    source_members = safe_archive_members(source.content, wheel=False)
    verified_artifacts = verify_artifacts(store, manifest["artifacts"], source_members)
    build = store.read_json(manifest["build_evidence"])
    _verify_build(
        store, build, verified_artifacts, expected_source_revision, source, path
    )
    installation = store.read_json(manifest["installation_evidence"])
    aggregate = object_fields(
        installation.data,
        {"schema_version", "source_revision", "python", "openclaw"},
        "candidate_installation_fields",
    )
    if (
        aggregate["schema_version"] != "agentguard-product-installation/1"
        or aggregate["source_revision"] != expected_source_revision
    ):
        raise CandidateError("candidate_installation_identity")
    reports = {
        runtime: store.read_json(aggregate[runtime])
        for runtime in ("python", "openclaw")
    }
    _verify_python_install(
        store, reports["python"], verified_artifacts, expected_source_revision
    )
    _verify_node_install(
        store,
        reports["openclaw"],
        next(a for a in verified_artifacts if a.kind == "npm_tgz"),
        expected_source_revision,
    )
    verify_checkout(path, expected_source_revision)
    store.recheck_reads()
    return VerifiedCandidate(
        manifest,
        document.canonical_digest,
        verified_artifacts,
        source,
        build,
        installation,
        reports,
    )
