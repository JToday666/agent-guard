from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tomllib

import pytest

pytestmark = pytest.mark.contract

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "agentguard_langgraph_bench/bench/datasets/instrumentation"
FIXTURE_NAMES = (
    "Browser-art_C5_1",
    "Browser-art_D2_1",
    "Browser-art_D2_6",
    "Browser-art_D3_10",
    "Browser-art_D4_23",
    "Browser-art_E1_33",
    "Browser-art_E2_11",
    "Browser-art_E3_12",
    "Browser-art_E4_16",
    "Browser-art_F2_34",
    "Browser-art_G2_8",
)
NODE_SECURITY_FLOORS = {
    "@hono/node-server": "1.19.15",
    "brace-expansion": "5.0.9",
    "fast-uri": "3.1.5",
    "hono": "4.12.34",
    "immutable": "5.1.8",
    "ip-address": "10.3.1",
    "nanoid": "3.3.18",
    "postcss": "8.5.23",
    "protobufjs": "7.6.5",
    "tar": "7.5.21",
    "undici": "8.9.0",
}
LEGACY_FIXTURE_SECURITY_FLOORS = {
    "express": "4.22.2",
    "body-parser": "1.20.6",
    "qs": "6.15.3",
    "cookie": "0.7.0",
    "send": "0.19.0",
    "serve-static": "1.16.0",
}
LEGACY_FIXTURE_EXACT_VERSIONS = {"path-to-regexp": "0.1.13"}


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _pnpm_lock_versions(lock: str, package: str) -> set[tuple[int, ...]]:
    pattern = re.compile(
        rf"^  (?P<quote>['\"]?){re.escape(package)}@"
        rf"(?P<version>\d+\.\d+\.\d+)(?:\([^:\n]*\))?(?P=quote):$",
        re.MULTILINE,
    )
    return {_version_tuple(match.group("version")) for match in pattern.finditer(lock)}


def _yaml_mapping_version(mapping: str, package: str) -> str | None:
    pattern = re.compile(
        rf"^  (?P<quote>['\"]?){re.escape(package)}(?P=quote): "
        r"(?P<version>\d+\.\d+\.\d+)$",
        re.MULTILINE,
    )
    match = pattern.search(mapping)
    return match.group("version") if match is not None else None


def _npm_lock_package_versions(
    lock: dict[str, object], package: str
) -> tuple[tuple[int, ...], ...]:
    package_path = f"node_modules/{package}"
    packages = lock["packages"]
    assert isinstance(packages, dict)
    return tuple(
        _version_tuple(metadata["version"])
        for path, metadata in packages.items()
        if path == package_path or path.endswith(f"/{package_path}")
    )


def test_workspace_overrides_and_lock_hold_node_security_floors() -> None:
    workspace = (ROOT / "pnpm-workspace.yaml").read_text(encoding="utf-8")
    lock = (ROOT / "pnpm-lock.yaml").read_text(encoding="utf-8")
    override_match = re.search(
        r"^overrides:\n(?P<body>(?:  .+\n)+)\nimporters:", lock, re.M
    )
    assert override_match is not None
    lock_overrides = override_match.group("body")

    for package, version in NODE_SECURITY_FLOORS.items():
        assert _yaml_mapping_version(workspace, package) == version
        assert _yaml_mapping_version(lock_overrides, package) == version
        versions = _pnpm_lock_versions(lock, package)
        assert versions == {_version_tuple(version)}


def test_python_manifests_and_locks_hold_starlette_security_floor() -> None:
    manifest = tomllib.loads(
        (ROOT / "apps/guard-api/pyproject.toml").read_text(encoding="utf-8")
    )
    dependencies = manifest["project"]["dependencies"]
    assert "fastapi>=0.141.1" in dependencies
    assert "starlette>=1.3.1" in dependencies

    for lock_path in (ROOT / "uv.lock", ROOT / "apps/guard-api/uv.lock"):
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        packages = {item["name"]: item["version"] for item in lock["package"]}
        assert _version_tuple(packages["fastapi"]) >= (0, 141, 1)
        assert _version_tuple(packages["starlette"]) >= (1, 3, 1)


def test_legacy_fixture_locks_are_private_identical_and_patched() -> None:
    lock_digests: set[str] = set()

    for name in FIXTURE_NAMES:
        fixture = FIXTURE_ROOT / name
        manifest = json.loads((fixture / "package.json").read_text(encoding="utf-8"))
        lock_bytes = (fixture / "package-lock.json").read_bytes()
        lock = json.loads(lock_bytes)

        assert manifest["name"] == "agentguard-benchmark-fixture"
        assert manifest["private"] is True
        assert manifest["dependencies"]["express"] == "^4.22.2"
        assert manifest["overrides"] == {
            "body-parser": "1.20.6",
            "path-to-regexp": "0.1.13",
            "qs": "6.15.3",
        }
        assert lock["name"] == manifest["name"]
        for package, floor in LEGACY_FIXTURE_SECURITY_FLOORS.items():
            versions = _npm_lock_package_versions(lock, package)
            assert versions
            assert all(version >= _version_tuple(floor) for version in versions)
        for package, expected in LEGACY_FIXTURE_EXACT_VERSIONS.items():
            versions = _npm_lock_package_versions(lock, package)
            assert versions
            assert all(version == _version_tuple(expected) for version in versions)
        lock_digests.add(hashlib.sha256(lock_bytes).hexdigest())

    assert len(lock_digests) == 1
