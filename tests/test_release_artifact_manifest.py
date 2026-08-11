from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

SOURCE_REVISION = "a" * 40


def _load_manifest_tool() -> ModuleType:
    script = Path(__file__).parents[1] / "scripts" / "release-artifact-manifest.py"
    spec = importlib.util.spec_from_file_location("release_artifact_manifest", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _artifact(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_release_manifest_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    tool = _load_manifest_tool()
    wheel = tmp_path / "python" / "package-1.0-py3-none-any.whl"
    tarball = tmp_path / "npm" / "package-1.0.tgz"
    manifest_path = tmp_path / "release-artifact-manifest.json"
    _artifact(wheel, b"wheel-v1")
    _artifact(tarball, b"tarball-v1")

    manifest = tool.write_manifest(tmp_path, manifest_path, SOURCE_REVISION)

    assert manifest["artifact_count"] == 2
    assert manifest["source_revision"] == SOURCE_REVISION
    assert tool.verify_manifest(tmp_path, manifest_path, SOURCE_REVISION) == []
    wheel.write_bytes(b"wheel-tampered")
    assert tool.verify_manifest(tmp_path, manifest_path, SOURCE_REVISION) == [
        "artifact python/package-1.0-py3-none-any.whl size mismatch",
        "artifact python/package-1.0-py3-none-any.whl sha256 mismatch",
    ]


def test_release_manifest_rejects_duplicate_archive_names(tmp_path: Path) -> None:
    tool = _load_manifest_tool()
    _artifact(tmp_path / "current" / "package-1.0.tgz", b"current")
    _artifact(tmp_path / "stale" / "package-1.0.tgz", b"stale")

    try:
        tool.build_manifest(tmp_path, SOURCE_REVISION)
    except tool.ReleaseManifestError as exc:
        assert str(exc) == (
            "duplicate release archive names: package-1.0.tgz: "
            "current/package-1.0.tgz, stale/package-1.0.tgz"
        )
    else:
        raise AssertionError("duplicate archive names must be rejected")


def test_release_manifest_rejects_unmanifested_archive(tmp_path: Path) -> None:
    tool = _load_manifest_tool()
    manifest_path = tmp_path / "release-artifact-manifest.json"
    _artifact(tmp_path / "package-1.0.tgz", b"first")
    tool.write_manifest(tmp_path, manifest_path, SOURCE_REVISION)
    _artifact(tmp_path / "package-2.0.tgz", b"second")

    assert tool.verify_manifest(tmp_path, manifest_path, SOURCE_REVISION) == [
        "unmanifested artifacts on disk: package-2.0.tgz"
    ]
    parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert parsed["schema_version"] == "1.1"


def test_release_manifest_rejects_source_revision_mismatch(tmp_path: Path) -> None:
    tool = _load_manifest_tool()
    manifest_path = tmp_path / "release-artifact-manifest.json"
    _artifact(tmp_path / "package-1.0.tgz", b"first")
    tool.write_manifest(tmp_path, manifest_path, SOURCE_REVISION)

    assert tool.verify_manifest(tmp_path, manifest_path, "b" * 40) == [
        "manifest source_revision does not match the requested source"
    ]
