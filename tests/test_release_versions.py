from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil

import pytest

pytestmark = pytest.mark.contract


def _load_version_module():
    script = Path(__file__).resolve().parents[1] / "scripts/check-release-versions.py"
    spec = importlib.util.spec_from_file_location("check_release_versions", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_versions_are_consistent() -> None:
    versions = _load_version_module()
    assert versions.validate() == []
    assert versions.validate(versions.GIT_TAG) == []
    assert set(versions.PYTHON_PROJECTS) == {
        "aegis-agentguard-api",
        "aegis-agentguard-cli",
        "aegis-agentguard-core",
        "agentguard-langgraph-adapter",
    }
    assert versions.GHCR_TAG == "ghcr.io/jtoday666/agentguard-api:0.1.0-rc.1"


def test_release_tag_mismatch_is_rejected() -> None:
    versions = _load_version_module()
    errors = versions.validate("v0.1.0")
    assert errors == ["release tag 'v0.1.0' != 'v0.1.0-rc.1'"]


def _candidate_tree(tmp_path, module):
    paths = [
        *module.PYTHON_PROJECTS.values(),
        "uv.lock",
        "apps/guard-api/uv.lock",
        "apps/guard-api/Dockerfile",
    ]
    paths += [
        "packages/agentguard-core/agentguard_core/_version.py",
        "apps/guard-api/guard_api/_version.py",
        "apps/cli/agentguard_cli/_version.py",
        "packages/agentguard-openclaw-plugin/package.json",
        "packages/agentguard-openclaw-plugin/openclaw.plugin.json",
        "packages/agentguard-openclaw-plugin/src/index.ts",
        "packages/agentguard-openclaw-plugin/product-runtime/product/package.json",
        "packages/agentguard-openclaw-plugin/product-runtime/product/openclaw.plugin.json",
        "packages/agentguard-openclaw-plugin/product-runtime/factory.mjs",
    ]
    for relative in paths:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(module.ROOT / relative, target)
    module.ROOT = tmp_path
    assert module.validate() == []


@pytest.mark.parametrize(
    "relative,old,new,error",
    [
        (
            "packages/agentguard-langgraph-adapter/pyproject.toml",
            'version = "0.1.0rc1"',
            'version = "0.1.0"',
            "version",
        ),
        (
            "apps/guard-api/pyproject.toml",
            "aegis-agentguard-core==0.1.0rc1",
            "aegis-agentguard-core>=0.1.0rc1",
            "exact candidate",
        ),
        ("apps/cli/agentguard_cli/_version.py", '"0.1.0rc1"', '"0.1.0b1"', "fallback"),
        (
            "uv.lock",
            'source = { editable = "packages/agentguard-core" }',
            'source = { registry = "https://pypi.org/simple" }',
            "local source candidate",
        ),
        (
            "apps/guard-api/uv.lock",
            'source = { editable = "../../packages/agentguard-core" }',
            'source = { registry = "https://pypi.org/simple" }',
            "local source candidate",
        ),
        (
            "packages/agentguard-openclaw-plugin/product-runtime/product/package.json",
            '"0.1.0-rc.1"',
            '"0.1.0"',
            "Product package",
        ),
        (
            "packages/agentguard-openclaw-plugin/product-runtime/product/openclaw.plugin.json",
            '"0.1.0-rc.1"',
            '"0.1.0"',
            "Product package",
        ),
        (
            "packages/agentguard-openclaw-plugin/product-runtime/factory.mjs",
            '"0.1.0-rc.1"',
            '"0.1.0"',
            "factory self-reported",
        ),
        (
            "apps/guard-api/Dockerfile",
            "aegis-agentguard-core==0.1.0rc1",
            "aegis-agentguard-core==0.1.0b1",
            "release mapping",
        ),
    ],
)
def test_candidate_versions_reject_actual_source_drift(
    tmp_path, relative, old, new, error
):
    versions = _load_version_module()
    _candidate_tree(tmp_path, versions)
    path = tmp_path / relative
    content = path.read_text()
    assert old in content
    path.write_text(content.replace(old, new))
    assert any(error in item for item in versions.validate())


def test_all_python_candidates_and_both_locks_are_required(tmp_path):
    versions = _load_version_module()
    _candidate_tree(tmp_path, versions)
    assert versions.PYTHON_VERSION == "0.1.0rc1"
    package = json.loads(
        (tmp_path / "packages/agentguard-openclaw-plugin/package.json").read_text()
    )
    assert package["version"] == "0.1.0-rc.1"
    path = tmp_path / "uv.lock"
    path.write_text(
        path.read_text()
        + '\n[[package]]\nname = "agentguard-langgraph-adapter"\nversion = "0.1.0rc1"\nsource = { editable = "packages/agentguard-langgraph-adapter" }\n'
    )
    assert any("candidate version mismatch" in item for item in versions.validate())
