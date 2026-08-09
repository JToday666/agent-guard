from __future__ import annotations

import importlib.util
from pathlib import Path


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
    }
    assert versions.GHCR_TAG == "ghcr.io/jtoday666/agentguard-api:0.1.0-beta.1"


def test_release_tag_mismatch_is_rejected() -> None:
    versions = _load_version_module()
    errors = versions.validate("v0.1.0")
    assert errors == ["release tag 'v0.1.0' != 'v0.1.0-beta.1'"]
