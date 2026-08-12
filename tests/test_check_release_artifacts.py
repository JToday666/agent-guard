from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path
from types import ModuleType


def _load_scanner() -> ModuleType:
    script = Path(__file__).parents[1] / "scripts" / "check-release-artifacts.py"
    spec = importlib.util.spec_from_file_location("check_release_artifacts", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _wheel(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("package/LICENSE", "MIT")


def test_release_scanner_rejects_same_archive_name_in_multiple_directories(
    tmp_path: Path,
) -> None:
    scanner = _load_scanner()
    archive_name = "aegis_agentguard_api-0.1.0b1-py3-none-any.whl"
    scanner.EXPECTED_ARCHIVES = {archive_name}
    _wheel(tmp_path / "current" / archive_name)
    _wheel(tmp_path / "stale" / archive_name)

    errors = scanner.validate(tmp_path)

    assert errors == [
        (
            f"duplicate archive {archive_name}: "
            f"current/{archive_name}, stale/{archive_name}"
        )
    ]


def test_release_scanner_still_reports_distinct_unexpected_archives(
    tmp_path: Path,
) -> None:
    scanner = _load_scanner()
    expected = "aegis_agentguard_core-0.1.0b1-py3-none-any.whl"
    unexpected = "aegis_agentguard_meta-0.1.0b1-py3-none-any.whl"
    scanner.EXPECTED_ARCHIVES = {expected}
    _wheel(tmp_path / expected)
    _wheel(tmp_path / unexpected)

    errors = scanner.validate(tmp_path)

    assert errors == [f"unexpected archives: {unexpected}"]
