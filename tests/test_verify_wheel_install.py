from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.contract


def _load_script():
    path = Path(__file__).parents[1] / "scripts" / "verify-wheel-install.py"
    spec = importlib.util.spec_from_file_location("verify_wheel_install", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_local_wheels_selects_the_exact_built_artifacts(tmp_path: Path) -> None:
    module = _load_script()
    expected: list[Path] = []
    for directory in module._WHEEL_DIRECTORIES:
        wheel_dir = tmp_path / directory
        wheel_dir.mkdir()
        wheel = wheel_dir / f"{directory.replace('-', '_')}-0.1.0b1-py3-none-any.whl"
        wheel.write_bytes(b"local wheel")
        (wheel_dir / "source.tar.gz").write_bytes(b"sdist")
        expected.append(wheel)

    assert module._local_wheels(tmp_path) == expected


def test_local_wheels_rejects_missing_or_ambiguous_artifacts(tmp_path: Path) -> None:
    module = _load_script()
    for directory in module._WHEEL_DIRECTORIES:
        (tmp_path / directory).mkdir()

    with pytest.raises(RuntimeError, match="found 0"):
        module._local_wheels(tmp_path)

    first = tmp_path / module._WHEEL_DIRECTORIES[0]
    (first / "one.whl").write_bytes(b"one")
    (first / "two.whl").write_bytes(b"two")
    with pytest.raises(RuntimeError, match="found 2"):
        module._local_wheels(tmp_path)
