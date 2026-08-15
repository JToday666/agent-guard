from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_contract_tools():
    path = ROOT / "scripts" / "v21-contract-tools.py"
    spec = importlib.util.spec_from_file_location("v21_contract_tools", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_contract_freeze_package_is_schema_valid_and_cross_consistent() -> None:
    tools = _load_contract_tools()

    tools.validate()


def test_contract_machine_files_are_json_compatible_yaml() -> None:
    freeze_dir = ROOT / "docs" / "AgentGuard_Core_V2.1_Final_Contract_Freeze"

    for name in ("FREEZE_METADATA.yaml", "contract_freeze.yaml", "fusion_matrix.yaml"):
        parsed = json.loads((freeze_dir / name).read_text(encoding="utf-8"))
        assert isinstance(parsed, dict)


def test_frozen_status_has_matching_contract_and_review_signoff() -> None:
    freeze_dir = ROOT / "docs" / "AgentGuard_Core_V2.1_Final_Contract_Freeze"
    metadata = json.loads(
        (freeze_dir / "FREEZE_METADATA.yaml").read_text(encoding="utf-8")
    )
    contract = json.loads(
        (freeze_dir / "contract_freeze.yaml").read_text(encoding="utf-8")
    )

    assert metadata["status"] == "frozen"
    assert contract["status"] == "frozen"
    assert metadata["review_signoff"] == {
        "confirmed_by": "repository_owner",
        "confirmed_via": "explicit_user_confirmation_in_codex_task",
        "confirmed_at": "2026-08-14",
    }


def test_baseline_count_parses_pytest_collection_summary() -> None:
    tools = _load_contract_tools()

    assert tools._parse_collected_count("953 tests collected in 12.34s\n") == 953
    assert tools._parse_collected_count("noise\n1 test collected in 0.01s") == 1
    assert tools._parse_collected_count("no tests here") is None


def test_baseline_count_enforces_minimum_threshold(monkeypatch) -> None:
    tools = _load_contract_tools()
    monkeypatch.setattr(tools, "collect_test_count", lambda: 953)
    monkeypatch.setattr(sys, "argv", ["v21-contract-tools.py", "baseline-count"])
    assert tools.main() == 0

    monkeypatch.setattr(
        sys, "argv", ["v21-contract-tools.py", "baseline-count", "--min", "953"]
    )
    assert tools.main() == 0

    monkeypatch.setattr(
        sys, "argv", ["v21-contract-tools.py", "baseline-count", "--min", "954"]
    )
    with pytest.raises(ValueError, match="below the required baseline 954"):
        tools.main()
