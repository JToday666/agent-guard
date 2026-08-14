from __future__ import annotations

import importlib.util
import json
from pathlib import Path

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


def test_contract_checksum_manifest_is_current() -> None:
    tools = _load_contract_tools()

    tools.verify_checksums()
