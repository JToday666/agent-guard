from __future__ import annotations

import importlib.util
import json
import typing
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CT_FREEZE_DIR = ROOT / "docs" / "AgentGuard_Context_Isolation_Taint_Tracking_Final_RC"
V21_FREEZE_DIR = ROOT / "docs" / "AgentGuard_Core_V2.1_Final_Contract_Freeze"


def _load_contract_tools():
    path = ROOT / "scripts" / "ct-contract-tools.py"
    spec = importlib.util.spec_from_file_location("ct_contract_tools", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tools():
    return _load_contract_tools()


@pytest.fixture(scope="module")
def ct_contract() -> dict:
    return json.loads(
        (CT_FREEZE_DIR / "context_taint_contract_freeze.yaml").read_text(
            encoding="utf-8"
        )
    )


@pytest.fixture(scope="module")
def ct_metadata() -> dict:
    return json.loads(
        (CT_FREEZE_DIR / "CT_FREEZE_METADATA.yaml").read_text(encoding="utf-8")
    )


def test_ct_freeze_package_is_schema_valid_and_cross_consistent(tools) -> None:
    tools.validate()


def test_ct_machine_files_are_json_compatible_yaml() -> None:
    for name in (
        "context_taint_contract_freeze.yaml",
        "CT_FREEZE_METADATA.yaml",
        "context_taint_contract_freeze.schema.json",
    ):
        parsed = json.loads((CT_FREEZE_DIR / name).read_text(encoding="utf-8"))
        assert isinstance(parsed, dict)


def test_ct_frozen_status_requires_review_signoff(ct_contract, ct_metadata) -> None:
    assert ct_metadata["status"] == "frozen"
    assert ct_contract["status"] == ct_metadata["status"]
    assert ct_metadata["review_signoff"] == {
        "confirmed_by": "repository_owner",
        "confirmed_via": "explicit_user_confirmation_in_qoder_task",
        "confirmed_at": "2026-08-15",
    }


def test_ct_invariants_are_exactly_twelve(ct_contract) -> None:
    invariants = ct_contract["invariants"]
    expected_ids = {f"CT-F0-{index:02d}" for index in range(1, 13)}
    assert set(invariants) == expected_ids
    assert all(isinstance(name, str) and name for name in invariants.values())


def test_ct_enums_match_core_code(ct_contract) -> None:
    # Independent re-implementation (not via the tools script): import the
    # CURRENT core model symbols directly and compare against the YAML sets.
    from agentguard_core.security_context.facts import FlowFact
    from agentguard_core.signals.models import FactAuthority, FlowStrength, TaintLabel

    assert set(ct_contract["taint_labels"]) == set(typing.get_args(TaintLabel))
    assert set(ct_contract["flow_strength"]["order_best_to_worst"]) == set(
        typing.get_args(FlowStrength)
    )
    relation_args = set(typing.get_args(FlowFact.model_fields["relation"].annotation))
    assert set(ct_contract["flow_relations"]) == relation_args
    claim_authorities = {
        entry["fact_authority"] for entry in ct_contract["source_defaults"].values()
    } - {"inherit_memory_fact"}
    assert claim_authorities <= set(typing.get_args(FactAuthority))


def test_ct_budgets_match_core_constants(ct_contract) -> None:
    from agentguard_core.security_context.projection import provenance
    from agentguard_core.security_context.projection import provenance_lookup

    budgets = ct_contract["budgets"]
    assert budgets["provenance_max_depth"] == provenance_lookup.DEFAULT_LOOKUP_MAX_DEPTH
    assert (
        budgets["provenance_max_breadth"]
        == provenance_lookup.DEFAULT_LOOKUP_MAX_BREADTH
    )
    assert (
        budgets["provenance_node_budget"]
        == provenance_lookup.DEFAULT_LOOKUP_NODE_BUDGET
    )
    assert budgets["sticky_taint_summaries"] == provenance.MAX_STICKY_TAINT_SUMMARIES
    assert budgets["sticky_summary_refs"] == provenance.MAX_SUMMARY_REFS
    assert (
        budgets["sticky_summary_evidence_refs"] == provenance.MAX_SUMMARY_EVIDENCE_REFS
    )


def test_ct_cross_consistent_with_v21_freeze(ct_contract) -> None:
    v21_contract = json.loads(
        (V21_FREEZE_DIR / "contract_freeze.yaml").read_text(encoding="utf-8")
    )
    assert set(ct_contract["taint_labels"]) == set(v21_contract["taint_labels"])
    assert set(ct_contract["flow_strength"]["order_best_to_worst"]) == set(
        v21_contract["flow_strengths"]
    )


def test_ct_checksums_are_up_to_date(tools) -> None:
    tools.verify_checksums()
