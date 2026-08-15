#!/usr/bin/env python3
"""Validate the Context/Taint (CT) contract-freeze package (CT-PR-00).

CT-PR-00 scope: design package, machine freeze YAML, and contract tests
only. This tool never touches production code; it only validates that the
frozen machine files are internally consistent, stay aligned with the
CURRENT (already implemented) core model symbols, and remain
cross-consistent with the AgentGuard Core V2.1 freeze package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import typing
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
CT_FREEZE_DIR = ROOT / "docs" / "AgentGuard_Context_Isolation_Taint_Tracking_Final_RC"
CT_CONTRACT = CT_FREEZE_DIR / "context_taint_contract_freeze.yaml"
CT_SCHEMA = CT_FREEZE_DIR / "context_taint_contract_freeze.schema.json"
CT_METADATA = CT_FREEZE_DIR / "CT_FREEZE_METADATA.yaml"
CT_DECISIONS = CT_FREEZE_DIR / "12_未决问题处置与决策记录.md"
CHECKSUMS = CT_FREEZE_DIR / "SHA256SUMS.md"
V21_FREEZE_DIR = ROOT / "docs" / "AgentGuard_Core_V2.1_Final_Contract_Freeze"

EXPECTED_REVIEW_IDS = [f"CT-Q-{index:02d}" for index in range(1, 19)]

# Mirror tests/conftest.py: inject the core package path so the pure
# pydantic model modules can be imported without installation.
_CORE_PATH = ROOT / "packages" / "agentguard-core"
if _CORE_PATH.exists() and str(_CORE_PATH) not in sys.path:
    sys.path.insert(0, str(_CORE_PATH))


def _read_json_compatible_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"{path.name}: file does not exist") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name}: not JSON-compatible YAML ({exc})") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path.name}: top-level value must be an object")
    return value


def _literal_args(annotation: Any) -> set[str]:
    args = typing.get_args(annotation)
    if not args or not all(isinstance(item, str) for item in args):
        raise ValueError(f"expected a string Literal annotation, got {annotation!r}")
    return set(args)


def _validate_schema(instance_path: Path, schema_path: Path) -> dict[str, Any]:
    instance = _read_json_compatible_yaml(instance_path)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(instance),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        details = "; ".join(
            f"/{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
            for error in errors
        )
        raise ValueError(f"{instance_path.name} violates {schema_path.name}: {details}")
    return instance


def _validate_metadata(contract: dict[str, Any]) -> None:
    metadata = _read_json_compatible_yaml(CT_METADATA)
    status = metadata.get("status")
    if status not in {"candidate-for-freeze", "frozen"}:
        raise ValueError("CT_FREEZE_METADATA.yaml has an unsupported freeze status")
    if contract.get("status") != status:
        raise ValueError("CT metadata and contract freeze statuses differ")
    baseline_ref = metadata.get("design_baseline_ref")
    if baseline_ref != contract["repository_baseline"]["ref"]:
        raise ValueError(
            "CT_FREEZE_METADATA.yaml design_baseline_ref differs from "
            "contract repository_baseline.ref"
        )
    if status == "frozen":
        signoff = metadata.get("review_signoff")
        if not isinstance(signoff, dict) or not all(
            signoff.get(field)
            for field in ("confirmed_by", "confirmed_via", "confirmed_at")
        ):
            raise ValueError(
                "frozen metadata requires explicit review sign-off evidence"
            )
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(signoff["confirmed_at"])):
            raise ValueError(
                "review_signoff.confirmed_at must be an ISO date (YYYY-MM-DD)"
            )


def _validate_core_alignment(contract: dict[str, Any]) -> None:
    """Cross-check the frozen YAML against CURRENT core model symbols.

    Only pure pydantic model modules / constants are imported; nothing with
    DB/HTTP side effects is touched.
    """
    from agentguard_core.security_context import facts
    from agentguard_core.security_context.projection import provenance
    from agentguard_core.security_context.projection import provenance_lookup
    from agentguard_core.signals import models

    taint_labels = set(contract["taint_labels"])
    if taint_labels != set(typing.get_args(models.TaintLabel)):
        raise ValueError("frozen taint_labels differ from core TaintLabel")

    strengths = contract["flow_strength"]["order_best_to_worst"]
    if set(strengths) != set(typing.get_args(models.FlowStrength)):
        raise ValueError("frozen flow strength differ from core FlowStrength")

    relation_args = _literal_args(facts.FlowFact.model_fields["relation"].annotation)
    if set(contract["flow_relations"]) != relation_args:
        raise ValueError("frozen flow_relations differ from core FlowFact.relation")

    authority_args = set(typing.get_args(models.FactAuthority))
    claim_authorities = {
        entry["fact_authority"] for entry in contract["source_defaults"].values()
    } - {"inherit_memory_fact"}
    if not claim_authorities <= authority_args:
        missing = sorted(claim_authorities - authority_args)
        raise ValueError(
            f"source_defaults fact_authority values not in FactAuthority: {missing}"
        )

    source_type_args = _literal_args(
        facts.SourceFact.model_fields["source_type"].annotation
    )
    if not set(contract["source_defaults"]) <= source_type_args:
        unknown = sorted(set(contract["source_defaults"]) - source_type_args)
        raise ValueError(
            f"source_defaults keys not in SourceFact.source_type: {unknown}"
        )

    budgets = contract["budgets"]
    expected_budgets = {
        "provenance_max_depth": provenance_lookup.DEFAULT_LOOKUP_MAX_DEPTH,
        "provenance_max_breadth": provenance_lookup.DEFAULT_LOOKUP_MAX_BREADTH,
        "provenance_node_budget": provenance_lookup.DEFAULT_LOOKUP_NODE_BUDGET,
        "sticky_taint_summaries": provenance.MAX_STICKY_TAINT_SUMMARIES,
        "sticky_summary_refs": provenance.MAX_SUMMARY_REFS,
        "sticky_summary_evidence_refs": provenance.MAX_SUMMARY_EVIDENCE_REFS,
    }
    for name, expected in expected_budgets.items():
        if budgets[name] != expected:
            raise ValueError(
                f"budgets.{name}={budgets[name]} differs from core constant {expected}"
            )

    protected = set(contract["declassification"]["protected_labels"])
    if protected != set(getattr(provenance, "_PROTECTED_LABELS")):
        raise ValueError(
            "declassification.protected_labels differ from core _PROTECTED_LABELS"
        )

    producer_args = _literal_args(
        facts.DeclassificationFact.model_fields["producer"].annotation
    )
    if producer_args != {"trusted_declassifier"}:
        raise ValueError(
            "DeclassificationFact.producer must be exactly 'trusted_declassifier'"
        )

    lease_fields = set(facts.ExecutionLease.model_fields)
    binding_fields = set(contract["runtime"]["strong_binding_fields"])
    if not binding_fields <= lease_fields:
        missing = sorted(binding_fields - lease_fields)
        raise ValueError(
            f"runtime.strong_binding_fields missing from ExecutionLease: {missing}"
        )


def _validate_v21_cross_consistency(contract: dict[str, Any]) -> None:
    v21_contract = _read_json_compatible_yaml(V21_FREEZE_DIR / "contract_freeze.yaml")

    ct_taints = set(contract["taint_labels"])
    if ct_taints != set(v21_contract["taint_labels"]):
        raise ValueError("CT and V2.1 taint_labels differ")

    ct_strengths = set(contract["flow_strength"]["order_best_to_worst"])
    if ct_strengths != set(v21_contract["flow_strengths"]):
        raise ValueError("CT and V2.1 flow strength sets differ")

    machine_truth = ROOT / contract["fusion"]["machine_truth"]
    if not machine_truth.is_file():
        raise ValueError(f"fusion.machine_truth target does not exist: {machine_truth}")

    matrix = json.loads(machine_truth.read_text(encoding="utf-8"))
    matrix_taints: set[str] = set()
    rule_groups = ("flow_rules", "influence_rules", "memory_rules", "behavior_rules")
    for group in rule_groups:
        rules = matrix.get(group)
        if not isinstance(rules, list):
            raise ValueError(
                f"fusion matrix is missing rule group '{group}'; "
                "refusing to skip taint extraction"
            )
        for rule in rules:
            taint = rule.get("taint")
            if isinstance(taint, str):
                matrix_taints.add(taint)
            elif isinstance(taint, list):
                matrix_taints.update(item for item in taint if isinstance(item, str))
    if not matrix_taints:
        raise ValueError(
            "fusion matrix taint extraction yielded an empty set; "
            "the matrix structure likely drifted"
        )
    if not matrix_taints <= ct_taints:
        unknown = sorted(matrix_taints - ct_taints)
        raise ValueError(
            f"fusion matrix taint values not in CT taint_labels: {unknown}"
        )


def _validate_review_decisions(contract: dict[str, Any]) -> None:
    decisions = contract["freeze_review_decisions"]
    ids = [entry["id"] for entry in decisions]
    if ids != EXPECTED_REVIEW_IDS:
        raise ValueError(
            "freeze_review_decisions must list exactly CT-Q-01 through CT-Q-18 in order"
        )
    document = CT_DECISIONS.read_text(encoding="utf-8")
    for entry in decisions:
        review_id = entry["id"]
        suffix = review_id.removeprefix("CT-Q-")
        expected_ref = f"12_未决问题处置与决策记录.md#ct-q-{suffix}"
        if entry["answer_ref"] != expected_ref:
            raise ValueError(f"{review_id}: answer_ref must be {expected_ref}")
        if not re.search(rf"^## {re.escape(review_id)}\s*$", document, re.MULTILINE):
            raise ValueError(
                f"{review_id}: missing '## {review_id}' anchor in {CT_DECISIONS.name}"
            )


def validate() -> None:
    contract = _validate_schema(CT_CONTRACT, CT_SCHEMA)
    _validate_metadata(contract)
    _validate_core_alignment(contract)
    _validate_v21_cross_consistency(contract)
    _validate_review_decisions(contract)
    verify_checksums()


def _checksum_entries() -> list[tuple[str, int, str]]:
    entries: list[tuple[str, int, str]] = []
    for path in sorted(CT_FREEZE_DIR.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file() or path == CHECKSUMS:
            continue
        content = path.read_bytes()
        if path.suffix in {".json", ".md", ".yaml"}:
            content = content.replace(b"\r\n", b"\n")
        relative = path.relative_to(CT_FREEZE_DIR).as_posix()
        entries.append((relative, len(content), hashlib.sha256(content).hexdigest()))
    return entries


def render_checksums() -> str:
    lines = [
        "# 文件清单与 SHA256",
        "",
    ]
    for relative, size, digest in _checksum_entries():
        lines.append(f"- `{relative}` — {size} bytes — `sha256:{digest}`")
    return "\n".join(lines) + "\n"


def write_checksums() -> None:
    CHECKSUMS.write_text(render_checksums(), encoding="utf-8", newline="\n")


def verify_checksums() -> None:
    if not CHECKSUMS.is_file():
        raise FileNotFoundError(f"{CHECKSUMS.name} does not exist")
    expected = CHECKSUMS.read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
    actual = render_checksums()
    if expected != actual:
        raise ValueError(
            f"{CHECKSUMS.name} is stale; run the checksums --write command"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "validate", help="validate schemas and cross-file consistency"
    )
    checksums_parser = subparsers.add_parser(
        "checksums", help="write or verify the freeze package SHA256SUMS.md"
    )
    checksums_mode = checksums_parser.add_mutually_exclusive_group(required=True)
    checksums_mode.add_argument("--write", action="store_true")
    checksums_mode.add_argument("--verify", action="store_true")
    subparsers.add_parser(
        "all",
        help="validate first, then refresh and verify the SHA256SUMS.md manifest",
    )
    args = parser.parse_args()

    if args.command == "validate":
        validate()
    elif args.command == "checksums":
        write_checksums() if args.write else verify_checksums()
    else:
        validate()
        write_checksums()
        verify_checksums()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
