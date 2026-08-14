#!/usr/bin/env python3
"""Build and validate the V2.1 Final contract-freeze package."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
FREEZE_DIR = ROOT / "docs" / "AgentGuard_Core_V2.1_Final_Contract_Freeze"
COMBINED = FREEZE_DIR / "AgentGuard_Core_V2.1_Final_完整方案.md"
CHECKSUMS = FREEZE_DIR / "SHA256SUMS"
CHAPTERS = tuple(
    FREEZE_DIR / f"{index:02d}_{name}"
    for index, name in enumerate(
        (
            "最终架构与冻结边界.md",
            "F1字段与契约冻结.md",
            "状态投影_Provenance_Authority.md",
            "判定融合与Semantic契约.md",
            "兼容迁移与实施计划.md",
            "评测_性能_可信验收.md",
            "创新点与命题映射.md",
            "当前代码改造映射.md",
            "参考研究与证据要求.md",
            "冻结清单.md",
        )
    )
)


def _read_json_compatible_yaml(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name}: top-level value must be an object")
    return value


def render_combined() -> str:
    missing = [path.name for path in CHAPTERS if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing contract chapters: {', '.join(missing)}")
    metadata = _read_json_compatible_yaml(FREEZE_DIR / "FREEZE_METADATA.yaml")
    status_label = (
        "Contract Frozen"
        if metadata.get("status") == "frozen"
        else "Contract Freeze Candidate"
    )
    header = (
        "# AgentGuard Core V2.1-Final — 完整设计与实施方案\n\n"
        "> 本文件由分册按固定顺序聚合；分册是维护源。\n"
        f"> 当前状态：{status_label}。\n\n"
        "---\n\n"
    )
    chapters = "\n\n---\n\n".join(
        path.read_text(encoding="utf-8").strip() for path in CHAPTERS
    )
    return f"{header}{chapters}\n"


def build() -> None:
    COMBINED.write_text(render_combined(), encoding="utf-8", newline="\n")


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


def validate() -> None:
    contract = _validate_schema(
        FREEZE_DIR / "contract_freeze.yaml",
        FREEZE_DIR / "contract_freeze.schema.json",
    )
    matrix = _validate_schema(
        FREEZE_DIR / "fusion_matrix.yaml",
        FREEZE_DIR / "fusion_matrix.schema.json",
    )
    metadata = _read_json_compatible_yaml(FREEZE_DIR / "FREEZE_METADATA.yaml")

    status = metadata.get("status")
    if status not in {"candidate-for-freeze", "frozen"}:
        raise ValueError("FREEZE_METADATA.yaml has an unsupported freeze status")
    if contract.get("status") != status:
        raise ValueError("metadata and contract freeze statuses differ")
    if status == "frozen":
        signoff = metadata.get("review_signoff")
        if not isinstance(signoff, dict) or not all(
            signoff.get(field)
            for field in ("confirmed_by", "confirmed_via", "confirmed_at")
        ):
            raise ValueError(
                "frozen metadata requires explicit review sign-off evidence"
            )
        checklist = CHAPTERS[9].read_text(encoding="utf-8")
        design_checklist = checklist.split("## Evaluation", maxsplit=1)[0]
        allowed_implementation_items = {
            "rebuild determinism",
            "state flooding test",
            "localized gap degradation",
        }
        unchecked_design_items = {
            match.group(1).strip()
            for match in re.finditer(r"^- \[ \] (.+)$", design_checklist, re.MULTILINE)
        } - allowed_implementation_items
        if unchecked_design_items:
            raise ValueError(
                "frozen package has unsigned design items: "
                + ", ".join(sorted(unchecked_design_items))
            )

    dispositions = set(contract["fast_dispositions"])
    matrix_dispositions = set(matrix["disposition_priority"])
    if dispositions != matrix_dispositions:
        raise ValueError("contract and fusion matrix disposition enums differ")

    rule_ids = [
        rule["id"]
        for group in ("flow_rules", "influence_rules", "memory_rules", "behavior_rules")
        for rule in matrix[group]
    ]
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError("fusion matrix rule IDs must be unique")

    f0_ids = {item["id"] for item in contract["system_invariants"]}
    expected_f0 = {f"F0-{index}" for index in range(1, 13)}
    if f0_ids != expected_f0:
        raise ValueError("contract_freeze.yaml must define exactly F0-01 through F0-12")

    field_contract = CHAPTERS[1].read_text(encoding="utf-8")
    required_models = {
        "SequenceRef",
        "EvaluationClock",
        "CanonicalArguments",
        "RuntimeOutcomeFact",
        "BehaviorAggregate",
        "StickyTaintSummary",
        "ExecutionLease",
    }
    missing_models = sorted(required_models - set(contract["minimal_required_models"]))
    if missing_models:
        raise ValueError(f"minimal model list is missing: {', '.join(missing_models)}")
    undocumented_models = sorted(
        name for name in required_models if name not in field_contract
    )
    if undocumented_models:
        raise ValueError(
            f"field contract does not document: {', '.join(undocumented_models)}"
        )

    if (
        not COMBINED.is_file()
        or COMBINED.read_text(encoding="utf-8") != render_combined()
    ):
        raise ValueError("combined Markdown is stale; run the build command")


def _checksum_entries() -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for path in sorted(FREEZE_DIR.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file() or path == CHECKSUMS:
            continue
        relative = path.relative_to(FREEZE_DIR).as_posix()
        entries.append((hashlib.sha256(path.read_bytes()).hexdigest(), relative))
    return entries


def render_checksums() -> str:
    return "".join(
        f"{digest}  {relative}\n" for digest, relative in _checksum_entries()
    )


def write_checksums() -> None:
    CHECKSUMS.write_text(render_checksums(), encoding="utf-8", newline="\n")


def verify_checksums() -> None:
    if not CHECKSUMS.is_file():
        raise FileNotFoundError("SHA256SUMS does not exist")
    expected = CHECKSUMS.read_text(encoding="utf-8")
    actual = render_checksums()
    if expected != actual:
        raise ValueError("SHA256SUMS is stale; run the checksums --write command")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("build", help="rebuild the combined Markdown document")
    subparsers.add_parser(
        "validate", help="validate schemas and cross-file consistency"
    )
    checksums_parser = subparsers.add_parser(
        "checksums", help="write or verify SHA256SUMS"
    )
    checksums_mode = checksums_parser.add_mutually_exclusive_group(required=True)
    checksums_mode.add_argument("--write", action="store_true")
    checksums_mode.add_argument("--verify", action="store_true")
    subparsers.add_parser(
        "all", help="build, validate, and write the checksum manifest"
    )
    args = parser.parse_args()

    if args.command == "build":
        build()
    elif args.command == "validate":
        validate()
    elif args.command == "checksums":
        write_checksums() if args.write else verify_checksums()
    else:
        build()
        validate()
        write_checksums()
        verify_checksums()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
