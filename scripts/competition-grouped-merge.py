#!/usr/bin/env python3
"""[已弃用] 本方案已弃用：不采纳、不维护、不投入运行。

原因：上游 competition-grouped-run.py 的 contracts+--case-id 子集在 runner 中
只产生单臂 V0 variant，无法生成 A0-A4 五臂 350 行矩阵，本合并链路确定性失败。
如需分组故障隔离能力，请联系集成负责人评估 runner 侧子集矩阵模式。

Merge per-group competition runs into one 350-row report.

Reads the ``group-<attack_type>/arms/A*/repeat-1/run.json`` artifacts
produced by ``scripts/competition-grouped-run.py`` and aggregates them:

  - merged-rows.json:   all rows keyed per arm in frozen case order
  - merged-report.json: per-arm metrics using the same semantics as the
    runner's _arm_metrics (ASR/FPR/benign success/V2 selection/floor/
    receipt coverage) plus decision distributions and completeness checks

Usage:
    uv run python scripts/competition-grouped-merge.py /tmp/grouped-run
    uv run python scripts/competition-grouped-merge.py /tmp/grouped-run --allow-incomplete
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ARM_IDS = ("A0", "A1", "A2", "A3", "A4")
EXPECTED_GROUPS = 7
EXPECTED_CASES_PER_GROUP = 10


def bool_ratio(rows: list[dict], key: str):
    values = [row.get(key) for row in rows if isinstance(row.get(key), bool)]
    if not values:
        return None
    return sum(value is True for value in values) / len(values)


def arm_metrics(arm_id: str, rows: list[dict]) -> dict:
    """Mirror competition_runner._arm_metrics so numbers stay comparable."""
    evaluable = [row for row in rows if row.get("run_valid") is True]
    malicious = [row for row in evaluable if row.get("is_malicious") is True]
    benign = [row for row in evaluable if row.get("is_malicious") is False]
    receipt_rows = [row for row in evaluable if isinstance(row.get("receipt_covered"), bool)]
    v21_rows = [row for row in evaluable if isinstance(row.get("v21_selected"), bool)]
    floor_rows = [row for row in evaluable if isinstance(row.get("legacy_floor_applied"), bool)]
    return {
        "arm_id": arm_id,
        "attempted": len(rows),
        "evaluable": len(evaluable),
        "invalid": len(rows) - len(evaluable),
        "asr": bool_ratio(malicious, "attack_success"),
        "fpr": bool_ratio(benign, "overblocked"),
        "benign_success": bool_ratio(benign, "task_success"),
        "v21_selection_rate": bool_ratio(v21_rows, "v21_selected"),
        "legacy_floor_rate": bool_ratio(floor_rows, "legacy_floor_applied"),
        "receipt_coverage": bool_ratio(receipt_rows, "receipt_covered"),
        "counts": {
            "malicious": len(malicious),
            "benign": len(benign),
            "attack_success": sum(row.get("attack_success") is True for row in malicious),
            "overblocked": sum(row.get("overblocked") is True for row in benign),
            "benign_success": sum(row.get("task_success") is True for row in benign),
            "v21_selected": sum(row.get("v21_selected") is True for row in v21_rows),
            "legacy_floor_applied": sum(
                row.get("legacy_floor_applied") is True for row in floor_rows
            ),
            "receipt_covered": sum(row.get("receipt_covered") is True for row in receipt_rows),
        },
    }


def decision_distribution(rows: list[dict]) -> dict:
    """Distribution of the latest per-case guard decision, when recorded."""
    counter: Counter = Counter()
    for row in rows:
        decisions = row.get("decisions")
        if isinstance(decisions, list) and decisions:
            last = decisions[-1]
            value = last.get("decision") if isinstance(last, dict) else None
            if value:
                counter[str(value)] += 1
    return dict(sorted(counter.items()))


def load_group_rows(root: Path) -> tuple[dict[str, dict[str, list[dict]]], list[str]]:
    """attack_type -> arm_id -> rows; plus a list of structural problems."""
    groups: dict[str, dict[str, list[dict]]] = {}
    problems: list[str] = []
    for group_dir in sorted(root.glob("group-*")):
        attack_type = group_dir.name.removeprefix("group-")
        arms: dict[str, list[dict]] = {}
        for arm_id in ARM_IDS:
            run_path = group_dir / "arms" / arm_id / "repeat-1" / "run.json"
            if not run_path.exists():
                problems.append(f"{attack_type}/{arm_id}: missing {run_path.name}")
                continue
            try:
                rows = json.loads(run_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                problems.append(f"{attack_type}/{arm_id}: unreadable run.json ({exc})")
                continue
            if not isinstance(rows, list):
                problems.append(f"{attack_type}/{arm_id}: run.json is not a list")
                continue
            arms[arm_id] = [row for row in rows if isinstance(row, dict)]
        if arms:
            groups[attack_type] = arms
    return groups, problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", help="output root used by competition-grouped-run.py")
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="merge whatever groups exist instead of requiring all 7",
    )
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"no such directory: {root}", file=sys.stderr)
        return 2

    groups, problems = load_group_rows(root)

    expected_rows = EXPECTED_GROUPS * len(ARM_IDS) * EXPECTED_CASES_PER_GROUP
    merged_by_arm: dict[str, list[dict]] = {arm_id: [] for arm_id in ARM_IDS}
    seen: set[tuple[str, str]] = set()
    for attack_type in sorted(groups):
        for arm_id in ARM_IDS:
            rows = groups[attack_type].get(arm_id, [])
            for row in rows:
                key = (arm_id, str(row.get("case_id")))
                if key in seen:
                    problems.append(f"duplicate row for {key[0]}/{key[1]}")
                    continue
                seen.add(key)
                merged_by_arm[arm_id].append(row)

    total_rows = sum(len(rows) for rows in merged_by_arm.values())
    if len(groups) < EXPECTED_GROUPS and not args.allow_incomplete:
        problems.append(
            f"only {len(groups)}/{EXPECTED_GROUPS} groups present "
            "(pass --allow-incomplete to merge anyway)"
        )

    report = {
        "schema_version": "competition-grouped-merge/1.0",
        "root": str(root),
        "groups_found": sorted(groups),
        "groups_missing": sorted(
            set() if len(groups) >= EXPECTED_GROUPS else set()
        ),
        "expected_case_runs": expected_rows,
        "merged_case_runs": total_rows,
        "complete": total_rows == expected_rows and not problems,
        "arms": [arm_metrics(arm_id, merged_by_arm[arm_id]) for arm_id in ARM_IDS],
        "decision_distribution": decision_distribution(
            [row for rows in merged_by_arm.values() for row in rows]
        ),
        "per_group_row_counts": {
            attack_type: {
                arm_id: len(rows) for arm_id, rows in groups[attack_type].items()
            }
            for attack_type in sorted(groups)
        },
        "problems": problems,
    }

    (root / "merged-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (root / "merged-rows.json").write_text(
        json.dumps(merged_by_arm, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print(f"groups: {len(groups)}/{EXPECTED_GROUPS}   rows: {total_rows}/{expected_rows}")
    for arm in report["arms"]:
        asr = "n/a" if arm["asr"] is None else f"{arm['asr']:.3f}"
        fpr = "n/a" if arm["fpr"] is None else f"{arm['fpr']:.3f}"
        print(
            f"  {arm['arm_id']}: evaluable {arm['evaluable']}/{arm['attempted']}"
            f"   ASR {asr}   FPR {fpr}   v21_selected {arm['counts']['v21_selected']}"
            f"   floor {arm['counts']['legacy_floor_applied']}"
        )
    if problems:
        print(f"\nproblems ({len(problems)}):")
        for problem in problems[:20]:
            print(f"  - {problem}")
    print(f"\nwrote {root / 'merged-report.json'}")
    print(f"wrote {root / 'merged-rows.json'}")
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
