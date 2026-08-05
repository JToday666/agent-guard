#!/usr/bin/env python
"""Run a Core-only rule matrix over GuardEvent JSONL cases."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "packages" / "agentguard-core"
if str(CORE_PATH) not in sys.path:
    sys.path.insert(0, str(CORE_PATH))

from agentguard_core import GuardEvent, evaluate  # noqa: E402

BLOCKING_DECISIONS = {"ask", "deny"}


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cases = load_cases(args.dataset)
    evaluated_cases = [evaluate_case(case) for case in cases]
    report = build_report(evaluated_cases)
    write_report(report, args.output_dir)
    print(json.dumps({"ok": report["ok"], **report["summary"]}, sort_keys=True))
    return 0 if report["ok"] else 1


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args(argv)


def load_cases(path: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            case = json.loads(line)
            case["_line_number"] = line_number
            cases.append(case)
    return cases


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    event = GuardEvent.model_validate(case["event"])
    decision = evaluate(event)
    expected_rule_ids = list(case.get("expected_rule_ids", []))
    actual_rule_ids = [hit.rule_id for hit in decision.rule_hits]
    expected_decision = str(case["expected_decision"])
    actual_decision = decision.decision
    case_ok = (
        expected_decision == actual_decision and expected_rule_ids == actual_rule_ids
    )
    return {
        "case_id": str(case["case_id"]),
        "line_number": case["_line_number"],
        "is_malicious": event.is_malicious,
        "expected_decision": expected_decision,
        "actual_decision": actual_decision,
        "expected_rule_ids": expected_rule_ids,
        "rule_hits": actual_rule_ids,
        "blocked": actual_decision in BLOCKING_DECISIONS,
        "ok": case_ok,
        "reason": decision.reason,
    }


def build_report(cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "ok": all(case["ok"] for case in cases),
        "summary": summarize_cases(cases),
        "rules": summarize_rules(cases),
        "cases": {case["case_id"]: case for case in cases},
    }


def summarize_cases(cases: list[dict[str, Any]]) -> dict[str, Any]:
    blocked = [case for case in cases if case["blocked"]]
    allowed = [case for case in cases if not case["blocked"]]
    benign = [case for case in cases if case["is_malicious"] is False]
    malicious = [case for case in cases if case["is_malicious"] is True]
    false_positives = [case for case in benign if case["blocked"]]
    false_negatives = [case for case in malicious if not case["blocked"]]
    return {
        "case_count": len(cases),
        "blocked": len(blocked),
        "allowed": len(allowed),
        "fpr": (len(false_positives) / len(benign)) if benign else None,
        "fnr": (len(false_negatives) / len(malicious)) if malicious else None,
    }


def summarize_rules(cases: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        for rule_id in sorted(set(case["expected_rule_ids"]) | set(case["rule_hits"])):
            grouped[rule_id].append(case)
    return {
        rule_id: summarize_cases(rule_cases)
        | {"case_ids": [case["case_id"] for case in rule_cases]}
        for rule_id, rule_cases in sorted(grouped.items())
    }


def write_report(report: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "core-rule-matrix-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "core-rule-matrix-report.md").write_text(
        render_markdown(report), encoding="utf-8"
    )


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# AgentGuard Core Rule Matrix",
        "",
        f"- Status: {'passed' if report['ok'] else 'failed'}",
        f"- Cases: {summary['case_count']}",
        f"- Blocked: {summary['blocked']}",
        f"- Allowed: {summary['allowed']}",
        f"- FPR: {summary['fpr']}",
        f"- FNR: {summary['fnr']}",
        "",
        "## Rules",
        "",
        "| Rule | Cases | Blocked | Allowed | FPR | FNR |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for rule_id, rule in report["rules"].items():
        lines.append(
            f"| {rule_id} | {rule['case_count']} | {rule['blocked']} | {rule['allowed']} | {rule['fpr']} | {rule['fnr']} |"
        )
    lines.extend(["", "## Cases", ""])
    for case in report["cases"].values():
        lines.append(
            f"- `{case['case_id']}` expected={case['expected_decision']} actual={case['actual_decision']} "
            f"rule_hits={case['rule_hits']}"
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
