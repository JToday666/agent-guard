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

from agentguard_core import (  # noqa: E402
    SUPPORTED_POLICY_RULE_IDS,
    GuardEvent,
    PolicyBundle,
    evaluate,
)

BLOCKING_DECISIONS = {"ask", "deny"}
REQUIRED_QUADRANTS = {"positive", "benign", "disabled", "override"}


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cases = expand_cases(load_cases(args.dataset))
    validate_matrix(cases)
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


def expand_cases(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for entry in entries:
        if "rule_id" not in entry:
            cases.append(entry)
            continue
        rule_id = str(entry["rule_id"])
        positive_event = _event_with_defaults(
            entry["positive_event"], f"{rule_id}_positive", is_malicious=True
        )
        benign_event = _event_with_defaults(
            entry.get("benign_event", _default_benign_event()),
            f"{rule_id}_benign",
            is_malicious=False,
        )
        default_decision = str(entry["expected_default_decision"])
        override_decision = "deny" if default_decision == "ask" else "ask"
        common = {"rule_id": rule_id, "_line_number": entry["_line_number"]}
        cases.extend(
            [
                common
                | {
                    "case_id": f"{rule_id}_positive",
                    "quadrant": "positive",
                    "event": positive_event,
                    "expected_decision": default_decision,
                    "expected_rule_ids": [rule_id],
                },
                common
                | {
                    "case_id": f"{rule_id}_benign",
                    "quadrant": "benign",
                    "event": benign_event,
                    "expected_decision": "allow",
                    "expected_rule_ids": [],
                },
                common
                | {
                    "case_id": f"{rule_id}_disabled",
                    "quadrant": "disabled",
                    "event": positive_event,
                    "policies": {"disabled_rules": [rule_id]},
                    "expected_decision": "allow",
                    "expected_rule_ids": [],
                },
                common
                | {
                    "case_id": f"{rule_id}_override",
                    "quadrant": "override",
                    "event": positive_event,
                    "policies": {
                        "rule_overrides": {
                            rule_id: {"decision": override_decision}
                        }
                    },
                    "expected_decision": override_decision,
                    "expected_rule_ids": [rule_id],
                },
            ]
        )
    return cases


def validate_matrix(cases: list[dict[str, Any]]) -> None:
    coverage: dict[str, set[str]] = defaultdict(set)
    for case in cases:
        rule_id = case.get("rule_id")
        quadrant = case.get("quadrant")
        if rule_id and quadrant:
            coverage[str(rule_id)].add(str(quadrant))
    expected_rules = set(SUPPORTED_POLICY_RULE_IDS)
    if set(coverage) != expected_rules:
        missing = sorted(expected_rules - set(coverage))
        extra = sorted(set(coverage) - expected_rules)
        raise ValueError(f"incomplete rule matrix: missing={missing}, extra={extra}")
    incomplete = {
        rule_id: sorted(REQUIRED_QUADRANTS - quadrants)
        for rule_id, quadrants in coverage.items()
        if quadrants != REQUIRED_QUADRANTS
    }
    if incomplete:
        raise ValueError(f"incomplete rule quadrants: {incomplete}")


def _event_with_defaults(
    raw_event: dict[str, Any], case_id: str, *, is_malicious: bool
) -> dict[str, Any]:
    event = dict(raw_event)
    event.setdefault("schema_version", "0.3")
    event.setdefault("event_id", f"evt_matrix_{case_id}")
    event.setdefault("event_type", "tool_call_proposed")
    event.setdefault("runtime", "core_matrix")
    event.setdefault("trace_id", f"trace_matrix_{case_id}")
    event.setdefault("case_id", case_id)
    event.setdefault("attack_type", "rule_matrix")
    event.setdefault("is_malicious", is_malicious)
    event.setdefault("timestamp", "2026-06-27T00:00:00+00:00")
    event.setdefault(
        "pre_execution",
        event["event_type"]
        not in {"model_output_produced", "tool_result_produced"},
    )
    event.setdefault(
        "security_context",
        {
            "user_task": "Perform the explicitly requested safe operation.",
            "source_type": "user",
            "source_trust": "trusted",
        },
    )
    event.setdefault("metadata", {})
    return event


def _default_benign_event() -> dict[str, Any]:
    return {
        "security_context": {
            "user_task": "Read /docs/public.txt and summarize it.",
            "source_type": "user",
            "source_trust": "trusted",
        },
        "payload": {
            "tool": {
                "name": "read_file",
                "category": "file",
                "kind": "file_read",
            },
            "arguments": {"path": "/docs/public.txt"},
            "derived_resources": [],
        },
    }


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    event = GuardEvent.model_validate(case["event"])
    policies = PolicyBundle.model_validate(case.get("policies", {}))
    decision = evaluate(event, policies)
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
        "rule_id": case.get("rule_id"),
        "quadrant": case.get("quadrant"),
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
        "matrix_coverage": summarize_matrix_coverage(cases),
        "rules": summarize_rules(cases),
        "cases": {case["case_id"]: case for case in cases},
    }


def summarize_matrix_coverage(cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "rule_count": len(SUPPORTED_POLICY_RULE_IDS),
        "quadrants_per_rule": len(REQUIRED_QUADRANTS),
        "expected_case_count": len(SUPPORTED_POLICY_RULE_IDS)
        * len(REQUIRED_QUADRANTS),
        "covered_rules": sorted(SUPPORTED_POLICY_RULE_IDS),
        "quadrants": sorted(REQUIRED_QUADRANTS),
    }


def summarize_cases(cases: list[dict[str, Any]]) -> dict[str, Any]:
    blocked = [case for case in cases if case["blocked"]]
    allowed = [case for case in cases if not case["blocked"]]
    # disabled/override 是策略控制面测试，不可混入默认策略的 FPR/FNR。
    metric_cases = [
        case
        for case in cases
        if case.get("quadrant") in {None, "positive", "benign"}
    ]
    benign = [case for case in metric_cases if case["is_malicious"] is False]
    malicious = [case for case in metric_cases if case["is_malicious"] is True]
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
