"""Aggregate benchmark run artifacts for manual test6 audits.

This script is intentionally read-only. It summarizes the structured evidence
that the test6 plan asks a human auditor to inspect, but it never grants the
"allowed to proceed: yes" decision by itself.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


KEY_METRICS = [
    "case_count",
    "malicious_count",
    "benign_count",
    "valid_malicious_count",
    "invalid_case_count",
    "run_valid_rate",
    "invalid_run_rate",
    "metrics_reliable",
    "run_quality_pass",
    "benchmark_quality_interpretable",
    "evidence_complete_rate",
    "artifact_coverage_rate",
    "llm_request_count",
    "llm_timeout_count",
    "llm_connection_error_count",
    "llm_rate_limit_count",
]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_dir = Path(args.run_dir).expanduser().resolve()
    report = audit_run(run_dir)
    if args.output:
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown_output:
        markdown_output = Path(args.markdown_output).expanduser()
        markdown_output.parent.mkdir(parents=True, exist_ok=True)
        markdown_output.write_text(render_markdown(report, max_cases=args.max_cases), encoding="utf-8")
    if not args.output and not args.markdown_output:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    if args.require_all_valid and not report.get("quality_gate", {}).get("structured_all_valid"):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, help="Path to one benchmark run_<id> directory.")
    parser.add_argument("--output", help="Optional JSON report output path.")
    parser.add_argument("--markdown-output", help="Optional markdown report output path.")
    parser.add_argument("--max-cases", type=int, default=250, help="Maximum case rows to include in markdown.")
    parser.add_argument(
        "--require-all-valid",
        action="store_true",
        help="Exit non-zero if structured gates are not all valid. This still does not replace manual review.",
    )
    return parser


def audit_run(run_dir: Path) -> dict[str, Any]:
    files = _select_run_files(run_dir)
    summary, summary_error = _load_json_object(files.get("summary"))
    rows, run_error = _load_json_list(files.get("run"))
    manifest, manifest_error = _load_json_object(files.get("manifest"))
    artifact_integrity, artifact_error = _load_json_object(files.get("artifact_integrity"))
    csv_rows, csv_error = _load_csv(files.get("csv"))

    case_reports = [_case_report(run_dir, row) for row in rows]
    invalid_rows = [row for row in rows if row.get("run_valid") is False]
    invalid_case_results = [case for case in case_reports if case.get("case_result_run_valid") is False]
    mismatched_run_valid = [
        {
            "case_run_key": case["case_run_key"],
            "run_row": case["run_row_run_valid"],
            "case_result": case["case_result_run_valid"],
        }
        for case in case_reports
        if case.get("case_result_exists") and case.get("run_row_run_valid") != case.get("case_result_run_valid")
    ]
    csv_mismatches = _csv_mismatches(rows, csv_rows)

    counters = {
        "run_status": _counter(rows, "run_status"),
        "stop_reason": _counter(rows, "stop_reason"),
        "evidence_status": _counter(rows, "evidence_status"),
        "attack_type": _counter(rows, "attack_type"),
        "invalid_reasons": _invalid_reason_counter(rows),
    }
    browser = _browser_summary(case_reports)
    parse_errors = [
        error
        for error in [summary_error, run_error, manifest_error, artifact_error, csv_error]
        if error
    ]
    parse_errors.extend(error for case in case_reports for error in case.get("parse_errors", []))
    quality_gate = _quality_gate(summary, manifest, rows, case_reports, artifact_integrity)

    return {
        "schema_version": "agentguard_test6_run_audit/1.0",
        "run_dir": str(run_dir),
        "note": "Read-only audit helper. It does not replace the required human allowed-to-proceed decision.",
        "files": {key: str(value) if value is not None else None for key, value in files.items()},
        "summary_metrics": {key: summary.get(key) for key in KEY_METRICS if key in summary},
        "artifact_integrity": {
            "ok": artifact_integrity.get("ok"),
            "case_count": artifact_integrity.get("case_count"),
            "error": artifact_integrity.get("error"),
        },
        "manifest": manifest,
        "counters": counters,
        "quality_gate": quality_gate,
        "invalid_cases": [_row_brief(row) for row in invalid_rows],
        "case_cross_checks": {
            "case_count": len(case_reports),
            "missing_case_results": [case["case_run_key"] for case in case_reports if not case.get("case_result_exists")],
            "invalid_case_results": [
                {
                    "case_run_key": case["case_run_key"],
                    "invalid_reasons": case.get("case_result_invalid_reasons"),
                }
                for case in invalid_case_results
            ],
            "mismatched_run_valid": mismatched_run_valid,
            "csv_mismatches": csv_mismatches,
            "tool_results_parse_errors": [
                {"case_run_key": case["case_run_key"], "error": case.get("tool_results_error")}
                for case in case_reports
                if case.get("tool_results_error")
            ],
            "evidence_index_parse_errors": [
                {"case_run_key": case["case_run_key"], "error": case.get("evidence_index_error")}
                for case in case_reports
                if case.get("evidence_index_error")
            ],
        },
        "browser_artifacts": browser,
        "case_rows": case_reports,
        "parse_errors": parse_errors,
        "manual_decision": {
            "all_valid": bool(quality_gate.get("structured_all_valid")),
            "allowed_to_proceed": "manual_review_required",
            "reason": "The test6 plan requires a human audit document with explicit allowed to proceed: yes.",
        },
    }


def render_markdown(report: dict[str, Any], *, max_cases: int = 250) -> str:
    lines = [
        "# test6 run audit helper report",
        "",
        "This report is generated by a read-only helper. It does not replace manual review.",
        "",
        "## Run",
        "",
        f"- run_dir: `{report.get('run_dir')}`",
        f"- structured_all_valid: `{report.get('quality_gate', {}).get('structured_all_valid')}`",
        f"- allowed_to_proceed: `manual_review_required`",
        "",
        "## Quality Gate",
        "",
        "| metric | value | pass |",
        "|---|---:|---|",
    ]
    for key, value in report.get("quality_gate", {}).items():
        lines.append(f"| {key} | `{value}` | {'yes' if value is True else 'no' if value is False else 'n/a'} |")
    lines.extend(["", "## Summary Metrics", "", "| metric | value |", "|---|---:|"])
    for key, value in report.get("summary_metrics", {}).items():
        lines.append(f"| {key} | `{value}` |")

    lines.extend(["", "## Invalid Cases", "", "| case_run_key | case_id | attack_type | run_status | stop_reason | invalid_reasons |", "|---|---|---|---|---|---|"])
    invalid_cases = report.get("invalid_cases") or []
    if invalid_cases:
        for row in invalid_cases[:max_cases]:
            lines.append(
                "| {case_run_key} | {case_id} | {attack_type} | {run_status} | {stop_reason} | {invalid_reasons} |".format(
                    case_run_key=row.get("case_run_key", ""),
                    case_id=row.get("case_id", ""),
                    attack_type=row.get("attack_type", ""),
                    run_status=row.get("run_status", ""),
                    stop_reason=row.get("stop_reason", ""),
                    invalid_reasons=", ".join(row.get("invalid_reasons") or []),
                )
            )
    else:
        lines.append("| none |  |  |  |  |  |")

    cross = report.get("case_cross_checks", {})
    lines.extend(
        [
            "",
            "## Cross Checks",
            "",
            f"- missing_case_results: `{cross.get('missing_case_results')}`",
            f"- mismatched_run_valid: `{cross.get('mismatched_run_valid')}`",
            f"- csv_mismatches: `{cross.get('csv_mismatches')}`",
            f"- tool_results_parse_errors: `{cross.get('tool_results_parse_errors')}`",
            f"- evidence_index_parse_errors: `{cross.get('evidence_index_parse_errors')}`",
            "",
            "## Browser Artifacts",
            "",
        ]
    )
    browser = report.get("browser_artifacts", {})
    for key, value in browser.items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Case Rows", "", "| case_run_key | run_valid | evidence | tool_errors | browser_manifest | real | diagnostic |", "|---|---:|---|---:|---:|---:|---:|"])
    for case in (report.get("case_rows") or [])[:max_cases]:
        lines.append(
            "| {case_run_key} | `{run_valid}` | {evidence_status} | {tool_error_count} | `{browser_manifest_exists}` | `{real_browser_artifact}` | `{diagnostic_artifact}` |".format(
                case_run_key=case.get("case_run_key"),
                run_valid=case.get("run_row_run_valid"),
                evidence_status=case.get("evidence_status"),
                tool_error_count=case.get("tool_error_count"),
                browser_manifest_exists=case.get("browser_manifest_exists"),
                real_browser_artifact=case.get("real_browser_artifact"),
                diagnostic_artifact=case.get("diagnostic_artifact"),
            )
        )
    lines.append("")
    return "\n".join(lines)


def _select_run_files(run_dir: Path) -> dict[str, Path | None]:
    return {
        "summary": _single_glob(run_dir, "summary_*.json"),
        "run": _single_glob(run_dir, "run_*.json", exclude_prefix="manifest_"),
        "csv": _single_glob(run_dir, "run_*.csv"),
        "manifest": _single_glob(run_dir, "manifest_run_*.json"),
        "artifact_integrity": run_dir / "artifact_integrity_manifest.json"
        if (run_dir / "artifact_integrity_manifest.json").exists()
        else None,
    }


def _single_glob(root: Path, pattern: str, *, exclude_prefix: str = "") -> Path | None:
    paths = sorted(path for path in root.glob(pattern) if not exclude_prefix or not path.name.startswith(exclude_prefix))
    return paths[-1] if paths else None


def _load_json_object(path: Path | None) -> tuple[dict[str, Any], str | None]:
    if path is None or not path.exists():
        return {}, "missing_json_object"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {}, f"{path.name}:{exc}"
    if not isinstance(payload, dict):
        return {}, f"{path.name}:not_object"
    return payload, None


def _load_json_list(path: Path | None) -> tuple[list[dict[str, Any]], str | None]:
    if path is None or not path.exists():
        return [], "missing_json_list"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [], f"{path.name}:{exc}"
    if not isinstance(payload, list):
        return [], f"{path.name}:not_list"
    return [item for item in payload if isinstance(item, dict)], None


def _load_csv(path: Path | None) -> tuple[list[dict[str, str]], str | None]:
    if path is None or not path.exists():
        return [], None
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle)), None
    except Exception as exc:
        return [], f"{path.name}:{exc}"


def _case_report(run_dir: Path, row: dict[str, Any]) -> dict[str, Any]:
    case_run_key = str(row.get("case_run_key") or row.get("case_id") or "")
    case_dir = run_dir / "cases" / case_run_key
    case_result, case_error = _load_json_object(case_dir / "case_result.json" if case_dir.exists() else None)
    evidence, evidence_error = _load_json_object(case_dir / "evidence_index.json" if case_dir.exists() else None)
    browser_summary, browser_summary_error = _load_json_object(case_dir / "browser_action_summary.json" if case_dir.exists() else None)
    tool_results, tool_results_error = _load_jsonl(case_dir / "tool_results.jsonl" if case_dir.exists() else None)
    browser_manifest, browser_manifest_error = _load_json_object(case_dir / "browser_replay" / "manifest.json" if case_dir.exists() else None)
    browser_replay_state, replay_state_error = _load_json_object(case_dir / "browser_replay" / "replay_state.json" if case_dir.exists() else None)
    parse_errors = [
        error
        for error in [case_error, evidence_error, browser_summary_error, tool_results_error, browser_manifest_error, replay_state_error]
        if error and "missing" not in error
    ]
    browser_manifest_exists = bool((case_dir / "browser_replay" / "manifest.json").exists())
    real_browser = _first_bool(browser_manifest, browser_replay_state, "real_browser_artifact")
    diagnostic = _first_bool(browser_manifest, browser_replay_state, "diagnostic_artifact")
    return {
        "case_run_key": case_run_key,
        "case_id": row.get("case_id"),
        "attack_type": row.get("attack_type"),
        "run_row_run_valid": row.get("run_valid"),
        "case_result_exists": bool(case_result),
        "case_result_run_valid": case_result.get("run_valid") if case_result else None,
        "case_result_invalid_reasons": case_result.get("invalid_reasons") if case_result else None,
        "run_status": row.get("run_status"),
        "stop_reason": row.get("stop_reason"),
        "invalid_reasons": row.get("invalid_reasons") or [],
        "evidence_status": row.get("evidence_status"),
        "llm_request_count": row.get("llm_request_count"),
        "tool_error_count": len([item for item in tool_results if _tool_result_is_error(item)]),
        "fatal_tool_error_count": row.get("fatal_tool_error_count"),
        "tool_results_count": len(tool_results),
        "tool_results_error": tool_results_error if tool_results_error and "missing" not in tool_results_error else None,
        "evidence_index_error": evidence_error if evidence_error and "missing" not in evidence_error else None,
        "evidence_index_exists": bool(evidence),
        "browser_action_count": row.get("browser_action_count") or browser_summary.get("action_count"),
        "browser_started": bool(browser_manifest.get("browser_started") or browser_replay_state.get("browser_started")),
        "browser_manifest_exists": browser_manifest_exists,
        "real_browser_artifact": real_browser,
        "diagnostic_artifact": diagnostic,
        "browser_manifest_ok": browser_manifest.get("ok") if browser_manifest else None,
        "parse_errors": parse_errors,
    }


def _load_jsonl(path: Path | None) -> tuple[list[dict[str, Any]], str | None]:
    if path is None or not path.exists():
        return [], "missing_jsonl"
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_no}: {exc}")
            continue
        if isinstance(payload, dict):
            rows.append(payload)
        else:
            errors.append(f"line {line_no}: not_object")
    return rows, "; ".join(errors) if errors else None


def _counter(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    return dict(Counter(str(row.get(key)) for row in rows))


def _invalid_reason_counter(rows: list[dict[str, Any]]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for row in rows:
        for reason in row.get("invalid_reasons") or []:
            counter[str(reason)] += 1
    return dict(counter)


def _row_brief(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_run_key": row.get("case_run_key"),
        "case_id": row.get("case_id"),
        "attack_type": row.get("attack_type"),
        "run_status": row.get("run_status"),
        "stop_reason": row.get("stop_reason"),
        "evidence_status": row.get("evidence_status"),
        "invalid_reasons": row.get("invalid_reasons") or [],
        "llm_request_count": row.get("llm_request_count"),
        "tool_names": [call.get("tool_name") or call.get("name") for call in row.get("tool_calls") or [] if isinstance(call, dict)],
        "final_answer_preview": str(row.get("final_answer") or "")[:240],
    }


def _csv_mismatches(rows: list[dict[str, Any]], csv_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    if not csv_rows:
        return []
    by_key = {str(row.get("case_run_key") or row.get("case_id")): row for row in csv_rows}
    mismatches: list[dict[str, Any]] = []
    for row in rows:
        key = str(row.get("case_run_key") or row.get("case_id"))
        csv_row = by_key.get(key)
        if not csv_row:
            mismatches.append({"case_run_key": key, "reason": "missing_csv_row"})
            continue
        csv_valid = _coerce_csv_bool(csv_row.get("run_valid"))
        if csv_valid is not None and csv_valid != row.get("run_valid"):
            mismatches.append({"case_run_key": key, "run_json": row.get("run_valid"), "csv": csv_valid})
    return mismatches


def _coerce_csv_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    return None


def _browser_summary(case_reports: list[dict[str, Any]]) -> dict[str, Any]:
    attempted = [
        case
        for case in case_reports
        if case.get("browser_action_count") or case.get("browser_manifest_exists") or case.get("browser_started")
    ]
    return {
        "attempt_or_artifact_case_count": len(attempted),
        "manifest_case_count": len([case for case in case_reports if case.get("browser_manifest_exists")]),
        "real_browser_artifact_case_count": len([case for case in case_reports if case.get("real_browser_artifact") is True]),
        "diagnostic_artifact_case_count": len([case for case in case_reports if case.get("diagnostic_artifact") is True]),
        "missing_manifest_after_browser_activity": [
            case["case_run_key"]
            for case in attempted
            if not case.get("browser_manifest_exists")
        ],
        "diagnostic_artifact_cases": [
            case["case_run_key"]
            for case in case_reports
            if case.get("diagnostic_artifact") is True
        ],
    }


def _quality_gate(
    summary: dict[str, Any],
    manifest: dict[str, Any],
    rows: list[dict[str, Any]],
    case_reports: list[dict[str, Any]],
    artifact_integrity: dict[str, Any],
) -> dict[str, Any]:
    invalid_rows = [row for row in rows if row.get("run_valid") is False]
    missing_case_results = [case for case in case_reports if not case.get("case_result_exists")]
    invalid_case_results = [case for case in case_reports if case.get("case_result_run_valid") is False]
    parse_error_count = sum(len(case.get("parse_errors", [])) for case in case_reports)
    gates = {
        "run_integrity_ok": manifest.get("run_integrity_ok"),
        "case_count_matches_expected": _case_count_matches(summary, manifest, rows),
        "missing_case_ids_empty": not manifest.get("missing_case_ids"),
        "missing_case_result_ids_empty": not manifest.get("missing_case_result_ids") and not missing_case_results,
        "artifact_missing_case_ids_empty": not manifest.get("artifact_missing_case_ids"),
        "invalid_case_count_zero": summary.get("invalid_case_count") in (0, None) and not invalid_rows and not invalid_case_results,
        "invalid_run_rate_zero": summary.get("invalid_run_rate") in (0, 0.0, None),
        "run_valid_rate_one": summary.get("run_valid_rate") in (1, 1.0, None) and not invalid_rows,
        "all_case_results_valid": not invalid_case_results and not missing_case_results,
        "artifact_integrity_ok": artifact_integrity.get("ok") in (True, None),
        "parse_error_count_zero": parse_error_count == 0,
    }
    gates["structured_all_valid"] = all(value is True for value in gates.values())
    return gates


def _case_count_matches(summary: dict[str, Any], manifest: dict[str, Any], rows: list[dict[str, Any]]) -> bool:
    expected = manifest.get("expected_case_count") or summary.get("case_count")
    if expected is None:
        return True
    return int(expected) == len(rows)


def _tool_result_is_error(item: dict[str, Any]) -> bool:
    status = str(item.get("status") or "").lower()
    return bool(item.get("error") or status in {"error", "tool_timeout", "fatal_tool_exception"})


def _first_bool(first: dict[str, Any], second: dict[str, Any], key: str) -> bool | None:
    for payload in (first, second):
        if key in payload:
            return bool(payload[key])
    return None


if __name__ == "__main__":
    raise SystemExit(main())
