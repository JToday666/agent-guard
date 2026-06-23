"""Generate agent_abuse iteration audit tables from run artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


CASE_IDS = [f"AA-{index:03d}" for index in range(1, 11)]
FIX_CATEGORIES = {
    "planner_prompt",
    "payload",
    "page_affordance",
    "browser_runtime",
    "business_event",
    "termination",
    "evaluator_false_positive",
    "evaluator_false_negative",
    "metrics_reporting",
    "llm_timeout",
    "artifact_missing",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-run-dir", required=True)
    parser.add_argument("--closure-run-dir", required=True)
    parser.add_argument("--closure-on-partial-run-dir", required=True)
    parser.add_argument("--replay-run-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    run_dirs = {
        "raw": Path(args.raw_run_dir),
        "closure": Path(args.closure_run_dir),
        "closure_on_partial": Path(args.closure_on_partial_run_dir),
        "replay": Path(args.replay_run_dir),
    }
    rows = [_case_row(case_id, run_dirs) for case_id in CASE_IDS]
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_render_markdown(rows, run_dirs), encoding="utf-8")
    print(str(output))
    return 0


def _case_row(case_id: str, run_dirs: dict[str, Path]) -> dict[str, Any]:
    row: dict[str, Any] = {"case_id": case_id, "modes": {}}
    for mode, run_dir in run_dirs.items():
        case_result = _load_case_result(run_dir, case_id)
        verdict = case_result.get("agent_abuse_verdict") if isinstance(case_result.get("agent_abuse_verdict"), dict) else {}
        row["modes"][mode] = {
            "completion_level": case_result.get("completion_level", "missing"),
            "attack_success": case_result.get("attack_success"),
            "harm_attempted": case_result.get("harm_attempted"),
            "business_effect_validated": verdict.get("business_effect_validated"),
            "raw_business_event_detected": verdict.get("raw_business_event_detected"),
            "artifact_dir": case_result.get("case_artifact_dir") or str(_case_dir(run_dir, case_id)),
        }
    return row


def _load_case_result(run_dir: Path, case_id: str) -> dict[str, Any]:
    path = _case_dir(run_dir, case_id) / "case_result.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _case_dir(run_dir: Path, case_id: str) -> Path:
    direct = run_dir / "cases" / case_id
    if direct.exists() or run_dir.name.startswith("run_"):
        return direct
    candidates = sorted(run_dir.glob("run_*/cases/" + case_id))
    return candidates[-1] if candidates else direct


def _render_markdown(rows: list[dict[str, Any]], run_dirs: dict[str, Path]) -> str:
    lines = [
        "# Agent Abuse Iteration Manual Audit",
        "",
        "## Run Directories",
        "",
        *[f"- {mode}: `{path}`" for mode, path in run_dirs.items()],
        "",
        "## Case-by-case Manual Audit",
        "",
        "| Case | Human verdict | Evaluator verdict | Match? | Evidence | Root cause | Fix category |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        mode = row["modes"].get("closure") or {}
        evaluator = mode.get("completion_level", "missing")
        evidence = f"closure={evaluator}; raw={row['modes'].get('raw', {}).get('completion_level', 'missing')}; replay={row['modes'].get('replay', {}).get('completion_level', 'missing')}"
        fix_hint = "artifact_missing" if evaluator == "missing" else ""
        lines.append(f"| {row['case_id']} | manual_review_required | {evaluator} | TBD | {evidence} | TBD | {fix_hint} |")
    lines.extend(
        [
            "",
            "## Fix Category Options",
            "",
            ", ".join(sorted(FIX_CATEGORIES)),
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
