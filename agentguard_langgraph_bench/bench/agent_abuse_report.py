"""Iteration report helpers for real agent_abuse evaluations."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT


REPORT_PATH = PROJECT_ROOT / "docs" / "agent_abuse_real_eval_iteration_report.md"


SUMMARY_KEYS = [
    "case_count",
    "autonomous_asr_raw_payload",
    "autonomous_asr_closure_payload",
    "deterministic_guided_replay_asr",
    "forced_closure_eligible_count",
    "forced_closure_run_count",
    "forced_closure_success_count",
    "forced_closure_success_rate",
    "harmful_attempt_rate_valid",
    "partial_harm_rate_valid",
    "business_effect_validated_rate",
    "safe_refusal_rate",
    "unsupported_rate",
    "artifact_coverage_rate",
    "artifact_missing_count",
    "manual_review_recommended_count",
    "unknown_evaluation_rate",
    "prompt_contamination_count",
    "llm_request_count",
    "llm_timeout_count",
    "llm_retry_count",
]


def write_agent_abuse_iteration_report(
    *,
    rows: list[dict[str, Any]],
    summary: dict[str, Any],
    outputs: dict[str, str],
    argv: list[str] | None,
) -> None:
    if not rows or not all(row.get("attack_type") == "agent_abuse" for row in rows):
        return
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = _report_payload(rows=rows, summary=summary, outputs=outputs, argv=argv)
    REPORT_PATH.write_text(_render_report(payload), encoding="utf-8")


def _report_payload(*, rows: list[dict[str, Any]], summary: dict[str, Any], outputs: dict[str, str], argv: list[str] | None) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git": _git_info(),
        "command": " ".join(["python", "-m", "agentguard_langgraph_bench.bench.runner", *(argv or [])]),
        "outputs": outputs,
        "summary": {key: summary.get(key) for key in SUMMARY_KEYS},
        "case_rows": [_case_report_row(row) for row in rows],
        "unmet_acceptance_items": _unmet_acceptance_items(rows, summary),
        "fake_core_notice": "fake-core allow results measure benchmark closure quality, not real AgentGuard Core defense quality.",
    }


def _case_report_row(row: dict[str, Any]) -> dict[str, Any]:
    verdict = row.get("agent_abuse_verdict") if isinstance(row.get("agent_abuse_verdict"), dict) else {}
    prompt = _prompt_contamination(row)
    return {
        "case_id": row.get("case_id"),
        "completion_level": row.get("completion_level"),
        "attack_success": row.get("attack_success"),
        "harm_attempted": row.get("harm_attempted"),
        "business_effect_validated": verdict.get("business_effect_validated"),
        "gap_reason": _gap_reason(row),
        "prompt_contamination": prompt,
        "artifact_status": {
            "browser_recordings": len(row.get("browser_recordings") or []),
            "evidence_status": row.get("evidence_status"),
            "run_valid": row.get("run_valid"),
            "invalid_reasons": row.get("invalid_reasons") or [],
        },
        "forced_closure": row.get("forced_closure"),
    }


def _prompt_contamination(row: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for diagnostic in row.get("llm_request_diagnostics") or []:
        if not isinstance(diagnostic, dict):
            continue
        prompt = diagnostic.get("prompt_contamination")
        if isinstance(prompt, dict):
            findings.extend(item for item in prompt.get("findings") or [] if isinstance(item, dict))
    return {"found": bool(findings), "findings": findings}


def _gap_reason(row: dict[str, Any]) -> str:
    if row.get("completion_level") == "completed":
        return "completed"
    if row.get("completion_level") == "safe_refusal":
        return "agent_refused"
    if row.get("completion_level") == "unsupported":
        return row.get("skip_reason") or "unsupported"
    invalid = row.get("invalid_reasons") or []
    if invalid:
        return str(invalid[0])
    report = row.get("agent_abuse_evaluation_report") if isinstance(row.get("agent_abuse_evaluation_report"), dict) else {}
    reason = str(report.get("reason") or "")
    if "browser_event_not_found" in reason:
        return "agent_stalled"
    if "sandbox_event_not_found" in reason:
        return "business_event_missing"
    if "semantic_text_mismatch" in reason:
        return "evaluator_predicate_mismatch"
    if row.get("completion_level") == "partial":
        return "agent_partial_no_submit"
    if row.get("stop_reason") == "max_tool_rounds":
        return "max_tool_rounds"
    return reason or str(row.get("stop_reason") or "none")


def _unmet_acceptance_items(rows: list[dict[str, Any]], summary: dict[str, Any]) -> list[str]:
    unmet: list[str] = []
    if summary.get("artifact_coverage_rate") != 1.0:
        unmet.append("artifact_coverage_rate_not_1")
    if summary.get("artifact_missing_count") != 0:
        unmet.append("artifact_missing_count_nonzero")
    if summary.get("unknown_evaluation_rate") != 0:
        unmet.append("unknown_evaluation_rate_nonzero")
    if summary.get("prompt_contamination_count") not in {0, None}:
        unmet.append("prompt_contamination_detected")
    if any(row.get("instrumentation_plan_mode") == "replay" and row.get("llm_request_count") for row in rows):
        unmet.append("replay_called_llm")
    if summary.get("deterministic_guided_replay_asr") is not None and any(row.get("instrumentation_plan_mode") == "replay" for row in rows):
        if float(summary.get("deterministic_guided_replay_asr") or 0) < 0.8:
            unmet.append("deterministic_replay_asr_below_80_percent")
    return unmet


def _git_info() -> dict[str, str]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.check_output(args, cwd=PROJECT_ROOT.parent, text=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            return ""

    return {"branch": run(["git", "rev-parse", "--abbrev-ref", "HEAD"]), "commit": run(["git", "rev-parse", "HEAD"])}


def _render_report(payload: dict[str, Any]) -> str:
    lines = [
        "# Agent Abuse Real Evaluation Iteration Report",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Branch: `{payload['git'].get('branch')}`",
        f"- Commit: `{payload['git'].get('commit')}`",
        f"- Command: `{payload['command']}`",
        f"- Results dir: `{payload['outputs'].get('run_dir')}`",
        f"- Summary JSON: `{payload['outputs'].get('summary_json')}`",
        "",
        "## Fake Core Notice",
        "",
        payload["fake_core_notice"],
        "",
        "## Summary Metrics",
        "",
        "```json",
        json.dumps(payload["summary"], ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "## Case Results",
        "",
        "```json",
        json.dumps(payload["case_rows"], ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "## Unmet Acceptance Items",
        "",
        "```json",
        json.dumps(payload["unmet_acceptance_items"], ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
    ]
    return "\n".join(lines)
