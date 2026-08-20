"""Unit tests for the dual-arm A0/A4 effect metric calculators."""

from __future__ import annotations

from typing import Any

import pytest

from agentguard_langgraph_bench.bench.v2_effect_metrics import (
    BASELINE_ARM_ID,
    PRODUCT_ARM_ID,
    compute_arm_report,
    compute_overview,
    compute_paired_metrics,
    compute_performance_metrics,
    compute_safety_metrics,
    compute_stability_metrics,
    compute_usability_metrics,
    compute_v2_effect_metrics,
)


def _row(
    case_id: str,
    *,
    is_malicious: bool = True,
    attack_type: str = "prompt_injection",
    run_valid: bool = True,
    run_status: str = "completed",
    attack_success: bool | None = None,
    overblocked: bool | None = None,
    task_success: bool | None = None,
    comparisons: list[dict[str, Any]] | None = None,
    exchanges: list[dict[str, Any]] | None = None,
    tool_executions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "is_malicious": is_malicious,
        "attack_type": attack_type,
        "run_valid": run_valid,
        "run_status": run_status,
        "attack_success": attack_success,
        "overblocked": overblocked,
        "task_success": task_success,
        "decision_comparisons": comparisons or [],
        "model_exchanges": exchanges or [],
        "tool_executions": tool_executions or [],
    }


def _comparison(
    *,
    source: str = "v21",
    official: str | None = "deny",
    current: str | None = "allow",
    raw_v21: str | None = "deny",
) -> dict[str, Any]:
    return {
        "authority_source": source,
        "authority_mode": "active",
        "legacy_floor_applied": False,
        "official_decision": official,
        "current_decision": current,
        "raw_v21_decision": raw_v21,
    }


def test_safety_metrics_split_all_and_valid_malicious() -> None:
    rows = [
        _row("PI-001", attack_success=True),
        _row("PI-002", attack_success=False),
        _row("PI-003", attack_success=True, run_valid=False, run_status="timeout"),
        _row("JB-001", attack_type="jailbreak", attack_success=True),
        _row("BN-001", is_malicious=False, task_success=True),
    ]

    safety = compute_safety_metrics(rows)

    assert safety["malicious_all"] == 4
    assert safety["malicious_valid"] == 3
    assert safety["attack_success_count"] == 2
    assert safety["asr_all_malicious"] == pytest.approx(2 / 4)
    assert safety["asr_valid_malicious"] == pytest.approx(2 / 3)
    per_type = safety["per_attack_type_asr"]
    assert per_type["prompt_injection"]["asr"] == pytest.approx(0.5)
    assert per_type["jailbreak"]["asr"] == pytest.approx(1.0)
    assert per_type["tool_hijacking"]["asr"] is None
    assert per_type["tool_hijacking"]["valid"] == 0


def test_usability_metrics_cover_fpr_ask_and_recovery() -> None:
    rows = [
        _row(
            "BN-001",
            is_malicious=False,
            task_success=True,
            comparisons=[_comparison(official="allow", current="allow", raw_v21="allow")],
        ),
        _row(
            "BN-002",
            is_malicious=False,
            overblocked=True,
            task_success=True,
            comparisons=[_comparison(official="ask", current="allow", raw_v21="ask")],
        ),
        _row(
            "BN-003",
            is_malicious=False,
            overblocked=True,
            task_success=False,
            comparisons=[_comparison(official="deny", current="allow", raw_v21="deny")],
        ),
        _row("BN-004", is_malicious=False, run_valid=False),
        _row("PI-001", attack_success=True),
    ]

    usability = compute_usability_metrics(rows)

    assert usability["benign_all"] == 4
    assert usability["benign_valid"] == 3
    assert usability["benign_valid_rate"] == pytest.approx(3 / 4)
    assert usability["fpr"] == pytest.approx(2 / 3)
    assert usability["benign_task_completion"] == pytest.approx(2 / 3)
    assert usability["overblocked_count"] == 2
    assert usability["overblock_safe_recovery"] == pytest.approx(0.5)
    assert usability["ask_evaluation_count"] == 1
    assert usability["evaluation_count"] == 3
    assert usability["ask_rate"] == pytest.approx(1 / 3)


def test_stability_metrics_classify_failures() -> None:
    rows = [
        _row("PI-001", attack_success=True),
        _row("PI-002", run_valid=False, run_status="timeout"),
        _row("PI-003", run_valid=False, run_status="provider_fault"),
        _row("PI-004", run_valid=False, run_status="sandbox_crash"),
        _row(
            "PI-005",
            tool_executions=[{"action_id": "a1", "status": "exception"}],
        ),
    ]

    stability = compute_stability_metrics(rows)

    assert stability["valid_run_rate"] == pytest.approx(2 / 5)
    assert stability["timeout"] == 1
    assert stability["provider_fault"] == 1
    assert stability["infrastructure_failure"] == 1
    assert stability["tool_exception"] == 1


def test_performance_metrics_split_fast_and_slow_paths() -> None:
    rows = [
        _row(
            "PI-001",
            exchanges=[
                {"model_invoked": True, "elapsed_ms": 100, "tool_calls": []},
                {"model_invoked": True, "elapsed_ms": 300, "tool_calls": ["read_file"]},
            ],
        ),
        _row(
            "PI-002",
            exchanges=[{"model_invoked": True, "elapsed_ms": 200, "tool_calls": []}],
            comparisons=[
                _comparison(
                    official="deny", current="allow", raw_v21="deny"
                )
                | {"semantic_judgment_id": "semantic-1"}
            ],
        ),
    ]

    performance = compute_performance_metrics(
        rows, case_durations_ms={"PI-001": 1000.0, "PI-002": 3000.0}
    )

    assert performance["core_case_ms"]["p50"] == pytest.approx(2000.0)
    assert performance["model_exchange_ms"]["count"] == 3
    assert performance["fast_path_ms"]["count"] == 2
    assert performance["slow_path_ms"]["count"] == 1
    assert performance["slow_path_ms"]["p50"] == pytest.approx(300.0)
    assert performance["llm_deep_judgment_triggered"] == 1
    assert performance["llm_deep_judgment_rate"] == pytest.approx(0.5)


def test_percentiles_are_none_without_samples() -> None:
    performance = compute_performance_metrics([])
    assert performance["core_case_ms"]["p50"] is None
    assert performance["model_exchange_ms"]["count"] == 0


def test_v2_effect_metrics_attribute_saves_and_false_positives() -> None:
    rows = [
        # V2 official deny saves a current false negative on a malicious case.
        _row(
            "PI-001",
            comparisons=[
                _comparison(official="deny", current="allow", raw_v21="deny"),
                _comparison(official="allow", current="allow", raw_v21="allow"),
            ],
        ),
        # Disagreement on a benign case that V2 overblocks.
        _row(
            "BN-001",
            is_malicious=False,
            comparisons=[_comparison(official="ask", current="allow", raw_v21="ask")],
        ),
        # Current authority evaluation (floor) is not a V2 official decision.
        _row(
            "PI-002",
            comparisons=[
                _comparison(source="current", official="deny", current="deny", raw_v21="allow")
            ],
        ),
    ]

    effect = compute_v2_effect_metrics(rows)

    assert effect["evaluation_count"] == 4
    assert effect["v2_official_decision_count"] == 3
    assert effect["v2_official_decisions"] == {"allow": 1, "deny": 1, "ask": 1}
    assert effect["current_vs_v2_disagreement"] == 3
    assert effect["current_vs_v2_disagreement_malicious"] == 2
    assert effect["current_vs_v2_disagreement_benign"] == 1
    assert effect["v2_saves_over_current_false_negative"] == 1
    assert effect["v2_benign_false_positive"] == 1
    assert effect["disagreement_rate"] == pytest.approx(3 / 4)


def test_paired_metrics_compare_arms_on_shared_valid_malicious_cases() -> None:
    baseline = [
        _row("PI-001", attack_success=True),
        _row("PI-002", attack_success=True),
        _row("PI-003", attack_success=False),
        _row("PI-004", attack_success=True, run_valid=False),
        _row("BN-001", is_malicious=False, task_success=True),
    ]
    product = [
        _row("PI-001", attack_success=False),
        _row("PI-002", attack_success=True),
        _row("PI-003", attack_success=False),
        _row("PI-004", attack_success=True),
        _row("BN-001", is_malicious=False, task_success=True),
    ]

    paired = compute_paired_metrics(baseline, product)

    # PI-004 is invalid in the baseline arm, so it drops out of the pair.
    assert paired["paired_valid_malicious_count"] == 3
    assert paired["paired_case_ids"] == ["PI-001", "PI-002", "PI-003"]
    assert paired["paired_valid_asr_baseline"] == pytest.approx(2 / 3)
    assert paired["paired_valid_asr_product"] == pytest.approx(1 / 3)
    assert paired["blocked_successful_attack_count"] == 1
    assert paired["blocked_successful_attack_rate"] == pytest.approx(0.5)
    assert paired["baseline_arm_id"] == BASELINE_ARM_ID
    assert paired["product_arm_id"] == PRODUCT_ARM_ID


def test_arm_report_and_overview_answer_the_v2_question() -> None:
    baseline_rows = [
        _row("PI-001", attack_success=True),
        _row("PI-002", attack_success=False),
        _row("BN-001", is_malicious=False, task_success=True),
    ]
    product_rows = [
        _row(
            "PI-001",
            attack_success=False,
            comparisons=[_comparison(official="deny", current="allow", raw_v21="deny")],
        ),
        _row(
            "PI-002",
            attack_success=False,
            comparisons=[_comparison(official="allow", current="allow", raw_v21="allow")],
        ),
        _row(
            "BN-001",
            is_malicious=False,
            task_success=True,
            comparisons=[_comparison(official="allow", current="allow", raw_v21="allow")],
        ),
    ]

    baseline_report = compute_arm_report(BASELINE_ARM_ID, baseline_rows)
    product_report = compute_arm_report(
        PRODUCT_ARM_ID, product_rows, case_durations_ms={"PI-001": 10.0}
    )
    paired = compute_paired_metrics(baseline_rows, product_rows)
    overview = compute_overview(baseline_report, product_report, paired)

    assert overview["asr_valid_malicious_baseline"] == pytest.approx(0.5)
    assert overview["asr_valid_malicious_product"] == pytest.approx(0.0)
    assert overview["asr_reduction"] == pytest.approx(0.5)
    assert overview["paired_asr_reduction"] == pytest.approx(0.5)
    assert overview["v2_saves"] == 1
    assert overview["v2_benign_false_positive"] == 0
    assert product_report["v2_effect"]["v2_official_decisions"] == {
        "allow": 2,
        "deny": 1,
        "ask": 0,
    }
