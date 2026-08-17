from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from agentguard_core import (
    PreEnableReport,
    RatioMetric,
    build_pre_enable_report,
    evaluation_run_extension,
    validate_pre_enable_report,
)
from guard_api.models import EvaluationRun
from tests.support.auth import memory_store_with_adapter


def _evidence() -> dict[str, list[dict[str, object]]]:
    return {
        "failure_injection": [
            {
                "check_id": "fi-guard-api-unavailable",
                "kind": "failure_injection",
                "status": "passed",
                "evidence_refs": ["trace:fi-guard-api-unavailable"],
                "summary": "Protected action failed closed when evaluation was unavailable.",
            }
        ],
        "flag_rollback": [
            {
                "check_id": "rollback-v2-shadow-off",
                "kind": "flag_rollback",
                "status": "passed",
                "evidence_refs": ["evaluation:rollback-v2-shadow-off"],
                "summary": "Disabling the flag restored the current official path.",
            }
        ],
    }


def _report_payload() -> dict[str, object]:
    return {
        "receipt_observations": [
            {
                "observation_key": "action-1",
                "receipt_state": "authoritative_terminal",
            },
            {
                "observation_key": "action-2",
                "receipt_state": "link_conflict",
            },
            {"observation_key": "action-3", "receipt_state": "missing"},
        ],
        "decision_observations": [
            {
                "observation_key": "decision-1",
                "official_decision": "allow",
                "v2_shadow_decision": "deny",
                "is_malicious": True,
            },
            {
                "observation_key": "decision-2",
                "official_decision": "allow",
                "v2_shadow_decision": "ask",
                "is_malicious": False,
            },
            {
                "observation_key": "decision-3",
                "official_decision": "ask",
                "v2_shadow_decision": "allow",
                "is_malicious": False,
            },
        ],
        "attack_observations": [
            {"observation_key": "attack-1", "outcome": "harmful_execution"},
            {"observation_key": "attack-2", "outcome": "prevented"},
            {"observation_key": "attack-3", "outcome": "unknown"},
        ],
        "latency_observations": [
            {"observation_key": "latency-1", "latency_ms": 10},
            {"observation_key": "latency-2", "latency_ms": 30},
            {"observation_key": "latency-3", "latency_ms": None},
        ],
        **_evidence(),
    }


def test_pre_enable_report_aggregates_explicit_denominators() -> None:
    report = build_pre_enable_report(_report_payload())

    assert report.schema_version == "pre-enable-report/1.0"
    assert report.official_decision_source == "current"
    assert report.v2_decision_mode == "shadow"
    assert report.eligible_action_count == 3
    assert report.terminal_receipt_count == 1
    assert report.receipt_coverage == RatioMetric(numerator=1, denominator=3)
    assert report.link_conflicts == RatioMetric(numerator=1, denominator=3)
    assert report.official_v2_divergence == RatioMetric(numerator=3, denominator=3)
    assert report.benign_ask == RatioMetric(numerator=1, denominator=2)
    assert report.final_asr == RatioMetric(numerator=1, denominator=3)
    assert report.unknown_attack_outcome_count == 1
    assert report.latency.sample_coverage == RatioMetric(numerator=2, denominator=3)
    assert report.latency.average_ms == 20
    assert report.latency.p50_ms == 10
    assert report.latency.p95_ms == 30
    assert report.latency.p99_ms == 30
    assert report.functional_evidence_status == "passed"
    assert report.effect_gate.status == "skipped"
    assert report.effect_gate.mode == "observational"
    assert report.effect_gate.numerical_thresholds_applied is False
    assert report.formal_gate_b == "not_asserted"


def test_pre_enable_report_keeps_failed_functional_evidence_observable() -> None:
    payload = _report_payload()
    payload["failure_injection"][0]["status"] = "failed"  # type: ignore[index]

    report = build_pre_enable_report(payload)

    assert report.functional_evidence_status == "failed"
    assert report.effect_gate.status == "skipped"
    assert report.receipt_coverage.numerator == 1


def test_pre_enable_report_zero_denominators_are_explicit() -> None:
    report = build_pre_enable_report(_evidence())

    for metric in (
        report.receipt_coverage,
        report.link_conflicts,
        report.official_v2_divergence,
        report.benign_ask,
        report.final_asr,
        report.latency.sample_coverage,
    ):
        assert metric.numerator == 0
        assert metric.denominator == 0
        assert metric.value is None
    assert report.latency.average_ms is None


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.pop("failure_injection"),
        lambda payload: payload["flag_rollback"].clear(),
        lambda payload: payload["failure_injection"][0].update(kind="flag_rollback"),
        lambda payload: payload["receipt_observations"].append(
            deepcopy(payload["receipt_observations"][0])
        ),
    ],
)
def test_pre_enable_report_rejects_incomplete_or_ambiguous_evidence(mutation) -> None:
    payload = _report_payload()
    mutation(payload)

    with pytest.raises(ValidationError):
        build_pre_enable_report(payload)


def test_pre_enable_report_rejects_tampered_derived_values() -> None:
    report = build_pre_enable_report(_report_payload()).model_dump(mode="json")
    report["receipt_coverage"]["value"] = 1.0

    with pytest.raises(ValidationError, match="numerator / denominator"):
        PreEnableReport.model_validate(report)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report.update(unknown_attack_outcome_count=4),
        lambda report: report["link_conflicts"].update(numerator=3, value=1.0),
        lambda report: report["flag_rollback"][0].update(
            check_id=report["failure_injection"][0]["check_id"]
        ),
    ],
)
def test_pre_enable_report_rejects_cross_field_tampering(mutation) -> None:
    report = build_pre_enable_report(_report_payload()).model_dump(mode="json")
    mutation(report)

    with pytest.raises(ValidationError):
        PreEnableReport.model_validate(report)


def test_pre_enable_report_roundtrips_through_evaluation_run_api_and_store() -> None:
    report = build_pre_enable_report(_report_payload())
    report_payload = report.model_dump(mode="json")
    run_payload = {
        "run_id": "eval-c10-roundtrip",
        "run_at": "2026-08-17T00:00:00+00:00",
        "dataset_id": "reference-langgraph",
        "dataset_version": "c10",
        **evaluation_run_extension(report),
        "cases": [],
    }
    typed_run = EvaluationRun.model_validate(run_payload)
    assert typed_run.model_dump(mode="json")["pre_enable_report"] == report_payload

    store = memory_store_with_adapter()
    first = store.save_evaluation_run(typed_run)
    replay = store.save_evaluation_run(run_payload)
    assert first == replay
    stored = store.get_latest_evaluation_run()
    assert stored is not None
    assert stored["pre_enable_report"] == report_payload
    assert validate_pre_enable_report(stored["pre_enable_report"]) == report


def test_evaluation_run_extension_has_one_fixed_json_safe_key() -> None:
    report = build_pre_enable_report(_report_payload())

    extension = evaluation_run_extension(report.model_dump(mode="json"))

    assert set(extension) == {"pre_enable_report"}
    assert extension == {"pre_enable_report": report.model_dump(mode="json")}
