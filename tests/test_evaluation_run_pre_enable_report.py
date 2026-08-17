from __future__ import annotations

from math import inf, nan
from typing import cast

import pytest
from pydantic import ValidationError

from agentguard_core import (
    EvaluationRunPreEnableExtension,
    PreEnableReport,
    RatioMetric,
    ReceiptEligibilityDescriptor,
    ReceiptEligibilityExpectation,
    build_pre_enable_report,
    build_receipt_eligibility_descriptor,
    evaluation_run_extension,
    validate_evaluation_run_extension,
    validate_pre_enable_report,
)
from guard_api.models import EvaluationRun
from tests.support.auth import memory_store_with_adapter


_ELIGIBLE_ACTION_KEYS = ("action-1", "action-2", "action-3")


def _eligibility(
    action_keys: tuple[str, ...] = _ELIGIBLE_ACTION_KEYS,
) -> ReceiptEligibilityDescriptor:
    return build_receipt_eligibility_descriptor(
        eligibility_revision="c10-revision-1",
        runtime_profile="reference-langgraph",
        eligible_action_keys=action_keys,
        evidence_refs=("profile:reference-langgraph:receipt-eligibility:c10",),
    )


def _expectation(
    descriptor: ReceiptEligibilityDescriptor | None = None,
) -> ReceiptEligibilityExpectation:
    source = descriptor or _eligibility()
    return ReceiptEligibilityExpectation(
        eligibility_revision=source.eligibility_revision,
        runtime_profile=source.runtime_profile,
        eligibility_digest=source.eligibility_digest,
    )


def _evidence() -> dict[str, list[dict[str, object]]]:
    return {
        "failure_injection": [
            {
                "check_id": "fi-guard-api-unavailable",
                "kind": "failure_injection",
                "status": "passed",
                "evidence_refs": [
                    "test:tests/test_v21_09_pipeline.py::test_pipeline_phase_a_snapshot_read_failure_component_failure"
                ],
                "reason_code": "guard_api_unavailable_fail_closed",
            }
        ],
        "flag_rollback": [
            {
                "check_id": "rollback-v2-shadow-off",
                "kind": "flag_rollback",
                "status": "passed",
                "evidence_refs": [
                    "test:tests/test_v21_09_pipeline.py::test_pipeline_flag_off_response_byte_identical"
                ],
                "reason_code": "v2_shadow_flag_off_official_unchanged",
            }
        ],
    }


def _report_payload(
    descriptor: ReceiptEligibilityDescriptor | None = None,
) -> dict[str, object]:
    eligibility = descriptor or _eligibility()
    receipt_states = {
        "action-1": "authoritative_terminal",
        "action-2": "link_conflict",
        "action-3": "missing",
    }
    return {
        "receipt_eligibility": eligibility.model_dump(mode="json"),
        "receipt_observations": [
            {"action_key": key, "receipt_state": receipt_states[key]}
            for key in eligibility.eligible_action_keys
        ],
        "decision_observations": [
            {
                "observation_key": "decision-1",
                "official_decision": "allow",
                "v2_shadow_decision": "deny",
                "is_malicious": True,
                "divergence_category": "legacy_allow__v21_clear_deny",
            },
            {
                "observation_key": "decision-2",
                "official_decision": "allow",
                "v2_shadow_decision": "ask",
                "is_malicious": False,
                "divergence_category": "legacy_allow__v21_defer",
            },
            {
                "observation_key": "decision-3",
                "official_decision": "ask",
                "v2_shadow_decision": "allow",
                "is_malicious": False,
                "divergence_category": "legacy_ask__v21_clear_allow",
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


def _build_report(
    payload: dict[str, object] | None = None,
    *,
    expected: ReceiptEligibilityExpectation | None = None,
) -> PreEnableReport:
    return build_pre_enable_report(
        payload or _report_payload(),
        expected_receipt_eligibility=expected or _expectation(),
    )


def test_pre_enable_report_aggregates_explicit_denominators() -> None:
    report = _build_report()

    assert report.schema_version == "pre-enable-report/1.0"
    assert report.official_decision_source == "current"
    assert report.v2_decision_mode == "shadow"
    assert report.benign_ask_source == "v2_shadow"
    assert report.receipt_eligibility == _eligibility()
    assert report.eligible_action_count == 3
    assert report.terminal_receipt_count == 1
    assert report.receipt_coverage == RatioMetric(numerator=1, denominator=3)
    assert report.link_conflicts == RatioMetric(numerator=1, denominator=3)
    assert report.official_v2_divergence == RatioMetric(numerator=3, denominator=3)
    assert [(item.category, item.count) for item in report.divergence_categories] == [
        ("legacy_allow__v21_clear_deny", 1),
        ("legacy_allow__v21_defer", 1),
        ("legacy_ask__v21_clear_allow", 1),
    ]
    assert report.degraded_divergence_count == 0
    assert report.unexplained_divergence_count == 0
    assert report.divergence_explanation_coverage == RatioMetric(
        numerator=3, denominator=3
    )
    assert report.benign_ask == RatioMetric(numerator=1, denominator=2)
    assert report.decision_label_coverage == RatioMetric(numerator=3, denominator=3)
    assert report.decision_label_availability == "available"
    assert report.final_asr == RatioMetric(numerator=1, denominator=2)
    assert report.attack_outcome_coverage == RatioMetric(numerator=2, denominator=3)
    assert report.final_asr_availability == "partial"
    assert report.unknown_attack_outcome_count == 1
    assert report.latency.sample_coverage == RatioMetric(numerator=2, denominator=3)
    assert report.latency.average_ms == 20
    assert report.latency.p50_ms == 10
    assert report.latency.p95_ms == 30
    assert report.latency.p99_ms == 30
    assert report.latency.max_ms == 30
    assert report.functional_evidence_status == "passed"
    assert report.effect_gate.status == "skipped"
    assert report.effect_gate.mode == "observational"
    assert report.effect_gate.numerical_thresholds_applied is False
    assert report.formal_gate_b == "not_asserted"


def test_pre_enable_report_keeps_failed_functional_evidence_observable() -> None:
    payload = _report_payload()
    payload["failure_injection"][0]["status"] = "failed"  # type: ignore[index]

    report = _build_report(payload)

    assert report.functional_evidence_status == "failed"
    assert report.effect_gate.status == "skipped"
    assert report.receipt_coverage.numerator == 1


def test_pre_enable_report_zero_denominators_are_explicitly_unavailable() -> None:
    descriptor = _eligibility(())
    payload = {
        "receipt_eligibility": descriptor.model_dump(mode="json"),
        "receipt_observations": [],
        **_evidence(),
    }

    report = _build_report(payload, expected=_expectation(descriptor))

    for metric in (
        report.receipt_coverage,
        report.link_conflicts,
        report.official_v2_divergence,
        report.divergence_explanation_coverage,
        report.benign_ask,
        report.decision_label_coverage,
        report.final_asr,
        report.attack_outcome_coverage,
        report.latency.sample_coverage,
    ):
        assert metric == RatioMetric(numerator=0, denominator=0)
    assert report.decision_label_availability == "unavailable"
    assert report.final_asr_availability == "unavailable"
    assert report.latency.average_ms is None
    assert report.latency.max_ms is None


def test_all_unknown_attack_outcomes_do_not_serialize_as_zero_asr() -> None:
    payload = _report_payload()
    payload["attack_observations"] = [
        {"observation_key": "attack-1", "outcome": "unknown"},
        {"observation_key": "attack-2", "outcome": "unknown"},
    ]

    report = _build_report(payload)

    assert report.final_asr == RatioMetric(numerator=0, denominator=0)
    assert report.final_asr.value is None
    assert report.attack_outcome_coverage == RatioMetric(numerator=0, denominator=2)
    assert report.final_asr_availability == "unavailable"
    assert report.unknown_attack_outcome_count == 2


@pytest.mark.parametrize("invalid_latency", [inf, -inf, nan])
def test_pre_enable_report_rejects_non_finite_latency_inputs(
    invalid_latency: float,
) -> None:
    payload = _report_payload()
    payload["latency_observations"] = [
        {"observation_key": "latency-non-finite", "latency_ms": invalid_latency}
    ]

    with pytest.raises(ValidationError):
        _build_report(payload)


@pytest.mark.parametrize(
    "field", ["average_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms"]
)
@pytest.mark.parametrize("invalid_latency", [inf, -inf, nan])
def test_pre_enable_report_rejects_non_finite_derived_latency(
    field: str, invalid_latency: float
) -> None:
    report = _build_report().model_dump(mode="python")
    report["latency"][field] = invalid_latency

    with pytest.raises(ValidationError):
        PreEnableReport.model_validate(report)


def test_pre_enable_report_json_roundtrip_preserves_finite_latency() -> None:
    report = _build_report()

    encoded = report.model_dump_json()
    restored = PreEnableReport.model_validate_json(encoded)

    assert restored == report
    assert restored.latency.max_ms == 30
    assert '"average_ms":null' not in encoded


def test_pre_enable_report_rejects_inconsistent_latency_summary() -> None:
    report = _build_report().model_dump(mode="json")
    report["latency"]["max_ms"] = 5

    with pytest.raises(ValidationError, match="monotonic"):
        PreEnableReport.model_validate(report)


def test_receipt_eligibility_is_canonical_and_content_addressed() -> None:
    first = _eligibility()
    reordered = build_receipt_eligibility_descriptor(
        eligibility_revision=first.eligibility_revision,
        runtime_profile=first.runtime_profile,
        eligible_action_keys=tuple(reversed(_ELIGIBLE_ACTION_KEYS)),
        evidence_refs=tuple(reversed(first.evidence_refs)),
    )

    assert reordered == first
    assert first.eligibility_digest.startswith("sha256:")
    assert len(first.eligibility_digest) == 71


def test_receipt_eligibility_rejects_duplicate_or_tampered_content() -> None:
    with pytest.raises(ValidationError, match="sorted and unique"):
        build_receipt_eligibility_descriptor(
            eligibility_revision="c10-revision-1",
            runtime_profile="reference-langgraph",
            eligible_action_keys=("action-1", "action-1"),
            evidence_refs=("profile:reference-langgraph:receipt-eligibility:c10",),
        )

    descriptor = _eligibility().model_dump(mode="json")
    descriptor["eligible_action_keys"].pop()
    with pytest.raises(ValidationError, match="digest"):
        ReceiptEligibilityDescriptor.model_validate(descriptor)


def test_receipt_observations_must_exactly_cover_frozen_population() -> None:
    payload = _report_payload()
    payload["receipt_observations"].pop()  # type: ignore[union-attr]

    with pytest.raises(ValidationError, match="exactly cover"):
        _build_report(payload)


def test_recomputed_smaller_population_fails_trusted_profile_anchor() -> None:
    original = _eligibility()
    smaller = _eligibility(("action-1", "action-2"))
    payload = _report_payload(smaller)

    with pytest.raises(ValueError, match="trusted profile anchor"):
        _build_report(payload, expected=_expectation(original))


@pytest.mark.parametrize(
    "update",
    [
        {"eligibility_revision": "other-revision"},
        {"runtime_profile": "other-profile"},
        {"eligibility_digest": "sha256:" + "0" * 64},
    ],
)
def test_receipt_eligibility_rejects_wrong_trusted_identity(update) -> None:
    expected = _expectation().model_copy(update=update)

    with pytest.raises(ValueError, match="trusted profile anchor"):
        _build_report(expected=expected)


def test_observation_and_evidence_order_is_canonical() -> None:
    payload = _report_payload()
    receipt_observations = cast(
        list[dict[str, object]], payload["receipt_observations"]
    )
    payload["receipt_observations"] = list(reversed(receipt_observations))
    with pytest.raises(ValidationError, match="canonically"):
        _build_report(payload)

    payload = _report_payload()
    decision_observations = cast(
        list[dict[str, object]], payload["decision_observations"]
    )
    payload["decision_observations"] = list(reversed(decision_observations))
    with pytest.raises(ValidationError, match="canonically sorted"):
        _build_report(payload)


def test_divergence_vocabulary_and_explanation_coverage_are_strict() -> None:
    payload = _report_payload()
    payload["decision_observations"][0]["divergence_category"] = "invented"  # type: ignore[index]
    with pytest.raises(ValidationError, match="frozen vocabulary"):
        _build_report(payload)

    payload = _report_payload()
    payload["decision_observations"][0]["divergence_category"] = (  # type: ignore[index]
        "legacy_allow__v21_defer"
    )
    with pytest.raises(ValidationError, match="conflicts"):
        _build_report(payload)


def test_degraded_and_unexplained_divergence_remain_visible() -> None:
    payload = _report_payload()
    payload["decision_observations"][0]["divergence_category"] = (  # type: ignore[index]
        "degraded_component_failure"
    )
    payload["decision_observations"][1]["divergence_category"] = None  # type: ignore[index]

    report = _build_report(payload)

    assert report.official_v2_divergence == RatioMetric(numerator=3, denominator=3)
    assert report.degraded_divergence_count == 1
    assert report.unexplained_divergence_count == 1
    assert report.divergence_explanation_coverage == RatioMetric(
        numerator=2, denominator=3
    )


def test_decision_label_coverage_exposes_unlabeled_exclusions() -> None:
    payload = _report_payload()
    payload["decision_observations"][2]["is_malicious"] = None  # type: ignore[index]

    report = _build_report(payload)

    assert report.decision_label_coverage == RatioMetric(numerator=2, denominator=3)
    assert report.decision_label_availability == "partial"
    assert report.benign_ask == RatioMetric(numerator=1, denominator=1)

    for observation in payload["decision_observations"]:  # type: ignore[union-attr]
        observation["is_malicious"] = None
    report = _build_report(payload)
    assert report.decision_label_coverage == RatioMetric(numerator=0, denominator=3)
    assert report.decision_label_availability == "unavailable"
    assert report.benign_ask == RatioMetric(numerator=0, denominator=0)


def test_benign_ask_source_is_fixed_to_v2_shadow() -> None:
    payload = _report_payload()
    payload["benign_ask_source"] = "official"
    with pytest.raises(ValidationError):
        _build_report(payload)

    report = _build_report().model_dump(mode="json")
    report["benign_ask_source"] = "official"
    with pytest.raises(ValidationError):
        PreEnableReport.model_validate(report)


@pytest.mark.parametrize(
    "field,value",
    [
        ("summary", "free form text is not persisted"),
        ("reason_code", "sk-proj-1234567890abcdef"),
        ("evidence_refs", ["artifact:github_pat_" + "a" * 24]),
    ],
)
def test_evidence_checks_reject_free_text_and_credential_like_values(
    field: str, value: object
) -> None:
    payload = _report_payload()
    payload["failure_injection"][0][field] = value  # type: ignore[index]

    with pytest.raises(ValidationError):
        _build_report(payload)


@pytest.mark.parametrize(
    "field,value",
    [
        (
            "evidence_refs",
            ["authorization_fingerprint:hmac-sha256:" + "a" * 64],
        ),
        ("evidence_refs", ["lease_token:lease-v1:" + "b" * 64]),
        ("evidence_refs", ["artifact:hmac-sha256:" + "c" * 64]),
        ("reason_code", "runtime_binding_nonce_recorded"),
        ("reason_code", "secret_token_present"),
    ],
)
def test_evidence_checks_reject_runtime_authority_and_secret_material(
    field: str, value: object
) -> None:
    payload = _report_payload()
    payload["failure_injection"][0][field] = value  # type: ignore[index]

    with pytest.raises(ValidationError):
        _build_report(payload)


def test_evidence_checks_allow_plain_artifact_sha256_digest() -> None:
    payload = _report_payload()
    payload["failure_injection"][0]["evidence_refs"] = [  # type: ignore[index]
        "artifact:sha256:" + "d" * 64
    ]

    report = _build_report(payload)

    assert report.failure_injection[0].evidence_refs == ("artifact:sha256:" + "d" * 64,)


def test_pre_enable_report_rejects_tampered_derived_values() -> None:
    report = _build_report().model_dump(mode="json")
    report["receipt_coverage"]["value"] = 1.0

    with pytest.raises(ValidationError, match="numerator / denominator"):
        PreEnableReport.model_validate(report)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report.update(eligible_action_count=2),
        lambda report: report.update(unknown_attack_outcome_count=3),
        lambda report: report["link_conflicts"].update(numerator=3, value=1.0),
        lambda report: report["flag_rollback"][0].update(
            check_id=report["failure_injection"][0]["check_id"]
        ),
        lambda report: report.update(final_asr_availability="available"),
        lambda report: report.update(decision_label_availability="partial"),
    ],
)
def test_pre_enable_report_rejects_cross_field_tampering(mutation) -> None:
    report = _build_report().model_dump(mode="json")
    mutation(report)

    with pytest.raises(ValidationError):
        PreEnableReport.model_validate(report)


def test_typed_evaluation_run_extension_rejects_forged_gate_claim() -> None:
    report = _build_report().model_dump(mode="json")
    report["formal_gate_b"] = "passed"

    with pytest.raises(ValidationError):
        EvaluationRunPreEnableExtension.model_validate({"pre_enable_report": report})


def test_current_guard_evaluation_run_extra_is_a_known_untyped_gap() -> None:
    report = _build_report().model_dump(mode="json")
    report["formal_gate_b"] = "passed"
    run = EvaluationRun.model_validate(
        {
            "run_id": "eval-c10-known-untyped-gap",
            "run_at": "2026-08-17T00:00:00+00:00",
            "pre_enable_report": report,
        }
    )

    # Known blocker until Guard API may add an explicit typed field after CT04M.
    assert run.model_dump(mode="json")["pre_enable_report"]["formal_gate_b"] == "passed"
    with pytest.raises(ValidationError):
        EvaluationRunPreEnableExtension.model_validate({"pre_enable_report": report})


def test_pre_enable_report_roundtrips_through_untyped_extra_and_store() -> None:
    report = _build_report()
    expected = _expectation()
    report_payload = report.model_dump(mode="json")
    run_payload = {
        "run_id": "eval-c10-roundtrip",
        "run_at": "2026-08-17T00:00:00+00:00",
        "dataset_id": "reference-langgraph",
        "dataset_version": "c10",
        **evaluation_run_extension(
            report,
            expected_receipt_eligibility=expected,
        ),
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
    assert (
        validate_pre_enable_report(
            stored["pre_enable_report"],
            expected_receipt_eligibility=expected,
        )
        == report
    )


def test_evaluation_run_extension_has_one_fixed_json_safe_key() -> None:
    report = _build_report()
    expected = _expectation()

    extension = evaluation_run_extension(
        report.model_dump(mode="json"),
        expected_receipt_eligibility=expected,
    )
    validated = validate_evaluation_run_extension(
        extension,
        expected_receipt_eligibility=expected,
    )

    assert set(extension) == {"pre_enable_report"}
    assert validated.pre_enable_report == report
