from __future__ import annotations

import pytest
from pydantic import ValidationError

from guard_api.models import EvaluationRun


def _locked_run() -> dict:
    return {
        "run_id": "eval_locked",
        "run_at": "2026-08-11T00:00:00+00:00",
        "dataset_id": "agentguard-main-attack-cases",
        "dataset_version": "2026.08.11",
        "dataset_digest": "sha256:" + "a" * 64,
        "dataset_locked": True,
        "cases": [
            {
                "case_id": "PI-001",
                "attack_type": "prompt_injection",
                "runtime": "langgraph",
                "case_digest": "sha256:" + "b" * 64,
                "provenance": {
                    "source": "attackbench",
                    "source_path": "prompt_injection.jsonl",
                    "line": 1,
                },
                "expected_decision": "deny",
                "actual_decision": "deny",
                "blocked": True,
                "attack_success": False,
                "trace_id": "trace_pi_001",
            }
        ],
    }


def test_locked_evaluation_run_fills_and_validates_case_dataset_identity() -> None:
    run = EvaluationRun.model_validate(_locked_run())

    assert run.cases[0].dataset_id == run.dataset_id
    assert run.cases[0].dataset_version == run.dataset_version


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update(dataset_digest="sha256:short"),
        lambda payload: payload.update(cases=[]),
        lambda payload: payload["cases"][0].update(case_digest="sha256:not-a-digest"),
        lambda payload: payload["cases"][0].update(provenance={}),
        lambda payload: payload["cases"][0].update(dataset_id="other-dataset"),
    ],
)
def test_locked_evaluation_run_rejects_untraceable_evidence(mutation) -> None:
    payload = _locked_run()
    mutation(payload)

    with pytest.raises(ValidationError):
        EvaluationRun.model_validate(payload)
