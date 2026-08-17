from __future__ import annotations

import json
from pathlib import Path

import pytest
from agentguard_core.authority import TaskFact, task_digest_projection

from agentguard_langgraph_bench.bench.competition_models import (
    COMPETITION_PROFILE_ID,
    CompetitionConfigurationError,
    CompetitionSuite,
    OfficialDecisionSource,
    V21RolloutMode,
    authoritative_task_digest,
    load_competition_profile,
    parse_competition_profile,
)


def test_packaged_competition_profile_freezes_five_distinct_arms() -> None:
    profile = load_competition_profile()

    assert profile.profile_id == COMPETITION_PROFILE_ID
    assert profile.v21_rollout_mode is V21RolloutMode.ACTIVE
    assert [arm.arm_id for arm in profile.arms] == ["A0", "A1", "A2", "A3", "A4"]
    a0, a1, a2, a3, a4 = profile.arms
    assert a0.guard_enabled is False
    assert a0.official_decision_source is OfficialDecisionSource.NONE
    assert a1.official_decision_source is OfficialDecisionSource.CURRENT
    assert a1.v21_enabled is False
    assert a1.v21_rollout_mode is None
    assert a2.official_decision_source is OfficialDecisionSource.CURRENT
    assert a2.v21_rollout_mode is V21RolloutMode.SHADOW
    assert a3.official_decision_source is OfficialDecisionSource.V21
    assert a3.context_mode.value == "observe"
    assert a4.official_decision_source is OfficialDecisionSource.V21
    assert a4.context_mode.value == "required"
    assert profile.dataset.case_count == 70
    assert profile.identity.runtime_binding_id == (
        f"binding:{profile.identity.principal_id}"
    )
    assert profile.identity.agent_id == profile.agent_adapter
    assert profile.effective_digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("mode", "source"),
    [
        (V21RolloutMode.SHADOW, OfficialDecisionSource.CURRENT),
        (V21RolloutMode.LIMITED_ENABLE, OfficialDecisionSource.V21),
        (V21RolloutMode.ACTIVE, OfficialDecisionSource.V21),
    ],
)
def test_profile_rollout_override_keeps_off_separate_from_three_modes(
    mode: V21RolloutMode, source: OfficialDecisionSource
) -> None:
    profile = load_competition_profile().with_overrides(v21_rollout_mode=mode)

    assert profile.arms[1].v21_enabled is False
    assert profile.arms[1].v21_rollout_mode is None
    assert profile.arms[1].official_decision_source is OfficialDecisionSource.CURRENT
    for arm in profile.arms[3:]:
        assert arm.v21_enabled is True
        assert arm.v21_rollout_mode is mode
        assert arm.official_decision_source is source


def test_runtime_suite_and_subset_overrides_do_not_claim_qualification() -> None:
    profile = load_competition_profile().with_overrides(
        suite=CompetitionSuite.DEMO,
        full_corpus=False,
    )

    assert profile.suite is CompetitionSuite.DEMO
    assert profile.full_corpus is False
    assert profile.arms[3].v21_rollout_mode is V21RolloutMode.ACTIVE


def test_profile_parser_rejects_arm_roster_drift(tmp_path: Path) -> None:
    profile = load_competition_profile()
    raw = json.loads(profile.source_path.read_text(encoding="utf-8"))
    raw["arms"][1]["v21_rollout_mode"] = "shadow"
    raw["arms"][1]["v21_enabled"] = True

    with pytest.raises(CompetitionConfigurationError):
        parse_competition_profile(raw, source_path=tmp_path / "profile.json")


def test_profile_parser_rejects_self_asserted_runtime_binding(tmp_path: Path) -> None:
    profile = load_competition_profile()
    raw = json.loads(profile.source_path.read_text(encoding="utf-8"))
    raw["identity"]["runtime_binding_id"] = "client-selected-binding"

    with pytest.raises(CompetitionConfigurationError):
        parse_competition_profile(raw, source_path=tmp_path / "profile.json")


def test_profile_json_is_in_package_data() -> None:
    root = Path(__file__).resolve().parents[1]
    packaging = (root / "pyproject.toml").read_text(encoding="utf-8")

    assert '"profiles/*.json"' in packaging
    assert "agentguard-langgraph-competition" in packaging


def test_competition_task_digest_matches_authoritative_taskfact_projection() -> None:
    fact = TaskFact(
        task_id="task:test",
        scope_digest="hmac-sha256:" + "a" * 64,
        scope_key_id="competition-key",
        principal_id="competition-langgraph-runner",
        task_summary="summarize the public report",
        task_digest="sha256:" + "0" * 64,
        revision=1,
        status="active",
        action_constraints=[],
        resource_constraints=[],
        destination_constraints=[],
        producer="guard_api_task_ingress",
        evidence_refs=[],
    )

    assert authoritative_task_digest(fact.task_summary) == task_digest_projection(fact)
