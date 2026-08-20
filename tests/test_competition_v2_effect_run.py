"""Tests for the dual-arm A0/A4 effect evaluation driver script."""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from agentguard_langgraph_bench.bench import competition_parallel
from agentguard_langgraph_bench.bench.competition_models import (
    COMPETITION_PROFILE_ID,
    V21RolloutMode,
    load_competition_profile,
)
from agentguard_langgraph_bench.bench.competition_runner import (
    ArmRunResult,
    ProviderRuntimeConfig,
)


def _load_script() -> ModuleType:
    script = (
        Path(__file__).parents[1] / "scripts" / "competition-v2-effect-run.py"
    )
    spec = importlib.util.spec_from_file_location("competition_v2_effect_run", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before exec: slotted dataclasses resolve their namespace via
    # sys.modules[cls.__module__].
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _fake_provider() -> ProviderRuntimeConfig:
    return ProviderRuntimeConfig(
        provider_id="openai-compatible",
        model="qwen3.7-plus",
        base_url="https://provider.example/v1",
        api_key_env="COMPETITION_LLM_KEY",
        api_key="test-key",
    )


def _row(
    case_id: str,
    *,
    is_malicious: bool = True,
    attack_success: bool | None = None,
    overblocked: bool | None = None,
    task_success: bool | None = None,
    comparisons: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "is_malicious": is_malicious,
        "attack_type": "benign" if not is_malicious else "prompt_injection",
        "run_valid": True,
        "run_status": "completed",
        "attack_success": attack_success,
        "overblocked": overblocked,
        "task_success": task_success,
        "decision_comparisons": comparisons or [],
        "model_exchanges": [],
        "tool_executions": [],
    }


def _fake_arms_payload() -> dict[str, dict[str, Any]]:
    baseline_rows = [
        _row("PI-001", attack_success=True),
        _row("BN-001", is_malicious=False, task_success=True),
    ]
    product_rows = [
        _row(
            "PI-001",
            attack_success=False,
            comparisons=[
                {
                    "authority_source": "v21",
                    "authority_mode": "active",
                    "legacy_floor_applied": False,
                    "official_decision": "deny",
                    "current_decision": "allow",
                    "raw_v21_decision": "deny",
                }
            ],
        ),
        _row(
            "BN-001",
            is_malicious=False,
            task_success=True,
            comparisons=[
                {
                    "authority_source": "v21",
                    "authority_mode": "active",
                    "legacy_floor_applied": False,
                    "official_decision": "allow",
                    "current_decision": "allow",
                    "raw_v21_decision": "allow",
                }
            ],
        ),
    ]
    template = {
        "contracts": {"guard_api_loopback": {"status": "passed"}},
        "case_durations_ms": {"PI-001": 120.0, "BN-001": 80.0},
        "port_table": {},
    }
    return {
        "A0": {**template, "arm_id": "A0", "rows": baseline_rows},
        "A4": {**template, "arm_id": "A4", "rows": product_rows},
    }


def test_build_effect_arms_selects_frozen_a0_a4_product_shape() -> None:
    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)

    arms = module.build_effect_arms(profile)

    assert set(arms) == {"A0", "A4"}
    assert arms["A0"].guard_enabled is False
    assert arms["A4"].v21_rollout_mode is V21RolloutMode.ACTIVE
    assert arms["A4"].context_mode.value == "required"
    assert arms["A4"].rte_mode.value == "enforce"


def test_build_effect_arms_rejects_a_shadow_product_arm() -> None:
    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)

    shadowed = {
        arm.arm_id: (
            replace(arm, context_mode=type(arm.context_mode)("observe"))
            if arm.arm_id == "A4"
            else arm
        )
        for arm in profile.arms
    }

    class _ProfileView:
        arms = tuple(shadowed.values())

    with pytest.raises(Exception) as excinfo:
        module.build_effect_arms(_ProfileView())
    assert "context" in str(excinfo.value)


def test_run_requires_provider_configuration(tmp_path: Path) -> None:
    module = _load_script()

    exit_code = module.main(
        ["run", "--artifacts", str(tmp_path / "effect")]
    )

    assert exit_code == 2


def test_run_rejects_reused_artifacts_directory(tmp_path: Path) -> None:
    module = _load_script()
    artifacts = tmp_path / "effect"
    artifacts.mkdir()
    (artifacts / "stale.json").write_text("{}", encoding="utf-8")

    exit_code = module.main(
        [
            "run",
            "--artifacts",
            str(artifacts),
            "--llm-model",
            "m",
            "--llm-base-url",
            "https://provider.example/v1",
        ]
    )

    assert exit_code == 2


def test_serial_run_writes_report_and_arm_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    payloads = _fake_arms_payload()
    executed: list[str] = []

    def fake_resolve_provider(profile, args):
        return _fake_provider()

    def fake_execute(request):
        arm_id = module.EFFECT_ARM_IDS[request.arm_index]
        executed.append(arm_id)
        return payloads[arm_id]

    monkeypatch.setattr(module, "resolve_provider", fake_resolve_provider)
    monkeypatch.setattr(module, "execute_effect_arm", fake_execute)
    artifacts = tmp_path / "effect"

    exit_code = module.main(
        [
            "run",
            "--artifacts",
            str(artifacts),
            "--case-id",
            "PI-001",
            "--case-id",
            "BN-001",
            "--serial",
        ]
    )

    assert exit_code == 0
    assert executed == ["A0", "A4"]
    report = json.loads((artifacts / "effect-report.json").read_text())
    assert report["competition_qualified"] is False
    assert report["dataset"]["selected_case_count"] == 2
    assert report["provider"]["model"] == "qwen3.7-plus"
    assert report["paired"]["blocked_successful_attack_count"] == 1
    assert report["overview"]["asr_reduction"] == pytest.approx(1.0)
    assert report["arms"]["A4"]["v2_effect"]["v2_saves_over_current_false_negative"] == 1
    # Rows are merged back in frozen dataset order (BN before PI), not the
    # --case-id CLI order.
    rows = json.loads((artifacts / "arms/A0/run.json").read_text())
    assert [row["case_id"] for row in rows] == ["BN-001", "PI-001"]
    assert {row["case_id"]: row for row in rows} == {
        row["case_id"]: row for row in payloads["A0"]["rows"]
    }
    assert (artifacts / "arms/A4/durations.json").exists()
    assert (artifacts / "arms/A0/contracts.json").exists()


def test_default_repeats_keeps_flat_artifact_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without --repeats the artifact layout stays exactly as before: no
    repeat-N/ subdirectories and no repeats-summary.json."""

    module = _load_script()
    payloads = _fake_arms_payload()
    repeat_indexes: list[int] = []

    def fake_execute(request):
        arm_id = module.EFFECT_ARM_IDS[request.arm_index]
        repeat_indexes.append(request.repeat_index)
        return payloads[arm_id]

    monkeypatch.setattr(
        module, "resolve_provider", lambda profile, args: _fake_provider()
    )
    monkeypatch.setattr(module, "execute_effect_arm", fake_execute)
    artifacts = tmp_path / "effect"

    exit_code = module.main(
        [
            "run",
            "--artifacts",
            str(artifacts),
            "--case-id",
            "PI-001",
            "--case-id",
            "BN-001",
            "--serial",
        ]
    )

    assert exit_code == 0
    assert repeat_indexes == [0, 0]
    assert (artifacts / "effect-report.json").exists()
    assert (artifacts / "arms/A0/run.json").exists()
    assert not (artifacts / "repeat-0").exists()
    assert not (artifacts / "repeats-summary.json").exists()


def test_repeats_two_writes_repeat_subdirectories_and_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    payloads = _fake_arms_payload()
    executions: list[tuple[int, str]] = []

    def fake_execute(request):
        arm_id = module.EFFECT_ARM_IDS[request.arm_index]
        executions.append((request.repeat_index, arm_id))
        return payloads[arm_id]

    monkeypatch.setattr(
        module, "resolve_provider", lambda profile, args: _fake_provider()
    )
    monkeypatch.setattr(module, "execute_effect_arm", fake_execute)
    artifacts = tmp_path / "effect"

    exit_code = module.main(
        [
            "run",
            "--artifacts",
            str(artifacts),
            "--case-id",
            "PI-001",
            "--case-id",
            "BN-001",
            "--serial",
            "--repeats",
            "2",
        ]
    )

    assert exit_code == 0
    # Both arms ran in each repeat round with the matching repeat index.
    assert executions == [(0, "A0"), (0, "A4"), (1, "A0"), (1, "A4")]
    # Every repeat owns its own isolated artifact subdirectory.
    for index in (0, 1):
        repeat_dir = artifacts / f"repeat-{index}"
        assert (repeat_dir / "effect-report.json").exists()
        assert (repeat_dir / "arms/A0/run.json").exists()
        assert (repeat_dir / "arms/A4/run.json").exists()
    # Nothing leaks into the historical flat layout.
    assert not (artifacts / "effect-report.json").exists()
    assert not (artifacts / "arms").exists()
    summary = json.loads((artifacts / "repeats-summary.json").read_text())
    assert summary["repeat_count"] == 2
    assert [item["repeat_index"] for item in summary["repeats"]] == [0, 1]
    metrics = summary["repeats"][0]["metrics"]
    assert metrics["paired_valid_asr_baseline"] == pytest.approx(1.0)
    assert metrics["paired_valid_asr_product"] == pytest.approx(0.0)
    assert metrics["blocked_successful_attack_rate"] == pytest.approx(1.0)
    assert metrics["valid_run_rate_baseline"] == pytest.approx(1.0)
    assert metrics["valid_run_rate_product"] == pytest.approx(1.0)
    assert metrics["asr_valid_malicious_baseline"] == pytest.approx(1.0)
    assert metrics["asr_valid_malicious_product"] == pytest.approx(0.0)
    blocked = summary["aggregates"]["blocked_successful_attack_rate"]
    assert blocked["mean"] == pytest.approx(1.0)
    assert blocked["range"] == pytest.approx(0.0)
    assert blocked["sample_count"] == 2
    # Deterministic fake rows make every repeat identical, so all ranges
    # collapse to zero.
    for aggregate in summary["aggregates"].values():
        assert aggregate["range"] == pytest.approx(0.0)


def test_repeats_rejects_values_below_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    monkeypatch.setattr(
        module, "resolve_provider", lambda profile, args: _fake_provider()
    )

    exit_code = module.main(
        [
            "run",
            "--artifacts",
            str(tmp_path / "effect"),
            "--case-id",
            "BN-001",
            "--serial",
            "--repeats",
            "0",
        ]
    )

    assert exit_code == 2


def test_serial_run_fails_closed_when_an_arm_crashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()

    monkeypatch.setattr(module, "resolve_provider", lambda profile, args: _fake_provider())

    def exploding_execute(request):
        raise RuntimeError("fixture exploded")

    monkeypatch.setattr(module, "execute_effect_arm", exploding_execute)
    artifacts = tmp_path / "effect"

    exit_code = module.main(
        ["run", "--artifacts", str(artifacts), "--case-id", "BN-001", "--serial"]
    )

    assert exit_code == 2
    failure = json.loads((artifacts / "effect-failure.json").read_text())
    assert len(failure["failures"]) == 2
    assert "fixture exploded" in failure["failures"][0]
    assert not (artifacts / "effect-report.json").exists()


def test_serial_run_fail_soft_produces_partial_report_when_one_arm_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If one arm succeeds and the other crashes, a partial report is still
    generated with the surviving arm's data (fail-soft)."""

    module = _load_script()
    payloads = _fake_arms_payload()

    monkeypatch.setattr(
        module, "resolve_provider", lambda profile, args: _fake_provider()
    )

    def partial_execute(request):
        arm_id = module.EFFECT_ARM_IDS[request.arm_index]
        if arm_id == "A4":
            raise RuntimeError("A4 fixture exploded")
        return payloads["A0"]

    monkeypatch.setattr(module, "execute_effect_arm", partial_execute)
    artifacts = tmp_path / "effect"

    exit_code = module.main(
        ["run", "--artifacts", str(artifacts), "--case-id", "PI-001", "--serial"]
    )

    # Partial report should still be generated with A0 data.
    assert exit_code == 0
    report = json.loads((artifacts / "effect-report.json").read_text())
    assert "A0" in report["arms"]
    assert "A4" not in report["arms"]
    assert report["single_arm"] == "A0"
    assert report.get("run_failures")
    assert any("A4" in f for f in report["run_failures"])
    assert (artifacts / "arms/A0/run.json").exists()
    assert not (artifacts / "arms/A4/run.json").exists()


def test_parallel_worker_reports_failure_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()

    def exploding_execute(request):
        raise ValueError("port collision")

    monkeypatch.setattr(module, "execute_effect_arm", exploding_execute)
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    request = module.ArmWorkerRequest(
        arm_index=1,
        slot=7,
        port_table={},
        profile=profile,
        provider=_fake_provider(),
        cases=(),
        artifact_root=tmp_path,
    )
    recorded: list[tuple[Any, ...]] = []

    class _Queue:
        def put(self, payload):
            recorded.append(payload)

    module._arm_worker(request, _Queue())

    assert recorded == [("failed", 7, "ValueError", "port collision")]


def test_parallel_worker_writes_payload_to_file_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    fake_payload = {"arm_id": "A0", "rows": [{"case_id": "PI-001"}]}

    def fake_execute(request):
        return fake_payload

    monkeypatch.setattr(module, "execute_effect_arm", fake_execute)
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    request = module.ArmWorkerRequest(
        arm_index=0,
        slot=3,
        port_table={},
        profile=profile,
        provider=_fake_provider(),
        cases=(),
        artifact_root=tmp_path,
    )
    recorded: list[tuple[Any, ...]] = []

    class _Queue:
        def put(self, payload):
            recorded.append(payload)

    module._arm_worker(request, _Queue())

    assert len(recorded) == 1
    assert recorded[0][0] == "ok"
    assert recorded[0][1] == 3
    # payload[2] is the path to the shard file.
    payload_path = Path(recorded[0][2])
    assert payload_path.exists()
    assert json.loads(payload_path.read_text(encoding="utf-8")) == fake_payload


def test_arm_parallel_requires_single_arm_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    monkeypatch.setattr(module, "resolve_provider", lambda profile, args: _fake_provider())

    exit_code = module.main(
        [
            "run",
            "--artifacts",
            str(tmp_path / "effect"),
            "--arm-parallel",
            "3",
            "--case-id",
            "BN-001",
        ]
    )

    assert exit_code == 2


def test_single_arm_parallel_run_shards_cases_and_restores_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    case_ids = ["PI-001", "AA-001", "BN-001"]
    expected_order = [
        case.case_id for case in module._select_cases(profile, case_ids)
    ]
    seen_shards: list[list[str]] = []

    def fake_execute(request):
        arm_id = module.EFFECT_ARM_IDS[request.arm_index]
        assert arm_id == "A0"
        seen_shards.append([case.case_id for case in request.cases])
        return {
            "arm_id": arm_id,
            "rows": [
                _row(case.case_id, attack_success=True)
                for case in request.cases
            ],
            "contracts": {"probe": {"status": "passed"}},
            "case_durations_ms": {case.case_id: 10.0 for case in request.cases},
            "port_table": {},
        }

    monkeypatch.setattr(module, "resolve_provider", lambda profile, args: _fake_provider())
    monkeypatch.setattr(module, "execute_effect_arm", fake_execute)
    artifacts = tmp_path / "a0-parallel"

    exit_code = module.main(
        [
            "run",
            "--artifacts",
            str(artifacts),
            "--arm",
            "A0",
            "--arm-parallel",
            "2",
            "--serial",
            *[item for case_id in case_ids for item in ("--case-id", case_id)],
        ]
    )

    assert exit_code == 0
    assert len(seen_shards) == 2
    merged_input = [case_id for shard in seen_shards for case_id in shard]
    assert sorted(merged_input) == sorted(case_ids)
    report = json.loads((artifacts / "effect-report.json").read_text())
    assert report["single_arm"] == "A0"
    assert report["arm_parallel"] == 2
    assert "paired" not in report
    assert "overview" not in report
    rows = json.loads((artifacts / "arms/A0/run.json").read_text())
    assert [row["case_id"] for row in rows] == expected_order
    assert not (artifacts / "arms/A4").exists()


def test_execute_effect_arm_builds_unqualified_serial_arm_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    cases = module._select_cases(profile, ["BN-001"])
    captured: dict[str, Any] = {}

    def fake_execute_arm(arm_request, *, case_runner=None):
        captured["request"] = arm_request
        rows = case_runner(list(arm_request.cases), config=None)
        return ArmRunResult(rows=tuple(rows), contracts={"probe": {"status": "passed"}})

    monkeypatch.setattr(
        "agentguard_langgraph_bench.bench.competition_runtime.execute_competition_arm",
        fake_execute_arm,
    )
    monkeypatch.setattr(
        "agentguard_langgraph_bench.bench.runner.run_cases",
        lambda cases, **kwargs: [
            {"case_id": case.case_id} for case in cases
        ],
    )
    monkeypatch.setattr(competition_parallel, "apply_stream_environment", lambda table: {})
    monkeypatch.setattr(competition_parallel, "check_ports_available", lambda table: None)
    monkeypatch.setattr(
        competition_parallel, "rewrite_cases_for_ports", lambda cases, table: list(cases)
    )
    request = module.ArmWorkerRequest(
        arm_index=1,
        port_table={service: 19080 for service in competition_parallel.STREAM_SERVICE_DEFAULT_PORTS},
        profile=profile,
        provider=_fake_provider(),
        cases=cases,
        artifact_root=tmp_path,
    )

    payload = module.execute_effect_arm(request)

    arm_request = captured["request"]
    assert arm_request.arm.arm_id == "A4"
    assert arm_request.qualification_eligible is False
    assert arm_request.repeat_index == 0
    assert [case.case_id for case in arm_request.cases] == ["BN-001"]
    assert payload["arm_id"] == "A4"
    assert len(payload["rows"]) == 1
    assert "BN-001" in payload["case_durations_ms"]
