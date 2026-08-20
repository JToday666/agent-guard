"""六臂消融矩阵驱动脚本（scripts/ablation-matrix-run.py）的定向测试。"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from agentguard_langgraph_bench.bench import competition_parallel
from agentguard_langgraph_bench.bench.competition_models import (
    COMPETITION_PROFILE_ID,
    CompetitionSuite,
    load_competition_profile,
)
from agentguard_langgraph_bench.bench.competition_runner import (
    ArmRunRequest,
    ArmRunResult,
    InvalidCompetitionRun,
    ProviderRuntimeConfig,
)
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases


def _load_script() -> ModuleType:
    script = Path(__file__).parents[1] / "scripts" / "ablation-matrix-run.py"
    spec = importlib.util.spec_from_file_location("ablation_matrix_run", script)
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


def _fake_arm_payload(module: ModuleType, request: Any) -> dict[str, Any]:
    """伪造 execute_ablation_arm 的返回：core-off 攻击得手、Guard 臂阻止。"""

    rows = [
        {
            "case_id": case.case_id,
            "is_malicious": case.is_malicious,
            "attack_type": case.attack_type,
            "run_valid": True,
            "run_status": "completed",
            "attack_success": (
                case.is_malicious and request.label == module.CORE_OFF_LABEL
            ),
            "overblocked": None,
            "task_success": not case.is_malicious,
            "blocked": request.label != module.CORE_OFF_LABEL,
            "invalid_reasons": [],
            "decision_comparisons": [],
            "model_exchanges": [],
            "tool_executions": [],
        }
        for case in request.cases
    ]
    return {
        "label": request.label,
        "arm_id": request.arm.arm_id,
        "rows": rows,
        "contracts": {"probe": {"status": "passed"}},
        "case_durations_ms": {str(case.case_id): 50.0 for case in request.cases},
        "port_table": {},
    }


# ---------------------------------------------------------------------------
# 六臂派生
# ---------------------------------------------------------------------------


def test_build_ablation_arms_derives_six_arm_matrix() -> None:
    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)

    arms = module.build_ablation_arms(profile)

    assert list(arms) == list(module.ABLATION_ARM_LABELS)
    a0 = next(item for item in profile.arms if item.arm_id == "A0")
    a4 = next(item for item in profile.arms if item.arm_id == "A4")

    core_off = arms[module.CORE_OFF_LABEL]
    assert core_off.arm == a0
    assert core_off.arm.guard_enabled is False
    assert (core_off.partial, core_off.decision_invariant) == (False, False)

    full = arms[module.FULL_LABEL]
    assert full.arm == a4
    assert (full.partial, full.decision_invariant) == (False, False)

    no_context = arms[module.NO_CONTEXT_ISOLATION_LABEL]
    assert no_context.arm.context_mode.value == "observe"
    assert no_context.partial is False

    no_taint = arms[module.NO_PROVENANCE_TAINT_LABEL]
    assert no_taint.arm.ct_projection_enabled is False
    assert no_taint.partial is True

    no_memory = arms[module.NO_MEMORY_GUARD_LABEL]
    assert no_memory.arm == a4
    assert no_memory.policy_disabled_rules == ("P104_memory_poisoning",)
    assert no_memory.memory_not_required_env is True
    assert no_memory.partial is True

    no_semantic = arms[module.NO_SEMANTIC_JUDGE_LABEL]
    assert no_semantic.arm == a4
    assert no_semantic.decision_invariant is True

    # arm_id 保持 A0/A4 以通过 ArmSpec 白名单校验。
    assert {spec.arm.arm_id for spec in arms.values()} == {"A0", "A4"}


def test_build_ablation_arms_rejects_shadow_product_arm() -> None:
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

    with pytest.raises(InvalidCompetitionRun):
        module.build_ablation_arms(_ProfileView())


def test_arms_config_structure() -> None:
    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    arms = module.build_ablation_arms(profile)

    config = module.build_arms_config(
        profile, arms, plan_mode="replay", selected_labels=[module.FULL_LABEL]
    )

    assert config["schema_version"] == "ablation-matrix-arms-config/1.0"
    assert config["plan_mode"] == "replay"
    assert config["competition_qualified"] is False
    assert config["selected_labels"] == [module.FULL_LABEL]
    assert config["replay_limitation_note"]
    assert [item["label"] for item in config["arms"]] == list(
        module.ABLATION_ARM_LABELS
    )
    full_dump = next(
        item for item in config["arms"] if item["label"] == module.FULL_LABEL
    )
    assert full_dump["arm_id"] == "A4"
    no_memory_dump = next(
        item for item in config["arms"] if item["label"] == module.NO_MEMORY_GUARD_LABEL
    )
    assert no_memory_dump["partial"] is True
    assert no_memory_dump["policy_disabled_rules"] == ["P104_memory_poisoning"]


def test_arms_command_prints_matrix_without_running(
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_script()

    assert module.main(["arms"]) == 0

    out = capsys.readouterr().out
    for label in module.ABLATION_ARM_LABELS:
        assert label in out
    # 尾部输出 arms-config JSON 结构。
    payload = json.loads(out[out.index("{") :])
    assert payload["schema_version"] == "ablation-matrix-arms-config/1.0"
    assert [item["label"] for item in payload["arms"]] == list(
        module.ABLATION_ARM_LABELS
    )


# ---------------------------------------------------------------------------
# --group / --case-id 过滤
# ---------------------------------------------------------------------------


def test_load_groups_reads_frozen_dataset_groups() -> None:
    module = _load_script()

    groups = module.load_groups()

    assert "prompt_injection" in groups
    assert groups["prompt_injection"]
    assert all(isinstance(item, str) for item in groups["prompt_injection"])
    # 组名大小写敏感。
    assert "PROMPT_INJECTION" not in groups


def test_select_cases_union_and_frozen_order() -> None:
    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    group_map = {"alpha": ["PI-001"], "beta": ["BN-001", "AA-001"]}

    cases = module.select_cases(
        profile, case_ids=["BN-001"], group_names=["alpha"], groups=group_map
    )

    # 并集后保持冻结数据集顺序（BN 在 PI 之前），而非 CLI 顺序。
    assert [case.case_id for case in cases] == ["BN-001", "PI-001"]

    with pytest.raises(InvalidCompetitionRun) as excinfo:
        module.select_cases(profile, group_names=["nope"], groups=group_map)
    assert excinfo.value.reason_code == "group_selection_invalid"
    # 报错附上可用组列表（来自 load_groups/传入 groups 结果）。
    assert "alpha" in str(excinfo.value)
    assert "beta" in str(excinfo.value)

    with pytest.raises(InvalidCompetitionRun) as excinfo:
        module.select_cases(profile, case_ids=["ZZ-999"], groups=group_map)
    assert excinfo.value.reason_code == "case_selection_invalid"

    # 无过滤时返回全量冻结数据集。
    assert module.select_cases(profile, groups=group_map)


def test_select_cases_accepts_real_dataset_group() -> None:
    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)

    cases = module.select_cases(profile, group_names=["prompt_injection"])

    assert cases
    assert all(case.attack_type == "prompt_injection" for case in cases)


# ---------------------------------------------------------------------------
# 臂级断点续跑状态机
# ---------------------------------------------------------------------------


def test_arm_result_state_machine(tmp_path: Path) -> None:
    module = _load_script()
    repeat_root = tmp_path / "repeat-0"

    # result.json 缺失 → 未通过。
    assert module.arm_passed(repeat_root, module.FULL_LABEL) is False

    module.write_arm_result(
        repeat_root,
        module.FULL_LABEL,
        status="passed",
        duration_seconds=1.0,
        case_count=2,
        rows=[{"case_id": "PI-001"}],
        case_ids=["PI-001", "BN-001"],
    )
    assert module.arm_passed(repeat_root, module.FULL_LABEL) is True
    payload = json.loads(
        module.arm_result_path(repeat_root, module.FULL_LABEL).read_text()
    )
    assert payload["status"] == "passed"
    assert payload["case_count"] == 2
    assert payload["rows_sha256"]
    assert payload["case_ids_digest"] == module.case_ids_digest(
        ["PI-001", "BN-001"]
    )
    # case 集一致性：期望 case 数/case_ids 指纹不匹配时不视为已通过
    # （防止换 --group/--case-id 后误 skip 旧产物）。
    assert (
        module.arm_passed(
            repeat_root,
            module.FULL_LABEL,
            expected_case_count=3,
            expected_case_ids_digest=module.case_ids_digest(
                ["PI-001", "BN-001", "XX-999"]
            ),
        )
        is False
    )
    assert (
        module.arm_passed(
            repeat_root,
            module.FULL_LABEL,
            expected_case_count=2,
            expected_case_ids_digest=module.case_ids_digest(["PI-001", "BN-001"]),
        )
        is True
    )

    # failed 状态 → 重跑。
    module.write_arm_result(
        repeat_root,
        module.FULL_LABEL,
        status="failed",
        duration_seconds=1.0,
        case_count=0,
        error="boom",
    )
    assert module.arm_passed(repeat_root, module.FULL_LABEL) is False

    # 损坏 JSON → 视为未通过。
    module.arm_result_path(repeat_root, module.FULL_LABEL).write_text(
        "{broken", encoding="utf-8"
    )
    assert module.arm_passed(repeat_root, module.FULL_LABEL) is False

    # rows_sha256 只对确定性语义子集计算：trace_id/task_id 等每次执行
    # 唯一的非确定字段不改变指纹（原断言用无 trace_id 的 fake rows 是
    # 假阳性，这里显式构造含非确定字段的 rows 验证稳定）。
    def _volatile_row(suffix: str) -> dict[str, Any]:
        return {
            "case_id": "PI-001",
            "attack_type": "prompt_injection",
            "is_malicious": True,
            "run_valid": True,
            "run_status": "completed",
            "attack_success": False,
            "task_success": True,
            "instrumentation_plan_mode": "replay",
            "planning_source": "deterministic_replay",
            # 非确定字段：每次执行唯一。
            "task_fact": {
                "trace_id": f"trace-{suffix}",
                "task_id": f"task-{suffix}",
            },
        }

    assert module.rows_sha256([_volatile_row("r1")]) == module.rows_sha256(
        [_volatile_row("r2")]
    )
    # 语义字段变化必须改变指纹。
    assert module.rows_sha256([_volatile_row("r1")]) != module.rows_sha256(
        [{**_volatile_row("r1"), "attack_success": True}]
    )


def _run_argv(module: ModuleType, artifacts: Path, *extra: str) -> list[str]:
    return [
        "run",
        "--artifacts",
        str(artifacts),
        "--case-id",
        "PI-001",
        "--case-id",
        "BN-001",
        "--serial",
        *extra,
    ]


def test_run_skips_passed_arms_and_force_reruns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    executed: list[str] = []

    def fake_execute(request: Any) -> dict[str, Any]:
        executed.append(request.label)
        return _fake_arm_payload(module, request)

    monkeypatch.setattr(module, "execute_ablation_arm", fake_execute)
    monkeypatch.setattr(
        module, "resolve_provider", lambda profile, args: _fake_provider()
    )
    artifacts = tmp_path / "ablation"
    argv = _run_argv(module, artifacts)

    # 第一轮：六臂全部执行并标记 passed。
    assert module.main(argv) == 0
    assert executed == list(module.ABLATION_ARM_LABELS)
    first_result = (
        artifacts / "repeat-0" / "arms" / module.FULL_LABEL / "result.json"
    ).read_text()

    # 第二轮：已 passed 的臂全部跳过，产物原样保留。
    executed.clear()
    assert module.main(argv) == 0
    assert executed == []
    assert (
        artifacts / "repeat-0" / "arms" / module.FULL_LABEL / "result.json"
    ).read_text() == first_result

    # --force：全部重跑。
    executed.clear()
    assert module.main([*argv, "--force"]) == 0
    assert executed == list(module.ABLATION_ARM_LABELS)


def test_run_retries_failed_arm_on_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    state = {"explode_full": True}
    executed: list[str] = []

    def fake_execute(request: Any) -> dict[str, Any]:
        executed.append(request.label)
        if request.label == module.FULL_LABEL and state["explode_full"]:
            raise RuntimeError("full fixture exploded")
        return _fake_arm_payload(module, request)

    monkeypatch.setattr(module, "execute_ablation_arm", fake_execute)
    monkeypatch.setattr(
        module, "resolve_provider", lambda profile, args: _fake_provider()
    )
    artifacts = tmp_path / "ablation"
    argv = _run_argv(module, artifacts)

    # 第一轮：full 崩溃 → fail-soft 继续，其余臂完成；退出码非 0。
    assert module.main(argv) == int(module.ExitCode.INVALID_RUN)
    full_result = json.loads(
        (artifacts / "repeat-0" / "arms" / module.FULL_LABEL / "result.json").read_text()
    )
    assert full_result["status"] == "failed"
    assert "full fixture exploded" in full_result["error"]
    assert not (
        artifacts / "repeat-0" / "arms" / module.FULL_LABEL / "run.json"
    ).exists()
    core_off_result = json.loads(
        (
            artifacts / "repeat-0" / "arms" / module.CORE_OFF_LABEL / "result.json"
        ).read_text()
    )
    assert core_off_result["status"] == "passed"

    # 第二轮：仅 failed 的 full 臂重跑。
    state["explode_full"] = False
    executed.clear()
    assert module.main(argv) == 0
    assert executed == [module.FULL_LABEL]
    full_result = json.loads(
        (artifacts / "repeat-0" / "arms" / module.FULL_LABEL / "result.json").read_text()
    )
    assert full_result["status"] == "passed"


def test_run_reruns_passed_arm_when_case_set_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """断点续跑校验 case 集一致性（评审 Fix）：换 --case-id 集后已
    passed 的臂不误 skip，打 WARNING 后重跑；同集时仍然 skip。"""

    module = _load_script()
    executed: list[str] = []

    def fake_execute(request: Any) -> dict[str, Any]:
        executed.append(request.label)
        return _fake_arm_payload(module, request)

    monkeypatch.setattr(module, "execute_ablation_arm", fake_execute)
    monkeypatch.setattr(
        module, "resolve_provider", lambda profile, args: _fake_provider()
    )
    artifacts = tmp_path / "ablation"

    # 第一轮：仅 BN-001（1 例）。
    argv_partial = [
        "run",
        "--artifacts",
        str(artifacts),
        "--case-id",
        "BN-001",
        "--serial",
    ]
    assert module.main(argv_partial) == 0
    assert executed == list(module.ABLATION_ARM_LABELS)
    partial_result = json.loads(
        (
            artifacts / "repeat-0" / "arms" / module.FULL_LABEL / "result.json"
        ).read_text()
    )
    assert partial_result["case_count"] == 1
    assert partial_result["case_ids_digest"] == module.case_ids_digest(["BN-001"])

    # 第二轮：扩为 BN-001 + PI-001（冻结顺序）→ 不 skip，WARNING 后重跑。
    executed.clear()
    capsys.readouterr()
    argv_full = [
        "run",
        "--artifacts",
        str(artifacts),
        "--case-id",
        "PI-001",
        "--case-id",
        "BN-001",
        "--serial",
    ]
    assert module.main(argv_full) == 0
    assert executed == list(module.ABLATION_ARM_LABELS)
    captured = capsys.readouterr()
    assert "case 集" in captured.err
    full_result = json.loads(
        (
            artifacts / "repeat-0" / "arms" / module.FULL_LABEL / "result.json"
        ).read_text()
    )
    assert full_result["case_count"] == 2
    assert full_result["case_ids_digest"] == module.case_ids_digest(
        ["BN-001", "PI-001"]
    )

    # 第三轮：同集再跑 → 全部 skip，无 WARNING。
    executed.clear()
    capsys.readouterr()
    assert module.main(argv_full) == 0
    assert executed == []
    captured = capsys.readouterr()
    assert "case 集" not in captured.err


def test_run_duration_seconds_is_per_arm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """duration_seconds 是臂自身耗时（评审 Fix）：serial 下后执行臂不再
    包含前序臂耗时，由 execute_ablation_arm 返回的分片耗时聚合。"""

    module = _load_script()

    def fake_execute(request: Any) -> dict[str, Any]:
        payload = _fake_arm_payload(module, request)
        # 模拟 execute_ablation_arm 的臂级计时：每臂固定 3.0s。
        payload["shard_duration_seconds"] = 3.0
        return payload

    monkeypatch.setattr(module, "execute_ablation_arm", fake_execute)
    monkeypatch.setattr(
        module, "resolve_provider", lambda profile, args: _fake_provider()
    )
    artifacts = tmp_path / "ablation"

    assert module.main(_run_argv(module, artifacts)) == 0

    for label in module.ABLATION_ARM_LABELS:
        payload = json.loads(
            (artifacts / "repeat-0" / "arms" / label / "result.json").read_text()
        )
        # 每臂独立计时：serial 单分片 = 该臂自身 3.0s，而非 repeat 累计。
        assert payload["duration_seconds"] == 3.0


# ---------------------------------------------------------------------------
# report 汇总
# ---------------------------------------------------------------------------


def _report_row(
    case_id: str,
    *,
    is_malicious: bool = False,
    attack_success: bool | None = None,
    blocked: bool = False,
    run_valid: bool = True,
    invalid_reasons: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "is_malicious": is_malicious,
        "attack_type": "prompt_injection" if is_malicious else "benign",
        "run_valid": run_valid,
        "run_status": "completed" if run_valid else "invalid",
        "attack_success": attack_success,
        "overblocked": None,
        "task_success": not is_malicious,
        "blocked": blocked,
        "invalid_reasons": invalid_reasons or [],
        "decision_comparisons": [],
        "model_exchanges": [],
        "tool_executions": [],
    }


def _write_arm_fixture(
    root: Path, label: str, rows: list[dict[str, Any]], *, status: str = "passed"
) -> None:
    arm_dir = root / "arms" / label
    arm_dir.mkdir(parents=True, exist_ok=True)
    (arm_dir / "run.json").write_text(
        json.dumps(rows, ensure_ascii=False), encoding="utf-8"
    )
    (arm_dir / "durations.json").write_text(
        json.dumps({row["case_id"]: 100.0 for row in rows}), encoding="utf-8"
    )
    (arm_dir / "result.json").write_text(
        json.dumps({"status": status}), encoding="utf-8"
    )


def _write_full_matrix_fixture(module: ModuleType, artifacts: Path) -> None:
    repeat_root = artifacts / "repeat-0"
    repeat_root.mkdir(parents=True, exist_ok=True)
    malicious_kwargs = {"is_malicious": True}
    full_rows = [
        _report_row("PI-001", **malicious_kwargs, attack_success=False, blocked=True),
        _report_row("BN-001"),
    ]
    _write_arm_fixture(repeat_root, module.CORE_OFF_LABEL, [
        _report_row("PI-001", **malicious_kwargs, attack_success=True),
        _report_row("BN-001"),
    ])
    _write_arm_fixture(repeat_root, module.FULL_LABEL, full_rows)
    _write_arm_fixture(repeat_root, module.NO_CONTEXT_ISOLATION_LABEL, [
        # 消融后攻击失守（模块移除重新放行）。
        _report_row("PI-001", **malicious_kwargs, attack_success=True, blocked=False),
        _report_row("BN-001"),
    ])
    _write_arm_fixture(repeat_root, module.NO_PROVENANCE_TAINT_LABEL, [
        _report_row("PI-001", **malicious_kwargs, attack_success=False, blocked=True),
        # 一行无效行验证 invalid_reasons 分布。
        _report_row(
            "BN-001", run_valid=False, invalid_reasons=["runtime_limits_exceeded"]
        ),
    ])
    _write_arm_fixture(repeat_root, module.NO_MEMORY_GUARD_LABEL, full_rows)
    _write_arm_fixture(repeat_root, module.NO_SEMANTIC_JUDGE_LABEL, full_rows)


def test_report_summarizes_fixture_rows(tmp_path: Path) -> None:
    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    artifacts = tmp_path / "ablation"
    _write_full_matrix_fixture(module, artifacts)

    report, _ = module.build_ablation_report(
        profile=profile, artifacts=artifacts, plan_mode="replay"
    )

    assert report["plan_mode"] == "replay"
    assert report["competition_qualified"] is False
    assert report["report_repeat_index"] == 0
    assert set(report["arms"]) == set(module.ABLATION_ARM_LABELS)

    core_off = report["arms"][module.CORE_OFF_LABEL]
    assert core_off["safety"]["asr_valid_malicious"] == pytest.approx(1.0)
    assert core_off["blocked_rate"] == pytest.approx(0.0)
    full = report["arms"][module.FULL_LABEL]
    assert full["safety"]["asr_valid_malicious"] == pytest.approx(0.0)
    assert full["blocked_rate"] == pytest.approx(0.5)
    assert full["partial"] is False
    no_taint = report["arms"][module.NO_PROVENANCE_TAINT_LABEL]
    assert no_taint["partial"] is True
    assert no_taint["invalid_reasons"] == {"runtime_limits_exceeded": 1}
    no_semantic = report["arms"][module.NO_SEMANTIC_JUDGE_LABEL]
    assert no_semantic["decision_invariant"] is True

    # core-off 为 baseline 的 5 个 Guard 臂配对。
    assert set(report["paired_vs_core_off"]) == set(module.GUARD_ARM_LABELS)
    full_paired = report["paired_vs_core_off"][module.FULL_LABEL]
    assert full_paired["paired_valid_malicious_count"] == 1
    assert full_paired["attack_success_count_baseline"] == 1
    assert full_paired["attack_success_count_product"] == 0
    assert full_paired["blocked_successful_attack_count"] == 1

    # 每个消融臂 vs full 的模块净效应。
    assert set(report["module_net_vs_full"]) == set(module.ABLATION_VS_FULL_LABELS)
    nci_net = report["module_net_vs_full"][module.NO_CONTEXT_ISOLATION_LABEL]
    assert nci_net["module_removed_attack_success_count"] == 1
    assert nci_net["module_removed_attack_success_case_ids"] == ["PI-001"]
    taint_net = report["module_net_vs_full"][module.NO_PROVENANCE_TAINT_LABEL]
    assert taint_net["module_removed_attack_success_count"] == 0


def test_invalid_reasons_distribution_consumes_normalized_rows(
    tmp_path: Path,
) -> None:
    """invalid_reasons 分布消费 _normalize_case_row 归一化行（评审 Fix）：
    此前归一化行不含该键、报告分布恒空 {}；这里走真实归一化路径，用
    run_status 无效行验证分布非空，而不是手工塞键的 fake fixture。"""

    module = _load_script()
    from agentguard_langgraph_bench.bench.competition_runtime import (
        _normalize_case_row,
    )

    profile = load_competition_profile(COMPETITION_PROFILE_ID).with_overrides(
        suite=CompetitionSuite.DEMO, full_corpus=False
    )
    case = next(
        item
        for item in load_attack_cases(profile.dataset.path)
        if item.case_id == "BN-001"
    )
    arm = next(item for item in profile.arms if item.arm_id == "A4")
    request = ArmRunRequest(
        profile=profile,
        arm=arm,
        repeat_index=0,
        seed=0,
        cases=(case,),
        provider=_fake_provider(),
        artifact_directory=tmp_path / "arm",
        suite=CompetitionSuite.DEMO,
        qualification_eligible=False,
        plan_mode_override="replay",
    )
    raw = {
        "case_id": "BN-001",
        "run_valid": False,
        "run_status": "invalid",
        "planning_source": "deterministic_replay",
        "llm_request_count": 0,
        "model_exchanges": [],
        "invalid_reasons": ["runtime_limits_exceeded"],
    }
    row = _normalize_case_row(
        raw,
        case=case,
        request=request,
        policy_digest="a" * 64,
        task_fact={"status": "provisioned"},
        trace=None,
    )
    assert row["run_status"] == "invalid"
    assert row["invalid_reasons"] == ["runtime_limits_exceeded"]
    assert module._invalid_reasons_distribution([row]) == {
        "runtime_limits_exceeded": 1
    }


def test_report_blocked_rate_counts_run_status_blocked(tmp_path: Path) -> None:
    """replay 剧本中途被拦截的行没有 blocked 布尔字段，blocked_rate 应
    以 run_status == "blocked" 兕底计数。"""

    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    artifacts = tmp_path / "ablation"
    repeat_root = artifacts / "repeat-0"
    repeat_root.mkdir(parents=True)
    blocked_row = _report_row("PR-001", is_malicious=True, attack_success=False)
    blocked_row["run_status"] = "blocked"
    _write_arm_fixture(repeat_root, module.FULL_LABEL, [
        blocked_row,
        _report_row("BN-001"),
    ])
    _write_arm_fixture(repeat_root, module.CORE_OFF_LABEL, [
        _report_row("PR-001", is_malicious=True, attack_success=True),
        _report_row("BN-001"),
    ])

    report, _ = module.build_ablation_report(
        profile=profile,
        artifacts=artifacts,
        plan_mode="replay",
        selected_labels=[module.CORE_OFF_LABEL, module.FULL_LABEL],
    )

    full = report["arms"][module.FULL_LABEL]
    assert full["blocked_rate"] == pytest.approx(0.5)
    core_off = report["arms"][module.CORE_OFF_LABEL]
    assert core_off["blocked_rate"] == pytest.approx(0.0)


def test_report_incomplete_raises_unless_allowed(tmp_path: Path) -> None:
    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    artifacts = tmp_path / "ablation"
    _write_full_matrix_fixture(module, artifacts)
    # 抽掉 full 臂的产物。
    (artifacts / "repeat-0" / "arms" / module.FULL_LABEL / "run.json").unlink()

    with pytest.raises(InvalidCompetitionRun) as excinfo:
        module.build_ablation_report(profile=profile, artifacts=artifacts)
    assert excinfo.value.reason_code == "ablation_report_incomplete"

    report, _ = module.build_ablation_report(
        profile=profile, artifacts=artifacts, allow_incomplete=True
    )
    assert any(module.FULL_LABEL in item for item in report["problems"])
    assert module.FULL_LABEL not in report["arms"]


def test_report_command_standalone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_script()
    artifacts = tmp_path / "ablation"
    _write_full_matrix_fixture(module, artifacts)
    (artifacts / "arms-config.json").write_text(
        json.dumps({"plan_mode": "replay"}), encoding="utf-8"
    )

    assert module.main(["report", "--artifacts", str(artifacts)]) == 0

    report = json.loads((artifacts / "ablation-report.json").read_text())
    assert report["plan_mode"] == "replay"
    assert set(report["arms"]) == set(module.ABLATION_ARM_LABELS)
    markdown = (artifacts / "ablation-report.md").read_text()
    assert markdown.startswith("#")
    assert module.FULL_LABEL in markdown
    out = capsys.readouterr().out
    assert "六臂消融汇总" in out


def test_repeats_summary_stability_handles_missing_and_failed_repeats(
    tmp_path: Path,
) -> None:
    """stability 只对至少两轮都有指纹的臂判定（评审 Fix）：失败/缺失轮的
    None 不再字符串化混入集合（有失败轮误报 unstable、全 None 误报
    stable），不足两轮时置 None 并附各轮 status 明细。"""

    module = _load_script()
    artifacts = tmp_path / "ablation"
    repeat_root = artifacts / "repeat-0"
    repeat_root.mkdir(parents=True)
    module.write_arm_result(
        repeat_root,
        module.FULL_LABEL,
        status="passed",
        duration_seconds=1.0,
        case_count=1,
        rows=[{"case_id": "BN-001", "run_valid": True}],
        case_ids=["BN-001"],
    )
    module.write_arm_result(
        repeat_root,
        module.NO_CONTEXT_ISOLATION_LABEL,
        status="failed",
        duration_seconds=1.0,
        case_count=0,
        error="boom",
    )
    # 第二轮：full 正常（与第一轮同指纹）；no-context-isolation 缺失。
    repeat_root_1 = artifacts / "repeat-1"
    repeat_root_1.mkdir(parents=True)
    module.write_arm_result(
        repeat_root_1,
        module.FULL_LABEL,
        status="passed",
        duration_seconds=1.0,
        case_count=1,
        rows=[{"case_id": "BN-001", "run_valid": True}],
        case_ids=["BN-001"],
    )

    module._write_repeats_summary(
        artifacts,
        profile_id=COMPETITION_PROFILE_ID,
        failures=[],
        selected_labels=[module.FULL_LABEL, module.NO_CONTEXT_ISOLATION_LABEL],
    )
    summary = json.loads((artifacts / "repeats-summary.json").read_text())
    stability = summary["rows_sha256_stability"]
    # full：两轮都有指纹且相同 → stable True。
    assert (
        stability[module.FULL_LABEL]["rows_sha256_stable_across_repeats"] is True
    )
    assert stability[module.FULL_LABEL]["repeats_with_digest"] == 2
    # no-context-isolation：一轮 failed（无指纹）、一轮缺失 → 不足两轮，
    # 置 None 并附各轮 status 明细（旧逻辑会把 None 字符串化后误报 stable）。
    nci = stability[module.NO_CONTEXT_ISOLATION_LABEL]
    assert nci["rows_sha256_stable_across_repeats"] is None
    assert nci["repeats_with_digest"] == 0
    assert [item["status"] for item in nci["per_repeat_status"]] == [
        "failed",
        "missing",
    ]


# ---------------------------------------------------------------------------
# 请求构造与 provider 解析
# ---------------------------------------------------------------------------


def test_execute_ablation_arm_request_plumbing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """worker 构造的 ArmRunRequest 透传 plan_mode/policy，产物目录用 label，
    memory 豁免 env 在该臂注入。"""

    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    cases = module.select_cases(profile, case_ids=["BN-001"], groups={})
    captured: dict[str, Any] = {}

    def fake_execute_arm(arm_request, *, case_runner=None):
        captured["request"] = arm_request
        # 臂执行期间 memory 豁免 env 已注入（GuardApiSettings 构造时读取）。
        captured["memory_env_during_run"] = os.environ.get(
            module._MEMORY_NOT_REQUIRED_ENV
        )
        rows = case_runner(list(arm_request.cases), config=None)
        return ArmRunResult(
            rows=tuple(rows), contracts={"probe": {"status": "passed"}}
        )

    monkeypatch.setattr(
        "agentguard_langgraph_bench.bench.competition_runtime.execute_competition_arm",
        fake_execute_arm,
    )
    monkeypatch.setattr(
        "agentguard_langgraph_bench.bench.runner.run_cases",
        lambda cases, **kwargs: [{"case_id": case.case_id} for case in cases],
    )
    monkeypatch.setattr(
        competition_parallel, "apply_stream_environment", lambda table: {}
    )
    monkeypatch.setattr(competition_parallel, "check_ports_available", lambda table: None)
    monkeypatch.setattr(
        competition_parallel, "rewrite_cases_for_ports", lambda cases, table: list(cases)
    )
    monkeypatch.delenv(module._MEMORY_NOT_REQUIRED_ENV, raising=False)
    request = module.ArmWorkerRequest(
        label=module.NO_MEMORY_GUARD_LABEL,
        slot=0,
        repeat_index=0,
        port_table={
            service: 19080
            for service in competition_parallel.STREAM_SERVICE_DEFAULT_PORTS
        },
        profile=profile,
        provider=_fake_provider(),
        cases=cases,
        artifact_root=tmp_path / "repeat-0",
        arm=module.build_ablation_arms(profile)[module.NO_MEMORY_GUARD_LABEL].arm,
        plan_mode_override="replay",
        policy_disabled_rules=("P104_memory_poisoning",),
        memory_not_required_env=True,
    )

    payload = module.execute_ablation_arm(request)

    arm_request = captured["request"]
    assert arm_request.plan_mode_override == "replay"
    assert arm_request.policy_disabled_rules == ("P104_memory_poisoning",)
    assert arm_request.qualification_eligible is False
    # 产物目录使用 label 而非 arm_id。
    assert arm_request.artifact_directory == tmp_path / "repeat-0" / "arms" / (
        module.NO_MEMORY_GUARD_LABEL
    )
    assert payload["label"] == module.NO_MEMORY_GUARD_LABEL
    assert len(payload["rows"]) == 1
    assert "BN-001" in payload["case_durations_ms"]
    # memory required-checks 豁免 env 在臂执行期间注入、结束后恢复
    # （serial 模式下多个臂共享本进程，不泄漏到后续臂）。
    assert (
        captured["memory_env_during_run"]
        == module._MEMORY_NOT_REQUIRED_ENV_VALUE
    )
    assert module._MEMORY_NOT_REQUIRED_ENV not in os.environ
    monkeypatch.delenv(module._MEMORY_NOT_REQUIRED_ENV, raising=False)


def test_resolve_provider_replay_uses_placeholder(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    args = SimpleNamespace(
        plan_mode="replay",
        llm_provider_id=None,
        llm_model=None,
        llm_base_url=None,
        llm_api_key_env=None,
        temperature=None,
        request_timeout=None,
        max_retries=None,
        max_tool_rounds=None,
    )
    monkeypatch.delenv(profile.planner.api_key_env, raising=False)

    provider = module.resolve_provider(profile, args)

    assert provider.model == module._REPLAY_PROVIDER_PLACEHOLDER
    assert provider.base_url == module._REPLAY_PROVIDER_PLACEHOLDER
    assert provider.api_key == module._REPLAY_PROVIDER_PLACEHOLDER


def test_resolve_provider_autonomous_requires_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    args = SimpleNamespace(
        plan_mode="autonomous",
        llm_provider_id=None,
        llm_model=None,
        llm_base_url=None,
        llm_api_key_env=None,
        temperature=None,
        request_timeout=None,
        max_retries=None,
        max_tool_rounds=None,
    )
    monkeypatch.delenv(profile.planner.api_key_env, raising=False)

    with pytest.raises(InvalidCompetitionRun) as excinfo:
        module.resolve_provider(profile, args)
    assert excinfo.value.reason_code == "provider_configuration_missing"


# ---------------------------------------------------------------------------
# cmd_run 端到端（stub execute_ablation_arm）
# ---------------------------------------------------------------------------


def test_cmd_run_writes_full_layout_and_semantic_only_for_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    semantic_seen: dict[str, dict[str, str]] = {}

    def fake_execute(request: Any) -> dict[str, Any]:
        semantic_seen[request.label] = dict(request.semantic_env)
        return _fake_arm_payload(module, request)

    monkeypatch.setattr(module, "execute_ablation_arm", fake_execute)
    monkeypatch.setattr(
        module, "resolve_provider", lambda profile, args: _fake_provider()
    )
    monkeypatch.setenv("ABLATION_SEM_KEY", "sem-key")
    artifacts = tmp_path / "ablation"

    exit_code = module.main(
        _run_argv(
            module,
            artifacts,
            "--plan-mode",
            "autonomous",
            "--semantic-model",
            "sem-model",
            "--semantic-base-url",
            "http://semantic.example/v1",
            "--semantic-api-key-env",
            "ABLATION_SEM_KEY",
        )
    )

    assert exit_code == 0
    # V21-13 语义判定 env 仅注入 full 臂。
    assert (
        semantic_seen[module.FULL_LABEL]["AGENTGUARD_V21_SEMANTIC_ENABLED"] == "true"
    )
    for label in module.ABLATION_ARM_LABELS:
        if label != module.FULL_LABEL:
            assert semantic_seen[label] == {}

    assert (artifacts / "arms-config.json").exists()
    for label in module.ABLATION_ARM_LABELS:
        arm_dir = artifacts / "repeat-0" / "arms" / label
        assert (arm_dir / "run.json").exists()
        assert (arm_dir / "durations.json").exists()
        assert (arm_dir / "contracts.json").exists()
        assert (
            json.loads((arm_dir / "result.json").read_text())["status"] == "passed"
        )
    assert (artifacts / "repeats-summary.json").exists()
    summary = json.loads((artifacts / "repeats-summary.json").read_text())
    assert summary["repeat_count"] == 1
    assert set(summary["rows_sha256_stability"]) == set(module.ABLATION_ARM_LABELS)
    report = json.loads((artifacts / "ablation-report.json").read_text())
    assert report["plan_mode"] == "autonomous"
    assert set(report["arms"]) == set(module.ABLATION_ARM_LABELS)
    assert set(report["paired_vs_core_off"]) == set(module.GUARD_ARM_LABELS)
    assert set(report["module_net_vs_full"]) == set(module.ABLATION_VS_FULL_LABELS)
    assert (artifacts / "ablation-report.md").read_text().startswith("#")
    assert not (artifacts / "repeat-1").exists()


def test_cmd_run_replay_clears_semantic_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    semantic_seen: dict[str, dict[str, str]] = {}

    def fake_execute(request: Any) -> dict[str, Any]:
        semantic_seen[request.label] = dict(request.semantic_env)
        return _fake_arm_payload(module, request)

    monkeypatch.setattr(module, "execute_ablation_arm", fake_execute)
    monkeypatch.setattr(
        module, "resolve_provider", lambda profile, args: _fake_provider()
    )
    monkeypatch.setenv("ABLATION_SEM_KEY", "sem-key")
    artifacts = tmp_path / "ablation"

    exit_code = module.main(
        _run_argv(
            module,
            artifacts,
            "--semantic-model",
            "sem-model",
            "--semantic-base-url",
            "http://semantic.example/v1",
            "--semantic-api-key-env",
            "ABLATION_SEM_KEY",
        )
    )

    # 默认 replay 模式忽略 --semantic-*（零 LLM 回放）。
    assert exit_code == 0
    assert all(not env for env in semantic_seen.values())


def test_cmd_run_rejects_arm_parallel_without_single_arm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    monkeypatch.setattr(
        module, "resolve_provider", lambda profile, args: _fake_provider()
    )

    exit_code = module.main(_run_argv(module, tmp_path / "ablation", "--arm-parallel", "2"))

    assert exit_code == int(module.ExitCode.INVALID_RUN)


# ---------------------------------------------------------------------------
# --provider-rate-limit 接线（官方 runner 同模式）
# ---------------------------------------------------------------------------


def test_provider_rate_limit_token_wiring(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--provider-rate-limit 三态：未开启 token None；开启 + serial 打印
    no-op 说明并保持 None；开启 + parallel 创建 spawn context
    BoundedSemaphore token 并经 ArmWorkerRequest 字段传递。"""

    import multiprocessing

    module = _load_script()

    # 未开启：token None。
    args_off = SimpleNamespace(provider_rate_limit=None, serial=False)
    assert module._provider_token_for(args_off) is None

    # 开启 + serial：no-op 说明 + None。
    args_serial = SimpleNamespace(provider_rate_limit="1", serial=True)
    capsys.readouterr()
    assert module._provider_token_for(args_serial) is None
    assert "no-op" in capsys.readouterr().out

    # 开启 + parallel：spawn context 上的 BoundedSemaphore token。
    args_parallel = SimpleNamespace(provider_rate_limit="1", serial=False)
    token = module._provider_token_for(args_parallel)
    assert token is not None
    assert isinstance(token, multiprocessing.synchronize.BoundedSemaphore)

    # ArmWorkerRequest 字段：默认 None（未开启限流），显式传入后可回读。
    profile = load_competition_profile(COMPETITION_PROFILE_ID)
    cases = module.select_cases(profile, case_ids=["BN-001"], groups={})
    base_kwargs = dict(
        label=module.FULL_LABEL,
        slot=0,
        repeat_index=0,
        port_table={},
        profile=profile,
        provider=_fake_provider(),
        cases=cases,
        artifact_root=tmp_path,
        arm=module.build_ablation_arms(profile)[module.FULL_LABEL].arm,
    )
    assert module.ArmWorkerRequest(**base_kwargs).provider_global_token is None
    tokened = module.ArmWorkerRequest(**base_kwargs, provider_global_token=token)
    assert tokened.provider_global_token is token


def test_run_serial_provider_rate_limit_prints_noop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """serial + --provider-rate-limit：打印一行 no-op 说明，worker request
    的 token 为 None（行为与未开启时一致）。"""

    module = _load_script()

    def fake_execute(request: Any) -> dict[str, Any]:
        assert request.provider_global_token is None
        return _fake_arm_payload(module, request)

    monkeypatch.setattr(module, "execute_ablation_arm", fake_execute)
    monkeypatch.setattr(
        module, "resolve_provider", lambda profile, args: _fake_provider()
    )
    artifacts = tmp_path / "ablation"

    exit_code = module.main(
        _run_argv(module, artifacts, "--provider-rate-limit", "1")
    )

    assert exit_code == 0
    assert "provider-rate-limit" in capsys.readouterr().out
