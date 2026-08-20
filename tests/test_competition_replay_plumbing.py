"""改动 0（replay 接入竞赛管线）的定向回归测试。

覆盖：preflight 跳过、contracts skipped 条目、policy 禁用规则合并、
``_bench_config`` 计划模式透传、``_normalize_case_row`` 的 replay 放宽
路径与默认路径不变性、``BenchConfig`` competition_mode 校验接受 replay。
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from agentguard_langgraph_bench.bench.competition_models import (
    CompetitionSuite,
    load_competition_profile,
)
from agentguard_langgraph_bench.bench.competition_runner import (
    ArmRunRequest,
    InvalidCompetitionRun,
    ProviderRuntimeConfig,
)
from agentguard_langgraph_bench.bench import competition_runtime
from agentguard_langgraph_bench.bench.competition_runtime import (
    PolicyBundle,
    _bench_config,
    _competition_policy,
    _normalize_case_row,
    canonical_sha256,
    execute_competition_arm,
)
from agentguard_langgraph_bench.bench.config import BenchConfig
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases


def _replay_request(
    tmp_path: Path,
    *,
    plan_mode_override: str | None = "replay",
    arm_id: str = "A4",
    policy_disabled_rules: tuple[str, ...] = (),
) -> ArmRunRequest:
    profile = load_competition_profile("competition-langgraph-v2").with_overrides(
        suite=CompetitionSuite.DEMO,
        full_corpus=False,
    )
    case = next(
        item
        for item in load_attack_cases(profile.dataset.path)
        if item.case_id == "BN-001"
    )
    arm = next(item for item in profile.arms if item.arm_id == arm_id)
    return ArmRunRequest(
        profile=profile,
        arm=arm,
        repeat_index=0,
        seed=0,
        cases=(case,),
        provider=ProviderRuntimeConfig(
            provider_id="local-compatible",
            model="competition-stub-model",
            # replay 模式零 LLM，base_url 指向黑洞端口也不应被请求。
            base_url="http://127.0.0.1:9/v1",
            api_key_env="COMPETITION_LOCAL_KEY",
            api_key="local-key",
            temperature=0,
            request_timeout=5,
            max_retries=0,
            max_tool_rounds=2,
        ),
        artifact_directory=tmp_path / "arm",
        suite=CompetitionSuite.DEMO,
        qualification_eligible=False,
        plan_mode_override=plan_mode_override,
        policy_disabled_rules=policy_disabled_rules,
    )


def _replay_raw(request: ArmRunRequest, **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "case_id": request.cases[0].case_id,
        "run_valid": True,
        "run_status": "completed",
        "instrumentation_plan_mode": "replay",
        "planning_source": "deterministic_replay",
        "llm_request_count": 0,
        "model_exchanges": [],
        "tool_calls": [],
        "guided_plan_applied": False,
        "fallback_applied": False,
        "attack_success": None,
        "overblocked": None,
        "task_success": True,
    }
    row.update(overrides)
    return row


def test_bench_config_competition_mode_accepts_replay_only() -> None:
    """replay 仅限 effect/ablation 分析用途；guided 等其它值仍然拒绝。"""

    replay = BenchConfig(
        llm_enabled=True,
        competition_mode=True,
        competition_arm_id="A4",
        instrumentation_plan_mode="replay",
        llm_max_retries=0,
    )
    assert replay.instrumentation_plan_mode == "replay"

    with pytest.raises(ValueError, match="instrumentation_plan_mode=autonomous"):
        BenchConfig(
            llm_enabled=True,
            competition_mode=True,
            competition_arm_id="A4",
            instrumentation_plan_mode="guided",
            llm_max_retries=0,
        )


def test_bench_config_forwards_plan_mode_override(tmp_path: Path) -> None:
    """instrumentation_plan_mode 默认 autonomous，replay override 时透传。"""

    request = _replay_request(tmp_path, plan_mode_override=None)
    case_id = request.cases[0].case_id
    kwargs: dict[str, Any] = {
        "base_url": "http://127.0.0.1:8088",
        "adapter_token": "adapter-token",
        "scratch": tmp_path / "scratch",
        "task_ids": {case_id: "task-1"},
        "trace_ids": {case_id: "trace-1"},
    }

    default_config = _bench_config(replace(request, plan_mode_override=None), **kwargs)
    assert default_config.instrumentation_plan_mode == "autonomous"

    replay_config = _bench_config(
        replace(request, plan_mode_override="replay"), **kwargs
    )
    assert replay_config.instrumentation_plan_mode == "replay"


def test_normalize_case_row_accepts_replay_self_attestation(
    tmp_path: Path,
) -> None:
    """replay 行（deterministic_replay + 零 LLM）接受自证并透传真实字段。"""

    request = _replay_request(tmp_path)
    row = _normalize_case_row(
        _replay_raw(request),
        case=request.cases[0],
        request=request,
        policy_digest="a" * 64,
        task_fact={"status": "provisioned"},
        trace=None,
    )

    assert row["run_valid"] is True
    assert row["model_invoked"] is False
    # replay 透传 raw 中的真实计划模式/来源。
    assert row["instrumentation_plan_mode"] == "replay"
    assert row["planning_source"] == "deterministic_replay"
    # digest fallback 以冻结 case payload 计算。
    payload_digest = canonical_sha256(request.cases[0].input.payload)
    assert row["round_1_source_set_digest"] == payload_digest
    assert row["round_1_model_input_digest"] == payload_digest
    assert row["tool_schema_digest"] == payload_digest
    # invalid_reasons 透传（评审 Fix：raw 缺省时空列表，非空时原样透传，
    # 供消融 report 分布统计；官方 admission projection 会剥离该键）。
    assert row["invalid_reasons"] == []
    invalid_row = _normalize_case_row(
        _replay_raw(
            request,
            run_valid=False,
            run_status="invalid",
            invalid_reasons=["runtime_limits_exceeded"],
        ),
        case=request.cases[0],
        request=request,
        policy_digest="a" * 64,
        task_fact={"status": "provisioned"},
        trace=None,
    )
    assert invalid_row["invalid_reasons"] == ["runtime_limits_exceeded"]


def test_normalize_case_row_replay_relaxation_requires_real_self_attestation(
    tmp_path: Path,
) -> None:
    """planning_source/llm_request_count 不满足自证条件时仍按原逻辑报错。"""

    request = _replay_request(tmp_path)
    for overrides in (
        {"planning_source": "llm_autonomous"},
        {"llm_request_count": 3},
    ):
        with pytest.raises(InvalidCompetitionRun) as excinfo:
            _normalize_case_row(
                _replay_raw(request, **overrides),
                case=request.cases[0],
                request=request,
                policy_digest="a" * 64,
                task_fact={},
                trace=None,
            )
        assert excinfo.value.reason_code == "model_invocation_evidence_missing"


def test_normalize_case_row_default_path_is_unchanged(tmp_path: Path) -> None:
    """plan_mode_override 默认 None：无模型证据仍 fail-closed（原行为）。"""

    request = _replay_request(tmp_path, plan_mode_override=None)
    with pytest.raises(InvalidCompetitionRun) as excinfo:
        _normalize_case_row(
            _replay_raw(request),
            case=request.cases[0],
            request=request,
            policy_digest="a" * 64,
            task_fact={},
            trace=None,
        )
    assert excinfo.value.reason_code == "model_invocation_evidence_missing"


def test_execute_competition_arm_rejects_replay_with_qualification_eligible(
    tmp_path: Path,
) -> None:
    """硬护栏（评审 Fix）：replay + qualification_eligible 直接 fail-closed，
    防止未来调用点把回放数据误标为官方 qualification。"""

    request = replace(_replay_request(tmp_path), qualification_eligible=True)
    with pytest.raises(InvalidCompetitionRun) as excinfo:
        execute_competition_arm(request)
    assert excinfo.value.reason_code == "replay_not_qualification_eligible"


def test_execute_competition_arm_replay_skips_preflight_and_merges_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """replay e2e：preflight 零调用、contracts 输出 skipped、policy 合并
    请求级禁用规则、bench config 透传 replay、行字段来自 raw。"""

    # 保证 memory 豁免 env 审计条目在本测试里是确定性的空集。
    monkeypatch.delenv("AGENTGUARD_MEMORY_NOT_REQUIRED_ACTIONS", raising=False)
    request = _replay_request(
        tmp_path,
        plan_mode_override="replay",
        policy_disabled_rules=("P104_memory_poisoning",),
    )
    preflight_calls: list[Any] = []
    monkeypatch.setattr(
        competition_runtime,
        "_provider_tool_call_preflight",
        lambda req: preflight_calls.append(req),
    )
    real_write = competition_runtime._write_activation_manifest
    captured: dict[str, str] = {}

    def capture_write(req, *, scratch, policy_digest, server_secret):
        captured["policy_digest"] = policy_digest
        return real_write(
            req,
            scratch=scratch,
            policy_digest=policy_digest,
            server_secret=server_secret,
        )

    monkeypatch.setattr(
        competition_runtime, "_write_activation_manifest", capture_write
    )
    captured_config: dict[str, Any] = {}

    def stub_case_runner(cases, *, config=None, **kwargs):
        captured_config["config"] = config
        return [_replay_raw(request) for _ in cases]

    result = execute_competition_arm(request, case_runner=stub_case_runner)

    # preflight 是真实 LLM 请求，replay 模式下必须被跳过。
    assert preflight_calls == []
    preflight_contract = result.contracts["provider_tool_call_preflight"]
    assert preflight_contract["status"] == "skipped"
    assert preflight_contract["reason_code"] == "replay_mode_no_provider"

    # bench config 的计划模式来自 plan_mode_override。
    assert captured_config["config"].instrumentation_plan_mode == "replay"

    # policy 在冻结竞赛策略之上合并请求级禁用规则。
    base_policy = _competition_policy(request.arm)
    merged_policy = PolicyBundle(
        disabled_rules=sorted(
            set(base_policy.disabled_rules) | {"P104_memory_poisoning"}
        )
    )
    assert captured["policy_digest"] == canonical_sha256(
        merged_policy.model_dump(mode="json")
    )
    assert captured["policy_digest"] != canonical_sha256(
        base_policy.model_dump(mode="json")
    )

    row = result.rows[0]
    assert row["run_valid"] is True
    assert row["instrumentation_plan_mode"] == "replay"
    assert row["planning_source"] == "deterministic_replay"
    assert row["model_invoked"] is False

    # memory 豁免来源审计（评审 Fix）：contracts additive 条目记录运行期
    # 从 settings/env 实际读到的豁免集（env 未设置时空集），可归因。
    memory_contract = result.contracts["memory_not_required_actions"]
    assert memory_contract["status"] == "passed"
    assert memory_contract["env_name"] == "AGENTGUARD_MEMORY_NOT_REQUIRED_ACTIONS"
    assert memory_contract["actions"] == []


def test_arm_run_request_defaults_preserve_competition_behavior(
    tmp_path: Path,
) -> None:
    """新增字段默认值不改变既有构造点的请求语义。"""

    request = _replay_request(tmp_path, plan_mode_override=None)
    assert request.plan_mode_override is None
    assert request.policy_disabled_rules == ()
