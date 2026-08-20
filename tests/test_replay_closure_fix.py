"""replay 回放收尾修复（Spec 根因 1/2）的定向测试。

覆盖：
* 终态陈述不含任何 refusal marker 且逐字节确定；
* replay round>=2 返回纯文本收尾（同构 autonomous 文本终止），e2e 后
  run_status=completed 且无 planner_no_output；
* replay blocked 行补写终态陈述（final_answer 证据存在）；
* adapter ``_skipped_rag_answer`` 状态归一仅 replay 门控生效，autonomous
  路径逐字节不变；归一后的 status 可达 MP oracle 既有的 blocked 豁免识别；
* blocked-session 录制 writer 的产生、schema 与 replay 门控。
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from agentguard_langgraph_bench.bench.config import BenchConfig
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from agentguard_langgraph_bench.bench.replay_blocked_browser import (
    BLOCKED_SESSION_SOURCE,
    BLOCKED_STEP_EVENT_TYPE,
    maybe_supplement_replay_blocked_rag_answer,
    maybe_supplement_replay_blocked_recordings,
)
from agentguard_langgraph_bench.bench.runner import run_cases
from agentguard_langgraph_bench.bench.scoring.memory_poisoning import (
    _last_blocked_tool,
)
from agentguard_langgraph_bench.bench.tools import MockToolRegistry
from agentguard_langgraph_bench.demo_agent.graph import (
    _post_tool_capture,
    _replay_closure_statement,
    plan_tools_for_state,
)
from agentguard_langgraph_adapter.secure_tool_node import (
    SecureToolNode,
    _skipped_rag_answer,
)
from agentguard_langgraph_adapter.langgraph_adapter import create_guarded_tool_node


DATASET_DIR = (
    Path(__file__).resolve().parents[1]
    / "agentguard_langgraph_bench"
    / "bench"
    / "datasets"
    / "attack_cases"
)


def _case(case_id: str):
    return next(
        case
        for case in load_attack_cases(DATASET_DIR)
        if case.case_id == case_id
    )


# ---------------------------------------------------------------------------
# 根因 1：终态陈述与 replay 收尾
# ---------------------------------------------------------------------------


def test_replay_closure_statement_has_no_refusal_markers_and_is_deterministic():
    case = _case("BN-001")
    state = {
        "tool_results": [
            {"executed": True, "blocked": False},
            {"executed": False, "blocked": True},
        ]
    }

    statement = _replay_closure_statement(case, state)
    # 复用判分行使用的 refusal 检测，确保 benign/jailbreak 不会被误判 refused。
    from agentguard_langgraph_bench.bench.runtime.row_normalizer import (
        _looks_like_refusal,
    )

    assert statement
    assert _looks_like_refusal(statement) is False
    # 逐字节确定：同一输入多次调用输出一致（无时间戳/随机量）。
    assert _replay_closure_statement(case, state) == statement
    assert "Replay complete:" in statement


def test_replay_round2_returns_text_closure_and_round1_unchanged(tmp_path):
    case = _case("BN-001")
    tools = MockToolRegistry(tmp_path / "sandbox")
    config = BenchConfig(instrumentation_plan_mode="replay")
    state = {"attack_case": case.model_dump(), "tool_results": []}

    first = plan_tools_for_state(state, config, tools, round_index=1)
    assert first.tool_calls
    assert first.content == ""

    second = plan_tools_for_state(state, config, tools, round_index=2)
    assert second.tool_calls == []
    assert second.content
    from agentguard_langgraph_bench.bench.runtime.row_normalizer import (
        _looks_like_refusal,
    )

    assert _looks_like_refusal(second.content) is False


def test_replay_completed_row_has_no_planner_no_output(tmp_path):
    """e2e：core-off（defense off）replay 收尾后 valid 且 completed。"""
    case = _case("BN-001")
    rows = run_cases(
        [case],
        config=BenchConfig(
            defense_enabled=False,
            llm_enabled=True,
            instrumentation_plan_mode="replay",
            sandbox_dir=tmp_path / "sandbox",
            results_dir=tmp_path / "results",
        ),
        fake_core=True,
        fake_core_decision="allow",
        reset_environment=False,
    )

    row = rows[0]
    assert row["planning_source"] == "deterministic_replay"
    assert row["run_valid"] is True
    assert row["run_status"] == "completed"
    assert "planner_no_output" not in row.get("invalid_reasons", [])
    # 终态陈述成为 final_answer（与 autonomous 文本终止同构）。
    assert str(row.get("final_answer") or "").startswith("Replay complete:")


def test_replay_blocked_row_gets_final_answer_statement(tmp_path):
    """e2e：replay 被 block 的行同样产出终态陈述（final_answer 证据）。"""
    case = _case("AA-004")
    rows = run_cases(
        [case],
        config=BenchConfig(
            defense_enabled=True,
            llm_enabled=True,
            instrumentation_plan_mode="replay",
            sandbox_dir=tmp_path / "sandbox",
            results_dir=tmp_path / "results",
        ),
        fake_core=True,
        fake_core_decision="deny",
        reset_environment=False,
    )

    row = rows[0]
    assert row["run_status"] == "blocked"
    assert str(row.get("final_answer") or "").startswith("Replay complete:")
    assert "planner_no_output" not in row.get("invalid_reasons", [])


def test_post_tool_capture_backfills_statement_only_for_replay(tmp_path):
    """_post_tool_capture 的 blocked 补写只在 replay 门控下生效。"""
    case = _case("AA-004")
    blocked_results = [{"tool_name": "browser_start", "blocked": True, "executed": False}]
    base_state = {
        "attack_case": case.model_dump(),
        "tool_results": blocked_results,
        "last_tool_results": blocked_results,
        "round_index": 1,
    }

    replay_state = _post_tool_capture(
        base_state, BenchConfig(instrumentation_plan_mode="replay")
    )
    assert str(replay_state.get("last_model_content") or "").startswith("Replay complete:")

    autonomous_state = _post_tool_capture(
        base_state, BenchConfig(instrumentation_plan_mode="autonomous")
    )
    assert not autonomous_state.get("last_model_content")


# ---------------------------------------------------------------------------
# 根因 2（MP）：adapter 状态归一的 replay 门控
# ---------------------------------------------------------------------------


def test_skipped_rag_answer_status_normalized_only_in_replay():
    replay_result = _skipped_rag_answer("rag_answer", "call-1", replay=True)
    assert replay_result.status == "blocked"
    assert replay_result.blocked is True
    assert replay_result.decision == "deny"

    default_result = _skipped_rag_answer("rag_answer", "call-1", replay=False)
    assert default_result.status == "skipped_dependency"


def test_guarded_tool_node_receives_plan_mode_from_adapter_config():
    replay_adapter = SimpleNamespace(
        config=SimpleNamespace(instrumentation_plan_mode="replay")
    )
    autonomous_adapter = SimpleNamespace(
        config=SimpleNamespace(instrumentation_plan_mode="autonomous")
    )
    no_config_adapter = SimpleNamespace()

    gateway = object()
    replay_node = create_guarded_tool_node(replay_adapter, gateway=gateway)
    assert isinstance(replay_node, SecureToolNode)
    assert replay_node.instrumentation_plan_mode == "replay"

    autonomous_node = create_guarded_tool_node(autonomous_adapter, gateway=gateway)
    assert autonomous_node.instrumentation_plan_mode == "autonomous"

    legacy_node = create_guarded_tool_node(no_config_adapter, gateway=gateway)
    assert legacy_node.instrumentation_plan_mode is None


def test_normalized_status_reaches_memory_poisoning_blocked_exemption():
    """归一后的 status 可被 MP oracle 既有的 _last_blocked_tool 识别
    （oracle 零改动，仅验证接线达成豁免路径）。"""
    tool_calls = [
        {
            "tool_name": "rag_answer",
            "blocked": True,
            "executed": False,
            "status": _skipped_rag_answer("rag_answer", "c", replay=True).status,
        }
    ]
    assert _last_blocked_tool(tool_calls, "rag_answer") is not None

    legacy_calls = [
        {
            "tool_name": "rag_answer",
            "blocked": True,
            "executed": False,
            "status": _skipped_rag_answer("rag_answer", "c", replay=False).status,
        }
    ]
    assert _last_blocked_tool(legacy_calls, "rag_answer") is None


# ---------------------------------------------------------------------------
# 根因 2（AA/FE）：blocked-session 录制 writer
# ---------------------------------------------------------------------------


def _blocked_browser_row(case) -> dict:
    return {
        "case_id": case.case_id,
        "run_status": "blocked",
        "browser_recordings": [],
        "tool_calls": [
            {
                "tool_name": "browser_start",
                "executed": False,
                "blocked": True,
                "decision": "deny",
                "status": "blocked",
                "event": {"arguments": {"session_id": case.case_id, "url": "http://example/start"}},
            },
            {
                "tool_name": "browser_click",
                "executed": False,
                "blocked": True,
                "decision": "deny",
                "status": "blocked",
                "event": {"arguments": {"session_id": case.case_id, "selector": "testid=harm"}},
            },
        ],
    }


def test_blocked_session_recording_written_for_replay_blocked_case(tmp_path):
    case = _case("AA-004")
    row = _blocked_browser_row(case)
    config = BenchConfig(instrumentation_plan_mode="replay")

    assert maybe_supplement_replay_blocked_recordings(case, row, config, tmp_path) is True

    recordings = row["browser_recordings"]
    assert len(recordings) == 1
    recording = recordings[0]
    assert recording["source"] == BLOCKED_SESSION_SOURCE
    assert recording["session_id"] == case.case_id
    assert recording["browser_started"] is False
    for key in ("artifact_dir", "events", "final_dom", "action_metadata", "step_actions", "manifest"):
        assert recording.get(key), f"missing recording key: {key}"
        assert Path(str(recording[key])).exists()

    events = [
        json.loads(line)
        for line in Path(recording["events"]).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(events) == 2
    # 只如实记录 planned/blocked 步骤，绝不包含危害成功事件；事件类型
    # 专用，不会被 scoring 读成已执行的浏览器动作。
    for event in events:
        assert event["event_type"] == BLOCKED_STEP_EVENT_TYPE
        assert event["status"] == "blocked"
        assert event["blocked"] is True
        assert event["executed"] is False
        assert event["source"] == BLOCKED_SESSION_SOURCE
        assert "business_event" not in event
    assert [event["planned_action"] for event in events] == ["start", "click"]

    # 已有录制不重复补写。
    assert maybe_supplement_replay_blocked_recordings(case, row, config, tmp_path) is False
    assert len(row["browser_recordings"]) == 1


def test_blocked_session_recording_is_replay_gated(tmp_path):
    case = _case("AA-004")
    autonomous_config = BenchConfig(instrumentation_plan_mode="autonomous")
    row = _blocked_browser_row(case)
    assert maybe_supplement_replay_blocked_recordings(case, row, autonomous_config, tmp_path) is False
    assert row["browser_recordings"] == []

    # 无 blocked 浏览器步骤时 replay 也不补写。
    replay_config = BenchConfig(instrumentation_plan_mode="replay")
    row_no_browser = {"case_id": case.case_id, "browser_recordings": [], "tool_calls": []}
    assert maybe_supplement_replay_blocked_recordings(case, row_no_browser, replay_config, tmp_path) is False


# ---------------------------------------------------------------------------
# 根因 2（MP pre-model deny 臂）：blocked rag_answer 记录补写
# ---------------------------------------------------------------------------


def _blocked_mp_row(case) -> dict:
    """模拟 pre-model guard deny：工具未下发，tool_calls 无 rag_answer 记录。"""
    return {
        "case_id": case.case_id,
        "run_status": "blocked",
        "invalid_reasons": ["missing_terminal_action", "missing_rag_answer"],
        "tool_calls": [],
    }


def test_rag_answer_supplement_reaches_oracle_blocked_exemption():
    """replay blocked MP 行补写后可达 MP oracle 既有的 rag_answer_blocked
    豁免路径（oracle 零改动）：terminal=rag_answer_blocked、attack_success
    强制 False、missing 类 invalid 被 discard。"""
    from agentguard_langgraph_bench.bench.scoring.memory_poisoning import (
        build_memory_poisoning_evaluation_report,
    )

    case = _case("PR-001")
    row = _blocked_mp_row(case)
    config = BenchConfig(instrumentation_plan_mode="replay")

    assert maybe_supplement_replay_blocked_rag_answer(case, row, config) is True
    record = row["tool_calls"][-1]
    assert record["tool_name"] == "rag_answer"
    assert record["blocked"] is True
    assert record["status"] == "blocked"
    assert record["executed"] is False
    assert record["source"] == BLOCKED_SESSION_SOURCE
    # 逐字节确定：call_id 只依赖 case_id。
    assert record["call_id"] == f"replay_blocked_{case.case_id}_rag_answer"
    # 不重复补写。
    assert maybe_supplement_replay_blocked_rag_answer(case, row, config) is False

    assert _last_blocked_tool(row["tool_calls"], "rag_answer") is not None
    report = build_memory_poisoning_evaluation_report(case, row)
    assert report.terminal_action == "rag_answer_blocked"
    assert report.attack_success is False
    assert "missing_terminal_action" not in report.invalid_reasons
    assert "missing_rag_answer" not in report.invalid_reasons


def test_rag_answer_supplement_is_gated():
    case = _case("PR-001")
    replay_config = BenchConfig(instrumentation_plan_mode="replay")
    autonomous_config = BenchConfig(instrumentation_plan_mode="autonomous")

    # autonomous 路径 no-op（逐字节不变）。
    row = _blocked_mp_row(case)
    assert maybe_supplement_replay_blocked_rag_answer(case, row, autonomous_config) is False
    assert row["tool_calls"] == []

    # 非 blocked 终止 no-op。
    row = _blocked_mp_row(case)
    row["run_status"] = "completed"
    assert maybe_supplement_replay_blocked_rag_answer(case, row, replay_config) is False

    # 已存在 rag_answer 记录时 no-op（不覆盖真实记录）。
    row = _blocked_mp_row(case)
    row["tool_calls"] = [{"tool_name": "rag_answer", "executed": True, "status": "success"}]
    assert maybe_supplement_replay_blocked_rag_answer(case, row, replay_config) is False
    assert len(row["tool_calls"]) == 1

    # 非 memory_poisoning 案例 no-op。
    bn_case = _case("BN-001")
    row = _blocked_mp_row(bn_case)
    assert maybe_supplement_replay_blocked_rag_answer(bn_case, row, replay_config) is False


# ---------------------------------------------------------------------------
# repeats 稳定性：单例本地服务的端口表移位重绑
# ---------------------------------------------------------------------------


def test_loopback_singletons_rebind_when_port_table_shifts(monkeypatch):
    """serial repeats 在同进程内移位端口表；单例服务必须重绑到新端口，
    否则被重写 case 的 URL 会 connection refused（BN-004 类 fatal_tool_exception）。"""
    from agentguard_langgraph_bench.bench import tools

    monkeypatch.setenv("AGENTGUARD_BENIGN_API_PORT", "18191")
    tools._ensure_benign_api_server()
    first = tools._BENIGN_API_SERVER
    assert first is not None and first.server_address[1] == 18191

    # 同端口：复用同一实例（行为不变）。
    tools._ensure_benign_api_server()
    assert tools._BENIGN_API_SERVER is first

    # 端口移位：关闭旧服务并重绑新端口。
    monkeypatch.setenv("AGENTGUARD_BENIGN_API_PORT", "18192")
    tools._ensure_benign_api_server()
    second = tools._BENIGN_API_SERVER
    assert second is not first
    assert second.server_address[1] == 18192

    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        assert probe.connect_ex(("127.0.0.1", 18192)) == 0


# ---------------------------------------------------------------------------
# forced-closure 诊断看守：收尾改动改变了诊断内层 replay 行形态
# ---------------------------------------------------------------------------


def test_forced_closure_diagnostic_contract_under_replay_closure(tmp_path):
    """直接调 _run_forced_closure_diagnostic 的契约断言（取舍：真实触发需
    autonomous LLM 跑出 partial 结果，成本过高；这里直接驱动诊断内层的
    replay + llm_enabled=False 重跑，看守收尾改动后的行形态）。"""
    from agentguard_langgraph_bench.bench.runner import _run_forced_closure_diagnostic

    case = _case("AA-004")
    config = BenchConfig(
        instrumentation_plan_mode="autonomous",
        closure_on_partial=True,
        sandbox_dir=tmp_path / "sandbox",
        results_dir=tmp_path / "results",
    )
    parent_dir = tmp_path / "case_artifacts"
    parent_dir.mkdir()

    result = _run_forced_closure_diagnostic(
        case,
        config=config,
        benchmark_run_id="t1",
        parent_case_result_dir=parent_dir,
    )

    # 诊断行永不计入 autonomous ASR。
    assert result["enabled"] is True
    assert result["counts_for_autonomous_asr"] is False
    assert result["status"] == "completed"
    assert result["planning_source"] == "deterministic_replay"
    assert result["llm_request_count"] == 0
    assert (parent_dir / "closure_result.json").exists()

    # 收尾改动后的内层行形态看守：诊断内层是 replay + llm_enabled=False，
    # 固定 allow → 单轮执行后 stop_reason=completed（不进 round-2 收尾，
    # final_answer 为空是该路径的既有合法形态）；关键看守点是不得被
    # 收尾改动引入 planner_no_output / 破坏 completed+valid 形态。
    import glob

    closure_row_files = glob.glob(
        str(parent_dir / "forced_closure_results" / "run_*" / "cases" / "*" / "case_result.json")
    )
    assert closure_row_files
    with open(closure_row_files[0], encoding="utf-8") as handle:
        closure_row = json.load(handle)
    assert closure_row.get("run_status") == "completed"
    assert closure_row.get("run_valid") is True
    assert "planner_no_output" not in (closure_row.get("invalid_reasons") or [])
    final_answer = str(closure_row.get("final_answer") or "")
    assert final_answer == "" or final_answer.startswith("Replay complete:")


def test_forced_closure_gating_contract():
    """_should_run_forced_closure 门控：仅 autonomous + closure_on_partial +
    非成功/非完成 + harmful_attempt_detected 的 attempted/partial 行触发。"""
    from agentguard_langgraph_bench.bench.runner import _should_run_forced_closure

    case = _case("AA-004")
    closure_config = BenchConfig(
        instrumentation_plan_mode="autonomous", closure_on_partial=True
    )
    replay_config = BenchConfig(
        instrumentation_plan_mode="replay", closure_on_partial=True
    )
    partial_row = {
        "attack_success": False,
        "completion_level": "attempted",
        "agent_abuse_verdict": {"harmful_attempt_detected": True},
    }

    assert _should_run_forced_closure(case, partial_row, closure_config) is True
    # 已完成 / 已成功 / 非 autonomous / 关 closure 均不触发。
    assert (
        _should_run_forced_closure(
            case, {**partial_row, "completion_level": "completed"}, closure_config
        )
        is False
    )
    assert (
        _should_run_forced_closure(
            case, {**partial_row, "attack_success": True}, closure_config
        )
        is False
    )
    assert _should_run_forced_closure(case, partial_row, replay_config) is False
    no_closure = BenchConfig(
        instrumentation_plan_mode="autonomous", closure_on_partial=False
    )
    assert _should_run_forced_closure(case, partial_row, no_closure) is False


def test_closure_on_partial_does_not_change_main_row_attack_success(tmp_path):
    """e2e：同一 AA 案例开/关 closure_on_partial 两跑，主行 attack_success
    必须一致（closure 只产诊断行，不改主行判分）。"""
    case = _case("AA-004")
    rows: dict[bool, dict] = {}
    for closure in (False, True):
        result_rows = run_cases(
            [case],
            config=BenchConfig(
                defense_enabled=False,
                llm_enabled=False,
                instrumentation_plan_mode="autonomous",
                closure_on_partial=closure,
                sandbox_dir=tmp_path / f"sandbox_{closure}",
                results_dir=tmp_path / f"results_{closure}",
            ),
            fake_core=True,
            fake_core_decision="allow",
            reset_environment=False,
        )
        rows[closure] = result_rows[0]

    assert rows[True]["attack_success"] == rows[False]["attack_success"]
    assert rows[True]["run_valid"] == rows[False]["run_valid"]
    # 若触发了 closure：诊断行不计入 ASR；未触发也允许（门控未满足）。
    closure_payload = rows[True].get("forced_closure")
    if closure_payload:
        assert closure_payload["counts_for_autonomous_asr"] is False
