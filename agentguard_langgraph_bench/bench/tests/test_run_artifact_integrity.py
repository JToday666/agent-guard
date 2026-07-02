import csv
import json
from pathlib import Path

from agentguard_langgraph_bench.bench.evidence.artifact_integrity import build_artifact_integrity_manifest, check_case_artifacts
from agentguard_langgraph_bench.bench.metrics import calculate_metrics
from agentguard_langgraph_bench.bench.config import BenchConfig
from agentguard_langgraph_bench.bench.runner import (
    _case_result_dir,
    _langgraph_graph_module,
    _langgraph_graph_object,
    _preserve_runtime_infra_invalidity,
    _write_case_artifacts,
    write_results,
)
from agentguard_langgraph_bench.bench.tools import MockToolRegistry


def test_valid_asr_excludes_invalid_and_unknown_cases():
    rows = [
        {"case_id": "AA-003", "is_malicious": True, "run_valid": True, "attack_success": True, "completion_level": "completed"},
        {"case_id": "AA-007", "is_malicious": True, "run_valid": False, "attack_success": None, "completion_level": "unknown"},
        {"case_id": "AA-008", "is_malicious": True, "run_valid": True, "attack_success": False, "completion_level": "attempted", "harm_attempted": True},
    ]

    summary = calculate_metrics(rows, defense_enabled=True)

    assert summary["valid_evaluable_malicious_count"] == 2
    assert summary["asr_valid"] == 0.5
    assert summary["har_valid"] == 1.0
    assert summary["invalid_run_rate"] == 1 / 3
    assert summary["unknown_evaluation_rate"] == 1 / 3


def test_write_results_emits_run_manifest(tmp_path):
    rows = [
        {
            "case_id": "AA-001",
            "attack_type": "agent_abuse",
            "run_valid": False,
            "is_malicious": True,
            "benchmark_run_id": "20260621T000000000000Z",
        }
    ]
    case_dir = tmp_path / "run_20260621T000000000000Z" / "cases" / "AA-001"
    case_dir.mkdir(parents=True)
    (case_dir / "case_result.json").write_text("{}", encoding="utf-8")

    paths = write_results(rows, {}, tmp_path)

    assert "run_manifest" in paths
    assert Path(paths["run_manifest"]).exists()
    assert paths["run_dir"].endswith("run_20260621T000000000000Z")
    assert paths["case_artifacts_dir"].endswith("run_20260621T000000000000Z/cases")


def test_run_manifest_records_true_langgraph_gate_fields(tmp_path):
    rows = [
        {
            "case_id": "PI-001",
            "case_run_key": "PI-001",
            "attack_type": "prompt_injection",
            "run_valid": True,
            "is_malicious": True,
            "benchmark_run_id": "20260621T000000000010Z",
            "runtime": "langgraph",
            "adapter_name": "standalone-langgraph-subprocess",
            "langgraph_graph_module": "external.agent.graph",
            "langgraph_graph_object": "graph",
            "langgraph_recursion_limit": 240,
            "runtime_limits": {"max_tool_rounds": 120, "max_wall_clock_seconds": 600, "max_repeated_actions": 5},
            "browser_action_timeout": 45,
            "llm_request_timeout": 70,
            "llm_max_retries": 2,
            "llm_provider": "deepseek",
            "llm_model": "deepseek-v4-flash",
            "llm_enabled": True,
            "instrumentation_plan_mode": "autonomous",
            "planning_source": "llm_autonomous",
            "guided_plan_applied": False,
            "fallback_applied": False,
            "core_mode": "defense_off",
            "fake_core_decision": None,
            "tool_invocation_base_url": "http://127.0.0.1:18090/tools",
            "browser_mode": "real",
        }
    ]
    case_dir = tmp_path / "run_20260621T000000000010Z" / "cases" / "PI-001"
    case_dir.mkdir(parents=True)
    (case_dir / "case_result.json").write_text("{}", encoding="utf-8")

    paths = write_results(rows, {}, tmp_path)
    manifest = json.loads(Path(paths["run_manifest"]).read_text(encoding="utf-8"))

    assert manifest["runtime"] == "langgraph"
    assert manifest["agent_adapter"] == "standalone-langgraph-subprocess"
    assert manifest["langgraph_graph_module"] == "external.agent.graph"
    assert manifest["langgraph_recursion_limit"] == 240
    assert manifest["max_tool_rounds"] == 120
    assert manifest["max_wall_clock_seconds"] == 600
    assert manifest["llm_provider"] == "deepseek"
    assert manifest["llm_model"] == "deepseek-v4-flash"
    assert manifest["llm_enabled"] is True
    assert manifest["planning_source"] == "llm_autonomous"
    assert manifest["guided_plan_applied"] is False
    assert manifest["fallback_applied"] is False
    assert manifest["core_mode"] == "defense_off"
    assert manifest["fake_core_decision"] is None
    assert manifest["browser_mode"] == "real"
    assert manifest["tool_invocation_base_url"] == "http://127.0.0.1:18090/tools"


def test_standalone_langgraph_subprocess_has_default_graph_evidence():
    config = BenchConfig(agent_adapter="standalone-langgraph-subprocess", runtime="langgraph")
    adapter = type("Adapter", (), {"name": "standalone-langgraph-subprocess"})()

    assert _langgraph_graph_module(adapter, config).endswith("bench_tool_agent.py")
    assert _langgraph_graph_object(adapter, config) == "build_graph"


def test_runtime_infra_timeout_invalidity_survives_family_evaluator():
    row = {
        "run_valid": True,
        "run_status": "completed",
        "stop_reason": "adapter_timeout",
        "invalid_reasons": [],
    }

    _preserve_runtime_infra_invalidity(row)

    assert row["run_valid"] is False
    assert row["run_status"] == "adapter_timeout"
    assert row["invalid_reasons"] == ["adapter_timeout"]


def test_duplicate_case_ids_use_case_run_key_for_integrity(tmp_path):
    rows = [
        {
            "case_id": "PR-001",
            "case_run_key": "PR-001__memory_poisoning__1",
            "dataset_file": "memory_poisoning.jsonl",
            "attack_type": "memory_poisoning",
            "run_valid": True,
            "is_malicious": True,
            "benchmark_run_id": "20260621T000000000099Z",
        },
        {
            "case_id": "PR-001",
            "case_run_key": "PR-001__memory_poisoning_stateful__8",
            "dataset_file": "memory_poisoning_stateful.jsonl",
            "attack_type": "memory_poisoning",
            "run_valid": True,
            "is_malicious": True,
            "benchmark_run_id": "20260621T000000000099Z",
        },
    ]
    for row in rows:
        case_dir = tmp_path / "run_20260621T000000000099Z" / "cases" / row["case_run_key"]
        case_dir.mkdir(parents=True)
        (case_dir / "case_result.json").write_text(json.dumps(row), encoding="utf-8")

    paths = write_results(rows, {}, tmp_path)
    manifest = json.loads(Path(paths["run_manifest"]).read_text(encoding="utf-8"))

    assert manifest["duplicate_case_ids"] == ["PR-001"]
    assert manifest["duplicate_case_run_keys"] == []
    assert manifest["run_integrity_ok"] is True


def test_write_results_preserves_top_level_memory_poisoning_summary(tmp_path):
    rows = [
        {
            "case_id": "PR-001-SEED",
            "attack_type": "memory_poisoning",
            "run_valid": True,
            "is_malicious": True,
            "benchmark_run_id": "20260621T000000000001Z",
            "metadata": {"stateful_long_term_memory": True},
        }
    ]
    case_dir = tmp_path / "run_20260621T000000000001Z" / "cases" / "PR-001-SEED"
    case_dir.mkdir(parents=True)
    (case_dir / "case_result.json").write_text("{}", encoding="utf-8")
    summary = {
        "memory_poisoning": {
            "memory_poisoning_stateful": {"scenario_count": 1},
            "memory_poisoning_quality": {"metrics_reliable": True},
        },
        "memory_poisoning_stateful": {"scenario_count": 1},
        "memory_poisoning_quality": {"metrics_reliable": True},
    }

    paths = write_results(rows, summary, tmp_path)
    written = json.loads(Path(paths["summary_json"]).read_text(encoding="utf-8"))

    assert written["memory_poisoning_stateful"]["scenario_count"] == 1
    assert written["memory_poisoning_quality"]["metrics_reliable"] is True
    assert written["run_manifest"]["dataset_kind"] == "memory_poisoning_stateful"


def test_memory_poisoning_case_artifacts_include_current_case_side_effects(tmp_path):
    sandbox = tmp_path / "sandbox"
    (sandbox / "memory").mkdir(parents=True)
    (sandbox / "rag").mkdir()
    (sandbox / "api").mkdir()
    (sandbox / "memory" / "store.jsonl").write_text(
        '\n'.join(
            [
                json.dumps({"source_case_id": "PR-001-SEED", "source_tool_call_id": "call_seed", "value": "24"}),
                json.dumps({"source_case_id": "PR-002-SEED", "source_tool_call_id": "call_other", "value": "Sinatra"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    for relative, record in {
        "memory/reads.jsonl": {"case_id": "PR-001-SEED", "found": True},
        "memory/searches.jsonl": {"case_id": "PR-001-SEED", "match_count": 1},
        "rag/queries.jsonl": {"case_id": "PR-001-SEED", "contexts": []},
        "rag/answers.jsonl": {"case_id": "PR-001-SEED", "answer": "24"},
        "api/requests.jsonl": {"case_id": "PR-001-SEED", "url": "local"},
    }.items():
        path = sandbox / relative
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    row = {
        "case_id": "PR-001-SEED",
        "attack_type": "memory_poisoning",
        "metadata": {"source_dataset": "PoisonedRAG"},
        "sandbox_dir": str(sandbox),
        "sandbox_diff": {
            "root": str(sandbox),
            "added": [
                {"relative_path": "memory/store.jsonl", "absolute_path": str(sandbox / "memory" / "store.jsonl")},
                {"relative_path": "memory/reads.jsonl", "absolute_path": str(sandbox / "memory" / "reads.jsonl")},
                {"relative_path": "memory/searches.jsonl", "absolute_path": str(sandbox / "memory" / "searches.jsonl")},
                {"relative_path": "rag/queries.jsonl", "absolute_path": str(sandbox / "rag" / "queries.jsonl")},
                {"relative_path": "rag/answers.jsonl", "absolute_path": str(sandbox / "rag" / "answers.jsonl")},
                {"relative_path": "api/requests.jsonl", "absolute_path": str(sandbox / "api" / "requests.jsonl")},
            ],
            "modified": [],
        },
        "tool_calls": [],
        "browser_recordings": [],
    }
    case_dir = tmp_path / "case"

    _write_case_artifacts(case_dir, row, None)

    current_store = case_dir / "side_effects" / "current_case" / "memory" / "store.jsonl"
    snapshot_store = case_dir / "side_effects" / "scenario_snapshot" / "memory" / "store.jsonl"
    evidence_index = json.loads((case_dir / "evidence_index.json").read_text(encoding="utf-8"))

    assert current_store.read_text(encoding="utf-8").count("\n") == 1
    assert "PR-002-SEED" not in current_store.read_text(encoding="utf-8")
    assert "PR-002-SEED" in snapshot_store.read_text(encoding="utf-8")
    assert evidence_index["memory_poisoning_artifacts"]["case_scoped_logs"] is True


def test_artifact_integrity_empty_run_is_not_ok(tmp_path):
    manifest = build_artifact_integrity_manifest(tmp_path / "empty_run")

    assert manifest["case_count"] == 0
    assert manifest["ok"] is False
    assert manifest["error"] == "no cases indexed"


def test_artifact_integrity_indexes_generic_tool_hijacking_case(tmp_path):
    run_dir = tmp_path / "run"
    case_dir = run_dir / "cases" / "MCP-020"
    for relative in (
        "case_result.json",
        "evidence_index.json",
        "sandbox_diff.json",
        "agent_visible_prompt_contamination.json",
        "llm_prompts/round_1_redacted.json",
        "llm_responses/round_1_redacted.json",
    ):
        path = case_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"case_id":"MCP-020"}', encoding="utf-8")
    for relative in (
        "tool_results.jsonl",
        "tool_call_events.jsonl",
        "audit_events.jsonl",
        "policy_decisions.jsonl",
        "mcp/calls.jsonl",
        "mcp/descriptors.jsonl",
        "mcp/catalog_diff.jsonl",
        "mcp/service_requests.jsonl",
    ):
        path = case_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"case_id":"MCP-020","request_id":"MCP-020"}\n', encoding="utf-8")

    manifest = build_artifact_integrity_manifest(run_dir)

    assert manifest["case_count"] == 1
    assert manifest["ok"] is True
    assert manifest["cases"]["MCP-020"]["case_scoped_mcp_logs"] is True



def test_write_results_includes_prompt_injection_auxiliary_columns(tmp_path):
    rows = [
        {
            "case_id": "PI-010",
            "attack_type": "prompt_injection",
            "is_malicious": True,
            "run_valid": True,
            "attack_success": False,
            "prompt_injection_attack_success": False,
            "task_success": True,
            "safe_completion": True,
            "overblocked": False,
            "attack_visibility_seen": True,
            "injection_intent_seen": False,
            "harm_path_probe": True,
            "instrumentation_plan_mode": "autonomous",
            "planning_source": "llm_autonomous",
            "guided_plan_applied": False,
            "fallback_applied": False,
            "stop_reason": "safe_completion",
            "run_status": "completed",
            "invalid_reasons": [],
            "successful_tool_count": 3,
            "tool_error_count": 0,
            "browser_action_count": 3,
            "task_terminal": True,
            "task_terminal_reason": "task_submit",
            "completed_round_index": 3,
            "llm_request_count": 2,
            "llm_timeout_count": 0,
            "llm_retry_count": 0,
            "evidence_status": "supported",
            "prompt_injection_evaluation_report": {"attack_visibility_seen": {"attack_visibility_seen": True}},
            "mcpsafety_evaluator": None,
            "mcpsafety_evidence_status": None,
            "benchmark_run_id": "20260621T000000000004Z",
        }
    ]
    case_dir = tmp_path / "run_20260621T000000000004Z" / "cases" / "PI-010"
    case_dir.mkdir(parents=True)
    (case_dir / "case_result.json").write_text("{}", encoding="utf-8")

    paths = write_results(rows, {}, tmp_path)
    with Path(paths["run_csv"]).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames is not None
        assert "prompt_injection_attack_success" in reader.fieldnames
        assert "attack_visibility_seen" in reader.fieldnames
        assert "injection_intent_seen" in reader.fieldnames
        assert "harm_path_probe" in reader.fieldnames
        assert "prompt_injection_evaluation_report" in reader.fieldnames
        csv_row = next(reader)

    assert csv_row["prompt_injection_attack_success"] == "False"
    assert csv_row["attack_visibility_seen"] == "True"
    assert csv_row["injection_intent_seen"] == "False"
    assert csv_row["harm_path_probe"] == "True"


def test_write_results_does_not_require_browser_artifact_for_safe_refusal(tmp_path):
    rows = [
        {
            "case_id": "AA-010",
            "attack_type": "agent_abuse",
            "run_valid": True,
            "run_status": "refused",
            "completion_level": "safe_refusal",
            "agent_abuse_verdict": {"safe_refusal": True},
            "is_malicious": True,
            "benchmark_run_id": "20260621T000000000001Z",
            "browser_recordings": [],
        }
    ]
    case_dir = tmp_path / "run_20260621T000000000001Z" / "cases" / "AA-010"
    case_dir.mkdir(parents=True)
    (case_dir / "case_result.json").write_text("{}", encoding="utf-8")

    paths = write_results(rows, {}, tmp_path)
    manifest = Path(paths["run_manifest"]).read_text(encoding="utf-8")

    assert '"run_integrity_ok": true' in manifest
    assert '"artifact_missing_case_ids": []' in manifest


def test_write_case_artifacts_creates_diagnostic_browser_replay_for_autonomous_planner_stall(tmp_path):
    row = {
        "case_id": "AA-009",
        "attack_type": "agent_abuse",
        "run_valid": True,
        "run_status": "llm_planning_error",
        "stop_reason": "llm_planning_error",
        "completion_level": "none",
        "agent_abuse_verdict": {"safe_refusal": False},
        "is_malicious": True,
        "benchmark_run_id": "20260621T000000000002Z",
        "instrumentation_plan_mode": "autonomous",
        "agent_visible_payload_mode": "original",
        "llm_request_count": 1,
        "llm_timeout_count": 1,
        "browser_recordings": [],
    }
    case_dir = tmp_path / "run_20260621T000000000002Z" / "cases" / "AA-009"

    _write_case_artifacts(case_dir, row, {"case_id": "AA-009"})
    paths = write_results([row], {}, tmp_path)

    assert (case_dir / "browser_replay" / "manifest.json").exists()
    assert row["browser_recordings"][0]["diagnostic_artifact"] is True
    manifest = Path(paths["run_manifest"]).read_text(encoding="utf-8")
    assert '"run_integrity_ok": true' in manifest
    assert '"artifact_missing_case_ids": []' in manifest
    integrity = Path(paths["artifact_integrity_manifest"]).read_text(encoding="utf-8")
    assert '"ok": true' in integrity
    assert '"diagnostic_artifact": true' in integrity


def test_write_case_artifacts_creates_diagnostic_browser_replay_for_prompt_injection_stall(tmp_path):
    row = {
        "case_id": "PI-009",
        "attack_type": "prompt_injection",
        "run_valid": False,
        "run_status": "llm_planning_error",
        "stop_reason": "llm_planning_error",
        "is_malicious": True,
        "benchmark_run_id": "20260621T000000000012Z",
        "instrumentation_plan_mode": "autonomous",
        "agent_visible_payload_mode": "original",
        "llm_request_count": 1,
        "llm_timeout_count": 1,
        "browser_recordings": [],
    }
    case_dir = tmp_path / "run_20260621T000000000012Z" / "cases" / "PI-009"

    _write_case_artifacts(case_dir, row, {"case_id": "PI-009"})
    paths = write_results([row], {}, tmp_path)

    assert (case_dir / "browser_replay" / "manifest.json").exists()
    assert row["browser_recordings"][0]["diagnostic_artifact"] is True
    manifest = Path(paths["run_manifest"]).read_text(encoding="utf-8")
    assert '"artifact_missing_case_ids": []' in manifest


def test_record_mode_browser_replay_is_diagnostic_integrity_ok(tmp_path):
    tools = MockToolRegistry(tmp_path / "sandbox", browser_mode="record")
    start = tools.browser_start(
        "http://127.0.0.1/local/page.html",
        run_id="PI-record",
        source_path="agentguard_langgraph_bench/bench/datasets/instrumentation/Browser-art_C5_1/contact_form/index.html",
    )
    tools.browser_input(session_id=start["session_id"], selector="id=comment", value="hello")
    tools.browser_click(session_id=start["session_id"], selector="testid=submit")
    recording = tools.finalize_browser_session(start["session_id"])

    row = {
        "case_id": "PI-record",
        "attack_type": "prompt_injection",
        "run_valid": True,
        "run_status": "completed",
        "is_malicious": True,
        "benchmark_run_id": "20260621T000000000013Z",
        "browser_recordings": [recording],
        "tool_calls": [],
    }
    case_dir = tmp_path / "run_20260621T000000000013Z" / "cases" / "PI-record"

    _write_case_artifacts(case_dir, row, {"case_id": "PI-record"})
    integrity = build_artifact_integrity_manifest(case_dir.parent.parent)
    case_integrity = integrity["cases"]["PI-record"]

    assert case_integrity["ok"] is True
    assert case_integrity["diagnostic_artifact"] is True
    assert "png_placeholder_size:1x1" in case_integrity["warnings"]
    assert "webm_too_small:0" not in case_integrity["critical_errors"]


def test_file_exfiltration_browser_case_missing_replay_gets_diagnostic_artifact(tmp_path):
    row = {
        "case_id": "FE-001",
        "attack_type": "file_exfiltration",
        "run_valid": False,
        "run_status": "llm_planning_error",
        "completion_level": "invalid",
        "is_malicious": True,
        "benchmark_run_id": "20260621T000000000003Z",
        "metadata": {"web_entry_source_path": "agentguard_langgraph_bench/bench/datasets/instrumentation/FE_001_booking_business/booking_business_taxi.html"},
        "browser_recordings": [],
    }
    case_dir = tmp_path / "run_20260621T000000000003Z" / "cases" / "FE-001"

    _write_case_artifacts(case_dir, row, {"case_id": "FE-001"})
    paths = write_results([row], {}, tmp_path)
    manifest = Path(paths["run_manifest"]).read_text(encoding="utf-8")

    assert (case_dir / "browser_replay" / "manifest.json").exists()
    assert row["browser_recordings"][0]["diagnostic_artifact"] is True
    assert '"run_integrity_ok": true' in manifest
    assert '"artifact_missing_case_ids": []' in manifest


def test_case_side_effect_archive_uses_only_current_sandbox_diff(tmp_path):
    sandbox = tmp_path / "sandbox"
    inherited = sandbox / "files" / "reports" / "old_case_report.json"
    current = sandbox / "files" / "reports" / "current_case_report.json"
    api = sandbox / "api" / "exfiltration_collector.jsonl"
    inherited.parent.mkdir(parents=True, exist_ok=True)
    api.parent.mkdir(parents=True, exist_ok=True)
    inherited.write_text("old", encoding="utf-8")
    current.write_text("current", encoding="utf-8")
    api.write_text('{"case_id":"FE-009"}\n', encoding="utf-8")
    row = {
        "case_id": "FE-009",
        "attack_type": "file_exfiltration",
        "sandbox_diff": {
            "root": str(sandbox),
            "added": [
                {
                    "relative_path": "files/reports/current_case_report.json",
                    "absolute_path": str(current),
                    "size": current.stat().st_size,
                    "sha256": "current-sha",
                },
                {
                    "relative_path": "api/exfiltration_collector.jsonl",
                    "absolute_path": str(api),
                    "size": api.stat().st_size,
                    "sha256": "api-sha",
                },
            ],
            "modified": [],
        },
        "browser_recordings": [],
    }
    case_dir = tmp_path / "case"

    _write_case_artifacts(case_dir, row, None)

    assert (case_dir / "reports_snapshot" / "files" / "reports" / "current_case_report.json").exists()
    assert not (case_dir / "reports_snapshot" / "files" / "reports" / "old_case_report.json").exists()
    manifest = (case_dir / "reports_snapshot" / "manifest.json").read_text(encoding="utf-8")
    assert "current_case_report.json" in manifest
    assert "old_case_report.json" not in manifest
    assert (case_dir / "api_snapshot" / "api" / "exfiltration_collector.jsonl").exists()


def test_write_case_artifacts_copies_relative_final_dom_references(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in (
        "events.jsonl",
        "action_metadata.jsonl",
        "step_actions.jsonl",
    ):
        (source / name).write_text('{"ok": true}\n', encoding="utf-8")
    (source / "final_dom.html").write_text('<html><head><link href="styles.css"></head><body></body></html>', encoding="utf-8")
    (source / "styles.css").write_text("body{color:#111}", encoding="utf-8")
    row = {
        "case_id": "AA-010",
        "browser_recordings": [
            {
                "artifact_dir": str(source),
                "events": str(source / "events.jsonl"),
                "action_metadata": str(source / "action_metadata.jsonl"),
                "step_actions": str(source / "step_actions.jsonl"),
                "final_dom": str(source / "final_dom.html"),
            }
        ],
    }
    case_dir = tmp_path / "case"

    _write_case_artifacts(case_dir, row, None)

    assert (case_dir / "browser_replay" / "styles.css").exists()


def test_write_case_artifacts_copies_final_dom_references_from_source_path(tmp_path):
    replay_source = tmp_path / "sandbox" / "browser" / "replay_artifacts" / "PI-006"
    replay_source.mkdir(parents=True)
    page_source = tmp_path / "instrumentation" / "bbc"
    local_pages = page_source / "local_pages"
    local_pages.mkdir(parents=True)
    (page_source / "index.html").write_text("<html></html>", encoding="utf-8")
    (local_pages / "home.html").write_text("<html>home</html>", encoding="utf-8")
    for name in (
        "events.jsonl",
        "action_metadata.jsonl",
        "step_actions.jsonl",
    ):
        (replay_source / name).write_text('{"ok": true}\n', encoding="utf-8")
    (replay_source / "final_dom.html").write_text(
        '<html><iframe src="local_pages/home.html"></iframe></html>',
        encoding="utf-8",
    )
    row = {
        "case_id": "PI-006",
        "browser_recordings": [
            {
                "artifact_dir": str(replay_source),
                "events": str(replay_source / "events.jsonl"),
                "action_metadata": str(replay_source / "action_metadata.jsonl"),
                "step_actions": str(replay_source / "step_actions.jsonl"),
                "final_dom": str(replay_source / "final_dom.html"),
                "source_path": str(page_source / "index.html"),
            }
        ],
    }
    case_dir = tmp_path / "case"

    _write_case_artifacts(case_dir, row, None)

    assert (case_dir / "browser_replay" / "local_pages" / "home.html").exists()


def test_write_case_artifacts_rewrites_browser_recording_paths_to_case_copy(tmp_path):
    source = tmp_path / "sandbox" / "browser" / "replay_artifacts" / "PI-006"
    source.mkdir(parents=True)
    for name in (
        "events.jsonl",
        "action_metadata.jsonl",
        "step_actions.jsonl",
        "manifest.json",
        "replay_state.json",
    ):
        (source / name).write_text('{"ok": true}\n', encoding="utf-8")
    (source / "final_dom.html").write_text("<html><body>done</body></html>", encoding="utf-8")
    (source / "final.png").write_bytes(b"png")
    row = {
        "case_id": "PI-006",
        "browser_recordings": [
            {
                "artifact_dir": str(source),
                "events": str(source / "events.jsonl"),
                "action_metadata": str(source / "action_metadata.jsonl"),
                "step_actions": str(source / "step_actions.jsonl"),
                "manifest": str(source / "manifest.json"),
                "replay_state": str(source / "replay_state.json"),
                "final_dom": str(source / "final_dom.html"),
                "screenshot": str(source / "final.png"),
            }
        ],
    }
    case_dir = tmp_path / "case"

    _write_case_artifacts(case_dir, row, None)

    recording = row["browser_recordings"][0]
    assert recording["artifact_dir"] == str(case_dir / "browser_replay")
    for key in ("events", "action_metadata", "step_actions", "manifest", "replay_state", "final_dom", "screenshot"):
        assert str(recording[key]).startswith(str(case_dir / "browser_replay"))
        assert Path(recording[key]).exists()


def test_write_case_artifacts_synthesizes_replay_manifest_when_source_missing(tmp_path):
    source = tmp_path / "sandbox" / "browser" / "replay_artifacts" / "PI-006"
    source.mkdir(parents=True)
    for name in (
        "events.jsonl",
        "action_metadata.jsonl",
        "step_actions.jsonl",
        "replay_state.json",
    ):
        (source / name).write_text('{"ok": true}\n', encoding="utf-8")
    (source / "report.html").write_text('<a href="manifest.json">manifest</a>', encoding="utf-8")
    row = {
        "case_id": "PI-006",
        "browser_recordings": [
            {
                "ok": True,
                "session_id": "PI-006",
                "artifact_dir": str(source),
                "events": str(source / "events.jsonl"),
                "action_metadata": str(source / "action_metadata.jsonl"),
                "step_actions": str(source / "step_actions.jsonl"),
                "report": str(source / "report.html"),
                "replay_state": str(source / "replay_state.json"),
                "manifest": str(source / "missing_manifest.json"),
            }
        ],
    }
    case_dir = tmp_path / "case"

    _write_case_artifacts(case_dir, row, None)

    manifest = case_dir / "browser_replay" / "manifest.json"
    assert manifest.exists()
    payload = manifest.read_text(encoding="utf-8")
    assert '"artifact_dir":' in payload
    assert row["browser_recordings"][0]["manifest"] == str(manifest)


def test_write_case_artifacts_completes_incomplete_replay_from_tool_calls(tmp_path):
    source = tmp_path / "sandbox" / "browser" / "replay_artifacts" / "PI-001"
    steps = source / "steps"
    steps.mkdir(parents=True)
    step = steps / "step_000_start.png"
    step.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR"
        b"\x00\x00\x00\x02\x00\x00\x00\x02\x08\x02\x00\x00\x00"
        b"\xfd\xd4\x9asa"
    )
    for name in ("events.jsonl", "replay_state.json", "video_timeline.json"):
        (source / name).write_text('{"ok": false}\n', encoding="utf-8")
    (source / "final_dom.html").write_text("<html><body></body></html>", encoding="utf-8")
    row = {
        "case_id": "PI-001",
        "browser_recordings": [
            {
                "ok": False,
                "session_id": "PI-001",
                "artifact_dir": str(source),
                "events": str(source / "events.jsonl"),
                "replay_state": str(source / "replay_state.json"),
                "video_timeline": str(source / "video_timeline.json"),
                "final_dom": str(source / "final_dom.html"),
                "video_save_error": "continuous_video_too_small:0",
            }
        ],
        "tool_calls": [
            {
                "tool_name": "browser_start",
                "call_id": "call-1",
                "status": "executed",
                "executed": True,
                "blocked": False,
                "event": {
                    "event_id": "evt-1",
                    "timestamp": "2026-06-26T00:00:00Z",
                    "arguments": {"run_id": "PI-001", "url": "http://127.0.0.1/page.html"},
                },
                "result": {"step_screenshot": str(step), "url": "http://127.0.0.1/page.html"},
            }
        ],
    }
    case_dir = tmp_path / "case"

    _write_case_artifacts(case_dir, row, None)

    replay = case_dir / "browser_replay"
    assert (replay / "events.jsonl").exists()
    assert (replay / "action_metadata.jsonl").exists()
    assert (replay / "step_actions.jsonl").exists()
    assert (replay / "steps" / step.name).exists()
    manifest = (replay / "manifest.json").read_text(encoding="utf-8")
    assert '"diagnostic_artifact": true' in manifest


def test_write_case_artifacts_does_not_mark_started_real_browser_failure_diagnostic(tmp_path):
    source = tmp_path / "sandbox" / "browser" / "replay_artifacts" / "PI-001"
    source.mkdir(parents=True)
    for name in ("events.jsonl", "action_metadata.jsonl", "step_actions.jsonl"):
        (source / name).write_text('{"timestamp":"2026-06-26T00:00:00Z"}\n', encoding="utf-8")
    (source / "manifest.json").write_text(
        json.dumps({"ok": False, "real_browser_artifact": True, "browser_started": True, "diagnostic_artifact": False}),
        encoding="utf-8",
    )
    (source / "replay_state.json").write_text(
        json.dumps({"ok": False, "real_browser_artifact": True, "browser_started": True, "diagnostic_artifact": False}),
        encoding="utf-8",
    )
    row = {
        "case_id": "PI-001",
        "browser_recordings": [
            {
                "ok": False,
                "session_id": "PI-001",
                "artifact_dir": str(source),
                "manifest": str(source / "manifest.json"),
                "replay_state": str(source / "replay_state.json"),
                "events": str(source / "events.jsonl"),
                "action_metadata": str(source / "action_metadata.jsonl"),
                "step_actions": str(source / "step_actions.jsonl"),
                "real_browser_artifact": True,
                "browser_started": True,
            }
        ],
        "tool_calls": [],
    }
    case_dir = tmp_path / "case"

    _write_case_artifacts(case_dir, row, None)

    manifest = json.loads((case_dir / "browser_replay" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["real_browser_artifact"] is True
    assert manifest["browser_started"] is True
    assert manifest["diagnostic_artifact"] is False


def test_diagnostic_replay_keeps_errors_but_not_critical_integrity_failure(tmp_path):
    replay = tmp_path / "case" / "browser_replay"
    replay.mkdir(parents=True)
    (replay / "manifest.json").write_text('{"diagnostic_artifact": true}', encoding="utf-8")
    (replay / "events.jsonl").write_text('{"event_type":"artifact_capture_error"}\n', encoding="utf-8")
    (replay / "action_metadata.jsonl").write_text('{"timestamp":"2026-06-26T00:00:00Z"}\n', encoding="utf-8")
    (replay / "step_actions.jsonl").write_text('{"timestamp":"2026-06-26T00:00:00Z"}\n', encoding="utf-8")
    (replay / "final.png").write_bytes(
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR"
        b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
        b"\x90wS\xde"
    )
    (replay / "final_full_page.png").write_bytes((replay / "final.png").read_bytes())
    (replay / "final_dom.html").write_text('<html><script src="missing.js"></script></html>', encoding="utf-8")
    (replay / "final_accessibility_tree.json").write_text('{"ok": false}', encoding="utf-8")
    (replay / "business_event_correlation_index.json").write_text('{"schema_version":"1.0"}', encoding="utf-8")
    (replay / "report.html").write_text('<a href="missing-manifest.json">missing</a>', encoding="utf-8")
    (replay / "replay_state.json").write_text(
        json.dumps(
            {
                "video_source": None,
                "raw_replay_absent": True,
                "step_screenshot_video_used": False,
                "continuous_frame_count": 0,
            }
        ),
        encoding="utf-8",
    )
    (replay / "video_timeline.json").write_text("{}", encoding="utf-8")

    result = check_case_artifacts(replay, root=tmp_path)

    assert result["ok"] is True
    assert result["critical_errors"] == []
    assert "html_missing_references" in result["errors"]


def test_aa004_diagnostic_replay_does_not_require_real_browser_terminal_markers(tmp_path):
    replay = tmp_path / "cases" / "AA-004" / "browser_replay"
    replay.mkdir(parents=True)
    (replay / "manifest.json").write_text('{"diagnostic_artifact": true}', encoding="utf-8")
    (replay / "events.jsonl").write_text('{"event_type":"planner_stalled_before_browser_start"}\n', encoding="utf-8")
    (replay / "action_metadata.jsonl").write_text('{"timestamp":"2026-06-26T00:00:00Z"}\n', encoding="utf-8")
    (replay / "step_actions.jsonl").write_text('{"timestamp":"2026-06-26T00:00:00Z"}\n', encoding="utf-8")
    png = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR"
        b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
        b"\x90wS\xde"
    )
    (replay / "final.png").write_bytes(png)
    (replay / "final_full_page.png").write_bytes(png)
    (replay / "final_dom.html").write_text("<html><body>diagnostic</body></html>", encoding="utf-8")
    (replay / "final_accessibility_tree.json").write_text('{"ok": true}', encoding="utf-8")
    (replay / "business_event_correlation_index.json").write_text('{"schema_version":"1.0"}', encoding="utf-8")
    (replay / "report.html").write_text("<html>diagnostic</html>", encoding="utf-8")
    (replay / "replay_state.json").write_text('{"diagnostic_artifact": true, "raw_replay_absent": true}', encoding="utf-8")
    (replay / "video_timeline.json").write_text("{}", encoding="utf-8")
    (replay / "replay.webm").write_bytes(b"")
    (replay / "trace.zip").write_bytes(b"")

    result = check_case_artifacts(replay, root=tmp_path)

    assert not any(str(item).startswith("aa004_final_dom_missing") for item in result["critical_errors"])


def test_html_integrity_ignores_snapshot_external_link_protocol(tmp_path):
    replay = tmp_path / "case" / "browser_replay"
    replay.mkdir(parents=True)
    html = replay / "final_dom.html"
    html.write_text(
        '<html><link rel="stylesheet" href="link://https://example.test/site.css">'
        '<script src="missing.js"></script></html>',
        encoding="utf-8",
    )

    result = check_case_artifacts(replay, root=tmp_path)
    final_dom = next(item for item in result["artifacts"] if item["type"] == "final_dom.html")

    assert final_dom["missing_references"] == ["missing.js"]


def test_write_case_artifacts_copies_agent_runtime_for_absolute_final_dom_ref(tmp_path):
    replay_source = tmp_path / "sandbox" / "browser" / "replay_artifacts" / "PI-009"
    replay_source.mkdir(parents=True)
    for name in (
        "events.jsonl",
        "action_metadata.jsonl",
        "step_actions.jsonl",
    ):
        (replay_source / name).write_text('{"ok": true}\n', encoding="utf-8")
    (replay_source / "final_dom.html").write_text(
        '<html><script src="/agent_runtime/web/c4_observable.js"></script></html>',
        encoding="utf-8",
    )
    row = {
        "case_id": "PI-009",
        "browser_recordings": [
            {
                "artifact_dir": str(replay_source),
                "events": str(replay_source / "events.jsonl"),
                "action_metadata": str(replay_source / "action_metadata.jsonl"),
                "step_actions": str(replay_source / "step_actions.jsonl"),
                "final_dom": str(replay_source / "final_dom.html"),
            }
        ],
    }
    run_root = tmp_path / "run"
    case_dir = run_root / "cases" / "PI-009"

    _write_case_artifacts(case_dir, row, None)
    result = check_case_artifacts(case_dir / "browser_replay", root=run_root)
    final_dom = next(item for item in result["artifacts"] if item["type"] == "final_dom.html")

    assert (run_root / "agent_runtime" / "web" / "c4_observable.js").exists()
    assert final_dom["missing_references"] == []


def test_case_artifact_paths_survive_cwd_changes(tmp_path, monkeypatch):
    workdir = tmp_path / "work"
    other = tmp_path / "other"
    workdir.mkdir()
    other.mkdir()
    monkeypatch.chdir(workdir)

    case_dir = _case_result_dir(Path("results"), "20260621T000000000000Z", "AA-001")
    monkeypatch.chdir(other)

    _write_case_artifacts(case_dir, {"case_id": "AA-001", "browser_recordings": []}, None)

    assert (workdir / "results" / "run_20260621T000000000000Z" / "cases" / "AA-001" / "case_result.json").exists()
