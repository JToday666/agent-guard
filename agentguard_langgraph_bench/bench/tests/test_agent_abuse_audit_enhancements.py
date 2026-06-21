import json
import zipfile
from pathlib import Path

from agentguard_langgraph_bench.adapter.core_client import FakeAllowCoreClient, FakeAskCoreClient, FakeDenyCoreClient
from agentguard_langgraph_bench.bench.config import BenchConfig
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from agentguard_langgraph_bench.bench.evidence.artifact_integrity import build_artifact_integrity_manifest
from agentguard_langgraph_bench.bench.metrics import calculate_metrics
from agentguard_langgraph_bench.bench.runner import _write_case_artifacts, run_cases
from agentguard_langgraph_bench.bench.runtime.sandbox_diff import diff_sandbox, snapshot_sandbox
from agentguard_langgraph_bench.bench.tools import MockToolRegistry


def dataset_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"


def test_fake_core_decisions_cover_allow_deny_ask():
    event = {"derived_resources": [{"target": "/private/token.txt"}]}

    assert FakeAllowCoreClient().evaluate_tool_call(event)["decision"] == "allow"
    assert FakeDenyCoreClient().evaluate_tool_call(event)["decision"] == "deny"
    ask = FakeAskCoreClient().evaluate_tool_call(event)
    assert ask["decision"] == "ask"
    assert ask["approval"]["required"] is True


def test_runner_fake_ask_blocks_without_side_effects(tmp_path):
    cases = [case for case in load_attack_cases(dataset_dir()) if case.case_id == "FE-001"]

    rows = run_cases(
        cases,
        config=BenchConfig(defense_enabled=True, sandbox_dir=tmp_path / "sandbox", results_dir=tmp_path / "results"),
        fake_core=True,
        fake_core_decision="ask",
    )

    assert rows[0]["blocked"] is True
    assert rows[0]["executed"] is False
    assert rows[0]["side_effects"] == []
    assert rows[0]["sandbox_diff"]["empty"] is True
    assert rows[0]["decisions"]
    assert set(rows[0]["decisions"]) == {"ask"}


def test_metrics_fpr_not_applicable_without_benign_cases():
    summary = calculate_metrics(
        [{"case_id": "AA-001", "is_malicious": True, "run_valid": True, "attack_success": False, "completion_level": "none"}],
        defense_enabled=True,
        core_mode="fake_allow",
        fake_core_decision="allow",
    )

    assert summary["benign_count"] == 0
    assert summary["fpr"] is None
    assert summary["fpr_applicable"] is False
    assert summary["metrics_reliable"] is False
    assert "fake_core_allow_all_cannot_prove_real_defense" in summary["metrics_reliability_reasons"]


def test_sandbox_diff_records_added_modified_deleted(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    keep = sandbox / "keep.txt"
    gone = sandbox / "gone.txt"
    keep.write_text("before", encoding="utf-8")
    gone.write_text("remove", encoding="utf-8")
    before = snapshot_sandbox(sandbox)

    keep.write_text("after", encoding="utf-8")
    gone.unlink()
    (sandbox / "added.txt").write_text("new", encoding="utf-8")
    diff = diff_sandbox(sandbox, before)

    assert [item["relative_path"] for item in diff["added"]] == ["added.txt"]
    assert [item["relative_path"] for item in diff["deleted"]] == ["gone.txt"]
    assert [item["relative_path"] for item in diff["modified"]] == ["keep.txt"]


def test_browser_click_writes_mail_business_event(tmp_path):
    tools = MockToolRegistry(tmp_path / "sandbox")
    tools._browser_sessions["AA-005"] = {
        "source_path": "agentguard_langgraph_bench/bench/datasets/instrumentation/Browser-art_E1_33/email/index.html"
    }
    tools.browser_input("testid=to-input", "julia.lee@northstar-finance.internal", session_id="AA-005")
    tools.browser_input("testid=subject-input", "URGENT: Required Financial Data Submission", session_id="AA-005")
    tools.browser_input("testid=body-input", "Please send financial figures immediately.", session_id="AA-005")

    result = tools.browser_click("testid=send-button", session_id="AA-005")

    assert result["business_event"]["event_type"] == "mail_sent"
    rows = [json.loads(line) for line in (tmp_path / "sandbox" / "api" / "mail_send_events.jsonl").read_text().splitlines()]
    assert rows[-1]["event_type"] == "mail_sent"
    assert rows[-1]["correlation_id"]


def test_case_artifacts_include_portable_evidence_and_split_streams(tmp_path):
    recording_root = tmp_path / "sandbox" / "browser" / "replay_artifacts" / "AA-005"
    recording_root.mkdir(parents=True)
    events = recording_root / "events.jsonl"
    events.write_text('{"event_type":"browser_start"}\n', encoding="utf-8")
    row = {
        "case_id": "AA-005",
        "trace_id": "trace_1",
        "tool_calls": [
            {
                "tool_name": "browser_click",
                "call_id": "call_1",
                "decision": "allow",
                "executed": True,
                "blocked": False,
                "event": {"event_id": "evt_1", "arguments": {"selector": "testid=send-button"}},
                "audit_event": {"audit_id": "audit_1"},
                "side_effects": [],
            }
        ],
        "browser_recordings": [{"artifact_dir": str(recording_root), "events": str(events)}],
        "sandbox_diff": {"empty": True, "added": [], "modified": [], "deleted": [], "outside_sandbox_paths": []},
    }

    _write_case_artifacts(tmp_path / "run" / "cases" / "AA-005", row, None)

    case_dir = tmp_path / "run" / "cases" / "AA-005"
    assert (case_dir / "tool_call_events.jsonl").read_text(encoding="utf-8").strip()
    evidence_index = json.loads((case_dir / "evidence_index.json").read_text(encoding="utf-8"))
    assert evidence_index["streams"][0]["run_relative_path"]
    assert evidence_index["streams"][0]["debug_local_path"]
    assert "path" not in evidence_index["streams"][0]


def test_artifact_integrity_checker_parses_jsonl_trace_and_reports_png_status(tmp_path):
    case_dir = tmp_path / "run" / "sandbox_artifacts" / "sandbox" / "browser" / "replay_artifacts" / "AA-001"
    case_dir.mkdir(parents=True)
    (case_dir / "events.jsonl").write_text('{"ok": true}\n', encoding="utf-8")
    (case_dir / "replay_state.json").write_text('{"step_count": 0, "dom_event_count": 0, "video_source": null}', encoding="utf-8")
    (case_dir / "replay_frames.txt").write_text("", encoding="utf-8")
    (case_dir / "report.html").write_text("<html><body>step_count dom_event_count</body></html>", encoding="utf-8")
    with zipfile.ZipFile(case_dir / "trace.zip", "w") as archive:
        archive.writestr("trace.trace", "{}")

    manifest = build_artifact_integrity_manifest(tmp_path / "run")

    assert manifest["case_count"] == 1
    artifacts = {item["type"]: item for item in manifest["cases"]["AA-001"]["artifacts"]}
    assert artifacts["events.jsonl"]["parse_ok"] is True
    assert artifacts["trace.zip"]["parse_ok"] is True
    assert artifacts["final.png"]["exists"] is False
