from agentguard_langgraph_bench.bench.claude_code_report import build_compact_report, write_compact_report
from agentguard_langgraph_bench.adapters.claude_code.adapter import _parse_json_result, _stderr_diagnostics


def _row(case_id="CC-VISION-001"):
    return {
        "case_id": case_id,
        "attack_type": "benign",
        "run_valid": True,
        "attack_success": False,
        "task_success": True,
        "tool_calls": [{"tool_name": "browser_start", "executed": True}],
        "final_answer": "VISION_PROBE_OK",
        "raw_state": {
            "tool_invoked": True,
            "native_refusal": False,
            "elapsed_ms": 12,
            "claude_response": {"usage": {"input_tokens": 3, "output_tokens": 4}, "total_cost_usd": 0.01},
            "image_delivery": {"count": 1, "delivered": 1, "items": [{"mime_type": "image/png", "sha256": "abc", "width": 10, "height": 10, "delivered": True}]},
        },
        "invalid_reasons": [],
    }


def test_compact_report_omits_prompt_and_image_binary():
    report = build_compact_report([_row()], run_id="r1", model="qwen3.7-plus")
    text = str(report)
    assert "VISION_PROBE_OK" not in text
    assert "data" not in text
    assert report["visual"]["image_delivered_count"] == 1
    assert report["cases"][0]["vision_probe_success"] is True


def test_compact_report_writes_json_and_markdown(tmp_path):
    paths = write_compact_report(build_compact_report([_row()], run_id="r1", model="qwen3.7-plus"), tmp_path)
    assert paths["summary_json"].endswith("summary.json")
    assert paths["summary_markdown"].endswith("summary.md")


def test_claude_json_parser_accepts_stderr_warning_without_marking_api_result_invalid():
    parsed = _parse_json_result('warning line\n{"is_error":false,"result":"ok"}\n')
    assert parsed == {"is_error": False, "result": "ok"}
    assert _stderr_diagnostics('[claude-code:unrecognized_model] {"model":"qwen3.7-plus"}')
