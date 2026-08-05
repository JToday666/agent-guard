from pathlib import Path
import json

from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases


def _cases():
    path = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases" / "prompt_injection.jsonl"
    return load_attack_cases(path)


def test_prompt_injection_jsonl_valid_and_contiguous():
    cases = _cases()
    assert [case.case_id for case in cases] == [f"PI-{idx:03d}" for idx in range(1, 11)]
    assert all(case.attack_type == "prompt_injection" for case in cases)
    assert all(case.expected_decision == "deny" for case in cases)
    assert all(case.is_malicious is True for case in cases)


def test_prompt_injection_source_type_is_web_injection():
    for case in _cases():
        assert case.input.source_type != "direct_user_instruction"
        assert case.metadata.get("attack_delivery") != "direct_user_instruction"


def test_prompt_injection_has_structured_oracles():
    for case in _cases():
        assert case.success_condition.type == "prompt_injection_harm_oracle"
        assert case.metadata.get("pi_schema_version") == "prompt_injection_oracle_v1"
        assert case.metadata.get("harm_oracle")
        assert all(isinstance(step, dict) and step.get("event_type") for step in case.metadata["harm_oracle"])
        assert case.metadata.get("success_oracle")
        assert all(isinstance(step, dict) and step.get("event_type") for step in case.metadata["success_oracle"])
        assert case.metadata.get("task_terminal_oracle")


def test_prompt_injection_web_entry_exists():
    root = Path(__file__).resolve().parents[3]
    for case in _cases():
        web_entry = root / case.metadata["web_entry_source_path"]
        assert web_entry.exists(), case.case_id


def test_prompt_injection_autonomous_tool_plan_is_browser_scoped():
    allowed = {"read_file", "browser_start", "browser_navigate", "browser_inspect", "browser_extract_text", "browser_input", "browser_click"}
    for case in _cases():
        assert {step.tool for step in case.tool_plan}.issubset(allowed), case.case_id
        assert case.metadata.get("pi_autonomous_tool_scope") == "browser_and_read_file_only"


def test_prompt_injection_has_no_guided_replay_or_affordance_metadata():
    for case in _cases():
        assert not getattr(case, "guided_success_plan", []), case.case_id
        assert not getattr(case, "closure_plan", []), case.case_id
        assert "case_plan_fallback" not in case.metadata, case.case_id
        assert "autonomous_page_affordance" not in case.metadata, case.case_id
        assert case.metadata.get("pi_prompt_contamination_policy") == "web_content_only_no_runner_prompt_attack_instructions"
        assert case.metadata.get("pi_strict_asr_policy") == "attack_success_requires_complete_real_browser_harm_oracle_event_sequence"


def test_prompt_injection_normal_task_difficulty_snapshot_not_reduced():
    for case in _cases():
        snapshot = case.metadata.get("normal_task_difficulty_snapshot")
        assert isinstance(snapshot, dict), case.case_id
        success_oracle = case.metadata.get("success_oracle") or []
        required_fields = sum(1 for step in success_oracle if step.get("event_type") in {"input", "change"})
        assert snapshot["required_fields_count"] == required_fields, case.case_id
        assert snapshot["required_actions_count"] == len(success_oracle), case.case_id
        assert snapshot["requires_result_or_terminal_confirmation"] is True, case.case_id
        assert case.metadata.get("attack_sink_distance_from_main_path") in {0, 1, 2}, case.case_id


def test_prompt_injection_replacements_are_diverse_and_authentic():
    cases = _cases()
    by_id = {case.case_id: case for case in cases}

    assert by_id["PI-002"].metadata.get("replacement_id") == "PI-002R"
    assert by_id["PI-003"].metadata.get("replacement_id") == "PI-003R"
    assert "Northstar FleetOps" in by_id["PI-002"].input.payload
    assert "NeuralForge" in by_id["PI-003"].input.payload

    booking_cases = [
        case.case_id
        for case in cases
        if "booking" in json.dumps({"input": case.input.model_dump(), "metadata": {"user_goal": case.metadata.get("user_goal")}}, ensure_ascii=False).lower()
    ]
    assert booking_cases == ["PI-007"]

    for case in cases:
        visible_payload = {
            "input": case.input.model_dump(),
            "user_goal": case.metadata.get("user_goal"),
        }
        serialized = json.dumps(visible_payload, ensure_ascii=False).lower()
        assert "mock" not in serialized, case.case_id
        assert "sandbox" not in serialized, case.case_id
        assert "demo" not in serialized, case.case_id
