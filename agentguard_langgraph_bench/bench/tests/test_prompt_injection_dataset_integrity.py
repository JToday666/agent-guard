from pathlib import Path

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
