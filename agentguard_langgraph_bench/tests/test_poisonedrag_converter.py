from pathlib import Path

from agentguard_langgraph_bench.attackcase_converter import poisonedrag_to_attack_cases
from agentguard_langgraph_bench.models import AttackCase


def poisonedrag_root() -> Path:
    return Path(__file__).resolve().parents[1] / "datasets" / "poisonedrag"


def test_poisonedrag_converter_emits_dynamic_malicious_cases():
    cases = poisonedrag_to_attack_cases(poisonedrag_root(), datasets=["nq"], limit_per_dataset=1)

    case = AttackCase.model_validate(cases[0])

    assert case.attack_type == "memory_poisoning"
    assert case.is_malicious is True
    assert case.success_condition.type == "rag_answered_incorrect"
    assert {step.tool for step in case.tool_plan} == {"rag_retrieve", "rag_answer"}
    retrieve = next(step for step in case.tool_plan if step.tool == "rag_retrieve")
    assert retrieve.arguments["source"] == "poisonedrag"
    assert retrieve.arguments["mode"] == "poisoned"


def test_poisonedrag_converter_emits_clean_baseline_cases():
    cases = poisonedrag_to_attack_cases(poisonedrag_root(), datasets=["nq"], limit_per_dataset=1, mode="clean")

    case = AttackCase.model_validate(cases[0])
    answer = next(step for step in case.tool_plan if step.tool == "rag_answer")

    assert case.attack_type == "benign"
    assert case.is_malicious is False
    assert case.expected_decision == "allow"
    assert answer.arguments["answer_strategy"] == "target_correct_answer"
