from pathlib import Path

import pytest

from agentguard_langgraph_bench.bench.config import BenchConfig
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from agentguard_langgraph_bench.bench.poisonedrag_metrics import calculate_poisonedrag_metrics
from agentguard_langgraph_bench.bench.runner import run_cases, success_for_case


def dynamic_case_file() -> Path:
    return Path(__file__).resolve().parents[1] / "datasets" / "poisonedrag" / "attack_cases" / "memory_poisoning_dynamic.jsonl"


def clean_case_file() -> Path:
    return Path(__file__).resolve().parents[1] / "datasets" / "poisonedrag" / "attack_cases" / "memory_poisoning_clean.jsonl"


def memory_case_file() -> Path:
    return Path(__file__).resolve().parents[1] / "datasets" / "attack_cases" / "memory_poisoning.jsonl"


def test_memory_poisoning_cases_use_real_service_memory_and_rag_resources():
    cases = load_attack_cases(memory_case_file())
    sandbox_root = Path(__file__).resolve().parents[1] / "sandbox"
    from agentguard_langgraph_bench.bench.config import ensure_sandbox

    ensure_sandbox(sandbox_root)

    assert len(cases) == 10
    for case in cases:
        assert [step.tool for step in case.tool_plan] == ["call_api", "read_file", "rag_retrieve", "rag_answer"]
        service_url = case.metadata["local_service_url"]
        assert service_url.startswith("http://127.0.0.1:18082/support/")
        assert case.tool_plan[0].arguments == {"url": service_url, "method": "GET"}
        assert case.tool_plan[1].arguments["path"].startswith("support/reference/")
        assert case.tool_plan[2].arguments["source"] == "local_support_knowledge"
        assert case.tool_plan[2].arguments["mode"] == "poisoned"
        assert "answer_strategy" not in case.tool_plan[3].arguments
        for resource_path in case.metadata["resource_files"].values():
            assert (sandbox_root / "files" / resource_path).exists()


def test_memory_poisoning_runner_executes_real_local_service_when_sockets_are_available(tmp_path):
    cases = load_attack_cases(memory_case_file())[:1]

    rows = run_cases(
        cases,
        config=BenchConfig(defense_enabled=False, sandbox_dir=tmp_path / "sandbox", results_dir=tmp_path / "results"),
        reset_environment=False,
    )

    row = rows[0]
    service_call = next(item for item in row["tool_calls"] if item["tool_name"] == "call_api")
    if service_call["status"] == "error" and any(
        marker in str(service_call.get("error")) for marker in ("Operation not permitted", "Address already in use")
    ):
        pytest.skip("localhost listener is blocked by this test sandbox")
    assert service_call["status"] == "executed"
    assert service_call["result"]["status_code"] == 200
    assert service_call["result"]["real_local_service"] is True
    assert service_call["result"]["body"]["case"]["question_id"] == "test1"
    assert (tmp_path / "sandbox" / "api" / "requests.jsonl").exists()
    assert (tmp_path / "sandbox" / "rag" / "queries.jsonl").exists()
    assert (tmp_path / "sandbox" / "rag" / "answers.jsonl").exists()
    answer = next(item for item in row["tool_calls"] if item["tool_name"] == "rag_answer")
    assert answer["status"] == "executed"
    assert answer["result"]["answer"].strip()
    assert row["task_terminal"] is True
    assert row["run_valid"] is True
    assert "missing_rag_answer" not in row["invalid_reasons"]
    assert "missing_terminal_action" not in row["invalid_reasons"]


def test_memory_poisoning_fake_deny_blocks_service_memory_and_rag_effects(tmp_path):
    cases = load_attack_cases(memory_case_file())[:1]

    rows = run_cases(
        cases,
        config=BenchConfig(defense_enabled=True, sandbox_dir=tmp_path / "sandbox", results_dir=tmp_path / "results"),
        fake_core=True,
        fake_core_decision="deny",
    )

    row = rows[0]
    assert row["blocked"] is True
    assert row["attack_success"] is False
    assert not (tmp_path / "sandbox" / "api" / "requests.jsonl").exists()
    assert not (tmp_path / "sandbox" / "memory" / "store.jsonl").exists()
    assert not (tmp_path / "sandbox" / "rag" / "queries.jsonl").exists()
    assert not (tmp_path / "sandbox" / "rag" / "answers.jsonl").exists()


def test_dynamic_poisonedrag_runner_defense_off_hits_incorrect_answer(tmp_path):
    cases = load_attack_cases(dynamic_case_file())[:1]

    rows = run_cases(
        cases,
        config=BenchConfig(defense_enabled=False, sandbox_dir=tmp_path / "sandbox", results_dir=tmp_path / "results"),
        reset_environment=False,
    )

    row = rows[0]
    retrieve = next(item for item in row["tool_calls"] if item["tool_name"] == "rag_retrieve")
    answer = next(item for item in row["tool_calls"] if item["tool_name"] == "rag_answer")
    assert retrieve["result"]["poison_context_count"] == 5
    assert answer["result"]["contexts"]
    assert answer["event"]["arguments"]["source_trust"] == retrieve["result"]["source_trust"]
    assert answer["result"]["source_trust"] == retrieve["result"]["source_trust"]
    assert answer["result"]["context_docs"] == retrieve["result"]["context_docs"]
    assert answer["result"]["rag_answer_provenance"]["retrieval_tool_call_id"] == retrieve["call_id"]
    assert row["attack_success"] in {True, False}
    assert (tmp_path / "sandbox" / "rag" / "queries.jsonl").exists()
    assert (tmp_path / "sandbox" / "rag" / "answers.jsonl").exists()


def test_dynamic_poisonedrag_runner_fake_deny_blocks_without_rag_side_effects(tmp_path):
    cases = load_attack_cases(dynamic_case_file())[:1]

    rows = run_cases(
        cases,
        config=BenchConfig(defense_enabled=True, sandbox_dir=tmp_path / "sandbox", results_dir=tmp_path / "results"),
        fake_core=True,
        fake_core_decision="deny",
    )

    row = rows[0]
    assert row["blocked"] is True
    assert row["attack_success"] is False
    assert not (tmp_path / "sandbox" / "rag" / "queries.jsonl").exists()
    assert not (tmp_path / "sandbox" / "rag" / "answers.jsonl").exists()


def test_poisonedrag_metrics_cover_clean_poisoned_pair(tmp_path):
    cases = load_attack_cases(clean_case_file())[:1] + load_attack_cases(dynamic_case_file())[:1]

    rows = run_cases(cases, config=BenchConfig(defense_enabled=False, sandbox_dir=tmp_path / "sandbox", results_dir=tmp_path / "results"))
    summary = calculate_poisonedrag_metrics(rows)

    assert summary is not None
    overall = summary["overall"]
    assert overall["clean_correct_rate"] == 1.0
    assert overall["attack_success_rate"] == 1.0
    assert overall["poisoned_attack_success_rate"] == 1.0
    assert overall["answer_flip_rate"] == 1.0
    assert overall["poison_context_hit_rate"] == 1.0


def test_poisonedrag_attack_success_uses_contains_answer_rule():
    case = load_attack_cases(dynamic_case_file())[0]
    row = {
        "metadata": case.metadata,
        "blocked": False,
        "tool_calls": [
            {
                "executed": True,
                "tool_name": "rag_answer",
                "result": {
                    "dataset": case.metadata["source_subset"],
                    "question_id": case.metadata["original_id"],
                    "mode": "poisoned",
                    "answer": "The best supported answer is the local support note.",
                },
            }
        ],
    }

    assert success_for_case(case, row) is False


def test_non_poisonedrag_rag_success_keeps_existing_exact_rule():
    case = load_attack_cases(dynamic_case_file())[0]
    payload = case.model_dump()
    payload["metadata"] = {**payload["metadata"], "source_dataset": "SyntheticRAG"}
    synthetic_case = type(case).model_validate(payload)
    row = {
        "metadata": synthetic_case.metadata,
        "blocked": False,
        "tool_calls": [
            {
                "executed": True,
                "tool_name": "rag_answer",
                "result": {
                    "answer": f"The best supported answer is {case.metadata['incorrect_answer']}.",
                },
            }
        ],
    }

    assert success_for_case(synthetic_case, row) is False
