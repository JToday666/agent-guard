from pathlib import Path

import pytest

from agentguard_langgraph_bench.bench.poisonedrag_data import PoisonedRagRepository


def poisonedrag_root() -> Path:
    return Path(__file__).resolve().parents[1] / "datasets" / "poisonedrag"


def test_poisonedrag_data_loads_adv_results():
    repo = PoisonedRagRepository(poisonedrag_root())

    cases = repo.list_cases("nq")

    assert len(cases) == 4
    assert cases[0].qid == "test1"
    assert cases[0].correct_answer == "23"
    assert cases[0].incorrect_answer == "24"
    assert len(cases[0].adv_texts) == 5


def test_poisonedrag_data_loads_clean_ranking_and_docs():
    repo = PoisonedRagRepository(poisonedrag_root())

    ranking = repo.get_clean_ranked_doc_ids("msmarco", "1163399", 5)
    docs = repo.get_clean_docs("msmarco", [doc_id for doc_id, _ in ranking])

    assert len(ranking) == 5
    assert list(docs) == [doc_id for doc_id, _ in ranking]
    assert all(docs[doc_id].text for doc_id in docs)


def test_poisonedrag_data_rejects_unknown_dataset():
    repo = PoisonedRagRepository(poisonedrag_root())

    with pytest.raises(ValueError, match="Unsupported PoisonedRAG dataset"):
        repo.list_cases("unknown")
