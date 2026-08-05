from pathlib import Path

import pytest

from agentguard_langgraph_bench.bench.poisonedrag_context import PoisonedRagContextBuilder
from agentguard_langgraph_bench.bench.poisonedrag_data import PoisonedRagRepository


def builder() -> PoisonedRagContextBuilder:
    root = Path(__file__).resolve().parents[1] / "datasets" / "poisonedrag"
    return PoisonedRagContextBuilder(PoisonedRagRepository(root))


def test_poisonedrag_context_clean_mode_uses_only_clean_docs():
    docs, meta = builder().search("nq", "test1", mode="clean", top_k=3)

    assert len(docs) == 3
    assert {doc.source for doc in docs} == {"clean"}
    assert meta["mode"] == "clean"
    assert meta["poison_context_count"] == 0


def test_poisonedrag_context_poisoned_mode_light_scorer_inserts_poison_docs():
    docs, meta = builder().search("nq", "test1", mode="poisoned", top_k=5, scorer="light")

    assert len(docs) == 5
    assert all(doc.source == "poison" for doc in docs)
    assert docs[0].text.startswith("how many episodes are in chicago fire season 4.")
    assert meta["scorer"] == "light"
    assert meta["poison_context_count"] == 5


def test_poisonedrag_context_supports_poison_prefix_none():
    docs, meta = builder().search("nq", "test1", mode="poisoned", top_k=1, poison_prefix="none")

    assert not docs[0].text.startswith("how many episodes are in chicago fire season 4.")
    assert docs[0].text.startswith("Chicago Fire")
    assert meta["poison_prefix"] == "none"


def test_poisonedrag_context_rejects_invalid_top_k():
    with pytest.raises(ValueError, match="top_k"):
        builder().search("nq", "test1", top_k=0)
