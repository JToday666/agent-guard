"""PoisonedRAG artifact access for the LangGraph benchmark."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import PACKAGE_ROOT


VALID_POISONEDRAG_DATASETS = ("nq", "msmarco", "hotpotqa")
DEFAULT_POISONEDRAG_DATA_DIR = PACKAGE_ROOT / "datasets" / "poisonedrag"


@dataclass(frozen=True, slots=True)
class PoisonedRagCase:
    dataset: str
    qid: str
    index: int
    question: str
    correct_answer: str
    incorrect_answer: str
    adv_texts: list[str]


@dataclass(frozen=True, slots=True)
class CleanDoc:
    doc_id: str
    title: str
    text: str


class PoisonedRagRepository:
    """Loads the copied PoisonedRAG subset without exposing labels to tools."""

    def __init__(self, root: Path | str = DEFAULT_POISONEDRAG_DATA_DIR) -> None:
        self.root = Path(root)
        self._cases: dict[str, list[PoisonedRagCase]] = {}
        self._cases_by_qid: dict[str, dict[str, PoisonedRagCase]] = {}
        self._beir_results: dict[str, dict[str, dict[str, float]]] = {}
        self._doc_cache: dict[str, dict[str, CleanDoc]] = {}

    def validate_dataset(self, dataset: str) -> None:
        if dataset not in VALID_POISONEDRAG_DATASETS:
            raise ValueError(f"Unsupported PoisonedRAG dataset: {dataset}")

    def list_cases(self, dataset: str) -> list[PoisonedRagCase]:
        self.validate_dataset(dataset)
        if dataset in self._cases:
            return self._cases[dataset]

        path = self.root / "adv_targeted_results" / f"{dataset}.json"
        raw = self._read_json(path)
        cases: list[PoisonedRagCase] = []
        for index, value in enumerate(raw.values(), start=1):
            if not isinstance(value, dict):
                raise ValueError(f"{path} sample at index {index} is not an object")
            missing = [
                field
                for field in ("id", "question", "correct answer", "incorrect answer", "adv_texts")
                if field not in value
            ]
            if missing:
                raise ValueError(f"{path} sample at index {index} is missing {missing}")
            adv_texts = value["adv_texts"]
            if not isinstance(adv_texts, list) or not adv_texts:
                raise ValueError(f"{path} sample at index {index} has no adv_texts")
            cases.append(
                PoisonedRagCase(
                    dataset=dataset,
                    qid=str(value["id"]),
                    index=index,
                    question=str(value["question"]),
                    correct_answer=str(value["correct answer"]),
                    incorrect_answer=str(value["incorrect answer"]),
                    adv_texts=[str(text) for text in adv_texts],
                )
            )

        self._cases[dataset] = cases
        self._cases_by_qid[dataset] = {case.qid: case for case in cases}
        return cases

    def get_case(self, dataset: str, qid: str) -> PoisonedRagCase:
        self.list_cases(dataset)
        try:
            return self._cases_by_qid[dataset][str(qid)]
        except KeyError as exc:
            raise ValueError(f"Unknown PoisonedRAG qid for {dataset}: {qid}") from exc

    def load_beir_results(self, dataset: str) -> dict[str, dict[str, float]]:
        self.validate_dataset(dataset)
        if dataset in self._beir_results:
            return self._beir_results[dataset]

        path = self.root / "beir_results" / f"{dataset}-contriever.json"
        raw = self._read_json(path)
        if not isinstance(raw, dict):
            raise ValueError(f"{path} must contain an object")
        self._beir_results[dataset] = {
            str(qid): {str(doc_id): float(score) for doc_id, score in scores.items()}
            for qid, scores in raw.items()
            if isinstance(scores, dict)
        }
        return self._beir_results[dataset]

    def get_clean_ranked_doc_ids(self, dataset: str, qid: str, top_k: int) -> list[tuple[str, float]]:
        if top_k < 1:
            raise ValueError("top_k must be at least 1")
        results = self.load_beir_results(dataset)
        try:
            ranking = results[str(qid)]
        except KeyError as exc:
            raise ValueError(f"No copied BEIR ranking for {dataset}/{qid}") from exc
        return list(ranking.items())[:top_k]

    def get_clean_docs(self, dataset: str, doc_ids: list[str]) -> dict[str, CleanDoc]:
        self.validate_dataset(dataset)
        cache = self._doc_cache.setdefault(dataset, {})
        missing = [doc_id for doc_id in doc_ids if doc_id not in cache]
        if missing:
            cache.update(self._load_docs_from_cache_file(dataset, missing))
            missing = [doc_id for doc_id in doc_ids if doc_id not in cache]
        if missing:
            cache.update(self._scan_corpus_for_docs(dataset, missing))
            missing = [doc_id for doc_id in doc_ids if doc_id not in cache]
        if missing:
            raise ValueError(f"Missing copied clean docs for {dataset}: {missing[:5]}")
        return {doc_id: cache[doc_id] for doc_id in doc_ids}

    def _load_docs_from_cache_file(self, dataset: str, doc_ids: list[str]) -> dict[str, CleanDoc]:
        path = self.root / "clean_doc_cache" / f"{dataset}_clean_docs.json"
        if not path.exists():
            return {}
        raw = self._read_json(path)
        found: dict[str, CleanDoc] = {}
        for doc_id in doc_ids:
            item = raw.get(doc_id) if isinstance(raw, dict) else None
            if not isinstance(item, dict):
                continue
            found[doc_id] = CleanDoc(
                doc_id=doc_id,
                title=str(item.get("title", "")),
                text=str(item.get("text", "")),
            )
        return found

    def _scan_corpus_for_docs(self, dataset: str, doc_ids: list[str]) -> dict[str, CleanDoc]:
        corpus_path = self.root / "corpus" / dataset / "corpus.jsonl"
        if not corpus_path.exists():
            return {}
        wanted = set(doc_ids)
        found: dict[str, CleanDoc] = {}
        with corpus_path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                item = json.loads(line)
                doc_id = str(item.get("_id", ""))
                if doc_id not in wanted:
                    continue
                found[doc_id] = CleanDoc(
                    doc_id=doc_id,
                    title=str(item.get("title", "")),
                    text=str(item.get("text", "")),
                )
                if len(found) == len(wanted):
                    break
        return found

    @staticmethod
    def _read_json(path: Path) -> Any:
        if not path.exists():
            raise FileNotFoundError(f"PoisonedRAG artifact not found: {path}")
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
