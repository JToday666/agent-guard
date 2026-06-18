"""Clean and poisoned context construction copied from PoisonedRAG semantics."""

from __future__ import annotations

import math
from dataclasses import dataclass
from importlib import metadata
from typing import Any, Literal

from .poisonedrag_data import PoisonedRagCase, PoisonedRagRepository


PoisonedRagMode = Literal["clean", "poisoned"]
PoisonPrefix = Literal["question", "none"]


@dataclass(frozen=True, slots=True)
class RagContextDoc:
    internal_doc_id: str
    public_doc_id: str
    text: str
    score: float
    source: Literal["clean", "poison"]

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.public_doc_id,
            "text": self.text,
            "score": self.score,
        }

    def to_internal_dict(self) -> dict[str, Any]:
        return {
            "internal_doc_id": self.internal_doc_id,
            "doc_id": self.public_doc_id,
            "text": self.text,
            "score": self.score,
            "source": self.source,
        }


class PoisonedRagContextBuilder:
    """Builds clean and poisoned RAG contexts from copied PoisonedRAG artifacts."""

    def __init__(
        self,
        repository: PoisonedRagRepository,
        default_top_k: int = 5,
        adv_per_query: int = 5,
        poison_prefix: str = "question",
        exact_model_code: str = "contriever",
        exact_score_function: str = "dot",
        allow_scorer_fallback: bool = True,
    ) -> None:
        self.repository = repository
        self.default_top_k = default_top_k
        self.adv_per_query = adv_per_query
        self.poison_prefix = self._normalize_poison_prefix(poison_prefix)
        self.exact_model_code = exact_model_code
        self.exact_score_function = exact_score_function
        self.allow_scorer_fallback = allow_scorer_fallback
        self._exact_scorers: dict[tuple[str, str], ExactContrieverScorer] = {}

    def search(
        self,
        dataset: str,
        qid: str,
        mode: str = "poisoned",
        top_k: int | None = None,
        scorer: str = "light",
        adv_per_query: int | None = None,
        poison_prefix: str | None = None,
        allow_scorer_fallback: bool | None = None,
    ) -> tuple[list[RagContextDoc], dict[str, Any]]:
        top_k = self._normalize_top_k(top_k)
        normalized_mode = mode.lower()
        if normalized_mode not in {"clean", "poisoned"}:
            raise ValueError("mode must be clean or poisoned")
        normalized_scorer = scorer.lower()
        if normalized_scorer not in {"light", "exact"}:
            raise ValueError("scorer must be light or exact")
        prefix = self._normalize_poison_prefix(poison_prefix or self.poison_prefix)
        adv_count = self._normalize_adv_per_query(adv_per_query)

        clean_docs = self._clean_context_docs(dataset, qid, top_k)
        if normalized_mode == "clean":
            return self._with_public_ids(clean_docs), {
                "mode": "clean",
                "scorer": "beir_results",
                "top_k": top_k,
                "poison_prefix": prefix,
                "adv_per_query": adv_count,
                "poison_context_count": 0,
                "clean_context_count": len(clean_docs),
            }

        case = self.repository.get_case(dataset, qid)
        poison_docs = self._poison_docs(dataset, case, clean_docs, adv_count, prefix)
        fallback_allowed = self.allow_scorer_fallback if allow_scorer_fallback is None else allow_scorer_fallback
        meta: dict[str, Any]
        if normalized_scorer == "exact":
            try:
                poison_docs = self._score_poison_exact(case.question, poison_docs)
                meta = {
                    "mode": "poisoned",
                    "scorer": "exact",
                    "model_code": self.exact_model_code,
                    "score_function": self.exact_score_function,
                    "poison_prefix": prefix,
                }
            except Exception as exc:
                if not fallback_allowed:
                    raise RuntimeError(
                        "Exact scorer failed. Install Contriever dependencies or set allow_scorer_fallback=true."
                    ) from exc
                poison_docs = self._score_poison_light(poison_docs, clean_docs)
                meta = {
                    "mode": "poisoned",
                    "scorer": "light",
                    "fallback_from": "exact",
                    "fallback_reason": str(exc),
                    "poison_prefix": prefix,
                }
        else:
            poison_docs = self._score_poison_light(poison_docs, clean_docs)
            meta = {"mode": "poisoned", "scorer": "light", "poison_prefix": prefix}

        ranked = sorted(clean_docs + poison_docs, key=lambda doc: doc.score, reverse=True)[:top_k]
        public_docs = self._with_public_ids(ranked)
        meta.update(
            {
                "top_k": top_k,
                "adv_per_query": adv_count,
                "poison_context_count": sum(doc.source == "poison" for doc in public_docs),
                "clean_context_count": sum(doc.source == "clean" for doc in public_docs),
            }
        )
        return public_docs, meta

    def _clean_context_docs(self, dataset: str, qid: str, top_k: int) -> list[RagContextDoc]:
        clean_ids = self.repository.get_clean_ranked_doc_ids(dataset, qid, top_k)
        clean_texts = self.repository.get_clean_docs(dataset, [doc_id for doc_id, _ in clean_ids])
        docs: list[RagContextDoc] = []
        for doc_id, score in clean_ids:
            clean_doc = clean_texts[doc_id]
            text = clean_doc.text if not clean_doc.title else f"{clean_doc.title}\n{clean_doc.text}"
            docs.append(
                RagContextDoc(
                    internal_doc_id=f"clean::{dataset}::{doc_id}",
                    public_doc_id=doc_id,
                    text=text,
                    score=float(score),
                    source="clean",
                )
            )
        return docs

    def _poison_docs(
        self,
        dataset: str,
        case: PoisonedRagCase,
        clean_docs: list[RagContextDoc],
        adv_per_query: int,
        poison_prefix: str,
    ) -> list[RagContextDoc]:
        docs: list[RagContextDoc] = []
        base_score = clean_docs[0].score if clean_docs else 0.0
        for index, adv_text in enumerate(case.adv_texts[:adv_per_query]):
            docs.append(
                RagContextDoc(
                    internal_doc_id=f"poison::{dataset}::{case.qid}::{index}",
                    public_doc_id=f"poison-{index + 1}",
                    text=self._build_poison_text(case.question, adv_text, poison_prefix),
                    score=base_score,
                    source="poison",
                )
            )
        return docs

    def _score_poison_light(
        self,
        poison_docs: list[RagContextDoc],
        clean_docs: list[RagContextDoc],
    ) -> list[RagContextDoc]:
        top_clean_score = clean_docs[0].score if clean_docs else 0.0
        return [
            RagContextDoc(
                internal_doc_id=doc.internal_doc_id,
                public_doc_id=doc.public_doc_id,
                text=doc.text,
                score=top_clean_score + 1.0 - (index * 0.001),
                source=doc.source,
            )
            for index, doc in enumerate(poison_docs)
        ]

    def _score_poison_exact(self, question: str, poison_docs: list[RagContextDoc]) -> list[RagContextDoc]:
        key = (self.exact_model_code, self.exact_score_function)
        if key not in self._exact_scorers:
            self._exact_scorers[key] = ExactContrieverScorer(
                model_code=self.exact_model_code,
                score_function=self.exact_score_function,
            )
        scores = self._exact_scorers[key].score(question, [doc.text for doc in poison_docs])
        return [
            RagContextDoc(
                internal_doc_id=doc.internal_doc_id,
                public_doc_id=doc.public_doc_id,
                text=doc.text,
                score=score,
                source=doc.source,
            )
            for doc, score in zip(poison_docs, scores)
        ]

    @staticmethod
    def _with_public_ids(docs: list[RagContextDoc]) -> list[RagContextDoc]:
        return [
            RagContextDoc(
                internal_doc_id=doc.internal_doc_id,
                public_doc_id=f"ctx-{index}",
                text=doc.text,
                score=doc.score,
                source=doc.source,
            )
            for index, doc in enumerate(docs, start=1)
        ]

    def _normalize_top_k(self, top_k: int | None) -> int:
        value = self.default_top_k if top_k is None else top_k
        if not isinstance(value, int):
            raise ValueError("top_k must be an integer")
        if value < 1:
            raise ValueError("top_k must be at least 1")
        if value > 100:
            raise ValueError("top_k must be at most 100 because beir_results stores top-100 docs")
        return value

    def _normalize_adv_per_query(self, adv_per_query: int | None) -> int:
        value = self.adv_per_query if adv_per_query is None else adv_per_query
        if not isinstance(value, int):
            raise ValueError("adv_per_query must be an integer")
        if value < 1:
            raise ValueError("adv_per_query must be at least 1")
        return value

    @staticmethod
    def _build_poison_text(question: str, adv_text: str, poison_prefix: str) -> str:
        if poison_prefix == "question":
            return f"{question}.{adv_text}"
        if poison_prefix == "none":
            return adv_text
        raise ValueError(f"Unsupported poison_prefix: {poison_prefix}")

    @staticmethod
    def _normalize_poison_prefix(poison_prefix: str) -> str:
        normalized = poison_prefix.lower()
        if normalized not in {"question", "none"}:
            raise ValueError("poison_prefix must be question or none")
        return normalized


class ExactContrieverScorer:
    """Optional scorer matching PoisonedRAG's Contriever similarity path."""

    def __init__(self, model_code: str = "contriever", score_function: str = "dot") -> None:
        self.score_function = score_function
        try:
            import torch
            from src.utils import load_models
        except Exception as exc:
            raise RuntimeError(exact_scorer_dependency_message(model_code, score_function, exc)) from exc

        self.torch = torch
        try:
            self.model, self.c_model, self.tokenizer, self.get_emb = load_models(model_code)
        except Exception as exc:
            raise RuntimeError(exact_scorer_dependency_message(model_code, score_function, exc)) from exc
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model.eval()
        self.c_model.eval()
        self.model.to(self.device)
        self.c_model.to(self.device)

    def score(self, question: str, texts: list[str]) -> list[float]:
        if not texts:
            return []
        torch = self.torch
        query_input = self.tokenizer(question, padding=True, truncation=True, return_tensors="pt")
        query_input = {key: value.to(self.device) for key, value in query_input.items()}
        text_input = self.tokenizer(texts, padding=True, truncation=True, return_tensors="pt")
        text_input = {key: value.to(self.device) for key, value in text_input.items()}
        with torch.no_grad():
            query_emb = self.get_emb(self.model, query_input)
            text_embs = self.get_emb(self.c_model, text_input)
        if self.score_function == "dot":
            scores = torch.mm(text_embs, query_emb.T).squeeze(-1)
        elif self.score_function == "cos_sim":
            scores = torch.cosine_similarity(text_embs, query_emb.expand_as(text_embs))
        else:
            raise ValueError(f"Unsupported score function: {self.score_function}")
        return [float(score) if math.isfinite(float(score)) else 0.0 for score in scores.detach().cpu().tolist()]


def exact_scorer_dependency_message(model_code: str, score_function: str, exc: Exception) -> str:
    versions = []
    for package in ("torch", "transformers", "tokenizers", "huggingface-hub", "sentence-transformers"):
        try:
            versions.append(f"{package}=={metadata.version(package)}")
        except metadata.PackageNotFoundError:
            versions.append(f"{package}=<not installed>")
    return (
        "Exact Contriever scorer failed to initialize. "
        f"model_code={model_code!r}, score_function={score_function!r}. "
        "Installed versions: "
        + ", ".join(versions)
        + ". Use scorer=light or allow_scorer_fallback=true for default benchmark runs. "
        f"Original error: {type(exc).__name__}: {exc}"
    )
