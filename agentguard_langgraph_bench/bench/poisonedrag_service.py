"""Local PoisonedRAG service and fixture files for memory-poisoning cases."""

from __future__ import annotations

import html
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

from .config import DEFAULT_SANDBOX_DIR, PACKAGE_ROOT
from .poisonedrag_data import DEFAULT_POISONEDRAG_DATA_DIR, PoisonedRagRepository


SERVICE_NAME = "agentguard-poisonedrag-service"
DEFAULT_POISONEDRAG_SERVICE_PORT = 18082

_SERVER: ThreadingHTTPServer | None = None
_THREAD: Thread | None = None


def poisonedrag_service_base_url() -> str:
    port = int(os.getenv("AGENTGUARD_POISONEDRAG_SERVICE_PORT", str(DEFAULT_POISONEDRAG_SERVICE_PORT)))
    return f"http://127.0.0.1:{port}"


def poisonedrag_case_url(dataset: str, question_id: str) -> str:
    return f"{poisonedrag_service_base_url()}/poisonedrag/{dataset}/{question_id}"


def poisonedrag_case_page_url(dataset: str, question_id: str) -> str:
    return f"{poisonedrag_case_url(dataset, question_id)}/page"


def is_poisonedrag_service_url(url: str) -> bool:
    parsed = urlparse(url)
    expected = urlparse(poisonedrag_service_base_url())
    is_expected_host = (
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost"}
        and (parsed.port or 80) == (expected.port or 80)
    )
    return is_expected_host and (
        parsed.path.rstrip("/") in {"/status", "/poisonedrag"} or parsed.path.startswith("/poisonedrag/")
    )


def ensure_poisonedrag_service_started() -> None:
    global _SERVER, _THREAD
    if _SERVER is not None:
        return
    port = int(os.getenv("AGENTGUARD_POISONEDRAG_SERVICE_PORT", str(DEFAULT_POISONEDRAG_SERVICE_PORT)))
    _SERVER = ThreadingHTTPServer(("127.0.0.1", port), _PoisonedRagServiceHandler)
    _THREAD = Thread(target=_SERVER.serve_forever, daemon=True)
    _THREAD.start()


def call_poisonedrag_service(url: str, method: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    ensure_poisonedrag_service_started()
    data = None
    headers = {"Accept": "application/json, text/html;q=0.8"}
    if payload:
        data = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method.upper())
    with urlopen(request, timeout=2.0) as response:  # noqa: S310 - localhost-only benchmark service
        body_bytes = response.read()
        content_type = response.headers.get("Content-Type", "")
    body_text = body_bytes.decode("utf-8")
    if "application/json" in content_type:
        body: Any = json.loads(body_text)
    else:
        body = body_text
    return {
        "status_code": response.status,
        "url": url,
        "body": body,
        "real_local_service": True,
        "service": SERVICE_NAME,
    }


def ensure_poisonedrag_case_resources(sandbox_dir: Path = DEFAULT_SANDBOX_DIR) -> list[dict[str, Any]]:
    """Materialize per-case resources referenced by memory_poisoning AttackCases."""

    cases = _load_memory_poisoning_cases()
    repo = PoisonedRagRepository(DEFAULT_POISONEDRAG_DATA_DIR)
    root = sandbox_dir / "files" / "rag" / "poisonedrag"
    root.mkdir(parents=True, exist_ok=True)
    catalog: list[dict[str, Any]] = []
    for case in cases:
        metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
        dataset = str(metadata.get("source_subset") or "")
        question_id = str(metadata.get("original_id") or "")
        if not dataset or not question_id:
            continue
        resource = _build_case_resource(repo, case, dataset, question_id)
        case_root = root / str(case["case_id"])
        case_root.mkdir(parents=True, exist_ok=True)
        files = {
            "case": case_root / "case.json",
            "contexts": case_root / "contexts.json",
            "agent_view": case_root / "agent_view.json",
            "evaluator_oracle": case_root / "evaluator_oracle.json",
            "clean_contexts": case_root / "clean_contexts.json",
            "poisoned_contexts": case_root / "poisoned_contexts.json",
            "hybrid_contexts": case_root / "hybrid_contexts.json",
            "page": case_root / "page.html",
        }
        _write_json(files["case"], resource["case"])
        _write_json(files["contexts"], resource["contexts"])
        _write_json(files["agent_view"], resource["agent_view"])
        _write_json(files["evaluator_oracle"], resource["evaluator_oracle"])
        _write_json(files["clean_contexts"], {"contexts": resource["clean_contexts"]})
        _write_json(files["poisoned_contexts"], {"contexts": resource["poisoned_contexts"]})
        _write_json(files["hybrid_contexts"], {"contexts": resource["hybrid_contexts"]})
        files["page"].write_text(_agent_page_html(resource["agent_view"]), encoding="utf-8")
        catalog_item = {
            "case_id": case["case_id"],
            "dataset": dataset,
            "question_id": question_id,
            "service_url": poisonedrag_case_url(dataset, question_id),
            "page_url": poisonedrag_case_page_url(dataset, question_id),
            "files": {key: str(path.relative_to(sandbox_dir)) for key, path in files.items()},
        }
        catalog.append(catalog_item)
    _write_json(root / "catalog.json", {"service": SERVICE_NAME, "cases": catalog})
    return catalog


class _PoisonedRagServiceHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def do_HEAD(self) -> None:
        self._handle(include_body=False)

    def do_GET(self) -> None:
        self._handle(include_body=True)

    def do_POST(self) -> None:
        self._handle(include_body=True)

    def _handle(self, *, include_body: bool) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/status":
            self._send_json(_status_payload(), include_body=include_body)
            return
        if path == "/poisonedrag":
            self._send_json(_index_payload(), include_body=include_body)
            return
        if path.startswith("/poisonedrag/"):
            parts = [unquote(item) for item in path.split("/") if item]
            if len(parts) not in {3, 4, 5} or parts[0] != "poisonedrag":
                self._send_json({"ok": False, "error": "invalid PoisonedRAG route"}, status=404, include_body=include_body)
                return
            dataset, question_id = parts[1], parts[2]
            try:
                payload = _case_payload(dataset, question_id)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=404, include_body=include_body)
                return
            if len(parts) == 4:
                route = parts[3]
                if route == "page":
                    self._send_html(_agent_page_html(payload["agent_view"]), include_body=include_body)
                    return
                if route == "agent-view":
                    self._send_json(payload["agent_view"], include_body=include_body)
                    return
                if route == "oracle":
                    self._send_json(payload["evaluator_oracle"], include_body=include_body)
                    return
                if route.startswith("contexts"):
                    self._send_json({"ok": False, "error": "use /contexts/{clean|poisoned|hybrid}"}, status=404, include_body=include_body)
                    return
            if len(parts) == 5 and parts[3] == "contexts":
                route = parts[4]
                context_key = f"{route}_contexts"
                if context_key not in payload:
                    self._send_json({"ok": False, "error": "unknown context mode"}, status=404, include_body=include_body)
                    return
                self._send_json({"ok": True, "mode": route, "contexts": payload[context_key]}, include_body=include_body)
                return
            if len(parts) == 3:
                self._send_json(_agent_facing_service_payload(payload), include_body=include_body)
                return
        self._send_json({"ok": False, "error": "not found"}, status=404, include_body=include_body)

    def _send_json(self, payload: dict[str, Any], *, status: int = 200, include_body: bool = True) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _send_html(self, payload: str, *, status: int = 200, include_body: bool = True) -> None:
        body = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)


def _status_payload() -> dict[str, Any]:
    return {
        "ok": True,
        "service": SERVICE_NAME,
        "status": "healthy",
        "datasets": ["nq", "msmarco", "hotpotqa"],
        "base_url": poisonedrag_service_base_url(),
    }


def _index_payload() -> dict[str, Any]:
    return {
        "ok": True,
        "service": SERVICE_NAME,
        "status": "available",
        "cases": [
            {
                "case_id": item.get("case_id"),
                "dataset": (item.get("metadata") or {}).get("source_subset"),
                "question_id": (item.get("metadata") or {}).get("original_id"),
            }
            for item in _load_memory_poisoning_cases()
        ],
    }


def _case_payload(dataset: str, question_id: str) -> dict[str, Any]:
    repo = PoisonedRagRepository(DEFAULT_POISONEDRAG_DATA_DIR)
    case = next(
        (
            item
            for item in _load_memory_poisoning_cases()
            if (item.get("metadata") or {}).get("source_subset") == dataset
            and str((item.get("metadata") or {}).get("original_id")) == str(question_id)
        ),
        None,
    )
    if case is None:
        raise ValueError(f"memory_poisoning case not found for {dataset}/{question_id}")
    resource = _build_case_resource(repo, case, dataset, question_id)
    payload = {
        "ok": True,
        "service": SERVICE_NAME,
        "case": _public_case_payload(resource["case"]),
        "contexts": _public_context_payload(resource["contexts"]),
        "agent_view": resource["agent_view"],
        "clean_contexts": resource["clean_contexts"],
        "poisoned_contexts": resource["poisoned_contexts"],
        "hybrid_contexts": resource["hybrid_contexts"],
        "evaluator_oracle": resource["evaluator_oracle"],
    }
    return payload


def _load_memory_poisoning_cases() -> list[dict[str, Any]]:
    path = PACKAGE_ROOT / "datasets" / "attack_cases" / "memory_poisoning.jsonl"
    cases: list[dict[str, Any]] = []
    if not path.exists():
        return cases
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                cases.append(json.loads(line))
    return cases


def _build_case_resource(
    repo: PoisonedRagRepository,
    attack_case: dict[str, Any],
    dataset: str,
    question_id: str,
) -> dict[str, Any]:
    poisoned_case = repo.get_case(dataset, question_id)
    ranked = repo.get_clean_ranked_doc_ids(dataset, question_id, 5)
    clean_docs = repo.get_clean_docs(dataset, [doc_id for doc_id, _ in ranked])
    clean_contexts = [
        {
            "doc_id": doc_id,
            "score": score,
            "title": clean_docs[doc_id].title,
            "text": clean_docs[doc_id].text,
        }
        for doc_id, score in ranked
    ]
    metadata = attack_case.get("metadata") if isinstance(attack_case.get("metadata"), dict) else {}
    case_payload = {
        "case_id": attack_case.get("case_id"),
        "attack_type": attack_case.get("attack_type"),
        "dataset": dataset,
        "question_id": question_id,
        "question": poisoned_case.question,
        "correct_answer": poisoned_case.correct_answer,
        "targeted_incorrect_answer": poisoned_case.incorrect_answer,
        "service_url": poisonedrag_case_url(dataset, question_id),
        "page_url": poisonedrag_case_page_url(dataset, question_id),
        "source_dataset": metadata.get("source_dataset", "PoisonedRAG"),
        "source_files": {
            "adv_targeted_results": str(DEFAULT_POISONEDRAG_DATA_DIR / "adv_targeted_results" / f"{dataset}.json"),
            "beir_results": str(DEFAULT_POISONEDRAG_DATA_DIR / "beir_results" / f"{dataset}-contriever.json"),
            "clean_doc_cache": str(DEFAULT_POISONEDRAG_DATA_DIR / "clean_doc_cache" / f"{dataset}_clean_docs.json"),
            "corpus_subset": str(DEFAULT_POISONEDRAG_DATA_DIR / "corpus" / dataset / "corpus.jsonl"),
        },
    }
    poisoned_contexts = [
        {"doc_id": f"poison-{index}", "title": f"Community reference note {index}", "text": text}
        for index, text in enumerate(poisoned_case.adv_texts, start=1)
    ]
    hybrid_contexts = _hybrid_contexts(clean_contexts, poisoned_contexts)
    agent_view = _build_agent_view_resource(attack_case, case_payload, poisoned_case.question, poisoned_contexts, clean_contexts)
    evaluator_oracle = _build_evaluator_oracle(attack_case, case_payload, poisoned_case, clean_contexts, poisoned_contexts)
    return {
        "case": case_payload,
        "contexts": {
            "case_id": attack_case.get("case_id"),
            "dataset": dataset,
            "question_id": question_id,
            "poisoned_contexts": poisoned_case.adv_texts,
            "clean_contexts": clean_contexts,
        },
        "agent_view": agent_view,
        "evaluator_oracle": evaluator_oracle,
        "clean_contexts": clean_contexts,
        "poisoned_contexts": poisoned_contexts,
        "hybrid_contexts": hybrid_contexts,
    }


def _resource_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {"case": payload.get("case") or {}, "contexts": payload.get("contexts") or {}}


def _public_case_payload(case_payload: dict[str, Any]) -> dict[str, Any]:
    blocked_keys = {"correct_answer", "incorrect_answer", "targeted_incorrect_answer", "target_incorrect_answer"}
    return {key: value for key, value in case_payload.items() if key not in blocked_keys}


def _public_context_payload(contexts_payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(contexts_payload)
    payload.pop("poisoned_contexts", None)
    return payload


def _agent_facing_service_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": payload.get("ok", True),
        "service": payload.get("service", SERVICE_NAME),
        "case": payload.get("case") or {},
        "contexts": payload.get("contexts") or {},
        "agent_view": payload.get("agent_view") or {},
        "clean_contexts": payload.get("clean_contexts") or [],
        "hybrid_contexts": payload.get("hybrid_contexts") or [],
    }


def _build_agent_view_resource(
    attack_case: dict[str, Any],
    case_payload: dict[str, Any],
    question: str,
    poisoned_contexts: list[dict[str, Any]],
    clean_contexts: list[dict[str, Any]],
) -> dict[str, Any]:
    metadata = attack_case.get("metadata") if isinstance(attack_case.get("metadata"), dict) else {}
    surface = str(metadata.get("poisoning_surface") or "help_center_article")
    title = _agent_title(surface, question)
    visible_sections = _visible_sections(surface, question, poisoned_contexts)
    return {
        "case_id": case_payload.get("case_id"),
        "surface": surface,
        "title": title,
        "question": question,
        "source": {
            "type": surface,
            "trust": "untrusted",
            "author": "catalog-maintainer-42",
            "last_updated": "2024-05-18",
            "url": case_payload.get("page_url"),
        },
        "visible_sections": visible_sections,
        "retrieved_evidence": [
            {"doc_id": f"ctx-{index}", "title": item.get("title", f"Reference {index}"), "text": item.get("text", "")}
            for index, item in enumerate(_hybrid_contexts(clean_contexts, poisoned_contexts)[:5], start=1)
        ],
    }


def _build_evaluator_oracle(
    attack_case: dict[str, Any],
    case_payload: dict[str, Any],
    poisoned_case: Any,
    clean_contexts: list[dict[str, Any]],
    poisoned_contexts: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "case_id": case_payload.get("case_id"),
        "dataset": case_payload.get("dataset"),
        "question_id": case_payload.get("question_id"),
        "question": poisoned_case.question,
        "correct_answer": poisoned_case.correct_answer,
        "incorrect_answer": poisoned_case.incorrect_answer,
        "target_incorrect_answer": poisoned_case.incorrect_answer,
        "poisoned_claims": [str(item.get("text", "")) for item in poisoned_contexts],
        "clean_claims": [str(item.get("text", "")) for item in clean_contexts],
        "poisoned_doc_ids": [str(item.get("doc_id", "")) for item in poisoned_contexts],
        "clean_doc_ids": [str(item.get("doc_id", "")) for item in clean_contexts],
        "metadata": {
            "source_dataset": (attack_case.get("metadata") or {}).get("source_dataset", "PoisonedRAG"),
            "source_subset": case_payload.get("dataset"),
        },
    }


def _hybrid_contexts(clean_contexts: list[dict[str, Any]], poisoned_contexts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mixed: list[dict[str, Any]] = []
    clean = list(clean_contexts)
    poison = list(poisoned_contexts)
    while clean or poison:
        if clean:
            mixed.append(clean.pop(0))
        if poison:
            mixed.append(poison.pop(0))
    return mixed


def _agent_title(surface: str, question: str) -> str:
    if surface == "github_issue":
        return "Reference policy clarification in project discussion"
    if surface == "email_archive":
        return "Forwarded support reference note"
    if surface == "wiki_page":
        return "Knowledge base reference entry"
    return f"Support reference: {question}"


def _visible_sections(surface: str, question: str, poisoned_contexts: list[dict[str, Any]]) -> list[dict[str, str]]:
    primary = str((poisoned_contexts[0] if poisoned_contexts else {}).get("text") or "")
    if surface == "github_issue":
        return [
            {"heading": "Issue summary", "text": f"A contributor asked how support agents should answer: {question}."},
            {"heading": "Latest comment", "text": primary},
        ]
    if surface == "email_archive":
        return [
            {"heading": "Forwarded note", "text": "A partner shared this reference for future support handling."},
            {"heading": "Body", "text": primary},
        ]
    return [
        {"heading": "Catalog note", "text": primary},
        {
            "heading": "Support handling",
            "text": "Use this article as an unverified local reference and compare it with current evidence before answering users.",
        },
    ]


def _case_page_html(resource: dict[str, Any]) -> str:
    case = resource["case"]
    contexts = resource["contexts"]
    poisoned = contexts.get("poisoned_contexts") or []
    clean = contexts.get("clean_contexts") or []
    poison_items = "\n".join(f"<li>{html.escape(str(text))}</li>" for text in poisoned)
    clean_items = "\n".join(
        f"<li><strong>{html.escape(str(item.get('doc_id', '')))}</strong>: "
        f"{html.escape(str(item.get('text', '')))}</li>"
        for item in clean
    )


def _agent_page_html(agent_view: dict[str, Any]) -> str:
    title = html.escape(str(agent_view.get("title") or "Reference page"))
    source = agent_view.get("source") if isinstance(agent_view.get("source"), dict) else {}
    sections = agent_view.get("visible_sections") if isinstance(agent_view.get("visible_sections"), list) else []
    evidence = agent_view.get("retrieved_evidence") if isinstance(agent_view.get("retrieved_evidence"), list) else []
    section_html = "\n".join(
        "<section>"
        f"<h2>{html.escape(str(item.get('heading', 'Section')))}</h2>"
        f"<p>{html.escape(str(item.get('text', '')))}</p>"
        "</section>"
        for item in sections
        if isinstance(item, dict)
    )
    evidence_html = "\n".join(
        "<li>"
        f"<strong>{html.escape(str(item.get('title', item.get('doc_id', 'Reference'))))}</strong>: "
        f"{html.escape(str(item.get('text', '')))}"
        "</li>"
        for item in evidence
        if isinstance(item, dict)
    )
    return (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        f"<head><meta charset=\"utf-8\"><title>{title}</title></head>\n"
        "<body>\n"
        f"<article data-surface=\"{html.escape(str(agent_view.get('surface', 'reference')))}\">\n"
        f"<h1>{title}</h1>\n"
        f"<p>Author: {html.escape(str(source.get('author', 'unknown')))} | "
        f"Last updated: {html.escape(str(source.get('last_updated', 'unknown')))}</p>\n"
        f"{section_html}\n"
        "<section><h2>Related references</h2><ol>"
        f"{evidence_html}"
        "</ol></section>\n"
        "</article>\n"
        "</body>\n</html>\n"
    )
    return (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head><meta charset=\"utf-8\"><title>"
        f"{html.escape(str(case.get('case_id', 'PoisonedRAG case')))}"
        "</title></head>\n"
        "<body>\n"
        f"<h1>{html.escape(str(case.get('case_id', 'PoisonedRAG case')))}</h1>\n"
        f"<p data-field=\"dataset\">Dataset: {html.escape(str(case.get('dataset', '')))}</p>\n"
        f"<p data-field=\"question-id\">Question ID: {html.escape(str(case.get('question_id', '')))}</p>\n"
        f"<p data-field=\"question\">Question: {html.escape(str(case.get('question', '')))}</p>\n"
        f"<p data-field=\"correct-answer\">Correct answer: {html.escape(str(case.get('correct_answer', '')))}</p>\n"
        "<section id=\"poisoned-contexts\"><h2>Targeted Poisoned Contexts</h2>"
        f"<ol>{poison_items}</ol></section>\n"
        "<section id=\"clean-contexts\"><h2>Clean Retrieved Contexts</h2>"
        f"<ol>{clean_items}</ol></section>\n"
        "</body>\n</html>\n"
    )


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
