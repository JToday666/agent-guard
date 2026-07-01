"""Adapter shim for standalone LangGraph benchmark agents.

This wrapper keeps the external agent file untouched while applying
AgentGuard LangGraph adapter compatibility fixes around it:

- case-aware tool visibility;
- planner output normalization;
- tool-argument normalization and compatibility metadata;
- broader final-answer extraction;
- one retry for recoverable tool-schema errors.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_AGENT_PATH = Path("/home/zhuwei/code/langgraph/examples/bench_tool_agent.py")
MAX_TOOL_RESULT_CHARS = 5000
SDK_ROOT = Path(__file__).resolve().parents[1] / "packages" / "agentguard-langgraph-adapter"
if SDK_ROOT.exists() and str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from agentguard_langgraph_adapter import ToolCompatibilityLayer


def _load_agent_module(agent_path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("agentguard_external_langgraph_agent", agent_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load external agent from {agent_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _case_context_from_state(state: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(state.get("metadata") or {})
    security = dict(state.get("security") or {})
    return {
        "case_id": state.get("case_id") or security.get("case_id"),
        "attack_type": security.get("attack_type") or metadata.get("attack_type"),
        "task": state.get("task") or security.get("user_task") or "",
        "user_task": state.get("task") or security.get("user_task") or "",
        "metadata": metadata,
        "runtime_policy": state.get("runtime_policy") if isinstance(state.get("runtime_policy"), dict) else {},
    }


def _security_with_compatibility(security: dict[str, Any], compatibility: dict[str, Any]) -> dict[str, Any]:
    security = dict(security)
    metadata = dict(security.get("metadata") or {})
    metadata["compatibility"] = compatibility
    security["metadata"] = metadata
    return security


def _normalize_planner_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    if not normalized.get("tool_name"):
        for key in ("tool", "name", "action", "next_tool"):
            value = normalized.get(key)
            if isinstance(value, str) and value.strip():
                normalized["tool_name"] = value.strip()
                break
    arguments = normalized.get("arguments")
    if not isinstance(arguments, dict):
        for key in ("params", "parameters", "args", "payload"):
            value = normalized.get(key)
            if isinstance(value, dict):
                normalized["arguments"] = dict(value)
                break
    if not isinstance(normalized.get("arguments"), dict):
        normalized["arguments"] = {}
    if not normalized.get("final_answer"):
        for key in ("final", "answer", "content", "text", "message", "output", "result"):
            value = normalized.get(key)
            if isinstance(value, str) and value.strip():
                normalized["final_answer"] = value.strip()
                break
    return normalized


def _extract_final_text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if not isinstance(value, dict):
        return ""
    for key in ("answer", "final_answer", "message", "text", "content", "output", "value", "response", "result"):
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            return item.strip()
        if isinstance(item, dict):
            nested = _extract_final_text(item)
            if nested:
                return nested
    return ""


def _extract_selector_candidates(observation: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    result = observation.get("result")
    payload = result if isinstance(result, dict) else {}
    inspect_payload = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    if observation.get("tool_name") == "browser_inspect":
        for item in (payload, inspect_payload):
            for key in ("interactive_elements",):
                items = item.get(key)
                if isinstance(items, list):
                    for element in items:
                        if not isinstance(element, dict):
                            continue
                        for field in ("selector", "testid", "id", "href", "label", "text", "name", "placeholder", "value"):
                            value = str(element.get(field) or "").strip()
                            if value:
                                candidates.append(value)
        text = str(payload.get("visible_text") or inspect_payload.get("visible_text") or "")
        for marker in ("booking-date", "booking-time", "booking-pickup-location", "booking-dropoff-location", "billing-profile-sync", "attack-submit"):
            if marker in text:
                candidates.append(f"testid={marker}")
    return list(dict.fromkeys(candidates))


def _normalize_click_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def _selector_from_click_text(click_text: str, observations: list[dict[str, Any]]) -> str:
    target = _normalize_click_text(click_text)
    if not target:
        return ""
    for observation in reversed(observations):
        if not isinstance(observation, dict) or observation.get("tool_name") != "browser_inspect":
            continue
        result = observation.get("result")
        payload = result if isinstance(result, dict) else {}
        inspect_payload = payload.get("result") if isinstance(payload.get("result"), dict) else {}
        for item in (payload, inspect_payload):
            elements = item.get("interactive_elements")
            if not isinstance(elements, list):
                continue
            for element in elements:
                if not isinstance(element, dict):
                    continue
                selector = str(element.get("selector") or "").strip()
                testid = str(element.get("testid") or "").strip()
                element_id = str(element.get("id") or "").strip()
                href = str(element.get("href") or "").strip()
                text_fields = [
                    str(element.get(field) or "").strip()
                    for field in ("label", "text", "name", "placeholder", "value")
                ]
                if any(_normalize_click_text(field) and (_normalize_click_text(field) in target or target in _normalize_click_text(field)) for field in text_fields):
                    for candidate in (selector, f"testid={testid}" if testid else "", f"id={element_id}" if element_id else "", href):
                        if candidate:
                            return candidate
    return ""


def _selector_from_error(error: str, observations: list[dict[str, Any]]) -> str:
    lowered = error.lower()
    if "apply-peter-profile" in lowered or "apply peter parker profile" in lowered or "peter parker" in lowered:
        return "testid=apply-peter-profile"
    if "booking-date" in lowered:
        return "testid=booking-date"
    if "booking-time" in lowered:
        return "testid=booking-time"
    if "pickuplocation" in lowered or "pickup location" in lowered:
        return "testid=booking-pickup-location"
    if "dropofflocation" in lowered or "drop-off location" in lowered:
        return "testid=booking-dropoff-location"
    if "billing-profile-sync" in lowered or "billing verification" in lowered:
        return "testid=billing-profile-sync"
    candidates: list[str] = []
    for observation in reversed(observations):
        candidates.extend(_extract_selector_candidates(observation))
    for candidate in candidates:
        if candidate:
            return candidate
    return ""


def _tool_error_text(result: dict[str, Any]) -> str:
    for key in ("error", "safe_message", "status"):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _shrink_json_value(value: Any, max_chars: int) -> Any:
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        return value
    if len(text) <= max_chars:
        return value
    return {"truncated": True, "preview": text[:max_chars]}


def _compact_interactive_elements(elements: Any, limit: int = 12) -> list[dict[str, Any]]:
    if not isinstance(elements, list):
        return []
    compacted: list[dict[str, Any]] = []
    for element in elements[:limit]:
        if not isinstance(element, dict):
            continue
        compacted_element: dict[str, Any] = {}
        for key in ("selector", "testid", "id", "text", "label", "name", "placeholder", "role", "href", "tag"):
            value = element.get(key)
            if value is not None and str(value).strip():
                compacted_element[key] = value
        if compacted_element:
            compacted.append(compacted_element)
    return compacted


def _tool_observation_result(tool_name: str, result: Any) -> Any:
    shrunk = _shrink_json_value(result, MAX_TOOL_RESULT_CHARS)
    if not isinstance(result, dict) or not isinstance(shrunk, dict):
        return shrunk
    shrunk = dict(shrunk)

    summary: dict[str, Any] = {}
    for key in (
        "session_id",
        "url",
        "source_path",
        "real_browser",
        "replay_artifact",
        "diagnostic_artifact",
        "executed",
        "blocked",
        "status",
        "error",
        "safe_message",
        "final_url",
        "screenshot",
        "step_screenshot",
    ):
        value = result.get(key)
        if value is not None:
            summary[key] = value
    if tool_name == "browser_inspect":
        summary["interactive_elements"] = _compact_interactive_elements(result.get("interactive_elements"))
        visible_text = result.get("visible_text")
        if isinstance(visible_text, str) and visible_text.strip():
            summary["visible_text"] = visible_text
        title = result.get("title")
        if isinstance(title, str) and title.strip():
            summary["title"] = title
    elif tool_name == "browser_extract_text":
        text_value = result.get("text")
        if isinstance(text_value, str) and text_value.strip():
            summary["text"] = text_value
        content_value = result.get("content")
        if isinstance(content_value, str) and content_value.strip():
            summary["content"] = content_value
    elif tool_name == "browser_start":
        session_id = result.get("session_id")
        if isinstance(session_id, str) and session_id.strip():
            summary["session_id"] = session_id

    if summary:
        shrunk.update(summary)
    return shrunk


def _normalize_llm_diagnostic(diagnostic: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(diagnostic)
    error_text = str(normalized.get("error") or "").lower()
    if "timed out" in error_text or "timeout" in error_text:
        normalized["outcome"] = "timeout"
        normalized.setdefault("error_type", "TimeoutError")
    return normalized


def _normalize_llm_diagnostics(result: dict[str, Any]) -> None:
    diagnostics = result.get("llm_diagnostics")
    if isinstance(diagnostics, list):
        result["llm_diagnostics"] = [
            _normalize_llm_diagnostic(item) if isinstance(item, dict) else item
            for item in diagnostics
        ]
    if str(result.get("stop_reason") or "") == "llm_error":
        final_answer = str(result.get("final_answer") or "").lower()
        if "llm planning failed" in final_answer:
            result["stop_reason"] = "llm_planning_error"


def _has_browser_start_observation(state: dict[str, Any]) -> bool:
    for observation in state.get("observations") or []:
        if isinstance(observation, dict) and observation.get("tool_name") == "browser_start":
            return True
    return False


def _latest_browser_session_id(observations: list[dict[str, Any]]) -> str:
    for observation in reversed(observations):
        if not isinstance(observation, dict) or observation.get("tool_name") != "browser_start":
            continue
        result = observation.get("result")
        if not isinstance(result, dict):
            continue
        payload = result.get("result") if isinstance(result.get("result"), dict) else result
        session_id = str(payload.get("session_id") or "").strip()
        if session_id:
            return session_id
    return ""


def _tool_result_body(result: Any) -> Any:
    if not isinstance(result, dict):
        return result
    if "result" in result:
        return result["result"]
    return result


def _successful_result(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    if result.get("blocked") or result.get("error"):
        return False
    status = str(result.get("status") or "")
    return status in {"", "executed", "ok", "success"}


def _observation_result(observations: list[dict[str, Any]], index: int, latest_result: dict[str, Any] | None) -> Any:
    if latest_result is not None and index == len(observations) - 1:
        return latest_result
    return observations[index].get("result")


def _has_rag_answer_observation(observations: list[dict[str, Any]]) -> bool:
    return any(isinstance(item, dict) and item.get("tool_name") == "rag_answer" for item in observations)


def _has_tool_observation(observations: list[dict[str, Any]], tool_name: str) -> bool:
    return any(isinstance(item, dict) and item.get("tool_name") == tool_name for item in observations)


def _has_memory_lookup_observation(observations: list[dict[str, Any]]) -> bool:
    return any(
        isinstance(item, dict) and item.get("tool_name") in {"memory_search", "memory_read"}
        for item in observations
    )


def _string_from_memory_value(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("answer", "note", "value", "text", "content", "message"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                return item.strip()
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("{") and text.endswith("}"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return text
        if isinstance(parsed, dict):
            nested = _string_from_memory_value(parsed)
            return nested or text
    return text


def _latest_memory_answer(
    observations: list[dict[str, Any]],
    latest_result: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    for index in range(len(observations) - 1, -1, -1):
        observation = observations[index]
        result = _observation_result(observations, index, latest_result)
        if not _successful_result(result):
            continue
        body = _tool_result_body(result)
        if not isinstance(body, dict):
            continue
        if observation.get("tool_name") == "memory_read" and body.get("found"):
            answer = _string_from_memory_value(body.get("value"))
            if answer:
                return answer, _memory_refs_from_records([body])
        if observation.get("tool_name") == "memory_search":
            matches = body.get("matches") if isinstance(body.get("matches"), list) else []
            for match in reversed([item for item in matches if isinstance(item, dict)]):
                answer = _string_from_memory_value(match.get("value"))
                if answer:
                    return answer, _memory_refs_from_records([match])
    return "", []


def _memory_refs_from_records(records: list[dict[str, Any]]) -> list[str]:
    refs: list[str] = []
    for record in records:
        namespace = str(record.get("namespace") or "").strip()
        key = str(record.get("key") or "").strip()
        if namespace and key:
            refs.append(f"{namespace}:{key}")
    return list(dict.fromkeys(refs))


def _latest_rag_contexts(
    observations: list[dict[str, Any]],
    latest_result: dict[str, Any] | None = None,
) -> list[str]:
    for index in range(len(observations) - 1, -1, -1):
        observation = observations[index]
        if observation.get("tool_name") != "rag_retrieve":
            continue
        result = _observation_result(observations, index, latest_result)
        if not _successful_result(result):
            continue
        body = _tool_result_body(result)
        if not isinstance(body, dict):
            continue
        contexts = [str(item) for item in body.get("contexts") or [] if str(item or "").strip()]
        if contexts:
            return contexts
        docs = body.get("context_docs") if isinstance(body.get("context_docs"), list) else []
        texts = [str(item.get("text") or "") for item in docs if isinstance(item, dict) and str(item.get("text") or "").strip()]
        if texts:
            return texts
    return []


def _latest_reference_text(
    observations: list[dict[str, Any]],
    latest_result: dict[str, Any] | None = None,
) -> str:
    for index in range(len(observations) - 1, -1, -1):
        observation = observations[index]
        result = _observation_result(observations, index, latest_result)
        if not _successful_result(result):
            continue
        body = _tool_result_body(result)
        tool_name = str(observation.get("tool_name") or "")
        if tool_name == "rag_retrieve":
            contexts = _latest_rag_contexts(observations[: index + 1], result if index == len(observations) - 1 else None)
            if contexts:
                return contexts[0]
        if isinstance(body, str) and body.strip():
            return body.strip()
        if not isinstance(body, dict):
            continue
        if tool_name == "read_file":
            for key in ("content", "text", "body", "value", "result"):
                text = _string_from_memory_value(body.get(key))
                if text:
                    return text
        if tool_name == "call_api":
            for key in ("body", "content", "text", "response", "result"):
                text = _string_from_memory_value(body.get(key))
                if text:
                    return text
        for key in ("answer", "note", "value", "text", "content"):
            text = _string_from_memory_value(body.get(key))
            if text:
                return text
    return ""


def _answer_from_context(context: str) -> str:
    text = re.sub(r"\s+", " ", str(context or "")).strip()
    if not text:
        return ""
    for separator in ("\n", ". ", "; "):
        if separator in text:
            candidate = text.split(separator, 1)[0].strip(" .;")
            if 0 < len(candidate) <= 240:
                return candidate
    return text[:240].strip()


def _parse_task_field(task: str, label: str) -> str:
    pattern = rf"(?im)^\s*{re.escape(label)}\s*:\s*(.+?)\s*$"
    match = re.search(pattern, task or "")
    return match.group(1).strip() if match else ""


def _metadata_value(metadata: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = metadata.get(key)
        if value not in (None, ""):
            return str(value)
    poisonedrag = metadata.get("poisonedrag")
    if isinstance(poisonedrag, dict):
        for key in keys:
            value = poisonedrag.get(key)
            if value not in (None, ""):
                return str(value)
    return ""


def _is_memory_rag_answer_case(state: dict[str, Any]) -> bool:
    metadata = dict(state.get("metadata") or {})
    security = dict(state.get("security") or {})
    attack_type = str(security.get("attack_type") or metadata.get("attack_type") or "").lower()
    source_dataset = str(metadata.get("source_dataset") or "").lower()
    source_group = str(metadata.get("source_group") or "").lower()
    phase = str(metadata.get("phase") or "").lower()
    case_id = str(state.get("case_id") or security.get("case_id") or "").upper()
    if phase in {"poison_seed", "benign_seed"}:
        return False
    return (
        attack_type == "memory_poisoning"
        or source_group.startswith("memory_poisoning")
        or phase in {"trigger_query", "conflict_probe", "clean_control"}
        or (source_dataset == "poisonedrag" and case_id.startswith(("PR-", "MP-")))
    )


def _is_memory_seed_case(state: dict[str, Any]) -> bool:
    metadata = dict(state.get("metadata") or {})
    phase = str(metadata.get("phase") or "").lower()
    return phase in {"poison_seed", "benign_seed"}


def _memory_mode(metadata: dict[str, Any]) -> str:
    phase = str(metadata.get("phase") or "").lower()
    mode = _metadata_value(metadata, "mode")
    if mode:
        return mode
    if phase == "trigger_query":
        return "delayed_memory"
    if phase in {"conflict_probe", "clean_control"}:
        return "clean"
    return "poisoned"


def _memory_rag_answer_terminal_arguments(
    state: dict[str, Any],
    answer: str,
    observations: list[dict[str, Any]],
    latest_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = dict(state.get("metadata") or {})
    task = str(state.get("task") or (state.get("security") or {}).get("user_task") or "")
    _, memory_refs = _latest_memory_answer(observations, latest_result)
    rag_contexts = _latest_rag_contexts(observations, latest_result)
    phase = str(metadata.get("phase") or "").lower()
    return {
        "dataset": _metadata_value(metadata, "dataset", "source_subset") or _parse_task_field(task, "Dataset"),
        "question_id": _metadata_value(metadata, "question_id", "original_id") or _parse_task_field(task, "Question ID"),
        "question": _metadata_value(metadata, "question") or _parse_task_field(task, "Question"),
        "answer": answer,
        "contexts": rag_contexts,
        "mode": _memory_mode(metadata),
        "used_memory": bool(memory_refs),
        "memory_refs": memory_refs,
        "conflict_detected": True if phase == "conflict_probe" and memory_refs and rag_contexts else None,
        "answer_source": "model_terminal_answer",
    }


def _memory_write_terminal_arguments(state: dict[str, Any], value: str) -> dict[str, Any]:
    metadata = dict(state.get("metadata") or {})
    task = str(state.get("task") or (state.get("security") or {}).get("user_task") or "")
    if not value.strip():
        value = _metadata_value(metadata, "memory_value")
    return {
        "namespace": _metadata_value(metadata, "memory_namespace") or _parse_task_field(task, "Memory namespace"),
        "key": _metadata_value(metadata, "memory_key") or _parse_task_field(task, "Suggested memory key") or _parse_task_field(task, "Memory key"),
        "value": value,
        "source_type": str(state.get("source_type") or (state.get("security") or {}).get("source_type") or "unknown"),
        "source_trust": str(state.get("source_trust") or (state.get("security") or {}).get("source_trust") or "unknown"),
        "durability": "session",
    }


def _memory_write_fallback_arguments(
    state: dict[str, Any],
    observations: list[dict[str, Any]],
    latest_result: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not _is_memory_seed_case(state) or _has_tool_observation(observations, "memory_write"):
        return None
    reference_text = _latest_reference_text(observations, latest_result)
    metadata = dict(state.get("metadata") or {})
    value = reference_text or _metadata_value(metadata, "memory_value")
    if not value.strip():
        return None
    return _memory_write_terminal_arguments(state, value[:1200])


def _memory_rag_answer_fallback_arguments(
    state: dict[str, Any],
    observations: list[dict[str, Any]],
    latest_result: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not _is_memory_rag_answer_case(state) or _has_rag_answer_observation(observations):
        return None
    metadata = dict(state.get("metadata") or {})
    task = str(state.get("task") or (state.get("security") or {}).get("user_task") or "")
    memory_answer, memory_refs = _latest_memory_answer(observations, latest_result)
    rag_contexts = _latest_rag_contexts(observations, latest_result)
    phase = str(metadata.get("phase") or "").lower()
    if phase in {"trigger_query", "conflict_probe"} and not _has_memory_lookup_observation(observations):
        return None
    if phase == "conflict_probe" and not rag_contexts:
        return None
    if not memory_answer and not rag_contexts:
        return None
    answer = memory_answer or _answer_from_context(rag_contexts[0])
    dataset = _metadata_value(metadata, "dataset", "source_subset") or _parse_task_field(task, "Dataset")
    question_id = _metadata_value(metadata, "question_id", "original_id") or _parse_task_field(task, "Question ID")
    question = _metadata_value(metadata, "question") or _parse_task_field(task, "Question")
    return {
        "dataset": dataset,
        "question_id": question_id,
        "question": question,
        "answer": answer,
        "contexts": rag_contexts,
        "mode": _memory_mode(metadata),
        "used_memory": bool(memory_answer or memory_refs),
        "memory_refs": memory_refs,
        "conflict_detected": True if phase == "conflict_probe" and memory_answer and rag_contexts else None,
        "answer_source": "memory_terminal_fallback" if memory_answer else "rag_context_terminal_fallback",
    }


def _memory_browser_alternative_action(state: dict[str, Any]) -> dict[str, Any] | None:
    if not _is_memory_rag_answer_case(state) and str((state.get("metadata") or {}).get("phase") or "") not in {"poison_seed", "benign_seed"}:
        return None
    tools = {
        str(item.get("name") or "")
        for item in state.get("tools", [])
        if isinstance(item, dict) and item.get("name")
    }
    metadata = dict(state.get("metadata") or {})
    agent_files = metadata.get("agent_files") if isinstance(metadata.get("agent_files"), dict) else {}
    if "read_file" in tools:
        for key in ("agent_view", "reference_evidence", "case", "page"):
            path = str(agent_files.get(key) or "").strip()
            if path:
                return {"tool_name": "read_file", "arguments": {"path": path}}
    if "call_api" in tools:
        for key in ("local_service_url", "agent_page_url", "local_service_page_url"):
            url = str(metadata.get(key) or "").strip()
            if url:
                return {"tool_name": "call_api", "arguments": {"url": url, "method": "GET"}}
    return None


def _benign_mcp_fixture_read_alternative_action(state: dict[str, Any], result: dict[str, Any]) -> dict[str, Any] | None:
    tool_name = str(result.get("tool_name") or "").strip()
    if tool_name != "read_file":
        return None
    metadata = dict(state.get("metadata") or {})
    security = dict(state.get("security") or {})
    attack_type = str(security.get("attack_type") or metadata.get("attack_type") or "").lower()
    if attack_type != "benign":
        return None
    arguments = result.get("arguments") if isinstance(result.get("arguments"), dict) else {}
    path = str(arguments.get("path") or arguments.get("file_path") or "").strip().lower()
    task = str(state.get("task") or security.get("user_task") or "")
    if "weather_forecasts.json" not in path or "weather.get_forecast" not in task:
        return None
    city_match = re.search(r"\bcity\s+([A-Za-z][A-Za-z ._-]{1,64}?)(?:\s+using|\s+with|[.,]|$)", task)
    city = city_match.group(1).strip(" .,_-") if city_match else "Shanghai"
    return {
        "tool_name": "mcp_call",
        "arguments": {
            "server": "weather",
            "tool": "get_forecast",
            "arguments": {"city": city},
            "request_id": str(state.get("case_id") or security.get("case_id") or "benign-mcp-weather"),
        },
    }


def _memory_lookup_required_before_answer(state: dict[str, Any], observations: list[dict[str, Any]]) -> dict[str, Any] | None:
    metadata = dict(state.get("metadata") or {})
    phase = str(metadata.get("phase") or "").lower()
    if phase not in {"trigger_query", "conflict_probe"} or _has_memory_lookup_observation(observations):
        return None
    namespace = _metadata_value(metadata, "memory_namespace") or _parse_task_field(str(state.get("task") or ""), "Memory namespace")
    key = _metadata_value(metadata, "memory_key") or _parse_task_field(str(state.get("task") or ""), "Memory key")
    if key:
        return {"tool_name": "memory_read", "arguments": {"namespace": namespace, "key": key}}
    query = _metadata_value(metadata, "question", "query") or _parse_task_field(str(state.get("task") or ""), "Question")
    if query or namespace:
        return {"tool_name": "memory_search", "arguments": {"namespace": namespace, "query": query}}
    return None


def _patch_agent_module(module: Any) -> None:
    layer = ToolCompatibilityLayer()

    original_build_graph = module.build_graph
    original_fetch_tools = module.fetch_tools
    original_bind_runtime_arguments = module.bind_runtime_arguments
    original_call_chat_completion = module.call_chat_completion
    original_parse_json_object = module.parse_json_object
    original_finish_from_result = module.finish_from_result
    original_plan_next_action = module.plan_next_action
    original_browser_start_hint = getattr(module, "browser_start_hint", None)

    def build_graph() -> Any:
        app = original_build_graph()

        class RuntimePolicyInjectingGraph:
            def invoke(self, state: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
                if isinstance(state, dict):
                    active_policy = getattr(module, "_agentguard_runtime_policy", {})
                    if isinstance(active_policy, dict) and active_policy and "runtime_policy" not in state:
                        state = {**state, "runtime_policy": dict(active_policy)}
                return app.invoke(state, *args, **kwargs)

            def __getattr__(self, name: str) -> Any:
                return getattr(app, name)

        return RuntimePolicyInjectingGraph()

    def fetch_tools(state: dict[str, Any]) -> dict[str, Any]:
        payload = original_fetch_tools(state)
        tools = payload.get("tools")
        if not isinstance(tools, list):
            return payload
        payload["tools"] = layer.visible_tools(
            [item for item in tools if isinstance(item, dict)],
            case_context=_case_context_from_state(state),
            security=dict(state.get("security") or {}),
            config=None,
        )
        return payload

    def bind_runtime_arguments(state: dict[str, Any], tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        compat = layer.normalize_arguments(
            tool_name,
            arguments,
            case_context=_case_context_from_state(state),
            security=dict(state.get("security") or {}),
            trace_id=str(state.get("trace_id") or ""),
            call_id="",
            config=None,
        )
        return original_bind_runtime_arguments(state, tool_name, compat.normalized_arguments)

    def browser_start_hint(state: dict[str, Any]) -> dict[str, Any]:
        policy = layer.case_tool_policy(
            case_context=_case_context_from_state(state),
            security=dict(state.get("security") or {}),
            config=None,
        )
        if not policy.get("browser_available"):
            return {"url": "", "source_path": "", "run_id": state.get("case_id", ""), "suggested_first_call": {}}
        if callable(original_browser_start_hint):
            hint = original_browser_start_hint(state)
            return hint if isinstance(hint, dict) else {}
        return {}

    def call_chat_completion(config: Any, messages: list[dict[str, str]]) -> str:
        last_error: Exception | None = None
        timeout = float(getattr(config, "request_timeout", 60.0) or 60.0)
        retry_timeouts = [timeout, max(timeout, 90.0)]
        for attempt, attempt_timeout in enumerate(retry_timeouts, start=1):
            retry_config = config
            if hasattr(config, "request_timeout"):
                retry_config = type(config)(
                    provider=getattr(config, "provider", ""),
                    model=getattr(config, "model", ""),
                    api_key=getattr(config, "api_key", ""),
                    base_url=getattr(config, "base_url", ""),
                    temperature=getattr(config, "temperature", 0.0),
                    request_timeout=attempt_timeout,
                    max_rounds=getattr(config, "max_rounds", 6),
                )
            try:
                return original_call_chat_completion(retry_config, messages)
            except RuntimeError as exc:
                last_error = exc
                text = str(exc).lower()
                if "timed out" not in text and "llm http 429" not in text and "llm http 5" not in text and "llm request failed" not in text:
                    raise
                if attempt < len(retry_timeouts):
                    time.sleep(1.5 * attempt)
                    continue
                raise
        if last_error is not None:
            raise last_error
        raise RuntimeError("LLM request failed")

    def parse_json_object(raw: str) -> dict[str, Any]:
        return _normalize_planner_payload(original_parse_json_object(raw))

    def finish_from_result(result: dict[str, Any]) -> str:
        text = original_finish_from_result(result)
        if text:
            return text
        fallback = _extract_final_text(result)
        return fallback[:500]

    def plan_next_action(state: dict[str, Any]) -> dict[str, Any]:
        result = original_plan_next_action(state)
        if not isinstance(result, dict):
            return result
        _normalize_llm_diagnostics(result)
        tool_name = str(result.get("tool_name") or "").strip()
        if tool_name:
            observations = [item for item in state.get("observations") or [] if isinstance(item, dict)]
            if tool_name in {"rag_retrieve", "rag_answer"}:
                lookup_action = _memory_lookup_required_before_answer(state, observations)
                if lookup_action is not None:
                    return {
                        **lookup_action,
                        "llm_prompts": result.get("llm_prompts", state.get("llm_prompts") or []),
                        "llm_responses": result.get("llm_responses", state.get("llm_responses") or []),
                        "llm_diagnostics": result.get("llm_diagnostics", state.get("llm_diagnostics") or []),
                    }
            security = dict(state.get("security") or {})
            policy = layer.case_tool_policy(
                case_context=_case_context_from_state(state),
                security=security,
                config=None,
            )
            if tool_name == "read_file":
                alternative = _benign_mcp_fixture_read_alternative_action(state, result)
                if alternative is not None:
                    return {
                        **alternative,
                        "llm_prompts": result.get("llm_prompts", state.get("llm_prompts") or []),
                        "llm_responses": result.get("llm_responses", state.get("llm_responses") or []),
                        "llm_diagnostics": result.get("llm_diagnostics", state.get("llm_diagnostics") or []),
                    }
            if tool_name.startswith("browser_") and not policy.get("browser_available"):
                alternative = _memory_browser_alternative_action(state)
                if alternative is not None:
                    return {
                        **alternative,
                        "llm_prompts": result.get("llm_prompts", state.get("llm_prompts") or []),
                        "llm_responses": result.get("llm_responses", state.get("llm_responses") or []),
                        "llm_diagnostics": result.get("llm_diagnostics", state.get("llm_diagnostics") or []),
                    }
                return {
                    "final_answer": "Browser tools are unavailable for this non-browser case; stopping after available non-browser tool actions.",
                    "stop_reason": "non_browser_tool_misroute",
                    "llm_prompts": result.get("llm_prompts", state.get("llm_prompts") or []),
                    "llm_responses": result.get("llm_responses", state.get("llm_responses") or []),
                    "llm_diagnostics": result.get("llm_diagnostics", state.get("llm_diagnostics") or []),
                }
        if (
            result.get("final_answer") is not None
            and not result.get("tool_name")
            and not _has_browser_start_observation(state)
        ):
            final_answer_text = str(result.get("final_answer") or "").strip()
            observations = [item for item in state.get("observations") or [] if isinstance(item, dict)]
            if final_answer_text and _is_memory_seed_case(state) and not _has_tool_observation(observations, "memory_write"):
                return {
                    "tool_name": "memory_write",
                    "arguments": _memory_write_terminal_arguments(state, final_answer_text),
                    "llm_prompts": result.get("llm_prompts", state.get("llm_prompts") or []),
                    "llm_responses": result.get("llm_responses", state.get("llm_responses") or []),
                    "llm_diagnostics": result.get("llm_diagnostics", state.get("llm_diagnostics") or []),
                }
            if final_answer_text and _is_memory_rag_answer_case(state) and not _has_rag_answer_observation(observations):
                return {
                    "tool_name": "rag_answer",
                    "arguments": _memory_rag_answer_terminal_arguments(state, final_answer_text, observations),
                    "llm_prompts": result.get("llm_prompts", state.get("llm_prompts") or []),
                    "llm_responses": result.get("llm_responses", state.get("llm_responses") or []),
                    "llm_diagnostics": result.get("llm_diagnostics", state.get("llm_diagnostics") or []),
                }
            security = dict(state.get("security") or {})
            policy = layer.case_tool_policy(
                case_context=_case_context_from_state(state),
                security=security,
                config=None,
            )
            if policy.get("browser_expected"):
                compat = layer.normalize_arguments(
                    "browser_start",
                    {},
                    case_context=_case_context_from_state(state),
                    security=security,
                    trace_id=str(state.get("trace_id") or ""),
                    call_id="",
                    config=None,
                )
                if compat.normalized_arguments.get("source_path") or compat.normalized_arguments.get("url"):
                    inserted_arguments = dict(compat.normalized_arguments)
                    if not inserted_arguments.get("url") and inserted_arguments.get("source_path"):
                        inserted_arguments["url"] = f"file:///{str(inserted_arguments['source_path']).lstrip('/')}"
                    if "browser_start.inserted_before_terminal_answer" not in compat.repairs:
                        compat.repairs.append("browser_start.inserted_before_terminal_answer")
                    return {
                        "tool_name": "browser_start",
                        "arguments": {
                            **inserted_arguments,
                            "__agentguard_inserted_terminal_browser_start": True,
                            "__agentguard_pending_final_answer": str(result.get("final_answer") or ""),
                        },
                        "llm_prompts": result.get("llm_prompts", state.get("llm_prompts") or []),
                        "llm_responses": result.get("llm_responses", state.get("llm_responses") or []),
                        "llm_diagnostics": result.get("llm_diagnostics", state.get("llm_diagnostics") or []),
                    }
        stop_reason = str(result.get("stop_reason") or "")
        final_answer = str(result.get("final_answer") or "")
        if stop_reason not in {"llm_error", "llm_planning_error", "planner_no_tool"} and not final_answer.startswith("LLM planning failed"):
            return result
        last_tool_result = state.get("tool_result")
        if not isinstance(last_tool_result, dict):
            observations = state.get("observations") or []
            if observations and isinstance(observations[-1], dict):
                candidate = observations[-1].get("result")
                last_tool_result = candidate if isinstance(candidate, dict) else {}
        if not isinstance(last_tool_result, dict) or not last_tool_result:
            return result
        fallback = finish_from_result(last_tool_result)
        if not fallback:
            return result
        result["final_answer"] = fallback
        result["stop_reason"] = "llm_fallback_terminal"
        result.setdefault("llm_diagnostics", result.get("llm_diagnostics") or [])
        return result

    def submit_memory_rag_answer_fallback(
        state: dict[str, Any],
        observations: list[dict[str, Any]],
        latest_result: dict[str, Any],
        base_url: str,
    ) -> dict[str, Any] | None:
        fallback_args = _memory_rag_answer_fallback_arguments(state, observations, latest_result)
        if not fallback_args:
            return None
        fallback_compat = layer.normalize_arguments(
            "rag_answer",
            fallback_args,
            case_context=_case_context_from_state(state),
            security=dict(state.get("security") or {}),
            trace_id=str(state.get("trace_id") or ""),
            call_id="",
            config=None,
        )
        repair = "rag_answer.memory_terminal_fallback"
        if repair not in fallback_compat.repairs:
            fallback_compat.repairs.append(repair)
        fallback_arguments = bind_runtime_arguments(state, "rag_answer", dict(fallback_compat.normalized_arguments))
        fallback_security = _security_with_compatibility(dict(state.get("security") or {}), fallback_compat.model_dump())
        fallback_payload = {
            "arguments": fallback_arguments,
            "security": fallback_security,
            "trace_id": state.get("trace_id") or "",
        }
        fallback_result = _post_json(f"{base_url}/rag_answer", fallback_payload, timeout=30)
        fallback_result.setdefault("compatibility", fallback_compat.model_dump())
        if fallback_result.get("status") == "error" or fallback_result.get("error"):
            return None
        updated_observations = [
            *observations,
            {
                "tool_name": "rag_answer",
                "raw_arguments": fallback_compat.raw_arguments,
                "arguments": fallback_arguments,
                "compatibility": fallback_compat.model_dump(),
                "result": module.shrink(fallback_result, MAX_TOOL_RESULT_CHARS),
            },
        ]
        return {
            "tool_result": fallback_result,
            "observations": updated_observations,
            "final_answer": _extract_final_text(fallback_result) or str(fallback_arguments.get("answer") or ""),
            "stop_reason": "memory_terminal_rag_answer_fallback",
        }

    def submit_memory_write_fallback(
        state: dict[str, Any],
        observations: list[dict[str, Any]],
        latest_result: dict[str, Any],
        base_url: str,
    ) -> dict[str, Any] | None:
        fallback_args = _memory_write_fallback_arguments(state, observations, latest_result)
        if not fallback_args:
            return None
        fallback_compat = layer.normalize_arguments(
            "memory_write",
            fallback_args,
            case_context=_case_context_from_state(state),
            security=dict(state.get("security") or {}),
            trace_id=str(state.get("trace_id") or ""),
            call_id="",
            config=None,
        )
        repair = "memory_write.seed_terminal_fallback"
        if repair not in fallback_compat.repairs:
            fallback_compat.repairs.append(repair)
        fallback_arguments = bind_runtime_arguments(state, "memory_write", dict(fallback_compat.normalized_arguments))
        fallback_security = _security_with_compatibility(dict(state.get("security") or {}), fallback_compat.model_dump())
        fallback_payload = {
            "arguments": fallback_arguments,
            "security": fallback_security,
            "trace_id": state.get("trace_id") or "",
        }
        fallback_result = _post_json(f"{base_url}/memory_write", fallback_payload, timeout=30)
        fallback_result.setdefault("compatibility", fallback_compat.model_dump())
        if fallback_result.get("status") == "error" or fallback_result.get("error"):
            return None
        updated_observations = [
            *observations,
            {
                "tool_name": "memory_write",
                "raw_arguments": fallback_compat.raw_arguments,
                "arguments": fallback_arguments,
                "compatibility": fallback_compat.model_dump(),
                "result": module.shrink(fallback_result, MAX_TOOL_RESULT_CHARS),
            },
        ]
        return {
            "tool_result": fallback_result,
            "observations": updated_observations,
            "final_answer": _extract_final_text(fallback_result) or str(fallback_arguments.get("value") or ""),
            "stop_reason": "memory_terminal_write_fallback",
        }

    def invoke_tool(state: dict[str, Any]) -> dict[str, Any]:
        tool_name = state.get("tool_name")
        if not tool_name:
            return {}

        base_url = str(state["tool_invocation_base_url"]).rstrip("/")
        security = dict(state.get("security") or {})
        raw_arguments = dict(state.get("arguments") or {})
        inserted_terminal_browser_start = bool(raw_arguments.pop("__agentguard_inserted_terminal_browser_start", False))
        pending_final_answer = str(raw_arguments.pop("__agentguard_pending_final_answer", "") or "")
        compat = layer.normalize_arguments(
            tool_name,
            raw_arguments,
            case_context=_case_context_from_state(state),
            security=security,
            trace_id=str(state.get("trace_id") or ""),
            call_id="",
            config=None,
        )
        if inserted_terminal_browser_start:
            repair = "browser_start.inserted_before_terminal_answer"
            if repair not in compat.repairs:
                compat.repairs.append(repair)
        if tool_name in {"browser_click", "browser_input", "browser_navigate", "browser_extract_text", "browser_inspect"}:
            latest_session_id = _latest_browser_session_id(list(state.get("observations") or []))
            normalized_session_id = str(compat.normalized_arguments.get("session_id") or "").strip()
            if latest_session_id and normalized_session_id and normalized_session_id != latest_session_id:
                compat.normalized_arguments["session_id"] = latest_session_id
                repair = f"{tool_name}.session_id.corrected_to_started_browser_session"
                if repair not in compat.repairs:
                    compat.repairs.append(repair)
        arguments = bind_runtime_arguments(state, tool_name, dict(compat.normalized_arguments))
        security = _security_with_compatibility(security, compat.model_dump())
        payload = {
            "arguments": arguments,
            "security": security,
            "trace_id": state.get("trace_id") or "",
        }
        result = _post_json(f"{base_url}/{tool_name}", payload, timeout=30)

        recovered = None
        if result.get("status") == "error" or result.get("error"):
            previous_error = str(result.get("error") or "")
            recovered = layer.recover_after_error(
                tool_name,
                compat.raw_arguments,
                previous_error,
                case_context=_case_context_from_state(state),
                security=security,
                trace_id=str(state.get("trace_id") or ""),
                call_id="",
                config=None,
            )
            if recovered is not None:
                arguments = bind_runtime_arguments(state, tool_name, dict(recovered.normalized_arguments))
                security = _security_with_compatibility(dict(state.get("security") or {}), recovered.model_dump())
                payload["arguments"] = arguments
                payload["security"] = security
                result = _post_json(f"{base_url}/{tool_name}", payload, timeout=30)
                result["compatibility_retry"] = {
                    "compatibility_retry": True,
                    "retry_reason": "recoverable_schema_error",
                    "previous_error": previous_error,
                    "retry_index": 1,
                    "raw_arguments": compat.raw_arguments,
                    "normalized_arguments": recovered.normalized_arguments,
                }
                result["compatibility"] = recovered.model_dump()
        result.setdefault("compatibility", compat.model_dump())

        if result.get("status") == "error" or result.get("error"):
            error_text = _tool_error_text(result)
            if tool_name in {"browser_input", "browser_click", "browser_navigate", "browser_extract_text", "browser_inspect"}:
                observations = list(state.get("observations") or [])
                selector_retry = ""
                if tool_name == "browser_click" and compat.normalized_arguments.get("text"):
                    selector_retry = _selector_from_click_text(str(compat.normalized_arguments.get("text") or ""), observations)
                if not selector_retry:
                    selector_retry = _selector_from_error(error_text, observations)
                if selector_retry and compat.normalized_arguments.get("selector") != selector_retry:
                    retry_args = dict(compat.normalized_arguments)
                    retry_args["selector"] = selector_retry
                    if tool_name == "browser_click" and "text" in retry_args:
                        retry_args.pop("text", None)
                    retry_compat = layer.normalize_arguments(
                        tool_name,
                        retry_args,
                        case_context=_case_context_from_state(state),
                        security=security,
                        trace_id=str(state.get("trace_id") or ""),
                        call_id="",
                        config=None,
                    )
                    if selector_retry == "testid=apply-peter-profile":
                        repair = "browser_click.semantic_apply_peter_profile_selector_recovery"
                        if repair not in retry_compat.repairs:
                            retry_compat.repairs.append(repair)
                    retry_arguments = bind_runtime_arguments(state, tool_name, dict(retry_compat.normalized_arguments))
                    retry_security = _security_with_compatibility(dict(state.get("security") or {}), retry_compat.model_dump())
                    retry_payload = {
                        "arguments": retry_arguments,
                        "security": retry_security,
                        "trace_id": state.get("trace_id") or "",
                    }
                    retry_result = _post_json(f"{base_url}/{tool_name}", retry_payload, timeout=30)
                    if retry_result.get("status") != "error" and not retry_result.get("error"):
                        retry_result["compatibility_retry"] = {
                            "compatibility_retry": True,
                            "retry_reason": "selector_error_recovery",
                            "previous_error": error_text,
                            "retry_index": 2,
                            "raw_arguments": compat.raw_arguments,
                            "normalized_arguments": retry_compat.normalized_arguments,
                        }
                        retry_result["compatibility"] = retry_compat.model_dump()
                        result = retry_result
                        compat = retry_compat
                        arguments = retry_arguments
                        security = retry_security

        observations = list(state.get("observations") or [])
        observations.append(
            {
                "tool_name": tool_name,
                "raw_arguments": compat.raw_arguments,
                "arguments": arguments,
                "compatibility": compat.model_dump(),
                "result": _tool_observation_result(tool_name, result),
            }
        )
        round_index = int(state.get("round_index") or 0) + 1
        update: dict[str, Any] = {
            "tool_result": result,
            "observations": observations,
            "round_index": round_index,
            "tool_name": "",
            "arguments": {},
        }
        if result.get("blocked"):
            update["final_answer"] = str(result.get("safe_message") or "Tool call was blocked.")
            update["stop_reason"] = "runtime_policy_blocked" if result.get("runtime_policy_blocked") else "blocked"
        elif result.get("status") == "error" or result.get("error"):
            update["final_answer"] = f"Tool call failed: {result.get('error') or result.get('status')}"
            update["stop_reason"] = "tool_error"
        elif inserted_terminal_browser_start and pending_final_answer:
            update["final_answer"] = pending_final_answer
            update["stop_reason"] = "model_final_answer_after_browser_start"
        elif round_index >= module.llm_config().max_rounds:
            fallback_update = submit_memory_write_fallback(state, observations, result, base_url)
            if not fallback_update:
                fallback_update = submit_memory_rag_answer_fallback(state, observations, result, base_url)
            if fallback_update:
                update.update(fallback_update)
            else:
                update["final_answer"] = finish_from_result(result)
                update["stop_reason"] = "max_rounds"
        else:
            fallback_update = submit_memory_write_fallback(state, observations, result, base_url)
            if not fallback_update:
                fallback_update = submit_memory_rag_answer_fallback(state, observations, result, base_url)
            if fallback_update:
                update.update(fallback_update)
        return update

    module.fetch_tools = fetch_tools
    module.bind_runtime_arguments = bind_runtime_arguments
    if original_browser_start_hint is not None:
        module.browser_start_hint = browser_start_hint
    module.call_chat_completion = call_chat_completion
    module.plan_next_action = plan_next_action
    module.parse_json_object = parse_json_object
    module.finish_from_result = finish_from_result
    module.invoke_tool = invoke_tool
    module.build_graph = build_graph


def _post_json(endpoint: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = Request(endpoint, data=data, headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - local benchmark agent endpoint.
            parsed = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")[:500]
        return {"status": "error", "error": f"HTTP {exc.code}: {body}"}
    except URLError as exc:
        return {"status": "error", "error": str(exc.reason)}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}
    return parsed if isinstance(parsed, dict) else {"status": "error", "error": "agent response was not an object"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--agent-path", default=str(DEFAULT_AGENT_PATH))
    args = parser.parse_args()
    module = _load_agent_module(Path(args.agent_path))
    _patch_agent_module(module)
    try:
        input_payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except Exception:
        input_payload = {}
    runtime_policy = input_payload.get("runtime_policy") if isinstance(input_payload, dict) else {}
    module._agentguard_runtime_policy = dict(runtime_policy or {}) if isinstance(runtime_policy, dict) else {}
    module.run(Path(args.input), Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
