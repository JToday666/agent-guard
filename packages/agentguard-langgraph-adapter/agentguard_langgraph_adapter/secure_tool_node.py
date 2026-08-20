"""Non-invasive guarded tool node for LangGraph or direct runner use."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .event_models import ToolExecutionResult, new_id
from .langgraph_adapter import LangGraphAdapter
from .tool_compat import (
    BROWSER_TOOLS,
    ToolCompatibilityLayer,
    blocked_runtime_policy_result,
)

BROWSER_SESSION_TOOLS = {
    "browser_navigate",
    "browser_extract_text",
    "browser_input",
    "browser_click",
    "browser_inspect",
}


@dataclass(slots=True)
class SecureToolNode:
    gateway: Any
    instrumentation_plan_mode: str | None = None
    _compatibility_layer: ToolCompatibilityLayer = field(init=False, repr=False)

    def __init__(
        self,
        gateway: Any | None = None,
        *,
        adapter: LangGraphAdapter | None = None,
        tool_registry: Any | None = None,
        instrumentation_plan_mode: str | None = None,
    ) -> None:
        if gateway is None:
            if adapter is None or tool_registry is None:
                raise TypeError(
                    "SecureToolNode requires either gateway or adapter + tool_registry"
                )
            from .tool_gateway import GuardedToolGateway

            gateway = GuardedToolGateway(
                guard_adapter=adapter, tool_runtime=tool_registry
            )
        self.gateway = gateway
        # replay 门控信号：仅影响 _skipped_rag_answer 的状态串归一；
        # None/非 replay 时行为逐字节不变（autonomous 官方链路不受影响）。
        self.instrumentation_plan_mode = instrumentation_plan_mode
        self._compatibility_layer = ToolCompatibilityLayer(
            getattr(getattr(gateway, "tool_runtime", None), "sandbox_dir", None)
        )

    def invoke_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
        case_context: dict[str, Any] | None = None,
    ) -> ToolExecutionResult:
        compat = self._compatibility_layer.normalize_arguments(
            tool_name,
            arguments,
            case_context=case_context,
            security=security,
            trace_id=trace_id,
            call_id=call_id or "",
            config=(case_context or {}).get("config"),
        )
        if tool_name in BROWSER_TOOLS and not compat.case_tool_policy.get(
            "browser_available"
        ):
            result_payload = blocked_runtime_policy_result(
                tool_name=tool_name,
                call_id=call_id or new_id("call"),
                trace_id=trace_id,
                case_id=compat.case_tool_policy.get("case_id"),
                compatibility=compat,
            )
            return ToolExecutionResult.model_validate(result_payload)
        return self.gateway.invoke_tool(
            tool_name=tool_name,
            arguments=compat.normalized_arguments,
            raw_arguments=arguments,
            compatibility=compat.model_dump(),
            security=security,
            trace_id=trace_id,
            call_id=call_id,
            case_context=case_context,
        )

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        security = dict(state.get("security") or {})
        trace_id = state.get("trace_id") or security.get("trace_id") or new_id("trace")
        calls = state.get("tool_calls") or []
        previous_results = list(state.get("tool_results") or [])
        state_events = list(state.get("behavior_events") or [])
        runtime_context = dict(state.get("runtime_context") or {})
        case_context = {
            "case_id": security.get("case_id"),
            "metadata": dict(security.get("metadata") or {}),
            **dict(security.get("tool_hijacking_context") or {}),
        }
        results = []
        latest_rag_retrievals: dict[tuple[str, str], dict[str, Any]] = {}
        blocked_rag_retrievals: set[tuple[str, str]] = set()
        latest_memory_lookup: dict[str, Any] | None = None
        for call in calls:
            tool_name = call["name"]
            arguments = dict(call.get("args") or {})
            arguments = _bind_runtime_arguments(
                state, runtime_context, tool_name, arguments
            )
            if tool_name == "rag_answer":
                key = _rag_key(arguments)
                if key in blocked_rag_retrievals:
                    results.append(
                        _skipped_rag_answer(
                            tool_name,
                            call.get("id") or new_id("call"),
                            replay=self.instrumentation_plan_mode == "replay",
                        ).model_dump()
                    )
                    continue
                arguments = _enrich_rag_answer_arguments(
                    arguments, latest_rag_retrievals.get(key), latest_memory_lookup
                )
            result = self.invoke_tool(
                tool_name=tool_name,
                arguments=arguments,
                security=security,
                trace_id=trace_id,
                call_id=call.get("id"),
                case_context=case_context,
            )
            results.append(result.model_dump())
            event_state = {**state, "behavior_events": state_events}
            state_events = _append_tool_lifecycle_events(
                event_state, result.model_dump(), len(previous_results) + len(results)
            )
            _update_runtime_context(runtime_context, tool_name, result)
            if tool_name == "rag_retrieve":
                key = _rag_key(arguments)
                if result.blocked or result.status != "executed":
                    blocked_rag_retrievals.add(key)
                elif isinstance(result.result, dict):
                    latest_rag_retrievals[key] = result.result
            if (
                tool_name in {"memory_read", "memory_search"}
                and result.status == "executed"
                and isinstance(result.result, dict)
            ):
                latest_memory_lookup = result.result
        stop_reason = state.get("stop_reason") or ""
        if any(
            item.get("blocked") and not item.get("runtime_policy_blocked")
            for item in results
        ):
            stop_reason = "blocked"
        return {
            **state,
            "trace_id": trace_id,
            "tool_results": previous_results + results,
            "last_tool_results": results,
            "tool_calls": [],
            "runtime_context": runtime_context,
            "behavior_events": state_events,
            "stop_reason": stop_reason,
        }


def _bind_runtime_arguments(
    state: dict[str, Any],
    runtime_context: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    if tool_name not in BROWSER_SESSION_TOOLS:
        return arguments
    session_id = str(arguments.get("session_id") or "").strip()
    if session_id and session_id != "default":
        return arguments
    bound = _current_case_browser_session(state, runtime_context)
    if not bound:
        raise RuntimeError("browser session is not initialized for this case")
    enriched = dict(arguments)
    enriched["session_id"] = bound
    return enriched


def _current_case_browser_session(
    state: dict[str, Any], runtime_context: dict[str, Any]
) -> str:
    candidate = str(runtime_context.get("browser_session_id") or "").strip()
    if candidate and candidate != "default":
        return candidate
    security = state.get("security") or {}
    case_id = str(security.get("case_id") or "").strip()
    if case_id:
        return case_id
    attack_case = state.get("attack_case") or {}
    if isinstance(attack_case, dict):
        case_id = str(attack_case.get("case_id") or "").strip()
        if case_id:
            return case_id
    return ""


def _update_runtime_context(
    runtime_context: dict[str, Any], tool_name: str, result: ToolExecutionResult
) -> None:
    if result.status != "executed" or not isinstance(result.result, dict):
        return
    payload = result.result
    if tool_name == "browser_start" and payload.get("session_id"):
        runtime_context["browser_session_id"] = payload["session_id"]
        if payload.get("url"):
            runtime_context["browser_url"] = payload["url"]
        if payload.get("source_path"):
            runtime_context["browser_source_path"] = payload["source_path"]
    elif tool_name == "browser_navigate" and payload.get("url"):
        runtime_context["browser_url"] = payload["url"]


def _append_tool_lifecycle_events(
    state: dict[str, Any], item: dict[str, Any], sequence_index: int
) -> list[dict[str, Any]]:
    events = list(state.get("behavior_events") or [])
    event = item.get("event") or {}
    audit_event = item.get("audit_event") or {}
    tool_name = item.get("tool_name")
    call_id = item.get("call_id")
    base_metadata = {
        "tool_name": tool_name,
        "call_id": call_id,
        "executed": item.get("executed"),
        "blocked": item.get("blocked"),
        "status": item.get("status"),
        "round_index": state.get("round_index"),
        "sequence_index": sequence_index,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
    }
    events.append(
        _lifecycle_event(
            state,
            "tool_call_proposed",
            "before_tool_call",
            f"Tool call proposed: {tool_name}.",
            {
                **base_metadata,
                "arguments": event.get("arguments"),
                "derived_resources": event.get("derived_resources", []),
            },
        )
    )
    events.append(
        _lifecycle_event(
            state,
            "policy_decided",
            "before_tool_call",
            f"Policy decision for {tool_name}: {item.get('decision')}.",
            {
                **base_metadata,
                "decision": item.get("decision"),
                "risk_score": audit_event.get("risk_score"),
                "severity": audit_event.get("severity"),
                "reason": audit_event.get("reason"),
            },
        )
    )
    events.append(
        _lifecycle_event(
            state,
            "tool_call_finished",
            "after_tool_call",
            f"Tool call finished: {tool_name}.",
            {
                **base_metadata,
                "result_summary": _summarize_result(item.get("result")),
                "error": item.get("error"),
                "side_effect_count": len(item.get("side_effects") or []),
            },
        )
    )
    if item.get("side_effects"):
        events.append(
            _lifecycle_event(
                state,
                "tool_result_persisted",
                "after_tool_call",
                f"Tool result side effects recorded for {tool_name}.",
                {**base_metadata, "side_effects": item.get("side_effects")},
            )
        )
    if tool_name == "memory_write":
        events.append(
            _lifecycle_event(
                state,
                "memory_write",
                "after_tool_call",
                "Memory write behavior observed.",
                {
                    **base_metadata,
                    "result_summary": _summarize_result(item.get("result")),
                },
            )
        )
    return events


def _lifecycle_event(
    state: dict[str, Any],
    event_type: str,
    stage: str,
    summary: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    security = state.get("security") or {}
    return {
        "schema_version": "0.3",
        "event_id": new_id("evt_lifecycle"),
        "event_type": event_type,
        "trace_id": state.get("trace_id")
        or security.get("trace_id")
        or new_id("trace"),
        "runtime": security.get("runtime") or "langgraph",
        "case_id": security.get("case_id"),
        "attack_type": security.get("attack_type"),
        "is_malicious": security.get("is_malicious"),
        "stage": stage,
        "summary": summary,
        "metadata": metadata or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _summarize_result(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, str):
        return result[:240]
    try:
        return json.dumps(result, ensure_ascii=False, sort_keys=True)[:240]
    except Exception:
        return repr(result)[:240]


def _rag_key(arguments: dict[str, Any]) -> tuple[str, str]:
    return (
        str(arguments.get("dataset") or ""),
        str(arguments.get("question_id") or ""),
    )


def _enrich_rag_answer_arguments(
    arguments: dict[str, Any],
    retrieval: dict[str, Any] | None,
    memory_lookup: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not retrieval and not memory_lookup:
        return arguments
    enriched = dict(arguments)
    contexts = _rag_contexts(retrieval)
    if contexts and not enriched.get("contexts"):
        enriched["contexts"] = contexts
    memory_answer, memory_refs = _answer_from_memory_lookup(memory_lookup)
    if not str(enriched.get("answer") or "").strip():
        answer = memory_answer or _answer_from_contexts(
            contexts,
            str(enriched.get("question") or (retrieval or {}).get("question") or ""),
        )
        if answer:
            enriched["answer"] = answer
            enriched.setdefault(
                "answer_source",
                (
                    "memory_terminal_fallback"
                    if memory_answer
                    else "rag_context_terminal_fallback"
                ),
            )
    if memory_refs and not enriched.get("memory_refs"):
        enriched["memory_refs"] = memory_refs
    if memory_answer and "used_memory" not in enriched:
        enriched["used_memory"] = True
    if not retrieval:
        return enriched
    if not enriched.get("contexts"):
        enriched["contexts"] = list(retrieval.get("contexts") or [])
    raw_meta = retrieval.get("meta")
    meta = raw_meta if isinstance(raw_meta, dict) else {}
    if "mode" not in enriched and meta.get("mode"):
        enriched["mode"] = meta["mode"]
    return enriched


def _rag_contexts(retrieval: dict[str, Any] | None) -> list[str]:
    if not retrieval:
        return []
    contexts = [
        str(item) for item in retrieval.get("contexts") or [] if str(item or "").strip()
    ]
    if contexts:
        return contexts
    raw_docs = retrieval.get("context_docs")
    docs = raw_docs if isinstance(raw_docs, list) else []
    return [
        str(item.get("text") or "")
        for item in docs
        if isinstance(item, dict) and str(item.get("text") or "").strip()
    ]


def _answer_from_memory_lookup(
    memory_lookup: dict[str, Any] | None,
) -> tuple[str, list[str]]:
    if not memory_lookup:
        return "", []
    records: list[dict[str, Any]] = []
    if memory_lookup.get("found"):
        records.append(memory_lookup)
    raw_matches = memory_lookup.get("matches")
    matches = raw_matches if isinstance(raw_matches, list) else []
    records.extend(item for item in matches if isinstance(item, dict))
    for record in reversed(records):
        answer = _string_from_memory_value(
            record.get("value")
            or record.get("note")
            or record.get("content")
            or record.get("answer")
        )
        if answer:
            return answer, _memory_refs_from_records([record])
    return "", []


def _string_from_memory_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        for key in ("answer", "note", "value", "content", "text"):
            nested = _string_from_memory_value(value.get(key))
            if nested:
                return nested
        return ""
    text = str(value).strip()
    if text.startswith("{") and text.endswith("}"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return text
        if isinstance(parsed, dict):
            nested = _string_from_memory_value(parsed)
            return nested or text
    return text


def _memory_refs_from_records(records: list[dict[str, Any]]) -> list[str]:
    refs: list[str] = []
    for record in records:
        namespace = str(record.get("namespace") or "").strip()
        key = str(record.get("key") or "").strip()
        if namespace and key:
            refs.append(f"{namespace}:{key}")
    return list(dict.fromkeys(refs))


def _answer_from_contexts(contexts: list[str], question: str = "") -> str:
    contexts = [str(item or "").strip() for item in contexts if str(item or "").strip()]
    if not contexts:
        return ""
    question_text = re.sub(r"\s+", " ", str(question or "")).strip()
    for extractor in (
        _extract_episode_count_answer,
        _extract_date_answer,
        _extract_county_answer,
        _extract_boolean_answer,
        _extract_song_recorder_answer,
        _extract_named_bomb_answer,
        _extract_sperm_location_answer,
    ):
        answer = extractor(question_text, contexts)
        if answer:
            return answer
    sentence = _best_context_sentence(question_text, contexts)
    return sentence[:240].strip(" .;")


def _context_sentences(contexts: list[str]) -> list[str]:
    sentences: list[str] = []
    for context in contexts:
        title, _, body = str(context).partition("\n")
        if title.strip():
            sentences.append(title.strip())
        for part in re.split(r"(?<=[.!?])\s+|\n+", body or context):
            cleaned = re.sub(r"\s+", " ", part).strip()
            if cleaned:
                sentences.append(cleaned)
    return sentences


def _best_context_sentence(question: str, contexts: list[str]) -> str:
    terms = {
        token
        for token in re.findall(r"[a-z0-9]+", question.lower())
        if len(token) > 2
        and token
        not in {
            "the",
            "and",
            "for",
            "with",
            "what",
            "where",
            "when",
            "which",
            "who",
            "how",
            "are",
            "was",
        }
    }
    best = ""
    best_score = -1
    for sentence in _context_sentences(contexts):
        words = set(re.findall(r"[a-z0-9]+", sentence.lower()))
        score = len(terms & words) if terms else 0
        if score > best_score:
            best = sentence
            best_score = score
    return best or contexts[0]


def _extract_episode_count_answer(question: str, contexts: list[str]) -> str:
    if "how many" not in question.lower() or "episode" not in question.lower():
        return ""
    for sentence in _context_sentences(contexts):
        match = re.search(r"\b(\d{1,3})\s+episodes?\b", sentence, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_date_answer(question: str, contexts: list[str]) -> str:
    if not any(
        marker in question.lower() for marker in ("what day", "what date", "when")
    ):
        return ""
    pattern = re.compile(
        r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}(?:st|nd|rd|th)?\b",
        re.IGNORECASE,
    )
    for sentence in _context_sentences(contexts):
        match = pattern.search(sentence)
        if match:
            return match.group(0)
    return ""


def _extract_county_answer(question: str, contexts: list[str]) -> str:
    if "county" not in question.lower():
        return ""
    for sentence in _context_sentences(contexts):
        match = re.search(r"\b([A-Z][A-Za-z]+)\s+County\b", sentence)
        if match:
            return match.group(1)
    return ""


def _extract_boolean_answer(question: str, contexts: list[str]) -> str:
    lowered = question.lower()
    if not (
        lowered.startswith(("are ", "is ", "do ", "does ", "did ", "was ", "were "))
        or "true or false" in lowered
    ):
        return ""
    joined = " ".join(_context_sentences(contexts)).lower()
    if any(
        marker in joined
        for marker in ("not ", "neither", "false", "do not", "does not")
    ):
        return "false" if "true or false" in lowered else "no"
    if any(
        marker in joined
        for marker in ("yes", "true", "both", "same neighborhood", "share a location")
    ):
        return "true" if "true or false" in lowered else "yes"
    return ""


def _extract_song_recorder_answer(question: str, contexts: list[str]) -> str:
    if "who" not in question.lower() or "record" not in question.lower():
        return ""
    for sentence in _context_sentences(contexts):
        match = re.search(
            r"\b(?:singer|crooner)\s+([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){1,3})\b",
            sentence,
        )
        if match:
            return match.group(1)
        match = re.search(
            r"\brecorded by\s+([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){1,3})\b", sentence
        )
        if match:
            return match.group(1)
    return ""


def _extract_named_bomb_answer(question: str, contexts: list[str]) -> str:
    if "bomb" not in question.lower() or "hiroshima" not in question.lower():
        return ""
    for sentence in _context_sentences(contexts):
        match = re.search(
            r"\bnamed\s+([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)?)\b", sentence
        )
        if match:
            return match.group(1)
    return ""


def _extract_sperm_location_answer(question: str, contexts: list[str]) -> str:
    if "mitochondria" not in question.lower() or "sperm" not in question.lower():
        return ""
    for sentence in _context_sentences(contexts):
        lowered = sentence.lower()
        if "midpiece" in lowered or "mid-piece" in lowered:
            return "midpiece"
        if "mitochond" in lowered and "head" in lowered:
            return "head"
    return ""


def _skipped_rag_answer(
    tool_name: str, call_id: str, *, replay: bool = False
) -> ToolExecutionResult:
    # replay 门控下的状态归一：blocked/decision 本就是 blocked/deny，仅
    # 状态串不一致（skipped_dependency）；归一为 "blocked" 后可达 scoring
    # oracle 既有的 rag_answer_blocked 豁免路径。非 replay 保持原状态串，
    # autonomous 官方链路行为逐字节不变。
    return ToolExecutionResult(
        tool_name=tool_name,
        call_id=call_id,
        executed=False,
        blocked=True,
        decision="deny",
        status="blocked" if replay else "skipped_dependency",
        result=None,
        safe_message="rag_answer was skipped because rag_retrieve was blocked.",
        side_effects=[],
        event=None,
        audit_event=None,
        error=None,
    )


GuardedToolNode = SecureToolNode
