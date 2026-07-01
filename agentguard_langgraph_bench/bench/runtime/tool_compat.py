"""Tool protocol compatibility for external autonomous benchmark agents."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from agentguard_langgraph_bench.bench.browser_runtime import local_url_for_source, resolve_local_source
from agentguard_langgraph_bench.bench.models import AttackCase
from agentguard_langgraph_bench.bench.scoring.tool_hijacking import case_extra_list


BROWSER_TOOLS = {
    "browser_start",
    "browser_navigate",
    "browser_input",
    "browser_click",
    "browser_extract_text",
    "browser_inspect",
}

MCP_CALL_ENVELOPE_KEYS = {
    "server",
    "tool",
    "arguments",
    "request_id",
    "hijacking",
    "descriptor",
    "catalog_view",
    "clean_descriptor",
    "poisoned_descriptor",
    "descriptor_diff",
}

RECOVERABLE_ERROR_MARKERS = (
    "unexpected keyword argument",
    "missing required positional argument",
    "missing_dataset_or_question_id",
    "browser session is not initialized",
    "real browser mode requires an instrumentation-local source_path",
)

UNSAFE_ERROR_MARKERS = (
    "permission denied",
    "blocked by core",
    "decision = deny",
    "unsafe path outside sandbox",
    "path escapes sandbox",
    "unsupported modality",
    "invalid local service port",
    "browser target not local instrumentation",
)


@dataclass(slots=True)
class ToolCompatibilityResult:
    tool_name: str
    raw_arguments: dict[str, Any]
    normalized_arguments: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    repairs: list[str] = field(default_factory=list)
    dropped_arguments: dict[str, Any] = field(default_factory=dict)
    added_arguments: dict[str, Any] = field(default_factory=dict)
    case_tool_policy: dict[str, Any] = field(default_factory=dict)

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


class ToolCompatibilityLayer:
    """Normalize common LLM tool-call dialects before guarded execution."""

    def __init__(self, sandbox_dir: Path | None = None) -> None:
        self.sandbox_dir = sandbox_dir
        self._last_browser_session_by_case: dict[str, str] = {}

    def set_sandbox_dir(self, sandbox_dir: Path | None) -> None:
        self.sandbox_dir = sandbox_dir

    def visible_tools(
        self,
        tools: list[dict[str, Any]],
        *,
        case: AttackCase | None = None,
        security: dict[str, Any] | None = None,
        config: Any | None = None,
    ) -> list[dict[str, Any]]:
        policy = self.case_tool_policy(case=case, security=security, config=config)
        visible: list[dict[str, Any]] = []
        for tool in tools:
            name = str(tool.get("name") or "")
            if name in BROWSER_TOOLS and not policy["browser_available"]:
                continue
            visible.append(self._manifest_overlay(dict(tool), policy=policy, case=case))
        return visible

    def case_tool_policy(
        self,
        *,
        case: AttackCase | None = None,
        security: dict[str, Any] | None = None,
        config: Any | None = None,
    ) -> dict[str, Any]:
        security = security or {}
        browser_expected = _is_browser_case(case, security)
        return {
            "browser_available": browser_expected,
            "browser_expected": browser_expected,
            "case_id": _case_id(case, security),
            "allowed_browser_tools": sorted(BROWSER_TOOLS) if browser_expected else [],
            "runtime": getattr(config, "runtime", None) if config is not None else security.get("runtime"),
        }

    def normalize_arguments(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        case: AttackCase | None = None,
        security: dict[str, Any] | None = None,
        trace_id: str = "",
        call_id: str = "",
        config: Any | None = None,
    ) -> ToolCompatibilityResult:
        raw = dict(arguments or {})
        policy = self.case_tool_policy(case=case, security=security, config=config)
        normalized = dict(raw)
        warnings: list[str] = []
        repairs: list[str] = []
        dropped: dict[str, Any] = {}
        added: dict[str, Any] = {}

        def alias(source: str, target: str, repair: str | None = None, *, drop: bool = True) -> None:
            if source not in normalized:
                return
            if target not in normalized or normalized.get(target) in (None, ""):
                normalized[target] = normalized[source]
                repairs.append(repair or f"{tool_name}.{source}_to_{target}")
            if drop:
                dropped[source] = normalized.pop(source)

        if tool_name == "browser_start":
            alias("session_id", "run_id", "browser_start.session_id_to_run_id")
            case_id = policy.get("case_id")
            if not normalized.get("run_id") and case_id:
                normalized["run_id"] = case_id
                added["run_id"] = case_id
                repairs.append("browser_start.run_id.defaulted_to_case_id")
            source_path = _browser_source_path(case, security)
            if not normalized.get("source_path") and source_path:
                normalized["source_path"] = source_path
                added["source_path"] = source_path
                repairs.append("browser_start.source_path.inferred_from_case")
            if normalized.get("source_path"):
                canonical_source_path = _canonical_source_path(str(normalized["source_path"]))
                if canonical_source_path and canonical_source_path != str(normalized["source_path"]):
                    normalized["source_path"] = canonical_source_path
                    repairs.append("browser_start.source_path.canonicalized_to_local_copy")
            if not normalized.get("url"):
                url = _browser_entry_url(case, security, str(normalized.get("source_path") or source_path))
                if url:
                    normalized["url"] = url
                    added["url"] = url
                    repairs.append("browser_start.url.inferred_from_case")
            if normalized.get("run_id") and policy.get("case_id"):
                self._last_browser_session_by_case[str(policy["case_id"])] = str(normalized["run_id"])

        elif tool_name in BROWSER_TOOLS:
            alias("run_id", "session_id", f"{tool_name}.run_id_to_session_id")
            if not normalized.get("session_id"):
                case_id = str(policy.get("case_id") or "")
                session_id = self._last_browser_session_by_case.get(case_id) or case_id
                if session_id:
                    normalized["session_id"] = session_id
                    added["session_id"] = session_id
                    repairs.append(f"{tool_name}.session_id.defaulted_to_case_context")
            if tool_name == "browser_navigate":
                alias("href", "url", "browser_navigate.href_to_url")
                alias("target", "url", "browser_navigate.target_to_url")
                alias("path", "url", "browser_navigate.path_to_url")
            elif tool_name == "browser_input":
                alias("target", "selector", "browser_input.target_to_selector")
                alias("text", "value", "browser_input.text_to_value")
                alias("content", "value", "browser_input.content_to_value")
                alias("body", "value", "browser_input.body_to_value")
            elif tool_name == "browser_click":
                if "target" in normalized and "selector" not in normalized and "text" not in normalized:
                    target = str(normalized.pop("target") or "")
                    if _looks_like_selector(target):
                        normalized["selector"] = target
                        added["selector"] = target
                        repairs.append("browser_click.target_to_selector")
                    elif target:
                        normalized["text"] = target
                        added["text"] = target
                        repairs.append("browser_click.target_to_text")
                alias("href", "selector", "browser_click.href_to_selector")
            elif tool_name in {"browser_extract_text", "browser_inspect"}:
                alias("target", "selector", f"{tool_name}.target_to_selector")

        elif tool_name in {"read_file", "write_file"}:
            for source in ("file_path", "filepath", "filename", "file", "relative_path", "pathname"):
                alias(source, "path", f"{tool_name}.{source}_to_path")
            if tool_name == "read_file" and not normalized.get("path"):
                default_path = _read_file_default(case, security)
                if default_path:
                    normalized["path"] = default_path
                    added["path"] = default_path
                    repairs.append("read_file.path.inferred_from_case_reference")
            if "path" in normalized:
                cleaned_path, warning = _normalize_sandbox_file_path(normalized["path"], self.sandbox_dir)
                if warning:
                    warnings.append(warning)
                if cleaned_path != normalized["path"]:
                    normalized["path"] = cleaned_path
                    repairs.append(f"{tool_name}.path.normalized")
            if tool_name == "write_file":
                for source in ("text", "body"):
                    alias(source, "content", f"write_file.{source}_to_content")

        elif tool_name == "mcp_call":
            for source in ("name", "tool_name", "method"):
                alias(source, "tool", f"mcp_call.{source}_to_tool")
            for source in ("params", "parameters", "args"):
                alias(source, "arguments", f"mcp_call.{source}_to_arguments")
            alias("server_name", "server", "mcp_call.server_name_to_server")
            alias("id", "request_id", "mcp_call.id_to_request_id")
            inferred = _infer_mcp_target(case, security, normalized)
            for key in ("server", "tool"):
                if not normalized.get(key) and inferred.get(key):
                    normalized[key] = inferred[key]
                    added[key] = inferred[key]
                    repairs.append(f"mcp_call.{key}.inferred_from_case")
            if "arguments" not in normalized:
                normalized["arguments"] = {}
                added["arguments"] = {}
                warnings.append("mcp_call.arguments.defaulted_to_empty")
            if not isinstance(normalized.get("arguments"), dict):
                normalized["arguments"] = {"value": normalized["arguments"]}
                repairs.append("mcp_call.arguments.wrapped_scalar")
            extra_arguments = {
                key: normalized.pop(key)
                for key in list(normalized)
                if key not in MCP_CALL_ENVELOPE_KEYS and not key.startswith("_")
            }
            if extra_arguments:
                normalized["arguments"] = {**normalized.get("arguments", {}), **extra_arguments}
                dropped.update(extra_arguments)
                repairs.append("mcp_call.top_level_fields_to_arguments")

        elif tool_name == "rag_retrieve":
            for source in ("question", "prompt", "q"):
                alias(source, "query", f"rag_retrieve.{source}_to_query", drop=False)
            alias("dataset_name", "dataset", "rag_retrieve.dataset_name_to_dataset")
            for source in ("qid", "id"):
                alias(source, "question_id", f"rag_retrieve.{source}_to_question_id")
            for key, value in _poisonedrag_defaults(case, security).items():
                if key not in normalized or normalized.get(key) in (None, ""):
                    normalized[key] = value
                    added[key] = value
                    repairs.append(f"rag_retrieve.{key}.inferred_from_case")

        elif tool_name == "rag_answer":
            for source in ("response", "final", "submitted_answer", "result"):
                alias(source, "answer", f"rag_answer.{source}_to_answer")
            for source in ("qid", "id"):
                alias(source, "question_id", f"rag_answer.{source}_to_question_id")
            for key, value in _poisonedrag_defaults(case, security).items():
                if key in {"dataset", "question_id", "mode"} and (key not in normalized or normalized.get(key) in (None, "")):
                    normalized[key] = value
                    added[key] = value
                    repairs.append(f"rag_answer.{key}.inferred_from_case")

        elif tool_name == "memory_write":
            for source in ("memory", "content", "text", "note"):
                alias(source, "value", f"memory_write.{source}_to_value")
            alias("id", "key", "memory_write.id_to_key")

        elif tool_name == "memory_search":
            for source in ("question", "q", "text"):
                alias(source, "query", f"memory_search.{source}_to_query")
            alias("limit", "top_k", "memory_search.limit_to_top_k")
            if not normalized.get("query"):
                query = _case_question(case, security) or _memory_key_default(case, security)
                if query:
                    normalized["query"] = query
                    added["query"] = query
                    repairs.append("memory_search.query.inferred_from_case")

        elif tool_name == "memory_read":
            alias("id", "key", "memory_read.id_to_key")
            memory_key = _memory_key_default(case, security)
            if memory_key and (not normalized.get("key")):
                normalized["key"] = memory_key
                added["key"] = memory_key
                repairs.append("memory_read.key.inferred_from_case")

        elif tool_name == "call_api":
            alias("endpoint", "url", "call_api.endpoint_to_url")
            for source in ("body", "data"):
                alias(source, "payload", f"call_api.{source}_to_payload")
            if normalized.get("method"):
                normalized["method"] = str(normalized["method"]).upper()

        elif tool_name == "send_email":
            for source in ("recipient", "email", "address"):
                alias(source, "to", f"send_email.{source}_to_to")
            alias("title", "subject", "send_email.title_to_subject")
            for source in ("message", "text", "content"):
                alias(source, "body", f"send_email.{source}_to_body")
            attachment_values = _extract_attachment_values(normalized)
            if attachment_values:
                body = str(normalized.get("body") or "")
                attachment_note = "Attachments referenced: " + ", ".join(attachment_values)
                normalized["body"] = f"{body}\n\n{attachment_note}".strip()
                added["body_attachment_note"] = attachment_note
                repairs.append("send_email.attachments_converted_to_body_note")
                for key in ("attachment_path", "attachment", "attachments", "files", "file_path", "filepath"):
                    if key in normalized:
                        dropped[key] = normalized.pop(key)

        elif tool_name == "code_exec":
            alias("cmd", "command", "code_exec.cmd_to_command")
            alias("code", "command", "code_exec.code_to_command")
            alias("script", "command", "code_exec.script_to_command")

        return ToolCompatibilityResult(
            tool_name=tool_name,
            raw_arguments=raw,
            normalized_arguments=normalized,
            warnings=warnings,
            repairs=repairs,
            dropped_arguments=dropped,
            added_arguments=added,
            case_tool_policy=policy,
        )

    def recover_after_error(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        error: str,
        *,
        case: AttackCase | None = None,
        security: dict[str, Any] | None = None,
        trace_id: str = "",
        call_id: str = "",
        config: Any | None = None,
    ) -> ToolCompatibilityResult | None:
        lowered = str(error or "").lower()
        if not any(marker in lowered for marker in RECOVERABLE_ERROR_MARKERS):
            return None
        if any(marker in lowered for marker in UNSAFE_ERROR_MARKERS):
            return None
        compat = self.normalize_arguments(
            tool_name,
            arguments,
            case=case,
            security=security,
            trace_id=trace_id,
            call_id=call_id,
            config=config,
        )
        if compat.normalized_arguments == dict(arguments or {}) and not compat.repairs:
            return None
        compat.repairs.append("recover_after_error.retry_with_normalized_arguments")
        return compat

    def _manifest_overlay(
        self,
        tool: dict[str, Any],
        *,
        policy: dict[str, Any],
        case: AttackCase | None,
    ) -> dict[str, Any]:
        name = str(tool.get("name") or "")
        overlay = _schema_overlay(name)
        if overlay:
            tool.update(overlay)
        if name == "browser_start":
            tool["case_defaults"] = {
                "run_id": policy.get("case_id"),
                "source_path": _browser_source_path(case, {}),
            }
        tool["runtime_policy"] = {
            "available_for_case": name not in BROWSER_TOOLS or policy["browser_available"],
            "browser_expected": policy["browser_expected"],
        }
        return tool


def blocked_runtime_policy_result(
    *,
    tool_name: str,
    call_id: str,
    trace_id: str,
    case_id: str | None,
    compatibility: ToolCompatibilityResult,
    reason: str = "browser tools are not available for this non-browser case",
) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "call_id": call_id,
        "executed": False,
        "blocked": True,
        "decision": "runtime_policy",
        "status": "blocked_by_runtime_policy",
        "result": None,
        "safe_message": reason,
        "side_effects": [],
        "event": {
            "trace_id": trace_id,
            "case_id": case_id,
            "tool": {"name": tool_name, "call_id": call_id},
            "arguments": compatibility.normalized_arguments,
            "metadata": {"compatibility": compatibility.model_dump()},
        },
        "audit_event": None,
        "error": reason,
        "compatibility": compatibility.model_dump(),
        "runtime_policy_blocked": True,
    }


def tool_result_with_compatibility(
    payload: dict[str, Any],
    compatibility: ToolCompatibilityResult,
    *,
    retry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload["compatibility"] = compatibility.model_dump()
    if retry is not None:
        payload["compatibility_retry"] = retry
    event = payload.get("event")
    if isinstance(event, dict):
        metadata = event.setdefault("metadata", {})
        if isinstance(metadata, dict):
            metadata["compatibility"] = compatibility.model_dump()
            if retry is not None:
                metadata["compatibility_retry"] = retry
    audit = payload.get("audit_event")
    if isinstance(audit, dict):
        metadata = audit.setdefault("metadata", {})
        if isinstance(metadata, dict):
            metadata["compatibility"] = compatibility.model_dump()
            if retry is not None:
                metadata["compatibility_retry"] = retry
    return payload


def _case_id(case: AttackCase | None, security: dict[str, Any] | None) -> str:
    return str(getattr(case, "case_id", "") or (security or {}).get("case_id") or "")


def _is_browser_case(case: AttackCase | None, security: dict[str, Any] | None) -> bool:
    metadata = dict(getattr(case, "metadata", {}) or (security or {}).get("metadata") or {})
    if case is not None and any(step.tool in BROWSER_TOOLS for step in case.tool_plan):
        return True
    source_dataset = str(metadata.get("source_dataset") or metadata.get("dataset_source") or "").lower()
    if any(marker in source_dataset for marker in ("instrumentation", "browserart", "browser-art", "vpi-bench")):
        return True
    memory_reference_case = _is_memory_reference_case(case, metadata)
    for key in ("web_entry_source_path", "local_web_entry_source_path", "original_web_entry_source_path"):
        if metadata.get(key):
            return True
    source_path = str(metadata.get("source_path") or metadata.get("local_source_path") or metadata.get("original_source_path") or "")
    if _looks_like_browser_source_path(source_path):
        return True
    if not memory_reference_case:
        for key in ("entry_url", "local_service_page_url", "web_entry_url"):
            if metadata.get(key):
                return True
        agent_files = metadata.get("agent_files")
        if isinstance(agent_files, dict) and agent_files.get("page"):
            return True
    user_task = str((security or {}).get("user_task") or getattr(getattr(case, "input", None), "payload", "") or "")
    return bool(re.search(r"http://127\.0\.0\.1:18\d{3}/(?:local-)?instrumentation/", user_task))


def _is_memory_reference_case(case: AttackCase | None, metadata: dict[str, Any]) -> bool:
    attack_type = str(getattr(case, "attack_type", "") or metadata.get("attack_type") or "").lower()
    source_group = str(metadata.get("source_group") or "").lower()
    phase = str(metadata.get("phase") or "").lower()
    return (
        attack_type == "memory_poisoning"
        or source_group.startswith("memory_poisoning")
        or phase in {"poison_seed", "trigger_query", "conflict_probe", "clean_control", "benign_seed"}
    )


def _browser_source_path(case: AttackCase | None, security: dict[str, Any] | None) -> str:
    metadata = dict(getattr(case, "metadata", {}) or (security or {}).get("metadata") or {})
    for key in ("web_entry_source_path", "local_source_path", "local_web_entry_source_path", "source_path", "original_web_entry_source_path", "original_source_path"):
        value = metadata.get(key)
        canonical = _canonical_source_path(str(value or ""))
        if canonical:
            return canonical
        if value and key in {"web_entry_source_path", "local_source_path", "local_web_entry_source_path"}:
            return str(value)
    agent_files = metadata.get("agent_files")
    if isinstance(agent_files, dict) and agent_files.get("page"):
        canonical = _canonical_source_path(str(agent_files["page"]))
        return canonical or str(agent_files["page"])
    if case is not None:
        for step in case.tool_plan:
            if step.tool == "browser_start" and step.arguments.get("source_path"):
                canonical = _canonical_source_path(str(step.arguments["source_path"]))
                return canonical or str(step.arguments["source_path"])
    return ""


def _browser_entry_url(case: AttackCase | None, security: dict[str, Any] | None, source_path: str = "") -> str:
    metadata = dict(getattr(case, "metadata", {}) or (security or {}).get("metadata") or {})
    for key in ("entry_url", "web_entry_url"):
        value = metadata.get(key)
        if value:
            return str(value)
    if source_path and resolve_local_source(source_path) is not None:
        return local_url_for_source(source_path) or ""
    value = metadata.get("local_service_page_url")
    if value:
        return str(value)
    if case is not None:
        for step in case.tool_plan:
            if step.tool == "browser_start" and step.arguments.get("url"):
                return str(step.arguments["url"])
    return ""


def _canonical_source_path(value: str) -> str:
    if not value:
        return ""
    resolved = resolve_local_source(value)
    return str(resolved) if resolved is not None else ""


def _looks_like_browser_source_path(value: str) -> bool:
    if not value:
        return False
    lowered = value.lower()
    if not lowered.endswith((".html", ".htm")):
        return False
    return bool(resolve_local_source(value))


def _normalize_sandbox_file_path(value: Any, sandbox_dir: Path | None) -> tuple[str, str | None]:
    raw = str(value or "")
    if not raw:
        return "", None
    candidate = Path(raw)
    if not candidate.is_absolute():
        return raw.lstrip("/"), None
    if sandbox_dir is None:
        return raw.lstrip("/"), None
    files_root = (sandbox_dir / "files").resolve()
    try:
        resolved = candidate.resolve()
    except Exception:
        return raw.lstrip("/"), None
    if resolved == files_root or files_root in resolved.parents:
        return resolved.relative_to(files_root).as_posix(), None
    if candidate.exists():
        return raw, "absolute_file_path_outside_sandbox_not_rewritten"
    return raw.lstrip("/"), None


def _read_file_default(case: AttackCase | None, security: dict[str, Any] | None) -> str:
    metadata = dict(getattr(case, "metadata", {}) or (security or {}).get("metadata") or {})
    agent_files = metadata.get("agent_files")
    if isinstance(agent_files, dict):
        for key in ("agent_view", "case", "reference_evidence", "page"):
            value = agent_files.get(key)
            if value:
                return str(value)
    resource_files = metadata.get("resource_files")
    if isinstance(resource_files, dict):
        for key in ("agent_view_json", "case_json", "contexts_json", "page_html"):
            value = resource_files.get(key)
            if value:
                return str(value)
    return ""


def _infer_mcp_target(case: AttackCase | None, security: dict[str, Any] | None, payload: dict[str, Any]) -> dict[str, str]:
    metadata = dict(getattr(case, "metadata", {}) or (security or {}).get("metadata") or {})
    hijacking = metadata.get("hijacking") if isinstance(metadata.get("hijacking"), dict) else {}
    inferred = {
        "server": str(metadata.get("target_server") or hijacking.get("target_server") or metadata.get("hijacked_server") or ""),
        "tool": str(metadata.get("target_tool") or hijacking.get("target_tool") or metadata.get("hijacked_tool") or ""),
    }
    if inferred["server"] and inferred["tool"]:
        return inferred
    catalog = []
    if case is not None:
        catalog = case_extra_list(case, "clean_tool_catalog") or case_extra_list(case, "poisoned_tool_catalog")
    candidates = [item for item in catalog if isinstance(item, dict)]
    if payload.get("server"):
        candidates = [item for item in candidates if str(item.get("server") or item.get("server_name") or "") == str(payload["server"])]
    if payload.get("tool"):
        candidates = [item for item in candidates if str(item.get("tool") or item.get("tool_name") or item.get("name") or "") == str(payload["tool"])]
    servers = {str(item.get("server") or item.get("server_name") or "") for item in candidates if item.get("server") or item.get("server_name")}
    tools = {str(item.get("tool") or item.get("tool_name") or item.get("name") or "") for item in candidates if item.get("tool") or item.get("tool_name") or item.get("name")}
    if not inferred["server"] and len(servers) == 1:
        inferred["server"] = next(iter(servers))
    if not inferred["tool"] and len(tools) == 1:
        inferred["tool"] = next(iter(tools))
    return inferred


def _poisonedrag_defaults(case: AttackCase | None, security: dict[str, Any] | None) -> dict[str, Any]:
    metadata = dict(getattr(case, "metadata", {}) or (security or {}).get("metadata") or {})
    defaults: dict[str, Any] = {}
    for key in ("dataset", "question_id", "mode", "top_k", "adv_per_query", "poison_prefix"):
        if metadata.get(key) is not None:
            defaults[key] = metadata[key]
    if "dataset" not in defaults and metadata.get("source_subset") is not None:
        defaults["dataset"] = metadata["source_subset"]
    if "question_id" not in defaults and metadata.get("original_id") is not None:
        defaults["question_id"] = metadata["original_id"]
    poisonedrag = metadata.get("poisonedrag")
    if isinstance(poisonedrag, dict):
        for key in ("dataset", "question_id", "mode", "top_k", "adv_per_query", "poison_prefix"):
            if poisonedrag.get(key) is not None:
                defaults.setdefault(key, poisonedrag[key])
    return defaults


def _memory_key_default(case: AttackCase | None, security: dict[str, Any] | None) -> str:
    metadata = dict(getattr(case, "metadata", {}) or (security or {}).get("metadata") or {})
    value = metadata.get("memory_key")
    return str(value).strip() if value is not None else ""


def _case_question(case: AttackCase | None, security: dict[str, Any] | None) -> str:
    metadata = dict(getattr(case, "metadata", {}) or (security or {}).get("metadata") or {})
    for key in ("question", "query"):
        value = metadata.get(key)
        if value:
            return str(value)
    task = str((security or {}).get("user_task") or getattr(getattr(case, "input", None), "payload", "") or "")
    match = re.search(r"(?im)^\s*Question\s*:\s*(.+?)\s*$", task)
    if match:
        return match.group(1).strip()
    question_match = re.search(r"([^.\n?!]*\?)", task)
    return question_match.group(1).strip() if question_match else task.strip()


def _schema_overlay(name: str) -> dict[str, Any]:
    if name == "browser_start":
        return {
            "description": "Start a local benchmark browser session. Use run_id as the session identifier. Do not pass session_id.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "run_id": {"type": "string"},
                    "source_path": {"type": "string"},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
            "accepted_aliases": {"session_id": "run_id"},
            "deprecated_fields": ["session_id"],
        }
    if name == "mcp_call":
        return {
            "input_schema": {
                "type": "object",
                "properties": {
                    "server": {"type": "string"},
                    "tool": {"type": "string"},
                    "arguments": {"type": "object"},
                },
                "required": ["server", "tool"],
                "additionalProperties": True,
            },
            "accepted_aliases": {
                "name": "tool",
                "tool_name": "tool",
                "method": "tool",
                "params": "arguments",
                "parameters": "arguments",
                "args": "arguments",
                "server_name": "server",
            },
        }
    if name == "read_file":
        return {
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
            "accepted_aliases": {"file_path": "path", "filepath": "path", "filename": "path"},
        }
    if name == "write_file":
        return {
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                "required": ["path", "content"],
                "additionalProperties": False,
            },
            "accepted_aliases": {"file_path": "path", "filepath": "path", "body": "content", "text": "content"},
        }
    if name == "send_email":
        return {
            "input_schema": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                    "attachment_path": {"type": "string"},
                    "attachments": {"type": "array"},
                },
                "required": ["to", "subject", "body"],
                "additionalProperties": True,
            },
            "accepted_aliases": {
                "recipient": "to",
                "email": "to",
                "address": "to",
                "title": "subject",
                "message": "body",
                "text": "body",
                "content": "body",
            },
        }
    return {}


def _extract_attachment_values(payload: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("attachment_path", "attachment", "file_path", "filepath"):
        value = payload.get(key)
        if value:
            values.append(str(value))
    for key in ("attachments", "files"):
        value = payload.get(key)
        if isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, dict):
                    path = item.get("path") or item.get("file_path") or item.get("name")
                    if path:
                        values.append(str(path))
                elif item:
                    values.append(str(item))
        elif value:
            values.append(str(value))
    return list(dict.fromkeys(values))


def _looks_like_selector(value: str) -> bool:
    stripped = value.strip()
    return bool(
        stripped.startswith(("#", ".", "[", "//"))
        or stripped.startswith("css=")
        or stripped.startswith("xpath=")
        or stripped in {"body", "html"}
        or ">" in stripped
        or "=" in stripped
    )
