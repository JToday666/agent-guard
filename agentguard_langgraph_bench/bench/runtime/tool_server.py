"""Local HTTP tool server backed by GuardedToolGateway."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from threading import Lock, Thread
from typing import Any
from urllib.parse import urlparse

from .tool_gateway import GuardedToolGateway
from .tool_compat import (
    BROWSER_TOOLS,
    ToolCompatibilityLayer,
    agent_visible_tool_result,
    blocked_runtime_policy_result,
    tool_result_with_compatibility,
)


class BenchmarkToolServer:
    def __init__(self, gateway: GuardedToolGateway, host: str = "127.0.0.1", port: int = 18090) -> None:
        self.gateway = gateway
        self.host = host
        self.port = port
        self._events: list[dict[str, Any]] = []
        self._bridge_events: list[dict[str, Any]] = []
        self._lock = Lock()
        self._server: HTTPServer | None = None
        self._thread: Thread | None = None
        self._active_case_context: dict[str, Any] | None = None
        self._terminal_by_case: dict[str, dict[str, Any]] = {}
        self._compatibility_layer = ToolCompatibilityLayer(getattr(gateway.tool_runtime, "sandbox_dir", None))

    @property
    def base_url(self) -> str:
        port = self._server.server_port if self._server is not None else self.port
        return f"http://{self.host}:{port}"

    def start(self) -> "BenchmarkToolServer":
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_GET(self) -> None:
                path = urlparse(self.path).path
                if path == "/health":
                    self._send_json({"ok": True, "service": "local-tool-server"})
                    return
                if path == "/tools":
                    tools = list(outer.gateway.tool_runtime.list_tools().values())
                    case_context = outer.case_context()
                    case = case_context.get("case") if case_context else None
                    visible_tools = outer._compatibility_layer.visible_tools(
                        tools,
                        case=case,
                        security=dict((case_context or {}).get("security") or {}),
                        config=(case_context or {}).get("config"),
                    )
                    for item in visible_tools:
                        item.setdefault("endpoint", f"{outer.base_url}/tools/{item.get('name')}")
                    self._send_json({"tools": visible_tools})
                    return
                if path == "/events":
                    with outer._lock:
                        events = list(outer._events)
                    self._send_json({"tool_results": events})
                    return
                self._send_json({"ok": False, "error": "not found"}, status=404)

            def do_POST(self) -> None:
                path = urlparse(self.path).path
                if path == "/reset-case":
                    outer.reset_case(clear_context=True)
                    self._send_json({"ok": True})
                    return
                if path == "/bridge-events":
                    payload = self._read_json()
                    if payload.get("case_id") == outer.case_context().get("case_id"):
                        outer.record_bridge_event(payload)
                    self._send_json({"ok": True})
                    return
                if path.startswith("/tools/"):
                    tool_name = path.removeprefix("/tools/").strip("/")
                    payload = self._read_json()
                    raw_arguments = dict(payload.get("arguments") or {})
                    case_context = outer.case_context()
                    case = case_context.get("case") if case_context else None
                    security = dict(payload.get("security") or (case_context or {}).get("security") or {})
                    trace_id = str(payload.get("trace_id") or security.get("trace_id") or "")
                    call_id = str(payload.get("call_id") or "")
                    compatibility = outer._compatibility_layer.normalize_arguments(
                        tool_name,
                        raw_arguments,
                        case=case,
                        security=security,
                        trace_id=trace_id,
                        call_id=call_id,
                        config=(case_context or {}).get("config"),
                    )
                    case_id = str(
                        compatibility.case_tool_policy.get("case_id")
                        or security.get("case_id")
                        or (case_context or {}).get("case_id")
                        or ""
                    )
                    terminal = outer._terminal_for_case(case_id)
                    if terminal is not None:
                        result_payload = outer._terminal_not_completed_result(
                            tool_name=tool_name,
                            call_id=call_id or f"terminal_{len(outer.events()) + 1}",
                            trace_id=trace_id,
                            case_id=case_id,
                            terminal=terminal,
                        )
                        result_payload = tool_result_with_compatibility(result_payload, compatibility)
                        with outer._lock:
                            outer._events.append(result_payload)
                        self._send_json(agent_visible_tool_result(result_payload))
                        return
                    if tool_name in BROWSER_TOOLS and not compatibility.case_tool_policy.get("browser_available"):
                        result_payload = blocked_runtime_policy_result(
                            tool_name=tool_name,
                            call_id=call_id or f"runtime_policy_{len(outer.events()) + 1}",
                            trace_id=trace_id,
                            case_id=compatibility.case_tool_policy.get("case_id"),
                            compatibility=compatibility,
                        )
                        with outer._lock:
                            outer._events.append(result_payload)
                        self._send_json(agent_visible_tool_result(result_payload))
                        return
                    result = outer.gateway.invoke_tool(
                        tool_name=tool_name,
                        arguments=compatibility.normalized_arguments,
                        raw_arguments=raw_arguments,
                        compatibility=compatibility.model_dump(),
                        security=security,
                        trace_id=trace_id,
                        call_id=payload.get("call_id"),
                        case_context=case_context,
                    )
                    dumped = result.model_dump()
                    dumped = tool_result_with_compatibility(dumped, compatibility)
                    if dumped.get("status") == "error":
                        recovered = outer._compatibility_layer.recover_after_error(
                            tool_name,
                            raw_arguments,
                            str(dumped.get("error") or ""),
                            case=case,
                            security=security,
                            trace_id=trace_id,
                            call_id=str(dumped.get("call_id") or call_id or ""),
                            config=(case_context or {}).get("config"),
                        )
                        if recovered is not None:
                            retry_result = outer.gateway.invoke_tool(
                                tool_name=tool_name,
                                arguments=recovered.normalized_arguments,
                                raw_arguments=raw_arguments,
                                compatibility=recovered.model_dump(),
                                security=security,
                                trace_id=trace_id,
                                call_id=payload.get("call_id"),
                                case_context=case_context,
                            ).model_dump()
                            dumped = tool_result_with_compatibility(
                                retry_result,
                                recovered,
                                retry={
                                    "compatibility_retry": True,
                                    "retry_reason": "recoverable_schema_error",
                                    "previous_error": dumped.get("error"),
                                    "retry_index": 1,
                                    "raw_arguments": raw_arguments,
                                    "normalized_arguments": recovered.normalized_arguments,
                                },
                            )
                    with outer._lock:
                        outer._events.append(dumped)
                        outer._maybe_latch_terminal_locked(case_id, dumped)
                    self._send_json(agent_visible_tool_result(dumped))
                    return
                self._send_json({"ok": False, "error": "not found"}, status=404)

            def _read_json(self) -> dict[str, Any]:
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    parsed = json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError:
                    parsed = {}
                return parsed if isinstance(parsed, dict) else {}

            def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
                body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError) as exc:
                    outer._record_server_event(
                        {
                            "tool_name": "_server",
                            "call_id": "",
                            "executed": False,
                            "blocked": False,
                            "decision": None,
                            "status": "client_disconnected",
                            "error": type(exc).__name__,
                            "path": self.path,
                        }
                    )

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def set_case_context(self, case: Any, context: Any) -> None:
        self._compatibility_layer.set_sandbox_dir(getattr(self.gateway.tool_runtime, "sandbox_dir", None))
        security = dict(getattr(context, "security", {}) or {})
        hijacking_context = dict(getattr(context, "tool_hijacking_context", {}) or {})
        self._active_case_context = {
            **hijacking_context,
            "case": case,
            "case_id": getattr(case, "case_id", security.get("case_id", "")),
            "attack_type": getattr(case, "attack_type", security.get("attack_type", "")),
            "is_malicious": getattr(case, "is_malicious", security.get("is_malicious", None)),
            "metadata": dict(getattr(case, "metadata", {}) or security.get("metadata") or {}),
            "tool_plan_summary": [
                {"tool": step.tool, "arguments": dict(step.arguments or {})}
                for step in getattr(case, "tool_plan", [])
            ],
            "security": security,
            "config": getattr(context, "config", None),
        }

    def clear_case_context(self) -> None:
        self._active_case_context = None

    def case_context(self) -> dict[str, Any]:
        return dict(self._active_case_context or {})

    def reset_case(self, *, clear_context: bool = True) -> None:
        with self._lock:
            self._events.clear()
            self._bridge_events.clear()
            self._terminal_by_case.clear()
        if clear_context:
            self.clear_case_context()

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def record_bridge_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._bridge_events.append(dict(event))

    def bridge_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._bridge_events)

    def _record_server_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._events.append(dict(event))

    def _terminal_for_case(self, case_id: str) -> dict[str, Any] | None:
        if not case_id:
            return None
        with self._lock:
            terminal = self._terminal_by_case.get(case_id)
            return dict(terminal) if terminal is not None else None

    def _maybe_latch_terminal_locked(self, case_id: str, result: dict[str, Any]) -> None:
        if not case_id or case_id in self._terminal_by_case:
            return
        if result.get("runtime_policy_blocked"):
            return
        if not result.get("blocked"):
            return
        if result.get("terminal_reason") == "security_block_terminal":
            return
        reason = str(result.get("terminal_reason") or result.get("block_semantics") or "security_block")
        self._terminal_by_case[case_id] = {
            "case_id": case_id,
            "call_id": result.get("call_id"),
            "tool_name": result.get("tool_name"),
            "decision": result.get("decision") or "deny",
            "terminal_reason": reason,
        }

    def _terminal_not_completed_result(
        self,
        *,
        tool_name: str,
        call_id: str,
        trace_id: str,
        case_id: str,
        terminal: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "tool_name": tool_name,
            "call_id": call_id,
            "executed": False,
            "blocked": True,
            "decision": terminal.get("decision") or "deny",
            "status": "not_completed",
            "result": None,
            "safe_message": "The requested action was not completed because this case already reached a terminal security block.",
            "side_effects": [],
            "event": {"trace_id": trace_id, "case_id": case_id, "arguments": {}},
            "audit_event": None,
            "runtime_terminal": True,
            "terminal_reason": "security_block_terminal",
            "block_semantics": "security_block_terminal",
            "counts_as_effective_block": False,
            "terminal_from_call_id": terminal.get("call_id"),
            "terminal_from_tool_name": terminal.get("tool_name"),
            "terminal_from_reason": terminal.get("terminal_reason"),
        }

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
