"""Local HTTP tool server backed by GuardedToolGateway."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from typing import Any
from urllib.parse import urlparse

from .tool_gateway import GuardedToolGateway


class BenchmarkToolServer:
    def __init__(self, gateway: GuardedToolGateway, host: str = "127.0.0.1", port: int = 18090) -> None:
        self.gateway = gateway
        self.host = host
        self.port = port
        self._events: list[dict[str, Any]] = []
        self._lock = Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: Thread | None = None

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
                    self._send_json({"ok": True, "service": "agentguard-benchmark-tool-server"})
                    return
                if path == "/tools":
                    tools = list(outer.gateway.tool_runtime.list_tools().values())
                    for item in tools:
                        item.setdefault("endpoint", f"{outer.base_url}/tools/{item.get('name')}")
                    self._send_json({"tools": tools})
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
                    with outer._lock:
                        outer._events.clear()
                    self._send_json({"ok": True})
                    return
                if path.startswith("/tools/"):
                    tool_name = path.removeprefix("/tools/").strip("/")
                    payload = self._read_json()
                    result = outer.gateway.invoke_tool(
                        tool_name=tool_name,
                        arguments=dict(payload.get("arguments") or {}),
                        security=dict(payload.get("security") or {}),
                        trace_id=str(payload.get("trace_id") or (payload.get("security") or {}).get("trace_id") or ""),
                        call_id=payload.get("call_id"),
                    )
                    dumped = result.model_dump()
                    with outer._lock:
                        outer._events.append(dumped)
                    self._send_json(dumped)
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
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def reset_case(self) -> None:
        with self._lock:
            self._events.clear()

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
