"""Tiny fake Agent Security Core server that always denies tool calls."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .core_client import FakeDenyCoreClient


class FakeCoreHandler(BaseHTTPRequestHandler):
    server_version = "AgentGuardFakeCore/0.1"

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        payload = self._read_json()
        if self.path in {"/v1/evaluate/tool-call", "/v1/guard/evaluate"}:
            body = FakeDenyCoreClient().evaluate_tool_call(payload)
            self._send_json(200, body)
            return
        if self.path in {"/v1/audit/event", "/v1/audit/events"}:
            body = {"ok": True, "audit_id": payload.get("audit_id")}
            self._send_json(200, body)
            return
        self._send_json(404, {"error": "not found"})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode(
            "utf-8"
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a fake AgentGuard Core that always denies"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    server = ThreadingHTTPServer((args.host, args.port), FakeCoreHandler)
    print(f"Fake Agent Security Core listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
