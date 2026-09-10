"""Local transport fault injection around the real Guard API, with no provider.

Requests still reach the actual API unless a test explicitly selects a delivery
outage. Request tampering exercises the API's own 409/422 validation. A lost or
damaged response is injected only after the upstream response has been received.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
from threading import Event, Lock, Thread
import time
from typing import Literal
from urllib.parse import urlsplit

import httpx

Fault = Literal[
    "none",
    "disconnect_before",
    "disconnect_after",
    "tamper_parent",
    "tamper_ack",
    "wrong_audit_id",
    "reject_409",
    "reject_422",
]


@dataclass(slots=True)
class DeliveryExchange:
    request_body: bytes = field(repr=False)
    upstream_status: int | None = None
    upstream_body: bytes | None = field(default=None, repr=False)
    fault: Fault = "none"
    audit_id: str | None = None
    forwarded_digest: str | None = None
    response_status: int | None = None
    received_at: float = field(default_factory=time.monotonic)
    upstream_received_at: float | None = None

    @property
    def request_digest(self) -> str:
        return hashlib.sha256(self.request_body).hexdigest()


@dataclass(slots=True)
class DeliveryResponseGate:
    audit_id: str
    reached: Event = field(default_factory=Event, repr=False)
    release: Event = field(default_factory=Event, repr=False)


@dataclass(slots=True)
class DeliveryProxy:
    base_url: str
    exchanges: list[DeliveryExchange] = field(default_factory=list, repr=False)
    _fault: Fault = field(default="none", repr=False)
    _remaining: int | None = field(default=None, repr=False)
    _audit_id: str | None = field(default=None, repr=False)
    _gate: DeliveryResponseGate | None = field(default=None, repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def inject(
        self, fault: Fault, *, count: int | None = None, audit_id: str | None = None
    ) -> None:
        if count is not None and count <= 0:
            raise ValueError("fault count must be positive")
        with self._lock:
            self._fault, self._remaining = fault, count
            self._audit_id = audit_id

    def pause_response(self, audit_id: str) -> DeliveryResponseGate:
        """Pause a selected response only after the real API has replied."""
        with self._lock:
            if self._gate is not None:
                raise ValueError("A response gate is already installed")
            self._gate = DeliveryResponseGate(audit_id)
            return self._gate

    def _next_fault(self, body: bytes) -> DeliveryExchange:
        try:
            payload = json.loads(body)
            audit_id = payload.get("audit_id") if isinstance(payload, dict) else None
        except (ValueError, UnicodeError):
            audit_id = None
        with self._lock:
            selected = self._audit_id is None or self._audit_id == audit_id
            exchange = DeliveryExchange(
                body, fault=self._fault if selected else "none", audit_id=audit_id
            )
            self.exchanges.append(exchange)
            if selected and self._remaining is not None:
                self._remaining -= 1
                if self._remaining == 0:
                    self._fault, self._remaining = "none", None
            return exchange


@contextmanager
def product_delivery_proxy(upstream_url: str) -> Iterator[DeliveryProxy]:
    """Forward only to the test's loopback API; audit faults never affect models."""

    upstream = urlsplit(upstream_url)
    if upstream.scheme != "http" or upstream.hostname != "127.0.0.1":
        raise ValueError("delivery proxy requires the isolated loopback API")
    proxy = DeliveryProxy(base_url="")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_POST(self) -> None:
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self._forward(raw)

        def do_GET(self) -> None:
            self._forward(b"")

        def _forward(self, raw: bytes) -> None:
            exchange = (
                proxy._next_fault(raw)
                if self.command == "POST" and self.path == "/v1/audit/events"
                else None
            )
            fault = exchange.fault if exchange is not None else "none"
            if fault in {"reject_409", "reject_422"}:
                status = 409 if fault == "reject_409" else 422
                content = b'{"ok":false,"error":{"code":"TEST_DELIVERY_FAULT"}}'
                assert exchange is not None
                exchange.response_status = status
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            if fault == "disconnect_before":
                self._disconnect()
                return
            forwarded = raw
            if fault in {"tamper_parent", "tamper_ack"}:
                payload = json.loads(raw)
                if fault == "tamper_parent":
                    payload["trace_id"] = "trace:transport-tampered-parent"
                else:
                    payload["metadata"]["activation_ack"]["ack_token"] = (
                        "hmac-sha256:" + "0" * 64
                    )
                forwarded = json.dumps(payload).encode("utf-8")
            headers = {
                key: value
                for key, value in self.headers.items()
                if key.lower() not in {"host", "content-length", "connection"}
            }
            try:
                if exchange is not None:
                    exchange.forwarded_digest = hashlib.sha256(forwarded).hexdigest()
                with httpx.Client(timeout=3, trust_env=False) as client:
                    response = client.request(
                        self.command,
                        upstream_url + self.path,
                        headers=headers,
                        content=forwarded,
                    )
            except httpx.HTTPError:
                self._disconnect()
                return
            content = response.content
            if exchange is not None:
                exchange.upstream_status = response.status_code
                exchange.upstream_body = content
                exchange.upstream_received_at = time.monotonic()
                with proxy._lock:
                    gate = proxy._gate
                if gate is not None and exchange.audit_id == gate.audit_id:
                    gate.reached.set()
                    if not gate.release.wait(timeout=10):
                        self._disconnect()
                        return
            if fault == "disconnect_after":
                self._disconnect()
                return
            if fault == "wrong_audit_id":
                payload = response.json()
                payload["audit_id"] = "audit_outcome_wrong_transport_ack"
                content = json.dumps(payload).encode("utf-8")
            self.send_response(response.status_code)
            if exchange is not None:
                exchange.response_status = response.status_code
            self.send_header("Content-Type", response.headers.get("Content-Type", ""))
            self.send_header("Content-Length", str(len(content)))
            if "cache-control" in response.headers:
                self.send_header("Cache-Control", response.headers["cache-control"])
            for cookie in response.headers.get_list("set-cookie"):
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(content)

        def _disconnect(self) -> None:
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    proxy.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        name="product-delivery-contract-proxy",
        daemon=True,
    )
    thread.start()
    try:
        yield proxy
    finally:
        if proxy._gate is not None:
            proxy._gate.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("Delivery test proxy did not stop")
