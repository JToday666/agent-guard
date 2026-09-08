"""Local transport fault injection around the real Guard API, with no provider.

Requests still reach the actual API unless a test explicitly selects a delivery
outage. Request tampering exercises the API's own 409/422 validation. A lost or
damaged response is injected only after the upstream response has been received.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
from threading import Lock, Thread
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
]


@dataclass(slots=True)
class DeliveryExchange:
    request_body: bytes = field(repr=False)
    upstream_status: int | None = None
    upstream_body: bytes | None = field(default=None, repr=False)
    fault: Fault = "none"


@dataclass(slots=True)
class DeliveryProxy:
    base_url: str
    exchanges: list[DeliveryExchange] = field(default_factory=list, repr=False)
    _fault: Fault = field(default="none", repr=False)
    _remaining: int | None = field(default=None, repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def inject(self, fault: Fault, *, count: int | None = None) -> None:
        if count is not None and count <= 0:
            raise ValueError("fault count must be positive")
        with self._lock:
            self._fault, self._remaining = fault, count

    def _next_fault(self, body: bytes) -> DeliveryExchange:
        with self._lock:
            exchange = DeliveryExchange(body, fault=self._fault)
            self.exchanges.append(exchange)
            if self._remaining is not None:
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
            exchange = (
                proxy._next_fault(raw) if self.path == "/v1/audit/events" else None
            )
            fault = exchange.fault if exchange is not None else "none"
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
                with httpx.Client(timeout=3, trust_env=False) as client:
                    response = client.post(
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
            if fault == "disconnect_after":
                self._disconnect()
                return
            if fault == "wrong_audit_id":
                payload = response.json()
                payload["audit_id"] = "audit_outcome_wrong_transport_ack"
                content = json.dumps(payload).encode("utf-8")
            self.send_response(response.status_code)
            self.send_header("Content-Type", response.headers.get("Content-Type", ""))
            self.send_header("Content-Length", str(len(content)))
            if "cache-control" in response.headers:
                self.send_header("Cache-Control", response.headers["cache-control"])
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
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("Delivery test proxy did not stop")
