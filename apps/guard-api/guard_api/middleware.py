"""Guard API transport-level safety middleware."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.types import Message, Receive, Scope, Send

from guard_api.errors import error_response

AsgiApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class RequestBodyLimitMiddleware:
    """Reject oversized request bodies before Pydantic or JSON materialization."""

    def __init__(self, app: AsgiApp, *, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = _content_length(scope)
        if content_length is not None and content_length > self.max_body_bytes:
            await self._reject(scope, receive, send)
            return

        received_bytes = 0

        async def limited_receive() -> Message:
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self.max_body_bytes:
                    raise _RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _RequestBodyTooLarge:
            await self._reject(scope, receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = error_response(
            "REQUEST_TOO_LARGE",
            status_code=413,
            details={"max_body_bytes": self.max_body_bytes},
        )
        await response(scope, receive, send)


class _RequestBodyTooLarge(Exception):
    pass


def _content_length(scope: Scope) -> int | None:
    for raw_name, raw_value in scope.get("headers", []):
        if raw_name.lower() != b"content-length":
            continue
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            return None
        return max(value, 0)
    return None
