"""Global single-token provider serialization for parallel streams (task #4).

Seven parallel streams multiply the instantaneous provider QPS.  Instead of a
per-worker RPS token bucket, the run optionally enforces the simplest possible
client-side ceiling: one global token shared by every stream worker, so at
most one provider (LLM) request is in flight across the whole parallel matrix
at any moment.  The token is a ``BoundedSemaphore(1)`` created on the spawn
context in the parent process and passed to each spawned worker through
``StreamWorkerRequest``; workers install it process-locally on start-up.

Semantics:

- ``global_provider_token()`` wraps one provider call (including its whole
  retry sequence): acquire before, release after.  When no token is installed
  (parallel limiting disabled, or serial runs) it is a zero-overhead no-op and
  behaviour is identical to the unlimited status quo.
- ``--provider-rate-limit`` on the CLI therefore acts as an enable flag: any
  accepted value turns the global single token on for parallel runs.
"""

from __future__ import annotations

import contextlib
from typing import Any, Iterator


# Process-local installation of the run-wide token.  Each spawn worker is a
# separate process, so installing the shared semaphore once at worker start-up
# covers every arm and case executed inside that worker.
_GLOBAL_PROVIDER_TOKEN: Any | None = None


def install_global_provider_token(token: Any | None) -> None:
    """Install (or clear) the process-local global provider token."""

    global _GLOBAL_PROVIDER_TOKEN
    _GLOBAL_PROVIDER_TOKEN = token


def global_provider_token_installed() -> bool:
    """Whether this process serializes provider calls against a token."""

    return _GLOBAL_PROVIDER_TOKEN is not None


@contextlib.contextmanager
def global_provider_token() -> Iterator[None]:
    """Hold the global provider token for the duration of one provider call.

    A missing token (limiting disabled or serial execution) yields immediately
    with zero overhead.
    """

    token = _GLOBAL_PROVIDER_TOKEN
    if token is None:
        yield
        return
    token.acquire()
    try:
        yield
    finally:
        token.release()


__all__ = [
    "global_provider_token",
    "global_provider_token_installed",
    "install_global_provider_token",
]
