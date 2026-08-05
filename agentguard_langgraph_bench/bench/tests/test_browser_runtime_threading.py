from __future__ import annotations

from http.server import ThreadingHTTPServer

from agentguard_langgraph_bench.bench.runtime.tool_server import BenchmarkToolServer


class _Runtime:
    def list_tools(self) -> dict[str, dict]:
        return {}


class _Gateway:
    tool_runtime = _Runtime()


def test_benchmark_tool_server_uses_threading_http_server() -> None:
    server = BenchmarkToolServer(_Gateway(), port=0).start()
    try:
        assert isinstance(server._server, ThreadingHTTPServer)
        assert hasattr(server._server, "process_request_thread")
    finally:
        server.stop()
