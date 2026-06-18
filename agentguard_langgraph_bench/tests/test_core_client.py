import httpx

from agentguard_langgraph_bench.config import BenchConfig
from agentguard_langgraph_bench.core_client import AgentGuardCoreClient, CoreClientError


def test_core_client_posts_authorization_header(monkeypatch):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/v1/evaluate/tool-call":
            return httpx.Response(
                200,
                json={
                    "decision_id": "dec_http",
                    "decision": "allow",
                    "risk_score": 0,
                    "severity": "low",
                    "rule_hits": [],
                    "reason": "test allow",
                    "safe_message": None,
                    "approval": None,
                    "latency_ms": 1,
                },
            )
        if request.url.path == "/v1/audit/event":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, json={"error": "not found"})

    class TestClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

    monkeypatch.setattr(httpx, "Client", TestClient)
    client = AgentGuardCoreClient(BenchConfig(core_base_url="http://core.test", token="secret-token"))

    decision = client.evaluate_tool_call({"event_id": "evt_1"})
    audit = client.submit_audit_event({"audit_id": "audit_1"})

    assert decision["decision"] == "allow"
    assert audit["ok"] is True
    assert [request.url.path for request in requests] == ["/v1/evaluate/tool-call", "/v1/audit/event"]
    assert all(request.headers["authorization"] == "Bearer secret-token" for request in requests)


def test_core_client_invalid_json_raises(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-json")

    class TestClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

    monkeypatch.setattr(httpx, "Client", TestClient)
    client = AgentGuardCoreClient(BenchConfig(core_base_url="http://core.test", token="secret-token"))

    try:
        client.evaluate_tool_call({"event_id": "evt_1"})
    except CoreClientError as exc:
        assert "invalid JSON" in str(exc)
    else:
        raise AssertionError("CoreClientError was not raised")
