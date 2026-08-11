from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from agentguard_cli.cli import run
from agentguard_cli.endpoint_policy import (
    GuardApiEndpointError as CliEndpointError,
)
from agentguard_cli.endpoint_policy import (
    validate_guard_api_base_url as validate_cli_endpoint,
)
from agentguard_langgraph_adapter.core_client import (
    AgentGuardCoreClient,
    CoreClientError,
)
from agentguard_langgraph_adapter.endpoint_policy import (
    GuardApiEndpointError as AdapterEndpointError,
)
from agentguard_langgraph_adapter.endpoint_policy import (
    validate_guard_api_base_url as validate_adapter_endpoint,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "guard_api_endpoint_policy.json"


def test_python_consumers_share_guard_api_endpoint_policy() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    validators = (validate_cli_endpoint, validate_adapter_endpoint)

    for case in fixture["allowed"]:
        for validate in validators:
            assert validate(case["input"]) == case["normalized"]
    for value in fixture["rejected"]:
        with pytest.raises(CliEndpointError):
            validate_cli_endpoint(value)
        with pytest.raises(AdapterEndpointError):
            validate_adapter_endpoint(value)


def test_cli_rejects_unsafe_target_before_transport_or_token_exposure() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    stderr = io.StringIO()
    exit_code = run(
        ["launch"],
        env={
            "AGENTGUARD_API_URL": "http://user@attacker.example",
            "AGENTGUARD_CONTROL_TOKEN": "control-secret",
        },
        stdout=io.StringIO(),
        stderr=stderr,
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 2
    assert calls == 0
    assert "control-secret" not in stderr.getvalue()
    assert "attacker.example" not in stderr.getvalue()


def test_cli_rejects_redirect_without_second_request() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            307,
            headers={"location": "https://attacker.example/collect"},
        )

    stderr = io.StringIO()
    exit_code = run(
        ["launch"],
        env={
            "AGENTGUARD_API_URL": "https://guard.example",
            "AGENTGUARD_CONTROL_TOKEN": "control-secret",
        },
        stdout=io.StringIO(),
        stderr=stderr,
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 1
    assert len(requests) == 1
    assert requests[0].headers["authorization"] == "Bearer control-secret"
    assert "redirects are not allowed" in stderr.getvalue()


def test_adapter_rejects_unsafe_target_before_http_client(monkeypatch) -> None:
    def unexpected_client(*_args, **_kwargs):
        raise AssertionError("httpx.Client must not be constructed")

    monkeypatch.setattr(httpx, "Client", unexpected_client)
    client = AgentGuardCoreClient(
        SimpleNamespace(
            core_base_url="http://attacker.example",
            token="adapter-secret",
            timeout=1.0,
            core_api_mode="legacy",
        )
    )

    with pytest.raises(CoreClientError) as error:
        client.evaluate_tool_call({"event_id": "evt_unsafe"})

    assert "adapter-secret" not in str(error.value)
    assert "attacker.example" not in str(error.value)


def test_adapter_rejects_redirect_without_second_request(monkeypatch) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            308,
            headers={"location": "https://attacker.example/collect"},
        )

    class TestClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            assert kwargs["follow_redirects"] is False
            super().__init__(
                *args,
                transport=httpx.MockTransport(handler),
                **kwargs,
            )

    monkeypatch.setattr(httpx, "Client", TestClient)
    client = AgentGuardCoreClient(
        SimpleNamespace(
            core_base_url="https://guard.example",
            token="adapter-secret",
            timeout=1.0,
            core_api_mode="legacy",
        )
    )

    with pytest.raises(CoreClientError, match="redirects are not allowed"):
        client.evaluate_tool_call({"event_id": "evt_redirect"})

    assert len(requests) == 1
    assert requests[0].headers["authorization"] == "Bearer adapter-secret"
