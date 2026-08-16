from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
from typing import Any, Callable

import httpx
import pytest

import agentguard_langgraph_adapter.core_client as core_client_module
import agentguard_langgraph_adapter.strong_binding as strong_binding_module
from agentguard_langgraph_adapter.core_client import AgentGuardCoreClient
from agentguard_langgraph_adapter.event_models import (
    PolicyDecision,
    RuntimeGuardEvent,
    SecurityContext,
    ToolCallEvent,
    ToolDescriptor,
)
from agentguard_langgraph_adapter.strong_binding import (
    ExecutionLeaseConsumeError,
    ExecutionLeaseReference,
)
from agentguard_langgraph_adapter.tool_gateway import GuardedToolGateway
from agentguard_langgraph_bench.bench.runtime.tool_gateway import (
    GuardedToolGateway as BenchGuardedToolGateway,
)

FINGERPRINT = "hmac-sha256:" + "a" * 64
LEASE_TOKEN = "lease-v1:" + "b" * 64
RUNTIME_BINDING_ID = "binding:cred_langgraph"


def _binding(
    *, action_id: str = "call_strong", runtime_binding_id: str = RUNTIME_BINDING_ID
) -> dict[str, Any]:
    return {
        "schema_version": "2.1",
        "action_id": action_id,
        "authorization_fingerprint": FINGERPRINT,
        "runtime_binding_id": runtime_binding_id,
        "requires_execution_lease": True,
    }


def _decision(
    *,
    action_id: str = "call_strong",
    binding: object | None = None,
) -> PolicyDecision:
    return PolicyDecision(
        decision_id=f"dec_{action_id}",
        decision="ask",
        risk_score=70,
        severity="medium",
        reason="human review required",
        safe_message="Approval required.",
        approval={"approval_id": f"app_{action_id}", "required": True},
        policy_audit_id=f"audit_policy_{action_id}",
        enforcement_binding=(
            _binding(action_id=action_id) if binding is None else binding
        ),
    )


class _Runtime:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def snapshot(self) -> list[tuple[str, dict[str, Any]]]:
        return list(self.calls)

    def invoke(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool_name, dict(arguments)))
        return {"ok": True}

    def diff(self, before: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
        return [{"type": "call", "count": len(self.calls) - len(before)}]


class _StrongGuard:
    def __init__(
        self,
        *,
        decision: PolicyDecision | None = None,
        resolution: dict[str, Any] | None = None,
        consume_error: ExecutionLeaseConsumeError | None = None,
        wait_hook: Callable[[], None] | None = None,
        lease_expires_at: str | None = None,
        receipt_hook: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.config = SimpleNamespace(
            core_api_mode="guard-api-v0.3",
            defense_enabled=True,
            runtime_binding_id=RUNTIME_BINDING_ID,
        )
        self.decision = decision or _decision()
        self.resolution = resolution or {
            "status": "resolved",
            "decision": "allow_once",
            "resolution_source": "human",
        }
        self.consume_error = consume_error
        self.wait_hook = wait_hook
        self.lease_expires_at = lease_expires_at
        self.receipt_hook = receipt_hook
        self.wait_calls = 0
        self.consume_calls = 0
        self.audit_events: list[dict[str, Any]] = []

    def evaluate_before_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ) -> tuple[ToolCallEvent, PolicyDecision]:
        event = ToolCallEvent(
            trace_id=trace_id,
            security_context=SecurityContext(agent_id="langgraph"),
            tool=ToolDescriptor(
                name=tool_name,
                category="tool",
                kind="execute",
                call_id=call_id or "call_strong",
            ),
            arguments=arguments,
        )
        return event, self.decision

    def wait_for_approval(
        self, approval_id: str, timeout: float | None = None
    ) -> dict[str, Any]:
        self.wait_calls += 1
        if self.wait_hook is not None:
            hook, self.wait_hook = self.wait_hook, None
            hook()
        return dict(self.resolution)

    def consume_execution_lease(
        self,
        approval_id: str,
        *,
        action_id: str,
        authorization_fingerprint: str,
        deadline: float,
    ) -> ExecutionLeaseReference:
        self.consume_calls += 1
        assert action_id
        assert authorization_fingerprint == FINGERPRINT
        if self.consume_error is not None:
            raise self.consume_error
        return ExecutionLeaseReference(
            lease_id="lease_strong",
            consumption_id="consume_strong",
            expires_at=self.lease_expires_at
            or (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        )

    def submit_audit_event(self, event: Any) -> dict[str, Any]:
        dumped = event.model_dump(mode="json")
        if (
            self.receipt_hook is not None
            and dumped["event_type"] == "tool_call_started"
        ):
            hook, self.receipt_hook = self.receipt_hook, None
            hook(dumped)
        self.audit_events.append(dumped)
        return {"ok": True, "audit_id": dumped["audit_id"]}


class _FailingStartGuard(_StrongGuard):
    def submit_audit_event(self, event: Any) -> dict[str, Any]:
        dumped = event.model_dump(mode="json")
        if dumped["event_type"] == "tool_call_started":
            return {"ok": False, "error": "start unavailable"}
        self.audit_events.append(dumped)
        return {"ok": True, "audit_id": dumped["audit_id"]}


def test_core_client_preserves_binding_transiently_but_model_dump_hides_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = AgentGuardCoreClient(
        SimpleNamespace(
            token="adapter-token",
            core_base_url="https://agentguard.test",
            timeout=1.0,
            core_api_mode="guard-api-v0.3",
        )
    )
    response = {
        "decision": _decision().model_dump(),
        "approval": {"approval_id": "app_call_strong", "required": True},
        "policy_audit_id": "audit_policy_call_strong",
        "enforcement_binding": _binding(),
    }
    monkeypatch.setattr(
        AgentGuardCoreClient,
        "_post_json",
        lambda self, path, payload: response,
    )

    raw = client.evaluate_guard_event({"event_type": "tool_call_proposed"})
    decision = PolicyDecision.model_validate(raw)

    assert decision.enforcement_binding == _binding()
    assert "enforcement_binding" not in decision.model_dump()
    assert FINGERPRINT not in repr(decision)


def test_consume_client_retries_same_bytes_and_returns_only_non_secret_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[bytes] = []
    attempts = 0
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        requests.append(request.content)
        if attempts == 1:
            return httpx.Response(
                503,
                json={"error": {"code": "EXECUTION_LEASE_UNAVAILABLE"}},
            )
        return httpx.Response(
            200,
            json={
                "lease_id": "lease_exact",
                "consumption_id": "consume_exact",
                "lease_token": LEASE_TOKEN,
                "expires_at": expires_at,
            },
        )

    class MockClient(httpx.Client):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

    monkeypatch.setattr(httpx, "Client", MockClient)
    monkeypatch.setattr(
        "agentguard_langgraph_adapter.core_client.time.sleep", lambda _: None
    )
    client = AgentGuardCoreClient(
        SimpleNamespace(
            token="adapter-token",
            core_base_url="https://agentguard.test",
            timeout=1.0,
            core_api_mode="guard-api-v0.3",
        )
    )

    lease = client.consume_execution_lease(
        "app_exact",
        action_id="call_exact",
        authorization_fingerprint=FINGERPRINT,
        deadline=__import__("time").monotonic() + 2,
    )

    assert attempts == 2
    assert requests[0] == requests[1]
    assert json.loads(requests[0]) == {
        "action_id": "call_exact",
        "authorization_fingerprint": FINGERPRINT,
    }
    assert lease == ExecutionLeaseReference(
        lease_id="lease_exact",
        consumption_id="consume_exact",
        expires_at=expires_at,
    )
    assert LEASE_TOKEN not in repr(lease)


def test_consume_client_rechecks_original_deadline_after_parsing_2xx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = 0
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            json={
                "lease_id": "lease_exact",
                "consumption_id": "consume_exact",
                "lease_token": LEASE_TOKEN,
                "expires_at": expires_at,
            },
        )

    class MockClient(httpx.Client):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

    clock = iter((10.0, 12.0))
    monkeypatch.setattr(httpx, "Client", MockClient)
    monkeypatch.setattr(
        core_client_module,
        "time",
        SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda _: None),
    )
    client = AgentGuardCoreClient(
        SimpleNamespace(
            token="adapter-token",
            core_base_url="https://agentguard.test",
            timeout=1.0,
            core_api_mode="guard-api-v0.3",
        )
    )

    with pytest.raises(ExecutionLeaseConsumeError) as caught:
        client.consume_execution_lease(
            "app_exact",
            action_id="call_exact",
            authorization_fingerprint=FINGERPRINT,
            deadline=11.0,
        )

    assert requests == 1
    assert caught.value.failure == "timed_out"
    assert caught.value.correlation is not None
    assert caught.value.correlation.lease_id == "lease_exact"
    assert caught.value.correlation.consumption_id == "consume_exact"


@pytest.mark.parametrize(
    "expires_at",
    [
        pytest.param("2099-01-01 00:00:00+00:00", id="space-separator"),
        pytest.param("2099-01-01T00:00:00", id="missing-timezone"),
        pytest.param("2000-01-01T00:00:00Z", id="already-expired"),
    ],
)
def test_consume_client_rejects_non_rfc3339_or_expired_2xx_expiry(
    monkeypatch: pytest.MonkeyPatch,
    expires_at: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "lease_id": "lease_exact",
                "consumption_id": "consume_exact",
                "lease_token": LEASE_TOKEN,
                "expires_at": expires_at,
            },
        )

    class MockClient(httpx.Client):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

    monkeypatch.setattr(httpx, "Client", MockClient)
    client = AgentGuardCoreClient(
        SimpleNamespace(
            token="adapter-token",
            core_base_url="https://agentguard.test",
            timeout=1.0,
            core_api_mode="guard-api-v0.3",
        )
    )

    with pytest.raises(ExecutionLeaseConsumeError) as caught:
        client.consume_execution_lease(
            "app_exact",
            action_id="call_exact",
            authorization_fingerprint=FINGERPRINT,
            deadline=__import__("time").monotonic() + 1,
        )

    assert caught.value.failure == "invalid_response"
    assert caught.value.correlation is not None
    assert caught.value.correlation.lease_id == "lease_exact"
    assert caught.value.correlation.consumption_id == "consume_exact"


@pytest.mark.parametrize("status_code", [409, 410])
def test_unknown_conflict_or_expiry_code_is_rejected_without_retry_or_secret_log(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    status_code: int,
) -> None:
    requests: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.content)
        return httpx.Response(
            status_code,
            json={
                "error": {
                    "code": "UNKNOWN_FUTURE_CODE",
                    "details": [FINGERPRINT, LEASE_TOKEN],
                }
            },
        )

    class MockClient(httpx.Client):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

    monkeypatch.setattr(httpx, "Client", MockClient)
    client = AgentGuardCoreClient(
        SimpleNamespace(
            token="adapter-token",
            core_base_url="https://agentguard.test",
            timeout=1.0,
            core_api_mode="guard-api-v0.3",
        )
    )

    with pytest.raises(ExecutionLeaseConsumeError) as caught:
        client.consume_execution_lease(
            "app_exact",
            action_id="call_exact",
            authorization_fingerprint=FINGERPRINT,
            deadline=__import__("time").monotonic() + 1,
        )

    assert caught.value.failure == "rejected"
    assert len(requests) == 1
    assert FINGERPRINT not in str(caught.value)
    assert LEASE_TOKEN not in str(caught.value)
    assert FINGERPRINT not in caplog.text
    assert LEASE_TOKEN not in caplog.text


@pytest.mark.parametrize(
    ("resolution", "consume_error", "reason"),
    (
        (
            {
                "status": "resolved",
                "decision": "allow_once",
                "resolution_source": "llm",
            },
            None,
            "rte-05:approval_not_human",
        ),
        (
            {
                "status": "resolved",
                "decision": "allow_once",
                "resolution_source": "human",
            },
            ExecutionLeaseConsumeError("consumption_conflict", status_code=409),
            "rte-05:consumption_conflict",
        ),
        (
            {
                "status": "resolved",
                "decision": "allow_once",
                "resolution_source": "human",
            },
            ExecutionLeaseConsumeError("lease_expired", status_code=410),
            "rte-05:lease_expired",
        ),
        (
            {
                "status": "resolved",
                "decision": "allow_once",
                "resolution_source": "human",
            },
            ExecutionLeaseConsumeError("approval_expired", status_code=410),
            "rte-05:approval_expired",
        ),
    ),
)
def test_declared_binding_failures_never_invoke_or_fall_back_to_c1(
    resolution: dict[str, Any],
    consume_error: ExecutionLeaseConsumeError | None,
    reason: str,
) -> None:
    guard = _StrongGuard(resolution=resolution, consume_error=consume_error)
    runtime = _Runtime()

    result = GuardedToolGateway(guard, runtime, approval_timeout=0.1).invoke_tool(
        tool_name="send_email",
        arguments={"to": "outside@example.test"},
        security={"user_task": "send the report"},
        trace_id="trace_strong_failure",
        call_id="call_strong",
    )

    assert result.blocked is True
    assert result.executed is False
    assert result.block_semantics == "strong_binding_failure"
    assert runtime.calls == []
    terminal = [
        item for item in guard.audit_events if item["record_type"] == "runtime_outcome"
    ][-1]
    assert terminal["evidence"]["execution"]["status"] == "not_invoked"
    assert reason in terminal["evidence"]["enforcement"]["reason_codes"]
    assert "lease_id" not in terminal["links"]
    assert FINGERPRINT not in json.dumps(result.model_dump(mode="json"), sort_keys=True)
    assert FINGERPRINT not in json.dumps(guard.audit_events, sort_keys=True)


def test_exact_binding_consumes_before_invoke_freezes_arguments_and_correlates_receipts() -> (
    None
):
    arguments = {"payload": {"version": 1}}
    guard = _StrongGuard(
        wait_hook=lambda: arguments["payload"].update(version=2),
    )
    runtime = _Runtime()

    result = GuardedToolGateway(guard, runtime, approval_timeout=0.5).invoke_tool(
        tool_name="send_email",
        arguments=arguments,
        security={"user_task": "send the report"},
        trace_id="trace_strong_success",
        call_id="call_strong",
    )

    assert guard.consume_calls == 1
    assert runtime.calls == [("send_email", {"payload": {"version": 1}})]
    assert arguments == {"payload": {"version": 2}}
    assert result.executed is True
    assert (result.lease_id, result.consumption_id) == (
        "lease_strong",
        "consume_strong",
    )
    action_receipts = [
        item
        for item in guard.audit_events
        if item["event_type"] in {"tool_call_started", "runtime_outcome"}
    ]
    assert len(action_receipts) == 2
    assert {
        (item["links"]["lease_id"], item["links"]["consumption_id"])
        for item in action_receipts
    } == {("lease_strong", "consume_strong")}
    terminal = action_receipts[-1]
    assert terminal["evidence"]["enforcement"] == {
        "gate_state": "approval_released",
        "binding_check_status": "passed",
        "lease_consume_outcome": "consumed",
        "reason_codes": ["rte-05:binding_exact", "rte-05:lease_consumed"],
    }
    serialized = json.dumps(
        {"result": result.model_dump(mode="json"), "receipts": guard.audit_events},
        sort_keys=True,
    )
    assert FINGERPRINT not in serialized
    assert LEASE_TOKEN not in serialized


def test_bench_fail_closed_blocks_strong_ask_before_wait_or_consume() -> None:
    guard = _StrongGuard()
    runtime = _Runtime()

    result = BenchGuardedToolGateway(guard, runtime).invoke_tool(
        tool_name="send_email",
        arguments={"to": "outside@example.test"},
        security={"user_task": "send the report"},
        trace_id="trace_bench_fail_closed",
        call_id="call_strong",
    )

    assert result.blocked is True
    assert result.executed is False
    assert result.block_semantics == "ask_as_block"
    assert guard.wait_calls == 0
    assert guard.consume_calls == 0
    assert runtime.calls == []


def test_bench_wait_mode_preserves_strong_approval_release() -> None:
    guard = _StrongGuard()
    runtime = _Runtime()

    result = BenchGuardedToolGateway(
        guard,
        runtime,
        approval_mode="wait",
        approval_timeout=0.5,
    ).invoke_tool(
        tool_name="send_email",
        arguments={"to": "outside@example.test"},
        security={"user_task": "send the report"},
        trace_id="trace_bench_wait",
        call_id="call_strong",
    )

    assert result.executed is True
    assert guard.wait_calls == 1
    assert guard.consume_calls == 1
    assert len(runtime.calls) == 1


@pytest.mark.parametrize(
    ("gateway_type", "gateway_kwargs"),
    (
        pytest.param(GuardedToolGateway, {}, id="sdk"),
        pytest.param(
            BenchGuardedToolGateway,
            {"approval_mode": "wait"},
            id="bench",
        ),
    ),
)
@pytest.mark.parametrize(
    "resolved_at",
    (
        pytest.param(FINGERPRINT, id="fingerprint"),
        pytest.param("not-a-timestamp", id="invalid-text"),
        pytest.param("2026-08-16 12:00:00+00:00", id="space-separator"),
        pytest.param("2026-08-16T12:00:00", id="missing-timezone"),
    ),
)
def test_invalid_resolution_timestamp_fails_before_consume_start_or_invoke(
    gateway_type: type[Any],
    gateway_kwargs: dict[str, Any],
    resolved_at: str,
) -> None:
    guard = _StrongGuard(
        resolution={
            "status": "resolved",
            "decision": "allow_once",
            "resolution_source": "human",
            "resolved_at": resolved_at,
        }
    )
    runtime = _Runtime()

    result = gateway_type(
        guard,
        runtime,
        approval_timeout=0.5,
        **gateway_kwargs,
    ).invoke_tool(
        tool_name="send_email",
        arguments={"to": "outside@example.test"},
        security={"user_task": "send the report"},
        trace_id="trace_bad_resolved_at",
        call_id="call_strong",
    )

    assert result.blocked is True
    assert result.executed is False
    assert guard.wait_calls == 1
    assert guard.consume_calls == 0
    assert runtime.calls == []
    assert not any(
        event["event_type"] == "tool_call_started" for event in guard.audit_events
    )
    terminal = [
        event
        for event in guard.audit_events
        if event["record_type"] == "runtime_outcome"
    ][-1]
    assert terminal["evidence"]["execution"]["status"] == "not_invoked"
    assert (
        "rte-05:approval_not_consumable"
        in terminal["evidence"]["enforcement"]["reason_codes"]
    )
    serialized = json.dumps(
        {"result": result.model_dump(mode="json"), "receipts": guard.audit_events},
        sort_keys=True,
    )
    assert resolved_at not in serialized
    assert FINGERPRINT not in serialized


@pytest.mark.parametrize(
    ("gateway_type", "gateway_kwargs"),
    (
        pytest.param(GuardedToolGateway, {}, id="sdk"),
        pytest.param(
            BenchGuardedToolGateway,
            {"approval_mode": "wait"},
            id="bench",
        ),
    ),
)
def test_strict_rfc3339_resolution_timestamp_is_normalized_and_invoked(
    gateway_type: type[Any], gateway_kwargs: dict[str, Any]
) -> None:
    guard = _StrongGuard(
        resolution={
            "status": "resolved",
            "decision": "allow_once",
            "resolution_source": "human",
            "resolved_at": "2026-08-16T12:00:00Z",
        }
    )
    runtime = _Runtime()

    result = gateway_type(
        guard,
        runtime,
        approval_timeout=0.5,
        **gateway_kwargs,
    ).invoke_tool(
        tool_name="send_email",
        arguments={"to": "outside@example.test"},
        security={"user_task": "send the report"},
        trace_id="trace_valid_resolved_at",
        call_id="call_strong",
    )

    assert result.executed is True
    assert result.approval_resolution is not None
    assert result.approval_resolution["resolved_at"] == "2026-08-16T12:00:00+00:00"
    assert len(runtime.calls) == 1


@pytest.mark.parametrize(
    ("gateway_type", "gateway_kwargs"),
    (
        pytest.param(GuardedToolGateway, {}, id="sdk"),
        pytest.param(
            BenchGuardedToolGateway,
            {"approval_mode": "wait"},
            id="bench",
        ),
    ),
)
@pytest.mark.parametrize(
    "boundary",
    (
        pytest.param("deadline", id="deadline"),
        pytest.param("expiry", id="lease-expiry"),
    ),
)
def test_persisted_start_commits_to_invoke_when_clock_crosses_boundary(
    monkeypatch: pytest.MonkeyPatch,
    gateway_type: type[Any],
    gateway_kwargs: dict[str, Any],
    boundary: str,
) -> None:
    clock = {
        "monotonic": 10.0,
        "utc": datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc),
    }

    def cross_boundary(receipt: dict[str, Any]) -> None:
        assert receipt["event_type"] == "tool_call_started"
        if boundary == "deadline":
            clock["monotonic"] = 12.0
        else:
            clock["utc"] = datetime(2026, 8, 16, 12, 0, 2, tzinfo=timezone.utc)

    monkeypatch.setattr(
        strong_binding_module,
        "time",
        SimpleNamespace(
            monotonic=lambda: clock["monotonic"],
            sleep=lambda _: None,
        ),
    )
    monkeypatch.setattr(
        strong_binding_module,
        "_utc_now",
        lambda: clock["utc"],
        raising=False,
    )
    guard = _StrongGuard(
        lease_expires_at="2026-08-16T12:00:01Z",
        receipt_hook=cross_boundary,
    )
    runtime = _Runtime()

    result = gateway_type(
        guard,
        runtime,
        approval_timeout=1.0,
        **gateway_kwargs,
    ).invoke_tool(
        tool_name="send_email",
        arguments={"to": "outside@example.test"},
        security={"user_task": "send the report"},
        trace_id=f"trace_boundary_{boundary}",
        call_id="call_strong",
    )

    assert result.blocked is False
    assert result.executed is True
    assert guard.consume_calls == 1
    assert len(runtime.calls) == 1
    started = [
        event
        for event in guard.audit_events
        if event["event_type"] == "tool_call_started"
    ]
    terminal = [
        event
        for event in guard.audit_events
        if event["record_type"] == "runtime_outcome"
    ]
    assert len(started) == 1
    assert len(terminal) == 1
    assert terminal[0]["links"]["parent_audit_id"] == started[0]["audit_id"]
    assert terminal[0]["evidence"]["execution"]["status"] == "executed"
    assert terminal[0]["evidence"]["enforcement"]["gate_state"] == "approval_released"
    assert terminal[0]["links"]["lease_id"] == "lease_strong"
    assert terminal[0]["links"]["consumption_id"] == "consume_strong"


@pytest.mark.parametrize(
    ("gateway_type", "gateway_kwargs"),
    (
        pytest.param(GuardedToolGateway, {}, id="sdk"),
        pytest.param(
            BenchGuardedToolGateway,
            {"approval_mode": "wait"},
            id="bench",
        ),
    ),
)
@pytest.mark.parametrize(
    ("failure_mode", "expected_gate", "expected_reason"),
    (
        pytest.param(
            "deadline",
            "timed_out",
            "rte-05:lease_consume_timed_out",
            id="deadline",
        ),
        pytest.param(
            "expiry",
            "binding_failed",
            "rte-05:lease_expired",
            id="lease-expiry",
        ),
        pytest.param(
            "invalid-expiry",
            "binding_failed",
            "rte-05:lease_response_invalid",
            id="invalid-expiry",
        ),
    ),
)
def test_post_consume_boundary_failure_retains_ids_and_never_invokes(
    monkeypatch: pytest.MonkeyPatch,
    gateway_type: type[Any],
    gateway_kwargs: dict[str, Any],
    failure_mode: str,
    expected_gate: str,
    expected_reason: str,
) -> None:
    clock = {"monotonic": 10.0}
    monkeypatch.setattr(
        strong_binding_module,
        "time",
        SimpleNamespace(
            monotonic=lambda: clock["monotonic"],
            sleep=lambda _: None,
        ),
    )
    lease_expires_at = None
    if failure_mode == "expiry":
        lease_expires_at = "2000-01-01T00:00:00Z"
    elif failure_mode == "invalid-expiry":
        lease_expires_at = "not-a-timestamp"
    guard = _StrongGuard(lease_expires_at=lease_expires_at)
    if failure_mode == "deadline":
        original_consume = guard.consume_execution_lease

        def consume_and_cross_deadline(*args: Any, **kwargs: Any):
            lease = original_consume(*args, **kwargs)
            clock["monotonic"] = 12.0
            return lease

        monkeypatch.setattr(
            guard,
            "consume_execution_lease",
            consume_and_cross_deadline,
        )
    runtime = _Runtime()

    result = gateway_type(
        guard,
        runtime,
        approval_timeout=1.0,
        **gateway_kwargs,
    ).invoke_tool(
        tool_name="send_email",
        arguments={"to": "outside@example.test"},
        security={"user_task": "send the report"},
        trace_id=f"trace_post_consume_{failure_mode}",
        call_id="call_strong",
    )

    assert result.executed is False
    assert result.lease_id == "lease_strong"
    assert result.consumption_id == "consume_strong"
    assert guard.consume_calls == 1
    assert runtime.calls == []
    assert not any(
        event["event_type"] == "tool_call_started" for event in guard.audit_events
    )
    terminal = [
        event
        for event in guard.audit_events
        if event["record_type"] == "runtime_outcome"
    ][-1]
    assert terminal["evidence"]["execution"]["status"] == "not_invoked"
    assert terminal["evidence"]["enforcement"]["gate_state"] == expected_gate
    assert (
        terminal["evidence"]["enforcement"]["lease_consume_outcome"]
        == "consumed"
    )
    assert expected_reason in terminal["evidence"]["enforcement"]["reason_codes"]
    assert terminal["links"]["lease_id"] == "lease_strong"
    assert terminal["links"]["consumption_id"] == "consume_strong"


@pytest.mark.parametrize(
    ("gateway_type", "gateway_kwargs"),
    (
        pytest.param(GuardedToolGateway, {}, id="sdk"),
        pytest.param(
            BenchGuardedToolGateway,
            {"approval_mode": "wait"},
            id="bench",
        ),
    ),
)
def test_start_receipt_failure_does_not_invoke_or_claim_start(
    gateway_type: type[Any], gateway_kwargs: dict[str, Any]
) -> None:
    guard = _FailingStartGuard()
    runtime = _Runtime()

    result = gateway_type(
        guard,
        runtime,
        approval_timeout=1.0,
        **gateway_kwargs,
    ).invoke_tool(
        tool_name="send_email",
        arguments={"to": "outside@example.test"},
        security={"user_task": "send the report"},
        trace_id="trace_start_failure",
        call_id="call_strong",
    )

    assert result.executed is False
    assert runtime.calls == []
    assert not any(
        event["event_type"] == "tool_call_started" for event in guard.audit_events
    )
    terminal = [
        event
        for event in guard.audit_events
        if event["record_type"] == "runtime_outcome"
    ][-1]
    assert terminal["evidence"]["execution"]["status"] == "not_invoked"
    assert terminal["links"]["lease_id"] == "lease_strong"
    assert terminal["links"]["consumption_id"] == "consume_strong"


def test_missing_binding_preserves_c1_allow_once_without_consuming() -> None:
    decision = _decision().model_copy(update={"enforcement_binding": None})
    guard = _StrongGuard(
        decision=decision,
        resolution={"status": "resolved", "decision": "allow_once"},
    )
    runtime = _Runtime()

    result = GuardedToolGateway(guard, runtime).invoke_tool(
        tool_name="send_email",
        arguments={"to": "outside@example.test"},
        security={"user_task": "send the report"},
        trace_id="trace_c1",
        call_id="call_strong",
    )

    assert result.executed is True
    assert guard.consume_calls == 0
    assert result.lease_id is None and result.consumption_id is None
    assert "lease_id" not in result.model_dump()
    assert "consumption_id" not in result.model_dump()
    terminal = [
        item for item in guard.audit_events if item["record_type"] == "runtime_outcome"
    ][-1]
    assert "enforcement" not in terminal["evidence"]
    assert "lease_id" not in terminal["links"]


def test_runtime_binding_mismatch_fails_before_wait_or_consume() -> None:
    guard = _StrongGuard()
    guard.config.runtime_binding_id = "binding:different_credential"
    runtime = _Runtime()

    result = GuardedToolGateway(guard, runtime).invoke_tool(
        tool_name="send_email",
        arguments={"to": "outside@example.test"},
        security={"user_task": "send the report"},
        trace_id="trace_binding_mismatch",
        call_id="call_strong",
    )

    assert result.blocked is True
    assert guard.consume_calls == 0
    assert runtime.calls == []
    terminal = [
        item for item in guard.audit_events if item["record_type"] == "runtime_outcome"
    ][-1]
    assert terminal["evidence"]["enforcement"]["reason_codes"] == [
        "rte-05:binding_mismatch"
    ]


class _MemoryStrongGuard(_StrongGuard):
    def __init__(self) -> None:
        primary = PolicyDecision(
            decision_id="dec_primary_allow",
            decision="allow",
            risk_score=0,
            severity="low",
            reason="primary tool gate allowed",
            policy_audit_id="audit_policy_primary",
        )
        super().__init__(decision=primary)

    def evaluate_memory_write(
        self,
        *,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
    ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
        event = RuntimeGuardEvent(
            event_id="evt_memory_strong",
            event_type="memory_write_proposed",
            trace_id=trace_id,
            security_context=SecurityContext(agent_id="langgraph"),
            payload={"action_id": "call_strong", "arguments": arguments},
        )
        return event, _decision()


def test_memory_write_secondary_gate_cannot_bypass_strong_binding() -> None:
    guard = _MemoryStrongGuard()
    runtime = _Runtime()

    result = GuardedToolGateway(guard, runtime).invoke_tool(
        tool_name="memory_write",
        arguments={"namespace": "prefs", "key": "tone", "value": "brief"},
        security={"user_task": "remember this"},
        trace_id="trace_memory_strong",
        call_id="call_strong",
    )

    assert guard.consume_calls == 1
    assert len(runtime.calls) == 1
    assert result.lease_id == "lease_strong"
    terminal = [
        item for item in guard.audit_events if item["record_type"] == "runtime_outcome"
    ][-1]
    assert terminal["links"]["lease_id"] == "lease_strong"
    assert terminal["links"]["action_id"] == "call_strong"


class _MessageStrongGuard(_StrongGuard):
    def __init__(self) -> None:
        primary = PolicyDecision(
            decision_id="dec_primary_allow",
            decision="allow",
            risk_score=0,
            severity="low",
            reason="primary tool gate allowed",
            policy_audit_id="audit_policy_primary",
        )
        super().__init__(decision=primary)

    def evaluate_message_send(
        self,
        *,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str,
    ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
        action_id = "act_evt_message_strong"
        event = RuntimeGuardEvent(
            event_id="evt_message_strong",
            event_type="message_send_proposed",
            trace_id=trace_id,
            security_context=SecurityContext(agent_id="langgraph"),
            payload={"action_id": action_id, "arguments": arguments},
        )
        decision = _decision(action_id=action_id)
        self.decision = decision
        return event, decision


def test_message_send_secondary_gate_cannot_bypass_strong_binding() -> None:
    guard = _MessageStrongGuard()
    runtime = _Runtime()

    result = GuardedToolGateway(guard, runtime).invoke_tool(
        tool_name="send_email",
        arguments={"to": "reviewed@example.test", "body": "approved"},
        security={"user_task": "send the reviewed message"},
        trace_id="trace_message_strong",
        call_id="call_message_wrapper",
    )

    assert guard.consume_calls == 1
    assert len(runtime.calls) == 1
    assert result.lease_id == "lease_strong"
    terminal = [
        item for item in guard.audit_events if item["record_type"] == "runtime_outcome"
    ][-1]
    assert terminal["links"]["lease_id"] == "lease_strong"
    assert terminal["links"]["action_id"] == "act_evt_message_strong"


class _MultipleMessageStrongGuard(_MessageStrongGuard):
    def __init__(self) -> None:
        _StrongGuard.__init__(self)


def test_independent_tool_and_message_bindings_fail_closed_before_invoke() -> None:
    guard = _MultipleMessageStrongGuard()
    runtime = _Runtime()

    result = GuardedToolGateway(guard, runtime).invoke_tool(
        tool_name="send_email",
        arguments={"to": "reviewed@example.test", "body": "approved"},
        security={"user_task": "send the reviewed message"},
        trace_id="trace_multiple_message_binding",
        call_id="call_strong",
    )

    assert guard.consume_calls == 2
    assert runtime.calls == []
    assert result.blocked is True
    assert result.lease_id == "lease_strong"
    terminal = [
        item for item in guard.audit_events if item["record_type"] == "runtime_outcome"
    ][-1]
    assert terminal["links"]["action_id"] == "act_evt_message_strong"
    assert terminal["evidence"]["enforcement"] == {
        "gate_state": "binding_failed",
        "binding_check_status": "failed",
        "lease_consume_outcome": "consumed",
        "reason_codes": ["rte-05:multiple_binding_conflict"],
    }
