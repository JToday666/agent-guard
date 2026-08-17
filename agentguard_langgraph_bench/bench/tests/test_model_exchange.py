from __future__ import annotations

from types import SimpleNamespace

import pytest

from agentguard_langgraph_bench.bench.model_exchange import (
    ModelExchangeError,
    ModelExchangeInvocationError,
    ModelExchangeOutcome,
    build_canonical_input_digests,
    invoke_with_model_exchange,
    normalize_openai_base_url,
    resolve_api_key,
)


def _invoke(**overrides):
    values = {
        "model_input": [("system", "fixed protocol"), ("user", "public task")],
        "sources": [
            {"source_id": "protocol", "role": "system", "content": "fixed protocol"},
            {"source_id": "task", "role": "user", "content": "public task"},
        ],
        "tool_schemas": [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "parameters": {"type": "object"},
                },
            }
        ],
        "authority_binding": {"task_id": "task-1"},
        "case_id": "BN-001",
        "arm_id": "A4",
        "repeat_index": 0,
        "round_index": 1,
        "provider_id": "local-compatible",
        "model": "stub-model",
        "base_url": "http://127.0.0.1:43111/v1/",
        "context_mode": "required",
        "context_plan_digest": "sha256:" + "1" * 64,
        "transform_applied": True,
    }
    values.update(overrides)
    return invoke_with_model_exchange(**values)


def test_canonical_input_digests_are_stable_and_order_sensitive() -> None:
    first = build_canonical_input_digests(
        sources=[{"id": "one"}, {"id": "two"}],
        authority_binding={"task": "task-1"},
        model_input=[("system", "fixed"), ("user", "task")],
        tool_schemas=[{"name": "read_file"}],
    )
    same = build_canonical_input_digests(
        sources=[{"id": "one"}, {"id": "two"}],
        authority_binding={"task": "task-1"},
        model_input=[("system", "fixed"), ("user", "task")],
        tool_schemas=[{"name": "read_file"}],
    )
    reordered = build_canonical_input_digests(
        sources=[{"id": "two"}, {"id": "one"}],
        authority_binding={"task": "task-1"},
        model_input=[("system", "fixed"), ("user", "task")],
        tool_schemas=[{"name": "read_file"}],
    )

    assert first == same
    assert first.source_set_digest != reordered.source_set_digest
    assert set(first.public_dump()) == {
        "schema_version",
        "source_set_digest",
        "authority_binding_digest",
        "model_input_digest",
        "tool_schema_digest",
        "source_count",
        "message_count",
        "tool_schema_count",
    }


def test_successful_invoke_emits_display_safe_real_exchange_evidence() -> None:
    secret = "sk-secret-must-not-appear"

    class StubInvoker:
        def invoke(self, messages):
            assert messages[-1][1] == "public task"
            return SimpleNamespace(
                id="chatcmpl-local-1",
                content="",
                tool_calls=[
                    {"name": "read_file", "args": {"path": "/docs/public.txt"}}
                ],
                response_metadata={"request_id": "request-local-1"},
            )

    response, evidence = _invoke(invoker=StubInvoker())

    assert response.tool_calls[0]["name"] == "read_file"
    assert evidence.model_invoked is True
    assert evidence.outcome is ModelExchangeOutcome.SUCCESS
    assert evidence.tool_names == ("read_file",)
    assert evidence.context_plan_digest == "sha256:" + "1" * 64
    public = evidence.public_dump()
    assert "messages" not in public
    assert "response" not in public
    assert secret not in repr(public)
    assert public["endpoint_identity_digest"].startswith("sha256:")


def test_failed_invoke_preserves_attempt_evidence_without_exception_text() -> None:
    class FailingInvoker:
        def invoke(self, messages):
            raise TimeoutError("provider timeout with sk-private-detail")

    with pytest.raises(ModelExchangeInvocationError) as captured:
        _invoke(invoker=FailingInvoker())

    assert str(captured.value) == "model invocation failed: timeout"
    evidence = captured.value.evidence
    assert evidence.outcome is ModelExchangeOutcome.TIMEOUT
    assert evidence.request_observed is True
    assert evidence.response_observed is False
    assert "sk-private-detail" not in repr(evidence.public_dump())


@pytest.mark.parametrize(
    "value",
    [
        "http://provider.example/v1",
        "https://user:password@provider.example/v1",
        "https://provider.example/v1?token=secret",
        "file:///tmp/provider",
    ],
)
def test_provider_url_rejects_insecure_or_secret_bearing_values(value: str) -> None:
    with pytest.raises(ModelExchangeError):
        normalize_openai_base_url(value)


def test_key_resolution_uses_only_the_named_environment_variable() -> None:
    assert (
        resolve_api_key(
            "CUSTOM_PROVIDER_KEY", environ={"CUSTOM_PROVIDER_KEY": "secret"}
        )
        == "secret"
    )
    with pytest.raises(ModelExchangeError, match="credential is unavailable"):
        resolve_api_key("CUSTOM_PROVIDER_KEY", environ={"OPENAI_API_KEY": "wrong"})
