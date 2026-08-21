from __future__ import annotations

import pytest

from agentguard_core import (
    ApprovalIntent,
    AuditEvent,
    GuardDecision,
    GuardEvent,
    PolicyBundle,
)
from guard_api.services.evidence import build_audit_event


def _event(event_type: str, payload: dict[str, object]) -> GuardEvent:
    return GuardEvent.model_validate(
        {
            "event_id": f"evt_{event_type}",
            "event_type": event_type,
            "runtime": "langgraph",
            "trace_id": "trace_action_links",
            "security_context": {"user_task": "完成受控任务"},
            "payload": payload,
        }
    )


def _decision(value: str = "allow") -> GuardDecision:
    return GuardDecision(
        decision_id=f"dec_{value}",
        decision=value,
        risk_score=50 if value == "ask" else 0,
        severity="medium" if value == "ask" else "low",
        categories=[],
        rule_hits=[],
        reason="Test decision.",
        safe_message=None,
        approval_intent=ApprovalIntent(resource="") if value == "ask" else None,
        latency_ms=1,
    )


def _audit(
    event: GuardEvent,
    *,
    decision: GuardDecision | None = None,
    approval_id: str | None = None,
) -> AuditEvent:
    return build_audit_event(
        event,
        decision or _decision(),
        policy_bundle=PolicyBundle(),
        policy_revision=None,
        approval_id=approval_id,
    )


@pytest.mark.parametrize(
    ("event_type", "payload"),
    [
        (
            "context_assembled",
            {"sources": [], "will_enter_context": True, "sanitized": False},
        ),
        (
            "model_input_prepared",
            {
                "phase": "input",
                "content_preview": "task",
                "contains_instruction_like_text": False,
                "contains_sensitive_data": False,
                "sanitized": False,
            },
        ),
    ],
)
def test_routine_guard_hooks_do_not_claim_an_execution_action(
    event_type: str,
    payload: dict[str, object],
) -> None:
    audit = _audit(_event(event_type, payload))

    assert "action_id" not in audit.links
    assert "action_id" not in audit.metadata
    assert "action_name" not in audit.metadata


def test_context_payload_sources_are_preserved_in_browser_safe_evidence() -> None:
    audit = _audit(
        _event(
            "context_assembled",
            {
                "sources": [
                    {
                        "source_id": "message_001",
                        "source_type": "conversation",
                        "source_trust": "untrusted",
                        "summary": "untrusted context",
                        "contains_instruction_like_text": False,
                        "contains_sensitive_data": False,
                    }
                ],
                "will_enter_context": True,
                "sanitized": False,
            },
        )
    )

    guard_event = audit.evidence["guard_event"]
    assert isinstance(guard_event, dict)
    assert guard_event["context_sources"] == [
        {
            "source_id": "message_001",
            "source_type": "conversation",
            "source_trust": "untrusted",
            "summary": "untrusted context",
            "contains_instruction_like_text": False,
            "contains_sensitive_data": False,
        }
    ]


def test_approval_gated_guard_hook_retains_a_stable_action_link() -> None:
    event = _event(
        "model_input_prepared",
        {
            "phase": "input",
            "content_preview": "task",
            "contains_instruction_like_text": False,
            "contains_sensitive_data": False,
            "sanitized": False,
        },
    )

    audit = _audit(event, decision=_decision("ask"), approval_id="app_model_input")

    assert audit.links["action_id"] == f"act_{event.event_id}"
    assert audit.links["approval_id"] == "app_model_input"


def test_tool_result_reuses_the_original_tool_action_id() -> None:
    audit = _audit(
        _event(
            "tool_result_produced",
            {
                "tool": {"name": "read_file", "call_id": "call_read_001"},
                "result": {
                    "content_preview": "safe result",
                    "content_type": "text/plain",
                    "size_bytes": 11,
                },
                "will_enter_context": True,
                "will_persist": False,
                "sanitized": False,
                "contains_sensitive_data": False,
                "contains_instruction_like_text": False,
            },
        )
    )

    assert audit.links["action_id"] == "call_read_001"
    assert audit.metadata["source_tool_call_id"] == "call_read_001"
    assert audit.metadata["action_name"] == "read_file"


def test_tool_call_uses_the_original_tool_action_id() -> None:
    audit = _audit(
        _event(
            "tool_call_proposed",
            {
                "tool": {"name": "read_file", "call_id": "call_read_002"},
                "arguments": {"path": "/workspace/report.txt"},
                "derived_resources": [],
            },
        )
    )

    assert audit.links["action_id"] == "call_read_002"
    assert audit.metadata["action_id"] == "call_read_002"
    assert audit.metadata["action_name"] == "read_file"


@pytest.mark.parametrize(
    ("event_type", "payload"),
    [
        (
            "model_output_produced",
            {
                "phase": "output",
                "content_preview": "answer",
                "contains_instruction_like_text": False,
                "contains_sensitive_data": False,
                "sanitized": False,
            },
        ),
        (
            "memory_write_proposed",
            {
                "memory": {
                    "namespace": "profile",
                    "key": "summary",
                    "value_preview": "concise",
                    "source_trust": "trusted",
                    "operation": "write",
                },
                "will_persist": True,
                "requires_approval": False,
            },
        ),
        (
            "message_send_proposed",
            {
                "channel": "email",
                "recipient": "team@example.com",
                "content_preview": "status",
                "contains_sensitive_data": False,
                "sanitized": False,
            },
        ),
    ],
)
def test_intrinsic_agent_actions_use_the_canonical_guard_event_action_id(
    event_type: str,
    payload: dict[str, object],
) -> None:
    event = _event(event_type, payload)

    audit = _audit(event)

    assert audit.links["action_id"] == f"act_{event.event_id}"
    assert audit.metadata["action_id"] == f"act_{event.event_id}"


def test_explicit_source_action_id_is_preserved_for_memory_write() -> None:
    audit = _audit(
        _event(
            "memory_write_proposed",
            {
                "action_id": "call_memory_write_001",
                "memory": {
                    "namespace": "profile",
                    "key": "summary",
                    "value_preview": "concise",
                    "source_trust": "trusted",
                    "operation": "write",
                },
                "will_persist": True,
                "requires_approval": False,
            },
        )
    )

    assert audit.links["action_id"] == "call_memory_write_001"
    assert audit.metadata["action_id"] == "call_memory_write_001"
    assert audit.metadata["action_name"] == "memory_write_proposed"


def test_model_output_content_preview_is_projected() -> None:
    audit = _audit(
        _event(
            "model_output_produced",
            {
                "phase": "output",
                "content_preview": "报告已写入 /reports/briefing.txt。",
                "contains_instruction_like_text": False,
                "contains_sensitive_data": False,
                "sanitized": False,
            },
        )
    )

    guard_event = audit.evidence["guard_event"]
    assert isinstance(guard_event, dict)
    assert guard_event["content_preview"] == "报告已写入 /reports/briefing.txt。"


def test_message_send_content_preview_is_projected() -> None:
    audit = _audit(
        _event(
            "message_send_proposed",
            {
                "channel": "email",
                "recipient": "reviewer@example.com",
                "content_preview": "Reviewer briefing summary",
                "contains_sensitive_data": False,
                "sanitized": False,
            },
        )
    )

    guard_event = audit.evidence["guard_event"]
    assert isinstance(guard_event, dict)
    assert guard_event["content_preview"] == "Reviewer briefing summary"


def test_content_preview_is_redacted_like_user_task() -> None:
    audit = _audit(
        _event(
            "model_output_produced",
            {
                "phase": "output",
                "content_preview": "done; Bearer abcdef1234567890 used",
                "contains_instruction_like_text": False,
                "contains_sensitive_data": True,
                "sanitized": False,
            },
        )
    )

    guard_event = audit.evidence["guard_event"]
    assert isinstance(guard_event, dict)
    projected = str(guard_event["content_preview"])
    assert "abcdef1234567890" not in projected
    assert "[redacted]" in projected


def test_content_preview_is_truncated_to_the_frozen_limit() -> None:
    from guard_api.services.redaction import CONTENT_PREVIEW_LIMIT

    audit = _audit(
        _event(
            "model_output_produced",
            {
                "phase": "output",
                "content_preview": "x" * (CONTENT_PREVIEW_LIMIT + 500),
                "contains_instruction_like_text": False,
                "contains_sensitive_data": False,
                "sanitized": False,
            },
        )
    )

    guard_event = audit.evidence["guard_event"]
    assert isinstance(guard_event, dict)
    projected = str(guard_event["content_preview"])
    # truncate_text 语义：前 CONTENT_PREVIEW_LIMIT 字符 + "..." 后缀。
    assert projected == "x" * CONTENT_PREVIEW_LIMIT + "..."


@pytest.mark.parametrize(
    ("event_type", "payload"),
    [
        (
            "model_output_produced",
            {
                "phase": "output",
                "content_preview": "",
                "contains_instruction_like_text": False,
                "contains_sensitive_data": False,
                "sanitized": False,
            },
        ),
        (
            "message_send_proposed",
            {
                "channel": "email",
                "recipient": "reviewer@example.com",
                "content_preview": "",
                "contains_sensitive_data": False,
                "sanitized": False,
            },
        ),
    ],
)
def test_empty_content_preview_omits_the_projection_key(
    event_type: str,
    payload: dict[str, object],
) -> None:
    audit = _audit(_event(event_type, payload))

    guard_event = audit.evidence["guard_event"]
    assert isinstance(guard_event, dict)
    assert "content_preview" not in guard_event


def test_model_input_content_preview_is_not_projected() -> None:
    audit = _audit(
        _event(
            "model_input_prepared",
            {
                "phase": "input",
                "content_preview": "full prompt context",
                "contains_instruction_like_text": False,
                "contains_sensitive_data": False,
                "sanitized": False,
            },
        )
    )

    guard_event = audit.evidence["guard_event"]
    assert isinstance(guard_event, dict)
    assert "content_preview" not in guard_event
