from __future__ import annotations

from agentguard_core import (
    DerivedResource,
    GuardEngine,
    GuardEvent,
    PolicyBundle,
    RuleOverride,
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
    tool_category: str = "tool",
    tool_kind: str | None = None,
    derived_resources: list[DerivedResource] | None = None,
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
            tool=ToolDescriptor(name=tool_name, category=tool_category, kind=tool_kind),
            arguments=arguments,
            derived_resources=derived_resources or [],
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


def test_tool_identity_mismatch_is_denied() -> None:
    decision = evaluate(
        _event(
            tool_name="send_email",
            tool_category="file",
            tool_kind="file_read",
            arguments={"to": "user@agentguard.local", "body": "status"},
            user_task="Email the local status update",
        )
    )

    assert decision.decision == "deny"
    assert decision.risk_score == 88
    assert "tool_hijack" in decision.categories
    assert [hit.rule_id for hit in decision.rule_hits] == ["P002_tool_identity_mismatch"]


def test_tool_resource_direction_mismatch_is_denied() -> None:
    decision = evaluate(
        _event(
            tool_name="read_file",
            tool_category="file",
            tool_kind="file_read",
            arguments={"path": "/docs/public.txt"},
            user_task="Read /docs/public.txt and summarize it",
            derived_resources=[
                DerivedResource(
                    resource_type="message",
                    operation="send",
                    target="external@example.invalid",
                    direction="outbound",
                )
            ],
        )
    )

    assert decision.decision == "deny"
    assert decision.rule_hits[0].rule_id == "P002_tool_identity_mismatch"


def test_policy_bundle_can_disable_builtin_rule() -> None:
    decision = evaluate(
        _event(
            tool_name="read_file",
            arguments={"path": "/private/token.txt"},
            user_task="Read /private/token.txt",
        ),
        PolicyBundle(disabled_rules=["P001_sensitive_file_access"]),
    )

    assert decision.decision == "allow"
    assert decision.rule_hits == []


def test_policy_bundle_can_allow_email_domain() -> None:
    decision = evaluate(
        _event(
            tool_name="send_email",
            arguments={"to": "user@example.com", "subject": "status", "body": "ok"},
            user_task="Email user@example.com the status update",
        ),
        PolicyBundle(allowed_email_domains=["example.com"]),
    )

    assert decision.decision == "allow"
    assert decision.rule_hits == []


def test_policy_bundle_rule_override_can_escalate_external_send() -> None:
    decision = evaluate(
        _event(
            tool_name="send_email",
            arguments={"to": "external@example.invalid", "subject": "status", "body": "ok"},
            user_task="Email the status update",
        ),
        PolicyBundle(
            rule_overrides={
                "P005_external_send": RuleOverride(decision="deny", risk_score=80, severity="high")
            }
        ),
    )

    assert decision.decision == "deny"
    assert decision.risk_score == 80
    assert decision.severity == "high"
    assert decision.approval_intent is None
