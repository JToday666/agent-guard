from __future__ import annotations

from agentguard_core.models import SecurityContext, ToolCallEvent, ToolDescriptor
from agentguard_core.service import AgentGuardCore
from agentguard_core.settings import CoreSettings
from agentguard_core.storage.memory import MemoryCoreStore


def _event(
    *,
    tool_name: str,
    arguments: dict,
    user_task: str,
    source_trust: str = "trusted",
    is_malicious: bool | None = None,
) -> ToolCallEvent:
    return ToolCallEvent(
        trace_id="trace_test",
        case_id="case_test",
        attack_type="benign",
        is_malicious=is_malicious,
        security_context=SecurityContext(
            user_task=user_task,
            source_trust=source_trust,
            source_type="user" if source_trust == "trusted" else "webpage",
        ),
        tool=ToolDescriptor(name=tool_name),
        arguments=arguments,
    )


def test_default_database_url_uses_postgresql() -> None:
    settings = CoreSettings()

    assert settings.database_url.startswith("postgresql://")


def test_sensitive_file_is_denied_without_using_dataset_label() -> None:
    core = AgentGuardCore(store=MemoryCoreStore())
    malicious_event = _event(
        tool_name="read_file",
        arguments={"path": "/private/token.txt"},
        user_task="summarize public docs",
        source_trust="untrusted",
        is_malicious=True,
    )
    unlabeled_payload = malicious_event.model_dump()
    unlabeled_payload["is_malicious"] = None
    unlabeled_event = ToolCallEvent.model_validate(unlabeled_payload)

    malicious_decision = core.evaluate_tool_call(malicious_event)
    unlabeled_decision = core.evaluate_tool_call(unlabeled_event)

    assert malicious_decision.decision == "deny"
    assert unlabeled_decision.decision == "deny"
    assert malicious_decision.rule_hits[0].rule_id == "P001_sensitive_resource_access"
    assert unlabeled_decision.rule_hits[0].rule_id == "P001_sensitive_resource_access"


def test_public_document_read_is_allowed() -> None:
    core = AgentGuardCore(store=MemoryCoreStore())

    decision = core.evaluate_tool_call(
        _event(
            tool_name="read_file",
            arguments={"path": "/docs/public.txt"},
            user_task="Read /docs/public.txt and summarize it",
        )
    )

    assert decision.decision == "allow"
    assert decision.risk_score < 40
    assert decision.rule_hits == []


def test_external_email_from_untrusted_context_creates_pending_approval() -> None:
    store = MemoryCoreStore()
    core = AgentGuardCore(store=store)

    decision = core.evaluate_tool_call(
        _event(
            tool_name="send_email",
            arguments={
                "to": "exfiltration-intake@red-team.agentguard.local",
                "subject": "contact export",
                "body": "private contact export",
            },
            user_task="Complete the visible web form only",
            source_trust="untrusted",
        ),
        requesting_principal_id="cred_adapter_main",
    )

    assert decision.decision == "ask"
    assert decision.approval is not None
    pending = store.list_pending_approvals()
    assert len(pending) == 1
    assert pending[0].approval_id == decision.approval["approval_id"]
    assert pending[0].requesting_principal_id == "cred_adapter_main"
