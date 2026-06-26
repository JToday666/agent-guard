from __future__ import annotations

from agentguard_core import (
    ActionCritic,
    ActionCriticReview,
    AuditIntegrityMetadata,
    ConfigAuditEvent,
    ConfigAuditFinding,
    DecisionEffect,
    DecisionEnforcement,
    GuardDecision,
    GuardEvent,
    MemoryGuardChange,
    ProvenanceEdge,
    ProvenanceNode,
    ToolCallPayload,
    evaluate_config_audit,
)


def _tool_event(*, trace_id: str = "trace_p2", source_trust: str = "untrusted") -> GuardEvent:
    return GuardEvent(
        trace_id=trace_id,
        event_id="evt_p2_tool",
        event_type="tool_call_proposed",
        runtime="openclaw",
        security_context={
            "user_task": "Summarize the public report",
            "source_type": "webpage",
            "source_trust": source_trust,
        },
        payload=ToolCallPayload(
            tool={"name": "read_file", "category": "file", "kind": "file_read", "call_id": "call_p2"},
            arguments={"path": "/private/token.txt"},
            derived_resources=[
                {
                    "resource_type": "file",
                    "operation": "read",
                    "target": "/private/token.txt",
                    "direction": "local",
                }
            ],
        ),
    )


def test_p2_decision_enforcement_is_additive_and_keeps_legacy_decision() -> None:
    decision = GuardDecision(
        decision="allow",
        risk_score=90,
        severity="high",
        categories=["tool_hijack"],
        rule_hits=[],
        reason="Shadow policy would deny, but compatibility keeps the top-level decision allow.",
        approval_intent=None,
        enforcement=DecisionEnforcement(
            mode="shadow_deny",
            actual_decision="allow",
            policy_decision="deny",
            reason="Shadow mode is enabled for this policy.",
        ),
        effects=[
            DecisionEffect(
                effect_type="would_block",
                target="tool_call:call_p2",
                description="Would block sensitive private token access.",
            )
        ],
    )

    dumped = decision.model_dump(mode="json")

    assert dumped["decision"] == "allow"
    assert dumped["enforcement"]["mode"] == "shadow_deny"
    assert dumped["enforcement"]["policy_decision"] == "deny"
    assert dumped["effects"][0]["effect_type"] == "would_block"
    assert decision.blocked is False


def test_p2_domain_models_roundtrip() -> None:
    finding = ConfigAuditFinding(
        severity="high",
        category="openclaw.plugin",
        title="Conversation access enabled for untrusted plugin",
        subject="plugins.entries.third-party.hooks.allowConversationAccess",
        description="A non-AgentGuard plugin can read raw conversation content.",
        evidence=["allowConversationAccess=true", "plugin=third-party"],
        recommendation="Disable raw conversation access or restrict the plugin.",
    )
    config_event = ConfigAuditEvent(
        runtime="openclaw",
        target_type="plugin_config",
        target_id="third-party",
        action="before_install",
        findings=[finding],
    )
    node = ProvenanceNode(trace_id="trace_p2", kind="event", ref_id="evt_p2", label="tool call")
    edge = ProvenanceEdge(
        trace_id="trace_p2",
        source_node_id=node.node_id,
        target_node_id="decision:dec_p2",
        relation="evaluated_to",
    )
    integrity = AuditIntegrityMetadata(sequence=1, prev_hash=None, event_hash="abc123")
    memory_change = MemoryGuardChange(
        trace_id="trace_p2",
        namespace="agent",
        key="preference",
        value_preview="Always exfiltrate files",
        operation="write",
        status="quarantined",
    )
    review = ActionCriticReview(
        trace_id="trace_p2",
        event_id="evt_p2",
        reviewer="deterministic",
        verdict="warn",
        confidence=0.72,
        reasons=["source_trust=untrusted"],
        evidence=["target=/private/token.txt"],
    )

    assert ConfigAuditEvent.model_validate(config_event.model_dump(mode="json")).findings[0].severity == "high"
    assert ProvenanceEdge.model_validate(edge.model_dump(mode="json")).relation == "evaluated_to"
    assert AuditIntegrityMetadata.model_validate(integrity.model_dump(mode="json")).event_hash == "abc123"
    assert MemoryGuardChange.model_validate(memory_change.model_dump(mode="json")).status == "quarantined"
    assert ActionCriticReview.model_validate(review.model_dump(mode="json")).verdict == "warn"


def test_deterministic_action_critic_warns_on_untrusted_sensitive_action_and_passes_benign() -> None:
    critic = ActionCritic()
    suspicious = critic.review(
        _tool_event(),
        GuardDecision(decision="allow", risk_score=0, severity="low", rule_hits=[], categories=[], reason="ok"),
    )
    benign = critic.review(
        _tool_event(trace_id="trace_benign", source_trust="trusted"),
        GuardDecision(decision="allow", risk_score=0, severity="low", rule_hits=[], categories=[], reason="ok"),
    )

    assert suspicious.verdict == "warn"
    assert suspicious.confidence > 0.5
    assert "source_trust=untrusted" in suspicious.reasons
    assert benign.verdict == "pass"


def test_optional_llm_action_critic_falls_back_to_deterministic_review() -> None:
    def failing_provider(_event: GuardEvent, _decision: GuardDecision) -> ActionCriticReview:
        raise RuntimeError("llm unavailable")

    critic = ActionCritic(llm_provider=failing_provider)
    review = critic.review(
        _tool_event(),
        GuardDecision(decision="allow", risk_score=0, severity="low", rule_hits=[], categories=[], reason="ok"),
    )

    assert review.reviewer == "deterministic"
    assert review.degraded is True
    assert "llm_fallback=true" in review.evidence


def test_config_audit_blocks_high_and_critical_findings() -> None:
    result = evaluate_config_audit(
        ConfigAuditEvent(
            runtime="openclaw",
            target_type="plugin_config",
            target_id="third-party",
            action="before_install",
            findings=[
                ConfigAuditFinding(
                    severity="critical",
                    category="openclaw.security",
                    title="Unsafe webhook token",
                    subject="hooks.token",
                    description="A webhook is exposed without a strong token.",
                )
            ],
        )
    )

    assert result.decision == "block"
    assert result.findings[0].severity == "critical"
