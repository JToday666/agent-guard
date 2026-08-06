from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from agentguard_core import AuditEvent


def _audit_kwargs(**overrides):
    payload = {
        "audit_id": "audit_v04",
        "trace_id": "trace_v04",
        "summary": "Policy evaluation",
        "reason": "Rule matched.",
    }
    payload.update(overrides)
    return payload


def test_audit_event_04_policy_evaluation_accepts_evidence() -> None:
    event = AuditEvent(
        **_audit_kwargs(
            schema_version="0.4",
            record_type="policy_evaluation",
            decision="deny",
            risk_score=90,
            severity="high",
            blocked=True,
            evidence={"guard_decision": {"decision": "deny"}},
            links={"event_id": "evt_v04", "decision_id": "dec_v04"},
        )
    )

    assert event.schema_version == "0.4"
    assert event.record_type == "policy_evaluation"
    assert event.evidence == {"guard_decision": {"decision": "deny"}}


def test_audit_event_04_requires_record_type() -> None:
    with pytest.raises(PydanticValidationError):
        AuditEvent(
            **_audit_kwargs(
                schema_version="0.4",
                decision="deny",
                risk_score=90,
                severity="high",
                blocked=True,
            )
        )


def test_audit_event_04_policy_evaluation_requires_decision_fields() -> None:
    with pytest.raises(PydanticValidationError):
        AuditEvent(
            **_audit_kwargs(
                schema_version="0.4",
                record_type="policy_evaluation",
                decision=None,
                risk_score=None,
                severity=None,
                blocked=None,
            )
        )


def test_audit_event_04_runtime_observation_allows_null_decision_fields() -> None:
    event = AuditEvent(
        **_audit_kwargs(
            schema_version="0.4",
            record_type="runtime_observation",
            event_type="llm_output",
            stage="after_model_call",
            decision=None,
            risk_score=None,
            severity=None,
            blocked=None,
        )
    )

    assert event.decision is None
    assert event.blocked is None


def test_audit_event_rejects_unknown_record_type() -> None:
    with pytest.raises(PydanticValidationError):
        AuditEvent(
            **_audit_kwargs(schema_version="0.4", record_type="not_a_record_type")
        )


def test_audit_event_03_still_requires_decision_fields() -> None:
    with pytest.raises(PydanticValidationError):
        AuditEvent(**_audit_kwargs(schema_version="0.3", decision=None))


def test_audit_event_defaults_stay_on_03_without_record_type() -> None:
    event = AuditEvent(
        **_audit_kwargs(
            decision="allow", risk_score=0, severity="low", blocked=False
        )
    )

    assert event.schema_version == "0.3"
    assert event.record_type is None
    assert event.evidence is None
