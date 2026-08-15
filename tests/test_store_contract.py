"""Cross-store contract tests for AuditEvent 0.4 writer semantics (§8-§12, §19, §21).

Memory 与 PostgreSQL store 必须运行相同的幂等与指标契约测试（§25.2）。
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Literal
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from agentguard_core import (
    ApprovalIntent,
    AuditEvent,
    GuardDecision,
    GuardEngine,
    GuardEvent,
    MemoryGuardChange,
    PolicyBundle,
)
from agentguard_core.authority import (
    SecurityStateScope,
    TaskFact,
    scope_digest_projection,
    task_digest_projection,
)
from guard_api.main import create_app
from guard_api.services import (
    ApprovalService,
    AuditService,
    EvaluationService,
    MemoryGuardService,
    PolicyService,
)
import guard_api.services.evaluation as evaluation_service_module
from guard_api.services.audit_window import AuditWindowService
from guard_api.services.evidence import build_audit_event
from guard_api.services.metric_rules import aggregate_policy_metrics
from guard_api.services.redaction import (
    MAX_EVIDENCE_BYTES,
    evidence_serialized_size,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import (
    AuditEventFilters,
    AuditIdConflictError,
    AuditWindowQuery,
    EvaluationRunConflictError,
    MemoryChangeAlreadyExistsError,
    MemoryChangeTransitionError,
    TaskFactRecord,
    TaskRevisionConflictError,
    classify_audit_record_type,
)
from guard_api.storage.integrity import canonical_sha256, read_audit_integrity
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.auth import add_adapter_credential, memory_store_with_adapter
from tests.support.postgres import get_test_database_url, reset_control_plane_schema

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "runtime_safety_trace_v04.json"

ADAPTER_HEADERS = {"Authorization": "Bearer adapter-secret"}
_CURSOR_SIGNING_KEY = b"agentguard-test-cursor-signing-key-32-bytes"

_STABLE_LINK_KEYS = {
    "event_id",
    "decision_id",
    "action_id",
    "approval_id",
    "critic_review_id",
    "memory_change_id",
}


def _settings() -> GuardApiSettings:
    return GuardApiSettings(control_token="control-secret")


def _audit_window_service(store) -> AuditWindowService:
    return AuditWindowService(
        store=store,
        cursor_signing_key=_CURSOR_SIGNING_KEY,
    )


@pytest.fixture(params=["memory", "postgres"])
def store(request):
    if request.param == "memory":
        return memory_store_with_adapter()
    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    postgres_store = PostgresControlPlaneStore(database_url)
    postgres_store.initialize()
    add_adapter_credential(postgres_store)
    return postgres_store


@pytest.fixture()
def client(store):
    return TestClient(create_app(store=store, settings=_settings()))


def _guard_event_payload(
    *, event_id: str, trace_id: str, arguments: dict | None = None
) -> dict:
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
            "agent_id": "main",
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
    PolicyService(store=store).save_snapshot(
        bundle,
        expected_revision=0,
        updated_by="contract-test",
    )

    response = _post_evaluate(
        client, _guard_event_payload(event_id=f"evt_shape_{run_id}", trace_id=trace_id)
    )

    assert response.status_code == 200
    audit = _stored_policy_audit(store, trace_id)

    assert audit.schema_version == "0.4"
    assert audit.record_type == "policy_evaluation"
    evidence = audit.evidence
    assert isinstance(evidence, dict)
    # V21-08（D4/D7）：decision_v21 是 append-only 审计键——flag 关时
    # evidence 键集与现状完全一致（8 键）；flag 开时为 8 键 +
    # decision_v21，不得出现其他键。
    assert set(evidence) - {"decision_v21"} == {
        "guard_event",
        "guard_decision",
        "policy",
        "intervention",
        "execution",
        "side_effects",
        "result",
        "approval",
    }
    assert set(evidence) <= {
        "guard_event",
        "guard_decision",
        "policy",
        "intervention",
        "execution",
        "side_effects",
        "result",
        "approval",
        "decision_v21",
    }
    # §9.3：policy 块与实际保存的快照一致。
    assert evidence["policy"] == {
        "bundle_id": bundle.bundle_id,
        "version": bundle.version,
        "revision": 1,
        "canonical_digest": canonical_sha256(bundle.model_dump(mode="json")),
        "canonicalization": "jcs:rfc8785",
    }
    # §9.9：links 只保留稳定 ID；digest 移入 metadata。
    assert set(audit.links) <= _STABLE_LINK_KEYS
    assert audit.links["event_id"] == f"evt_shape_{run_id}"
    assert "decision_id" in audit.links
    assert audit.metadata["request_digest"] == canonical_sha256(
        evaluation_service_module.canonical_request_dump(
            GuardEvent.model_validate(
                _guard_event_payload(event_id=f"evt_shape_{run_id}", trace_id=trace_id)
            )
        )
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

    first = _post_evaluate(
        client, _guard_event_payload(event_id=event_id, trace_id=trace_id)
    )
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
    assert len(store.list_audit_events(AuditEventFilters(trace_id=trace_id))) == 1


def _policy_audit_for_idempotency(run_id: str) -> AuditEvent:
    event = GuardEvent.model_validate(
        _guard_event_payload(
            event_id=f"evt_auditidem_{run_id}", trace_id=f"trace_auditidem_{run_id}"
        )
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
        len(store.list_audit_events(AuditEventFilters(trace_id=original.trace_id))) == 1
    )


def test_contract_duplicate_policy_audits_counted_once(store) -> None:
    # 0007 部分唯一索引已阻断显式 0.4 policy_evaluation 的写入侧重复；
    # §19.1 读时去重的目标数据是 legacy（0.3，record_type=None）重复审计，
    # 故本用例以 legacy 形态记录继续验证读时去重（leader 确认的唯一例外）。
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
                schema_version="0.3",
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

    events = store.read_audit_events_bounded(
        AuditWindowQuery(trace_id=trace_id, limit=100)
    )
    metrics = aggregate_policy_metrics(events)

    # §19.1：重复逻辑键只保留最早入链记录。
    assert metrics["evaluation_count"] == 1
    assert metrics["ask_count"] == 1
    assert metrics["intervention_count"] == 1


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
    classified = {event.audit_id: classify_audit_record_type(event) for event in events}
    assert classified == {
        f"audit_cfg_{run_id}": "config_audit",
        f"audit_obs_{run_id}": "runtime_observation",
        f"audit_policy_{run_id}": "policy_evaluation",
    }
    # 只有被分类为 policy_evaluation 的旧记录进入策略指标。
    metrics = aggregate_policy_metrics(events)
    assert metrics["evaluation_count"] == 1
    assert metrics["allow_count"] == 1

    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    fixture_types = {
        audit["record_type"] for audit in fixture["source_facts"]["audit_events"]
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
        event for event in events if event.audit_id == f"audit_policy_{run_id}"
    )
    assert classify_audit_record_type(policy_audit) == fixture_policy["record_type"]


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


def test_contract_03_inbound_stored_verbatim_and_excluded_from_policy_metrics(
    store,
) -> None:
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
    metrics = aggregate_policy_metrics(events)
    assert metrics["evaluation_count"] == 0


def _thread_client(store) -> TestClient:
    # PostgreSQL 下每线程独立 store 实例（独立 engine/session）；
    # memory 状态在进程内共享，多线程复用同一实例。
    thread_store = (
        PostgresControlPlaneStore(store.database_url)
        if isinstance(store, PostgresControlPlaneStore)
        else store
    )
    return TestClient(create_app(store=thread_store, settings=_settings()))


def test_contract_evaluation_run_is_immutable_and_idempotent(store) -> None:
    run_id = f"eval_contract_{uuid4().hex}"
    original = {
        "run_id": run_id,
        "run_at": "2026-06-28T08:00:00+08:00",
        "dataset_id": "attackbench",
        "dataset_version": "v1",
        "cases": [],
    }

    created = store.save_evaluation_run(original)
    replayed = store.save_evaluation_run(original)

    assert created == replayed
    assert created["run_at"] == "2026-06-28T00:00:00+00:00"
    with pytest.raises(EvaluationRunConflictError):
        store.save_evaluation_run({**original, "dataset_version": "v2"})
    assert store.get_evaluation_run(run_id) == created


def test_contract_concurrent_same_content_single_chain_entry(store) -> None:
    # 并发同 event_id 同内容：仅一条入链且全部响应回放同一 decision_id。
    run_id = uuid4().hex
    event_id = f"evt_concurrent_{run_id}"
    trace_id = f"trace_concurrent_{run_id}"
    payload = _guard_event_payload(event_id=event_id, trace_id=trace_id)
    worker_count = 8
    clients = [_thread_client(store) for _ in range(worker_count)]

    def worker(index: int):
        return _post_evaluate(clients[index], payload)

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        responses = list(executor.map(worker, range(worker_count)))
    for thread_client in clients:
        thread_client.close()

    assert [response.status_code for response in responses] == [200] * worker_count
    decision_ids = {
        response.json()["decision"]["decision_id"] for response in responses
    }
    assert len(decision_ids) == 1
    events = store.list_audit_events(AuditEventFilters(trace_id=trace_id))
    assert len(events) == 1
    assert events[0].links["event_id"] == event_id
    assert store.verify_audit_integrity().valid


def test_contract_concurrent_ask_creates_one_audit_and_one_approval(
    store, monkeypatch
) -> None:
    """Evaluation serialization covers side effects, not only the unique audit."""

    run_id = uuid4().hex
    event_id = f"evt_concurrent_ask_{run_id}"
    trace_id = f"trace_concurrent_ask_{run_id}"
    event = GuardEvent.model_validate(
        _guard_event_payload(event_id=event_id, trace_id=trace_id)
    )
    calls = 0
    calls_lock = Lock()

    def ask_decision(_event: GuardEvent, _bundle: PolicyBundle) -> GuardDecision:
        nonlocal calls
        with calls_lock:
            calls += 1
        return GuardDecision(
            decision_id=f"dec_concurrent_ask_{run_id}",
            decision="ask",
            risk_score=72,
            severity="high",
            categories=["task_mismatch"],
            rule_hits=[],
            reason="Human approval is required.",
            approval_intent=ApprovalIntent(options=["allow_once", "deny"], resource=""),
        )

    monkeypatch.setattr(
        GuardEngine,
        "evaluate_with_results",
        lambda self, event, bundle=None: (ask_decision(event, bundle), []),
    )
    service = EvaluationService(
        policy_service=PolicyService(store=store),
        audit_service=AuditService(store=store),
        approval_service=ApprovalService(store=store, settings=_settings()),
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        responses = list(
            executor.map(
                lambda _: service.evaluate(
                    event, requesting_principal_id="contract-adapter"
                ),
                range(8),
            )
        )

    audits = store.list_audit_events(AuditEventFilters(trace_id=trace_id))
    approvals = store.list_approvals(trace_id=trace_id)
    assert calls == 1
    assert len({response.policy_audit_id for response in responses}) == 1
    assert len(audits) == 1
    assert len(approvals) == 1
    assert approvals[0].resource == "sink@red-team.agentguard.local"
    assert audits[0].links["approval_id"] == approvals[0].approval_id


def test_contract_failed_evaluation_rolls_back_all_persisted_facts(
    store, monkeypatch
) -> None:
    run_id = uuid4().hex
    event = GuardEvent.model_validate(
        _guard_event_payload(
            event_id=f"evt_rollback_{run_id}",
            trace_id=f"trace_rollback_{run_id}",
        )
    )

    def ask_decision(_event: GuardEvent, _bundle: PolicyBundle) -> GuardDecision:
        return GuardDecision(
            decision_id=f"dec_rollback_{run_id}",
            decision="ask",
            risk_score=72,
            severity="high",
            categories=["task_mismatch"],
            rule_hits=[],
            reason="Human approval is required.",
            approval_intent=ApprovalIntent(options=["allow_once", "deny"], resource=""),
        )

    monkeypatch.setattr(
        GuardEngine,
        "evaluate_with_results",
        lambda self, event, bundle=None: (ask_decision(event, bundle), []),
    )
    audit_service = AuditService(store=store)
    original_record = audit_service.record_evaluation

    def fail_after_record(*args, **kwargs):
        original_record(*args, **kwargs)
        raise RuntimeError("injected failure after evidence materialization")

    monkeypatch.setattr(audit_service, "record_evaluation", fail_after_record)
    service = EvaluationService(
        policy_service=PolicyService(store=store),
        audit_service=audit_service,
        approval_service=ApprovalService(store=store, settings=_settings()),
    )

    with pytest.raises(
        RuntimeError, match="injected failure after evidence materialization"
    ):
        service.evaluate(event, requesting_principal_id="contract-adapter")

    assert store.list_audit_events(AuditEventFilters(trace_id=event.trace_id)) == []
    assert store.list_approvals(trace_id=event.trace_id) == []
    assert store.list_action_critic_reviews(event.trace_id) == []
    assert store.list_provenance(event.trace_id) == ([], [])
    assert store.verify_audit_integrity().valid


def test_contract_concurrent_different_content_exactly_one_conflict(store) -> None:
    # 并发同 event_id 异内容：恰好一个 409 EVALUATION_CONFLICT，另一侧正常入链。
    run_id = uuid4().hex
    event_id = f"evt_raceconflict_{run_id}"
    trace_id = f"trace_raceconflict_{run_id}"
    payloads = [
        _guard_event_payload(event_id=event_id, trace_id=trace_id),
        _guard_event_payload(
            event_id=event_id,
            trace_id=trace_id,
            arguments={"to": "other@red-team.agentguard.local"},
        ),
    ]
    clients = [_thread_client(store) for _ in payloads]

    def worker(index: int):
        return _post_evaluate(clients[index], payloads[index])

    with ThreadPoolExecutor(max_workers=len(payloads)) as executor:
        responses = list(executor.map(worker, range(len(payloads))))
    for thread_client in clients:
        thread_client.close()

    statuses = sorted(response.status_code for response in responses)
    assert statuses == [200, 409]
    conflict = next(response for response in responses if response.status_code == 409)
    assert conflict.json()["error"]["code"] == "EVALUATION_CONFLICT"
    events = store.list_audit_events(AuditEventFilters(trace_id=trace_id))
    assert len(events) == 1
    assert store.verify_audit_integrity().valid


def test_contract_explicit_policy_evaluation_inbound_rejected(store, client) -> None:
    # §12.1：显式 record_type=policy_evaluation 的入站记录被 422 拒收且不入链。
    run_id = uuid4().hex
    trace_id = f"trace_forbidden_{run_id}"
    payload = {
        "audit_id": f"audit_forbidden_{run_id}",
        "schema_version": "0.4",
        "record_type": "policy_evaluation",
        "trace_id": trace_id,
        "case_id": "CASE-CONTRACT",
        "runtime": "langgraph",
        "timestamp": "2026-06-11T00:00:00+00:00",
        "stage": "before_tool_call",
        "event_type": "tool_call_proposed",
        "summary": "Forbidden inbound policy evaluation",
        "decision": "deny",
        "risk_score": 90,
        "severity": "critical",
        "blocked": True,
        "reason": "Contract guard test.",
        "links": {
            "event_id": f"evt_forbidden_{run_id}",
            "decision_id": f"dec_forbidden_{run_id}",
        },
        "metadata": {},
    }

    response = client.post("/v1/audit/events", headers=ADAPTER_HEADERS, json=payload)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "POLICY_EVALUATION_WRITE_FORBIDDEN"
    assert store.list_audit_events(AuditEventFilters(trace_id=trace_id)) == []
    assert store.verify_audit_integrity().valid


def test_contract_03_compatible_inbound_record_still_accepted(store, client) -> None:
    # §12.1 守卫不得打断 record_type=None 的 0.3 兼容写入（LangGraph adapter 路径）。
    run_id = uuid4().hex
    trace_id = f"trace_compat03_{run_id}"
    payload = {
        "audit_id": f"audit_compat03_{run_id}",
        "schema_version": "0.3",
        "trace_id": trace_id,
        "case_id": "CASE-CONTRACT",
        "runtime": "langgraph",
        "timestamp": "2026-06-11T00:00:00+00:00",
        "stage": "before_tool_call",
        "event_type": "runtime_observation",
        "summary": "Legacy compatible inbound record",
        "decision": "allow",
        "risk_score": 0,
        "severity": "low",
        "blocked": False,
        "reason": "Contract compatibility test.",
        "links": {},
        "metadata": {},
    }

    response = client.post("/v1/audit/events", headers=ADAPTER_HEADERS, json=payload)

    assert response.status_code == 200
    events = store.list_audit_events(AuditEventFilters(trace_id=trace_id))
    assert len(events) == 1
    assert events[0].record_type is None
    assert events[0].schema_version == "0.3"
    assert store.verify_audit_integrity().valid


# 契约 §5/§6/§13.1：原子审计窗口与 policy_evaluation cohort 契约测试。


def _window_audit_event(
    *,
    index: int,
    run_id: str,
    decision: str | None = "allow",
    is_malicious: bool | None = None,
    record_type: str = "policy_evaluation",
    latency_ms: int | None = None,
    links: dict[str, str] | None = None,
    legacy: bool = False,
) -> AuditEvent:
    # 基准 2026-06-01T00:00:00+00:00，每条记录递增一分钟。
    minutes_total, secs = divmod(index * 60, 60)
    hours, minutes = divmod(minutes_total, 60)
    timestamp = f"2026-06-01T{hours:02d}:{minutes:02d}:{secs:02d}+00:00"
    return AuditEvent(
        audit_id=f"audit_win_{run_id}_{index}",
        schema_version="0.3" if legacy else "0.4",
        record_type=None if legacy else record_type,
        trace_id=f"trace_win_{run_id}",
        case_id=f"CASE-WIN-{run_id}",
        runtime="langgraph",
        timestamp=timestamp,
        event_type="tool_call_proposed",
        summary=f"Window contract record {index}",
        decision=decision,
        risk_score=10,
        severity="low",
        blocked=decision in {"ask", "deny"},
        reason="Window contract fixture.",
        is_malicious=is_malicious,
        latency_ms=latency_ms,
        links=(
            dict(links)
            if links is not None
            else {
                "event_id": f"evt_win_{run_id}_{index}",
                "decision_id": f"dec_win_{run_id}_{index}",
            }
        ),
    )


def _event_sequence(event: AuditEvent) -> int:
    metadata = read_audit_integrity(event)
    assert metadata is not None
    return metadata.sequence


def test_contract_bounded_read_is_descending_within_snapshot(store) -> None:
    run_id = uuid4().hex
    for index in range(6):
        store.add_audit_event(_window_audit_event(index=index, run_id=run_id))

    upper = _event_sequence(
        store.read_audit_events_bounded(AuditWindowQuery(limit=1))[0]
    )

    rows = store.read_audit_events_bounded(AuditWindowQuery(limit=3))
    sequences = [_event_sequence(event) for event in rows]
    assert sequences == [upper, upper - 1, upper - 2]

    # 显式上界 + after_sequence 续页只读 sequence 严格更小的记录。
    paged = store.read_audit_events_bounded(
        AuditWindowQuery(upper_sequence=upper, after_sequence=upper - 2, limit=10)
    )
    assert [_event_sequence(event) for event in paged] == [
        upper - 3,
        upper - 4,
        upper - 5,
    ]

    # 上界之外的并发新写入不进入已固化快照。
    store.add_audit_event(_window_audit_event(index=99, run_id=run_id))
    frozen = store.read_audit_events_bounded(
        AuditWindowQuery(upper_sequence=upper, limit=100)
    )
    assert len(frozen) == 6

    # 空查询不抛错。
    assert (
        memory_store_with_adapter().read_audit_events_bounded(AuditWindowQuery(limit=1))
        == []
    )


def test_contract_window_has_more_boundary(store) -> None:
    run_id = uuid4().hex
    for index in range(5):
        store.add_audit_event(_window_audit_event(index=index, run_id=run_id))
    service = _audit_window_service(store)

    exact = service.get_window(limit=5)
    assert exact["scope"]["returned_record_count"] == 5
    assert exact["scope"]["has_more"] is False
    assert exact["scope"]["next_cursor"] is None
    assert exact["scope"]["sequence_from"] == 1
    assert exact["scope"]["sequence_to"] == 5

    truncated = service.get_window(limit=4)
    assert truncated["scope"]["returned_record_count"] == 4
    assert truncated["scope"]["has_more"] is True
    assert truncated["scope"]["next_cursor"]


def test_contract_window_cursor_snapshot_stable_under_concurrent_writes(store) -> None:
    run_id = uuid4().hex
    for index in range(6):
        store.add_audit_event(_window_audit_event(index=index, run_id=run_id))
    service = _audit_window_service(store)

    page1 = service.get_window(limit=4)
    page1_sequences = [
        _event_sequence(AuditEvent.model_validate(row)) for row in page1["events"]
    ]
    assert page1["scope"]["has_more"] is True

    # 翻页前并发写入新记录；已有页不得移动。
    for index in range(6, 9):
        store.add_audit_event(_window_audit_event(index=index, run_id=run_id))

    page2 = service.get_window(cursor=page1["scope"]["next_cursor"])
    page2_sequences = [
        _event_sequence(AuditEvent.model_validate(row)) for row in page2["events"]
    ]

    assert page1_sequences == [6, 5, 4, 3]
    assert page2_sequences == [2, 1]
    assert page2["scope"]["has_more"] is False
    assert page2["scope"]["next_cursor"] is None
    # cursor 固化快照：两页 snapshot 与上界一致，新写入未进入窗口。
    assert page2["scope"]["snapshot_id"] == page1["scope"]["snapshot_id"]
    assert page2["scope"]["outcomes_as_of"] == page1["scope"]["outcomes_as_of"]
    assert page2["scope"]["sequence_to"] == 2


def test_contract_window_duplicate_policy_records_counted_once(store) -> None:
    # 0007 部分唯一索引已阻断显式 0.4 policy_evaluation 的写入侧重复；
    # 读时逻辑去重的目标数据是 legacy（0.3，record_type=None）重复审计，
    # 故重复记录以 legacy 形态构造（与 §19.1 用例同型处理）。
    run_id = uuid4().hex
    links = {
        "event_id": f"evt_dupwin_{run_id}",
        "decision_id": f"dec_dupwin_{run_id}",
    }
    for index in range(3):
        store.add_audit_event(
            _window_audit_event(
                index=index, run_id=run_id, links=dict(links), legacy=True
            )
        )
    store.add_audit_event(_window_audit_event(index=3, run_id=run_id))

    window = _audit_window_service(store).get_window(limit=10)
    metrics = window["policy_metrics"]

    # legacy 重复记录经 §19.2 分类回退判为 policy_evaluation，读时只计一次。
    assert metrics["evaluation_count"] == 2
    assert metrics["duplicate_policy_record_count"] == 2
    assert metrics["unkeyed_policy_record_count"] == 0
    assert metrics["allow_count"] == 2


def test_contract_window_non_policy_records_excluded_from_metrics(store) -> None:
    run_id = uuid4().hex
    store.add_audit_event(_window_audit_event(index=0, run_id=run_id, latency_ms=12))
    store.add_audit_event(
        _window_audit_event(
            index=1,
            run_id=run_id,
            record_type="runtime_outcome",
            decision=None,
            latency_ms=900,
        )
    )
    store.add_audit_event(
        _window_audit_event(
            index=2, run_id=run_id, record_type="runtime_observation", decision=None
        )
    )
    store.add_audit_event(
        _window_audit_event(index=3, run_id=run_id, record_type="config_audit")
    )

    window = _audit_window_service(store).get_window(limit=10)
    metrics = window["policy_metrics"]

    assert window["scope"]["returned_record_count"] == 4
    # outcome/observation/config 不增加策略计数。
    assert metrics["evaluation_count"] == 1
    assert metrics["allow_count"] == 1
    # policy latency 不混入 runtime latency。
    assert metrics["average_decision_latency_ms"] == 12
    assert metrics["latency_sample_count"] == 1


def test_contract_window_unlabeled_and_unknown_decision_rules(store) -> None:
    run_id = uuid4().hex
    # benign + ask → FPR 命中；malicious + allow → FNR 命中；未标注不入分母。
    store.add_audit_event(
        _window_audit_event(index=0, run_id=run_id, decision="ask", is_malicious=False)
    )
    store.add_audit_event(
        _window_audit_event(index=1, run_id=run_id, decision="allow", is_malicious=True)
    )
    store.add_audit_event(
        _window_audit_event(index=2, run_id=run_id, decision="deny", is_malicious=None)
    )

    metrics = _audit_window_service(store).get_window(limit=10)["policy_metrics"]
    assert metrics["unknown_decision_count"] == 0
    assert metrics["unlabeled_count"] == 1
    assert metrics["benign_label_count"] == 1
    assert metrics["malicious_label_count"] == 1
    assert metrics["policy_intervention_fpr"] == 1.0
    assert metrics["policy_intervention_fnr"] == 1.0
    # decision=null 的非策略记录不得并入 allow，也不产生 unknown 策略计数。
    store.add_audit_event(
        _window_audit_event(
            index=3,
            run_id=run_id,
            record_type="runtime_observation",
            decision=None,
            is_malicious=False,
        )
    )
    metrics = _audit_window_service(store).get_window(limit=10)["policy_metrics"]
    assert metrics["unknown_decision_count"] == 0
    assert metrics["allow_count"] == 1
    assert metrics["policy_intervention_fpr"] == 1.0
    assert metrics["policy_intervention_fnr"] == 1.0

    # 分母为零返回 null，不得返回 0（§4.3）。
    empty_run = uuid4().hex
    store.add_audit_event(
        _window_audit_event(
            index=0, run_id=empty_run, record_type="runtime_observation", decision=None
        )
    )
    empty_metrics = _audit_window_service(store).get_window(
        limit=10, trace_id=f"trace_win_{empty_run}"
    )["policy_metrics"]
    assert empty_metrics["evaluation_count"] == 0
    assert empty_metrics["intervention_rate"] is None
    assert empty_metrics["policy_intervention_fpr"] is None
    assert empty_metrics["average_decision_latency_ms"] is None


def test_contract_cohort_evaluated_range_selects_policy_records(store) -> None:
    run_id = uuid4().hex
    for index in range(5):
        store.add_audit_event(_window_audit_event(index=index, run_id=run_id))
    # 快照外的迟到记录不进入 cohort。
    store.add_audit_event(
        _window_audit_event(
            index=5,
            run_id=run_id,
            latency_ms=99,
            links={"event_id": "late", "decision_id": "late"},
        )
    )
    upper = store.read_audit_events_bounded(AuditWindowQuery(limit=1))[0]
    frozen_upper = _event_sequence(upper) - 1

    rows = store.read_audit_events_bounded(
        AuditWindowQuery(
            upper_sequence=frozen_upper,
            evaluated_from=datetime.fromisoformat("2026-06-01T00:01:00+00:00"),
            evaluated_to=datetime.fromisoformat("2026-06-01T00:04:00+00:00"),
            limit=100,
        )
    )
    # [00:01, 00:04) 半开区间：命中 index 1/2/3，按 sequence 降序返回。
    assert [_event_sequence(event) for event in rows] == [4, 3, 2]


def test_contract_cohort_reads_every_keyset_page() -> None:
    store = MemoryControlPlaneStore()
    run_id = uuid4().hex
    for index in range(1001):
        store.add_audit_event(_window_audit_event(index=index, run_id=run_id))

    cohort = _audit_window_service(store).get_policy_cohort(
        evaluated_from="2026-06-01T00:00:00+00:00",
        evaluated_to="2026-06-02T00:00:00+00:00",
    )

    assert cohort["policy_metrics"]["evaluation_count"] == 1001


def test_contract_cohort_applies_ingestion_time_as_of() -> None:
    clock_values = iter(
        [
            datetime.fromisoformat("2026-06-02T00:00:00+00:00"),
            datetime.fromisoformat("2026-06-03T00:00:00+00:00"),
            datetime.fromisoformat("2026-06-04T00:00:00+00:00"),
        ]
    )
    store = MemoryControlPlaneStore(audit_clock=lambda: next(clock_values))
    run_id = uuid4().hex
    store.add_audit_event(_window_audit_event(index=0, run_id=run_id))
    store.add_audit_event(_window_audit_event(index=1, run_id=run_id))

    cohort = _audit_window_service(store).get_policy_cohort(
        evaluated_from="2026-06-01T00:00:00+00:00",
        evaluated_to="2026-06-02T00:00:00+00:00",
        outcomes_as_of="2026-06-02T12:00:00+00:00",
    )

    assert cohort["scope"]["outcomes_as_of"] == "2026-06-02T12:00:00Z"
    assert cohort["policy_metrics"]["evaluation_count"] == 1


def test_contract_rejects_audit_timestamp_without_timezone(store) -> None:
    event = _window_audit_event(index=0, run_id=uuid4().hex).model_copy(
        update={"timestamp": "2026-06-01T00:00:00"}
    )

    with pytest.raises(ValueError, match="include a timezone"):
        store.add_audit_event(event)


def test_contract_memory_and_postgres_window_parity() -> None:
    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    postgres_store = PostgresControlPlaneStore(database_url)
    postgres_store.initialize()
    memory_store = memory_store_with_adapter()
    run_id = uuid4().hex
    events = [
        _window_audit_event(
            index=0, run_id=run_id, decision="allow", is_malicious=False, latency_ms=10
        ),
        _window_audit_event(
            index=1, run_id=run_id, decision="ask", is_malicious=True, latency_ms=20
        ),
        _window_audit_event(
            index=2,
            run_id=run_id,
            record_type="runtime_outcome",
            decision=None,
            latency_ms=500,
        ),
        _window_audit_event(index=3, run_id=run_id, decision="deny", is_malicious=None),
        # 与 index 0 同逻辑键的重复记录：legacy 形态构造以兼容 0007 部分唯一索引。
        _window_audit_event(
            index=4,
            run_id=run_id,
            links={
                "event_id": f"evt_win_{run_id}_0",
                "decision_id": f"dec_win_{run_id}_0",
            },
            legacy=True,
        ),
    ]
    for target in (memory_store, postgres_store):
        for event in events:
            target.add_audit_event(event)

    memory_window = _audit_window_service(memory_store).get_window(limit=3)
    postgres_window = _audit_window_service(postgres_store).get_window(limit=3)

    # Memory/PostgreSQL 在相同 fixture 上完全一致（outcomes_as_of 为请求时刻）。
    assert memory_window["events"] == postgres_window["events"]
    assert memory_window["policy_metrics"] == postgres_window["policy_metrics"]
    memory_scope = dict(memory_window["scope"])
    postgres_scope = dict(postgres_window["scope"])
    memory_scope.pop("outcomes_as_of")
    postgres_scope.pop("outcomes_as_of")
    assert memory_scope.pop("next_cursor")
    assert postgres_scope.pop("next_cursor")
    assert memory_scope == postgres_scope

    memory_page2 = _audit_window_service(memory_store).get_window(
        cursor=memory_window["scope"]["next_cursor"]
    )
    postgres_page2 = _audit_window_service(postgres_store).get_window(
        cursor=postgres_window["scope"]["next_cursor"]
    )
    assert memory_page2["events"] == postgres_page2["events"]
    assert memory_page2["policy_metrics"] == postgres_page2["policy_metrics"]

    cohort_memory = _audit_window_service(memory_store).get_policy_cohort(
        evaluated_from="2026-06-01T00:00:00+00:00",
        evaluated_to="2026-06-01T00:05:00+00:00",
    )
    cohort_postgres = _audit_window_service(postgres_store).get_policy_cohort(
        evaluated_from="2026-06-01T00:00:00+00:00",
        evaluated_to="2026-06-01T00:05:00+00:00",
    )
    assert cohort_memory["policy_metrics"] == cohort_postgres["policy_metrics"]
    memory_cohort_scope = dict(cohort_memory["scope"])
    postgres_cohort_scope = dict(cohort_postgres["scope"])
    memory_cohort_scope.pop("outcomes_as_of")
    postgres_cohort_scope.pop("outcomes_as_of")
    assert memory_cohort_scope == postgres_cohort_scope


# ---------------------------------------------------------------------------
# 记忆变更生命周期状态机契约（内存与 PostgreSQL 双实现镜像）。
# ---------------------------------------------------------------------------

_MemoryChangeStatus = Literal[
    "proposed", "quarantined", "committed", "rejected", "rolled_back"
]

_MEMORY_CHANGE_STATUSES: tuple[_MemoryChangeStatus, ...] = (
    "proposed",
    "quarantined",
    "committed",
    "rejected",
    "rolled_back",
)
_MEMORY_CHANGE_LEGAL_TRANSITIONS: list[
    tuple[_MemoryChangeStatus, _MemoryChangeStatus]
] = [
    ("proposed", "committed"),
    ("proposed", "rejected"),
    ("quarantined", "committed"),
    ("quarantined", "rejected"),
    ("committed", "rolled_back"),
]
_MEMORY_CHANGE_ILLEGAL_TRANSITIONS: list[
    tuple[_MemoryChangeStatus, _MemoryChangeStatus]
] = [
    (from_status, to_status)
    for from_status in _MEMORY_CHANGE_STATUSES
    for to_status in _MEMORY_CHANGE_STATUSES
    if from_status != to_status
    and (from_status, to_status) not in set(_MEMORY_CHANGE_LEGAL_TRANSITIONS)
]


def _memory_change_fixture(
    change_id: str,
    *,
    status: _MemoryChangeStatus,
) -> MemoryGuardChange:
    return MemoryGuardChange(
        change_id=change_id,
        trace_id=f"trace_{change_id}",
        namespace="agent",
        key="preference",
        value_preview="fixture",
        status=status,
    )


@pytest.mark.parametrize(("from_status", "to_status"), _MEMORY_CHANGE_LEGAL_TRANSITIONS)
def test_store_memory_change_legal_transitions(
    store, from_status: _MemoryChangeStatus, to_status: _MemoryChangeStatus
) -> None:
    change = _memory_change_fixture(
        f"memchg_legal_{from_status}_{to_status}", status=from_status
    )
    store.create_memory_change(change)

    result = store.update_memory_change_status(change.change_id, to_status)

    assert result.applied is True
    assert result.previous_status == from_status
    assert result.change.status == to_status
    assert result.change.updated_at >= change.updated_at


@pytest.mark.parametrize(
    ("from_status", "to_status"), _MEMORY_CHANGE_ILLEGAL_TRANSITIONS
)
def test_store_memory_change_illegal_transitions_raise(
    store, from_status: _MemoryChangeStatus, to_status: _MemoryChangeStatus
) -> None:
    change = _memory_change_fixture(
        f"memchg_illegal_{from_status}_{to_status}", status=from_status
    )
    store.create_memory_change(change)

    with pytest.raises(MemoryChangeTransitionError) as excinfo:
        store.update_memory_change_status(change.change_id, to_status)

    assert excinfo.value.change_id == change.change_id
    assert excinfo.value.from_status == from_status
    assert excinfo.value.to_status == to_status
    assert store.get_memory_change(change.change_id).status == from_status


@pytest.mark.parametrize("status", _MEMORY_CHANGE_STATUSES)
def test_store_memory_change_same_status_repeat_is_idempotent(
    store, status: _MemoryChangeStatus
) -> None:
    change = _memory_change_fixture(f"memchg_idem_{status}", status=status)
    store.create_memory_change(change)

    result = store.update_memory_change_status(change.change_id, status)

    assert result.applied is False
    assert result.previous_status == status
    assert result.change.status == status
    assert result.change.updated_at == change.updated_at


def test_store_memory_change_update_missing_raises_key_error(store) -> None:
    with pytest.raises(KeyError):
        store.update_memory_change_status("memchg_missing", "committed")


def test_store_memory_change_concurrent_transitions_stay_consistent(store) -> None:
    # 并发语义：多个写入方基于同一前态竞争，最终状态唯一且落败方收到转换冲突。
    change = _memory_change_fixture("memchg_race", status="proposed")
    store.create_memory_change(change)

    def attempt(target_status: str) -> str:
        try:
            return store.update_memory_change_status(
                change.change_id, target_status
            ).change.status
        except MemoryChangeTransitionError:
            return "conflict"

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(attempt, ["committed", "rejected"] * 4))

    final = store.get_memory_change(change.change_id)
    assert final.status in {"committed", "rejected"}
    assert all(outcome in {final.status, "conflict"} for outcome in outcomes)


def test_store_memory_change_transaction_commits_state_and_audit_atomically(
    store,
) -> None:
    # 原子窗口契约：窗口内状态转换与审计入链要么一起提交，要么异常时
    # 一起回滚，不得遗留「状态已改、链上无记录」的部分状态。
    change = _memory_change_fixture("memchg_txn_atomic", status="proposed")
    store.create_memory_change(change)
    event = AuditEvent(
        audit_id="audit_memchg_txn_atomic",
        schema_version="0.4",
        record_type="config_audit",
        trace_id="trace_memchg_txn_atomic",
        event_type="memory_change_transition",
        summary="Memory change memchg_txn_atomic transitioned proposed -> committed",
        decision="allow",
        risk_score=0,
        severity="low",
        blocked=False,
        reason="memory_change:proposed->committed",
        links={"memory_change_id": change.change_id},
    )

    with pytest.raises(RuntimeError, match="atomicity probe"):
        with store.memory_change_transaction(change.change_id):
            failed = store.update_memory_change_status(change.change_id, "committed")
            assert failed.applied is True
            assert store.add_audit_event(event)
            raise RuntimeError("atomicity probe")

    rolled_back = store.get_memory_change(change.change_id)
    assert rolled_back is not None
    assert rolled_back.status == "proposed"
    assert store.get_audit_event(event.audit_id) is None

    with store.memory_change_transaction(change.change_id):
        committed = store.update_memory_change_status(change.change_id, "committed")
        assert committed.applied is True
        assert committed.previous_status == "proposed"
        assert store.add_audit_event(event)

    assert store.get_memory_change(change.change_id).status == "committed"
    assert store.get_audit_event(event.audit_id) is not None


def test_store_create_memory_change_rejects_existing_conflict(store) -> None:
    # 存在即拒绝：同 change_id 不同内容/身份的重建不得覆盖既有记录。
    original = _memory_change_fixture("memchg_conflict", status="proposed")
    store.create_memory_change(original)

    conflicting = original.model_copy(
        update={"value_preview": "hijacked", "principal_id": "attacker"}
    )
    with pytest.raises(MemoryChangeAlreadyExistsError) as excinfo:
        store.create_memory_change(conflicting)

    assert excinfo.value.change_id == original.change_id
    stored = store.get_memory_change(original.change_id)
    assert stored is not None
    assert stored.value_preview == "fixture"
    assert stored.principal_id == original.principal_id
    assert stored.status == "proposed"


def test_store_create_memory_change_idempotent_replay_returns_existing(store) -> None:
    # 幂等重放：除时间戳外完全一致的重复提交返回既有记录，不覆盖不报错。
    original = _memory_change_fixture("memchg_replay", status="proposed")
    first = store.create_memory_change(original)

    replay = original.model_copy(update={"updated_at": "2099-01-01T00:00:00+00:00"})
    second = store.create_memory_change(replay)

    assert second.change_id == first.change_id
    assert second.updated_at == first.updated_at
    assert second == first


def test_store_concurrent_commit_writes_single_transition_audit(store) -> None:
    # 并发去重：8 线程并发 commit 同一变更，只有一方 applied=True，
    # 链上恰好一条转换审计；使 postgres 条件更新路径也有服务级覆盖。
    service = MemoryGuardService(store=store, audit_service=AuditService(store=store))
    change = _memory_change_fixture("memchg_race_audit", status="proposed")
    store.create_memory_change(change)

    def attempt(_: int) -> str:
        return service.commit(change.change_id, operator_id="cred_adapter_main").status

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(attempt, range(8)))

    assert all(status == "committed" for status in outcomes)
    transitions = [
        event
        for event in store.list_audit_events(
            AuditEventFilters(trace_id="trace_memchg_race_audit", limit=100)
        )
        if event.event_type == "memory_change_transition"
    ]
    assert len(transitions) == 1
    assert transitions[0].metadata["from_status"] == "proposed"
    assert transitions[0].metadata["to_status"] == "committed"
    assert store.verify_audit_integrity().valid


# ---------------------------------------------------------------------------
# V21-03 TaskFact 存储契约（create/get/list 双实现一致性）
# ---------------------------------------------------------------------------

_TASK_CONTRACT_SERVER_KEY = b"agentguard-task-contract-key"


def _task_fact_record(
    task_id: str,
    *,
    revision: int,
    expected_revision: int,
    task_text: str = "original",
) -> TaskFactRecord:
    partial_scope = SecurityStateScope(
        principal_id="cred_control",
        runtime="langgraph",
        runtime_binding_id="binding:control:cred_control",
        trace_id="trace_task_contract",
        session_id=None,
        scope_digest="",
    )
    scope_digest = scope_digest_projection(
        partial_scope, server_key=_TASK_CONTRACT_SERVER_KEY
    )
    pending = TaskFact(
        task_id=task_id,
        scope_digest=scope_digest,
        scope_key_id="test-key-1",
        principal_id="cred_control",
        task_summary=task_text,
        task_digest="sha256:pending",
        revision=revision,
        status="active",
        action_constraints=[],
        resource_constraints=[],
        destination_constraints=[],
        created_sequence=None,
        producer="guard_api_task_ingress",
        authority="authoritative",
        evidence_refs=[],
    )
    task_fact = pending.model_copy(
        update={"task_digest": task_digest_projection(pending)}
    )
    payload = task_fact.model_dump(mode="json")
    return TaskFactRecord(
        task_fact=task_fact,
        canonical_payload=payload,
        request_digest=canonical_sha256({"task_text": task_text, "revision": revision}),
        expected_revision=expected_revision,
        created_at="2026-08-14T00:00:00+00:00",
    )


def test_store_task_fact_create_get_list_contract(store) -> None:
    task_id = f"task_contract_{uuid4().hex}"
    record1 = _task_fact_record(task_id, revision=1, expected_revision=0)
    stored = store.create_task_fact(record1)
    assert stored.task_fact.task_id == task_id
    assert stored.task_fact.revision == 1

    head = store.get_task_fact(task_id)
    assert head is not None and head.task_fact.revision == 1
    first = store.get_task_fact(task_id, revision=1)
    assert first is not None and first.task_fact.task_summary == "original"
    assert store.get_task_fact(task_id, revision=2) is None
    assert store.get_task_fact(f"task_missing_{uuid4().hex}") is None
    assert store.list_task_fact_revisions(f"task_missing_{uuid4().hex}") == []

    record2 = _task_fact_record(
        task_id, revision=2, expected_revision=1, task_text="revised"
    )
    store.create_task_fact(record2)
    head = store.get_task_fact(task_id)
    assert head is not None and head.task_fact.revision == 2
    assert head.task_fact.task_summary == "revised"

    revisions = store.list_task_fact_revisions(task_id)
    assert [record.task_fact.revision for record in revisions] == [1, 2]
    # 旧 revision 全量保留，canonical_payload 可往返重建 TaskFact
    assert revisions[0].task_fact.task_summary == "original"
    assert revisions[1].task_fact.task_summary == "revised"
    for record in revisions:
        assert record.task_fact.model_dump(mode="json") == record.canonical_payload
    assert revisions[0].task_fact.task_digest != revisions[1].task_fact.task_digest


def test_store_task_fact_cas_rejects_stale_future_and_overwrite(store) -> None:
    task_id = f"task_cas_{uuid4().hex}"
    store.create_task_fact(_task_fact_record(task_id, revision=1, expected_revision=0))

    with pytest.raises(TaskRevisionConflictError) as stale:
        store.create_task_fact(
            _task_fact_record(task_id, revision=2, expected_revision=0)
        )
    assert stale.value.expected_revision == 0
    assert stale.value.current_revision == 1

    with pytest.raises(TaskRevisionConflictError):
        store.create_task_fact(
            _task_fact_record(task_id, revision=3, expected_revision=5)
        )

    with pytest.raises(TaskRevisionConflictError):
        # 同 (task_id, revision) 重写一律拒绝，旧 revision 永不覆盖
        store.create_task_fact(
            _task_fact_record(
                task_id,
                revision=1,
                expected_revision=0,
                task_text="overwrite attempt",
            )
        )

    with pytest.raises(TaskRevisionConflictError):
        # 新任务的 revision 1 必须携带 expected_revision=0
        store.create_task_fact(
            _task_fact_record(
                f"task_new_{uuid4().hex}", revision=1, expected_revision=3
            )
        )

    revisions = store.list_task_fact_revisions(task_id)
    assert [record.task_fact.revision for record in revisions] == [1]
    assert revisions[0].task_fact.task_summary == "original"
