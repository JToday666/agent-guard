"""LangGraph competition authority integration at the Guard API boundary."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentguard_core import (
    ApprovalIntent,
    ContextBuildPayload,
    ContextSource,
    DecisionAuthority,
    GuardEvent,
    SecurityContext,
    V21SelectionResult,
    build_competition_activation_manifest,
    select_v21_authority as core_select_v21_authority,
)
from agentguard_core.actions.canonical_json import canonical_sha256

import guard_api.services.audit as audit_service_module
from guard_api.auth import AuthContext
from guard_api.main import create_app
from guard_api.security_state import SecurityStateService
from guard_api.services import (
    ApprovalService,
    AuditService,
    CriticalDecisionEvidenceError,
    EvaluationService,
    FrozenCompetitionActivation,
    PolicyService,
    V21PipelineService,
    V21ShadowService,
    load_frozen_competition_activation,
)
from guard_api.services.v21_pipeline import V21OfficialEvaluationUnavailableError
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import TaskFactRecord
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.test_v21_09_pipeline import (
    _TASK_ID,
    _commit_task_fact,
    _event,
    _task_fact,
)
from tests.support.auth import add_adapter_credential

_SECRET_BYTES = b"lgv2-api-official-test-secret-material"
_SECRET = base64.urlsafe_b64encode(_SECRET_BYTES).decode("ascii")


def _settings(**overrides: object) -> GuardApiSettings:
    values: dict[str, object] = {
        "control_token": "control-secret",
        "storage_backend": "memory",
        "v21_mode": "active",
        "v21_shadow_server_secret": _SECRET,
        "rte05_strong_binding_enabled": True,
    }
    values.update(overrides)
    return GuardApiSettings(**values)  # type: ignore[arg-type]


def _activation(policy_digest: str) -> FrozenCompetitionActivation:
    manifest = build_competition_activation_manifest(
        server_secret=_SECRET_BYTES,
        principal_id="principal_a",
        agent_id="main",
        runtime_binding_id="binding:principal_a",
        policy_digest=policy_digest,
        dataset_digest="sha256:" + "d" * 64,
        profile_digest="sha256:" + "e" * 64,
        selection_basis="profile_all",
    )
    return FrozenCompetitionActivation(
        manifest=manifest,
        source_path="/process/frozen/activation.json",
        content_digest=canonical_sha256(manifest.model_dump(mode="json")),
    )


def _stack(
    *,
    with_task: bool,
    task_principal_id: str = "principal_a",
) -> tuple[EvaluationService, MemoryControlPlaneStore]:
    settings = _settings()
    store = MemoryControlPlaneStore()
    if with_task:
        if task_principal_id == "principal_a":
            _commit_task_fact(store)
        else:
            task_fact = _task_fact().model_copy(
                update={"principal_id": task_principal_id}
            )
            store.create_task_fact(
                TaskFactRecord(
                    task_fact=task_fact,
                    canonical_payload=task_fact.model_dump(mode="json"),
                    request_digest="sha256:" + "7" * 64,
                    expected_revision=0,
                    created_at="2026-08-15T00:00:00Z",
                )
            )
    state = SecurityStateService(store)
    policy = PolicyService(store=store)
    activation = _activation(
        canonical_sha256(policy.current_snapshot().model_dump(mode="json"))
    )
    approvals = ApprovalService(store=store, settings=settings)
    pipeline = V21PipelineService(
        settings=settings,
        store=store,
        state_service=state,
        policy_service=policy,
    )
    return (
        EvaluationService(
            policy_service=policy,
            audit_service=AuditService(store=store),
            approval_service=approvals,
            v21_shadow_service=V21ShadowService(
                settings=settings,
                store=store,
                state_service=state,
            ),
            v21_pipeline=pipeline,
            competition_activation=activation,
        ),
        store,
    )


def _auth() -> AuthContext:
    return AuthContext(
        principal_type="component",
        principal_id="principal_a",
        role="adapter",
        scopes=["event:evaluate"],
        auth_method="bearer",
        runtime="langgraph",
        agent_id="main",
    )


def _assert_no_evaluation_state(store: MemoryControlPlaneStore) -> None:
    assert store.audit_events == []
    assert store.approvals == {}
    assert store.enforcement_bindings == {}
    assert store.action_critic_reviews == {}
    assert store.memory_changes == {}
    assert store.provenance_nodes == {}
    assert store.provenance_edges == {}


def _force_reviewable_v21_ask(monkeypatch: pytest.MonkeyPatch) -> None:
    def select_reviewable(**kwargs: Any) -> V21SelectionResult:
        raw = kwargs["raw_v21_decision"]
        assert raw is not None
        assessment = kwargs["assessment"]
        activation = kwargs["activation"]
        selected = raw.model_copy(
            update={
                "decision_id": "dec:v21-official:reviewable-ask-test",
                "decision": "ask",
                "approval_intent": ApprovalIntent(
                    resource=f"action:{assessment.action_id}",
                ),
                "latency_ms": None,
            }
        )
        authority = DecisionAuthority(
            source="v21",
            mode="active",
            selection_basis="profile_all",
            matched_path_ids=[],
            legacy_floor_applied=False,
            activation_ref_digest=activation.activation_ref_digest,
            approval_release="strong_binding_required",
        )
        return V21SelectionResult(
            selected_decision=selected,
            selected_decision_digest=canonical_sha256(
                selected.model_dump(mode="json")
            ),
            current_decision=kwargs["current_decision"],
            raw_v21_decision=raw,
            authority=authority,
        )

    monkeypatch.setattr(
        "guard_api.services.evaluation.select_v21_authority",
        select_reviewable,
    )


def test_active_selected_decision_authority_is_committed_and_replayed() -> None:
    evaluation, store = _stack(with_task=True)
    event = _event(
        event_id="evt_lgv2_active_allow",
        task_id=_TASK_ID,
        call_id="call_lgv2_active_allow",
    )

    first = evaluation.evaluate(event, auth_context=_auth())
    assert first.decision_authority is not None
    assert first.decision_authority.source == "v21"
    assert first.decision_authority.mode == "active"
    assert first.decision.decision_id.startswith("dec:v21-official:")

    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    assert (audit.model_extra or {})["decision_authority"] == (
        first.decision_authority.model_dump(mode="json")
    )
    assert audit.evidence is not None
    payload = audit.evidence["decision_authority"]["payload"]
    assert payload["selected_decision"] == first.decision.model_dump(mode="json")
    assert audit.evidence["guard_decision"] == first.decision.model_dump(mode="json")
    assert audit.evidence["decision_v21"]["payload"]["mode"] == "active"
    assert audit.evidence["decision_v21"]["payload"]["final_decision"] == (
        first.decision.decision
    )
    assert audit.metadata["v21_final_decision_id"] == first.decision.decision_id
    assert audit.metadata["v21_final_decision_digest"] == canonical_sha256(
        first.decision.model_dump(mode="json")
    )

    # Replay is rebuilt solely from committed audit data.  A live mode change
    # cannot reselect the historical decision or authority.
    assert evaluation.v21_pipeline is not None
    evaluation.v21_pipeline._mode = "shadow"  # noqa: SLF001 - replay probe.
    replay = evaluation.evaluate(event, auth_context=_auth())
    assert replay.decision == first.decision
    assert replay.decision_authority == first.decision_authority


def test_active_required_state_absence_is_unreleasable_v2_ask() -> None:
    evaluation, store = _stack(with_task=False)
    event = _event(
        event_id="evt_lgv2_active_no_task",
        task_id=None,
        call_id="call_lgv2_active_no_task",
    )

    response = evaluation.evaluate(event, auth_context=_auth())

    assert response.decision.decision == "ask"
    assert response.decision_authority is not None
    assert response.decision_authority.source == "v21"
    assert response.decision_authority.approval_release == "forbidden"
    assert response.approval is None
    assert response.enforcement_binding is None
    assert store.list_pending_approvals() == []


def test_active_context_assembled_ask_is_unreleasable_without_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation, store = _stack(with_task=True)
    observed_binding_eligibility: list[bool] = []

    def capture_eligibility(**kwargs: Any) -> V21SelectionResult:
        eligibility = kwargs["eligibility"]
        observed_binding_eligibility.append(eligibility.approval_binding_eligible)
        return core_select_v21_authority(**kwargs)

    monkeypatch.setattr(
        "guard_api.services.evaluation.select_v21_authority",
        capture_eligibility,
    )
    event = GuardEvent(
        event_id="evt_lgv2_context_ask",
        event_type="context_assembled",
        runtime="langgraph",
        trace_id="trace_pipeline_1",
        timestamp="2026-08-15T00:00:00+00:00",
        pre_execution=True,
        security_context=SecurityContext(
            user_task="pipeline fixture",
            agent_id="main",
        ),
        payload=ContextBuildPayload(
            sources=[
                ContextSource(
                    source_id="source_lgv2_context_ask",
                    source_type="user",
                    source_trust="trusted",
                    summary="pipeline fixture",
                    content_digest=canonical_sha256("pipeline fixture"),
                    role="user",
                    sequence_index=0,
                )
            ]
        ),
        metadata={"task_id": _TASK_ID},
    )

    response = evaluation.evaluate(event, auth_context=_auth())

    assert observed_binding_eligibility == [False]
    assert response.decision.decision == "ask"
    assert response.decision.approval_intent is None
    assert response.decision_authority is not None
    assert response.decision_authority.approval_release == "forbidden"
    assert response.approval is None
    assert response.enforcement_binding is None
    assert response.policy_audit_id is not None
    assert store.list_pending_approvals() == []
    assert store.enforcement_bindings == {}


def test_active_cross_principal_task_fact_returns_503_with_zero_evaluation_state(
    tmp_path: Path,
) -> None:
    store = MemoryControlPlaneStore()
    add_adapter_credential(store, principal_id="principal_a")
    task_fact = _task_fact().model_copy(update={"principal_id": "principal_other"})
    store.create_task_fact(
        TaskFactRecord(
            task_fact=task_fact,
            canonical_payload=task_fact.model_dump(mode="json"),
            request_digest="sha256:" + "7" * 64,
            expected_revision=0,
            created_at="2026-08-15T00:00:00Z",
        )
    )
    policy = PolicyService(store=store)
    activation = _activation(
        canonical_sha256(policy.current_snapshot().model_dump(mode="json"))
    )
    activation_path = tmp_path / "competition-activation.json"
    activation_path.write_text(
        json.dumps(activation.manifest.model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )
    activation_path.chmod(0o444)
    settings = _settings(
        task_scope_active_key_id="scope_key_test",
        task_scope_keys=json.dumps({"scope_key_test": _SECRET}),
        v21_competition_activation_path=str(activation_path),
    )
    event = _event(
        event_id="evt_lgv2_cross_principal",
        task_id=_TASK_ID,
        call_id="call_lgv2_cross_principal",
    )

    client = TestClient(create_app(store=store, settings=settings))
    response = client.post(
        "/v1/guard/evaluate",
        headers={"Authorization": "Bearer adapter-secret"},
        json=event.model_dump(mode="json"),
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == (
        "v21-competition:active_authority_precondition_failed"
    )
    assert store.get_policy_evaluation_by_event_id(event.event_id) is None
    _assert_no_evaluation_state(store)


def test_active_decision_evidence_degradation_rolls_back_every_side_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation, store = _stack(with_task=True)
    event = _event(
        event_id="evt_lgv2_critical_evidence",
        task_id=_TASK_ID,
        call_id="call_lgv2_critical_evidence",
    )
    original_sanitize = audit_service_module.sanitize_audit_event

    def degrade_decision_evidence(audit_event):
        sanitized = original_sanitize(audit_event)
        evidence = dict(sanitized.evidence or {})
        if "decision_authority" in evidence:
            evidence["decision_v21"] = {
                "_budget_dropped": True,
                "reason": "injected-critical-evidence-budget-fault",
            }
        return sanitized.model_copy(update={"evidence": evidence})

    monkeypatch.setattr(
        audit_service_module,
        "sanitize_audit_event",
        degrade_decision_evidence,
    )

    with pytest.raises(CriticalDecisionEvidenceError):
        evaluation.evaluate(event, auth_context=_auth())

    assert store.get_policy_evaluation_by_event_id(event.event_id) is None
    _assert_no_evaluation_state(store)


def test_active_reviewable_ask_commits_approval_binding_and_replays_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation, store = _stack(with_task=True)
    _force_reviewable_v21_ask(monkeypatch)
    event = _event(
        event_id="evt_lgv2_reviewable_ask",
        task_id=_TASK_ID,
        call_id="call_lgv2_reviewable_ask",
    )

    first = evaluation.evaluate(event, auth_context=_auth())

    assert first.decision.decision == "ask"
    assert first.decision.approval_intent is not None
    assert first.decision_authority is not None
    assert first.decision_authority.approval_release == "strong_binding_required"
    assert first.approval is not None
    assert first.approval.status == "pending"
    assert first.enforcement_binding is not None
    stored_binding = store.get_enforcement_binding(first.approval.approval_id)
    assert stored_binding is not None
    assert stored_binding.policy_audit_id == first.policy_audit_id
    assert stored_binding.action_id == first.enforcement_binding.action_id
    assert (
        stored_binding.authorization_fingerprint
        == first.enforcement_binding.authorization_fingerprint
    )
    assert len(store.approvals) == 1
    assert len(store.enforcement_bindings) == 1

    replay = evaluation.evaluate(event, auth_context=_auth())

    assert replay == first
    assert len(store.approvals) == 1
    assert len(store.enforcement_bindings) == 1
    assert len(
        [
            audit
            for audit in store.audit_events
            if audit.record_type == "policy_evaluation"
        ]
    ) == 1


def test_active_reviewable_ask_binding_failure_rolls_back_approval_and_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation, store = _stack(with_task=True)
    _force_reviewable_v21_ask(monkeypatch)
    event = _event(
        event_id="evt_lgv2_reviewable_binding_failure",
        task_id=_TASK_ID,
        call_id="call_lgv2_reviewable_binding_failure",
    )

    def fail_binding_write(_store, _record):
        raise RuntimeError("injected binding persistence failure")

    monkeypatch.setattr(
        MemoryControlPlaneStore,
        "save_enforcement_binding",
        fail_binding_write,
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        evaluation.evaluate(event, auth_context=_auth())

    assert raised.value.code == "V21_OFFICIAL_STRONG_BINDING_SAVE_FAILED"
    assert store.get_policy_evaluation_by_event_id(event.event_id) is None
    _assert_no_evaluation_state(store)


def test_activation_loader_verifies_read_only_server_owned_manifest(tmp_path) -> None:
    manifest = _activation("sha256:" + "c" * 64).manifest
    path = tmp_path / "activation.json"
    path.write_text(manifest.model_dump_json(), encoding="utf-8")
    path.chmod(0o400)

    loaded = load_frozen_competition_activation(
        _settings(v21_competition_activation_path=str(path))
    )

    assert loaded is not None
    assert loaded.manifest == manifest
    assert loaded.source_path == str(path)
