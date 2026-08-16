"""Gate A / INT-PR-01 production-path acceptance tests.

The tests deliberately exercise the public HTTP task/evaluate path and the
real Memory/PostgreSQL projectors. They keep the current-event action ephemeral
while proving that a verified, previously committed tool-result source can
influence the V2.1 shadow assessment through B2.
"""

from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentguard_core import GuardEvent
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.authority.models import EvaluationClock, SecurityStateScope
from agentguard_core.decisions import shadow as shadow_module
from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    OnlineSecurityState,
)
from agentguard_core.security_context.projection import generate_behavior_signals
from guard_api.main import create_app
from guard_api.security_state import SecurityStateService
from guard_api.security_state.transient import (
    TransientSecurityFacts,
    compute_overlay_digest,
)
from guard_api.services.ct_projection import CtProjectionService
from guard_api.services import evaluation as evaluation_module
from guard_api.services.evaluation import canonical_request_dump
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.auth import add_adapter_credential, memory_store_with_adapter
from tests.support.postgres import get_test_database_url, reset_control_plane_schema

_ADAPTER_HEADERS = {"Authorization": "Bearer adapter-secret"}
_CONTROL_HEADERS = {"Authorization": "Bearer control-secret"}
_TRACE_ID = "trace_gate_a_int_pr_01"
_SHADOW_SECRET = base64.urlsafe_b64encode(
    b"gate-a-int-pr-01-shadow-secret-material"
).decode("ascii")
_SCOPE_KEY = base64.b64encode(b"gate-a-scope-key-material-000001").decode("ascii")
_SCOPE_KEY_ID = "gate-a-scope-key-1"


def _settings(
    *,
    ct_enabled: bool = True,
    shadow_enabled: bool = True,
    shadow_secret: str | None = _SHADOW_SECRET,
) -> GuardApiSettings:
    return GuardApiSettings(
        control_token="control-secret",
        storage_backend="memory",
        v21_shadow_enabled=shadow_enabled,
        v21_shadow_server_secret=shadow_secret,
        ct_fact_projection_enabled=ct_enabled,
        task_scope_active_key_id=_SCOPE_KEY_ID,
        task_scope_keys=json.dumps({_SCOPE_KEY_ID: _SCOPE_KEY}),
    )


def _client_and_store(
    *, ct_enabled: bool = True
) -> tuple[TestClient, MemoryControlPlaneStore]:
    store = memory_store_with_adapter()
    client = TestClient(
        create_app(store=store, settings=_settings(ct_enabled=ct_enabled))
    )
    return client, store


def _test_dotenv_path() -> Path:
    """Resolve the private test DB config for a linked Git worktree."""

    root = Path(__file__).resolve().parents[1]
    local = root / ".env"
    if local.exists():
        return local
    git_pointer = root / ".git"
    if not git_pointer.is_file():
        return local
    prefix = "gitdir: "
    pointer = git_pointer.read_text(encoding="utf-8").strip()
    if not pointer.startswith(prefix):
        return local
    gitdir = Path(pointer.removeprefix(prefix)).resolve()
    commondir_file = gitdir / "commondir"
    if not commondir_file.exists():
        return local
    common_git_dir = (gitdir / commondir_file.read_text().strip()).resolve()
    shared = common_git_dir.parent / ".env"
    return shared if shared.exists() else local


def _create_task(client: TestClient) -> dict[str, Any]:
    response = client.post(
        "/v1/tasks",
        headers=_CONTROL_HEADERS,
        json={
            "task_text": "Summarize a tool result and send the approved summary.",
            "runtime": "langgraph",
            "trace_id": _TRACE_ID,
            "action_constraints": [],
            "resource_constraints": [],
            "destination_constraints": [],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _base_event(
    *, event_id: str, event_type: str, task_id: str, timestamp: str
) -> dict[str, Any]:
    return {
        "schema_version": "0.3",
        "event_id": event_id,
        "event_type": event_type,
        "runtime": "langgraph",
        "trace_id": _TRACE_ID,
        "timestamp": timestamp,
        "pre_execution": True,
        "security_context": {
            "user_task": "Summarize a tool result and send the approved summary.",
            "source_type": "user",
            "source_trust": "trusted",
            "agent_id": "main",
        },
        "metadata": {"task_id": task_id},
    }


def _tool_result_event(*, task_id: str, event_id: str, call_id: str) -> dict[str, Any]:
    event = _base_event(
        event_id=event_id,
        event_type="tool_result_produced",
        task_id=task_id,
        timestamp="2026-08-16T00:00:01+00:00",
    )
    event["payload"] = {
        "tool": {
            "name": "read_file",
            "category": "filesystem",
            "kind": "file_read",
            "call_id": call_id,
        },
        "result": {
            "content_preview": "Untrusted report contents.",
            "content_type": "text/plain",
            "size_bytes": 32,
        },
        "will_enter_context": True,
        "will_persist": False,
        "sanitized": False,
        "contains_sensitive_data": False,
        "contains_instruction_like_text": True,
        "derived_resources": [],
    }
    return event


def _model_output_event(
    *, task_id: str, event_id: str, visible_source_refs: list[str]
) -> dict[str, Any]:
    event = _base_event(
        event_id=event_id,
        event_type="model_output_produced",
        task_id=task_id,
        timestamp="2026-08-16T00:00:02+00:00",
    )
    event["security_context"]["visible_source_refs"] = visible_source_refs
    event["payload"] = {
        "phase": "output",
        "content_preview": "Summary prepared from the visible tool result.",
        "provider": "fixture",
        "model": "fixture-model",
        "contains_instruction_like_text": False,
        "contains_sensitive_data": False,
        "sanitized": False,
        "tool_plan": [],
    }
    return event


_OMITTED = object()


def _high_impact_event(
    *,
    task_id: str,
    event_id: str,
    call_id: str,
    visible_source_refs: object = _OMITTED,
) -> dict[str, Any]:
    event = _base_event(
        event_id=event_id,
        event_type="tool_call_proposed",
        task_id=task_id,
        timestamp="2026-08-16T00:00:03+00:00",
    )
    if visible_source_refs is not _OMITTED:
        event["security_context"]["visible_source_refs"] = visible_source_refs
    event["payload"] = {
        "tool": {
            "name": "send_email",
            "category": "message",
            "kind": "email_send",
            "call_id": call_id,
        },
        "arguments": {
            "to": "reviewer@example.invalid",
            "subject": "Report summary",
            "body": "The requested summary.",
        },
        "derived_resources": [],
    }
    return event


def _post_evaluate(client: TestClient, event: dict[str, Any]) -> dict[str, Any]:
    response = client.post("/v1/guard/evaluate", headers=_ADAPTER_HEADERS, json=event)
    assert response.status_code == 200, response.text
    return response.json()


def _decision_v21_payload(audit) -> dict[str, Any]:
    envelope = audit.evidence["decision_v21"]
    assert envelope["schema_version"] == "2.1"
    payload = envelope["payload"]
    assert isinstance(payload, dict)
    return payload


def _stable_response_dump(response: dict[str, Any]) -> dict[str, Any]:
    """Remove only per-evaluation IDs/timing from the official response."""

    stable = copy.deepcopy(response)
    stable.pop("policy_audit_id", None)
    decision = stable.get("decision")
    if isinstance(decision, dict):
        decision.pop("decision_id", None)
        decision.pop("latency_ms", None)
    approval = stable.get("approval")
    if isinstance(approval, dict):
        approval.pop("approval_id", None)
    return stable


def _online_state(store, scope_digest: str) -> OnlineSecurityState:
    record = store.get_security_state(scope_digest)
    assert record is not None
    assert record.dirty is False
    return OnlineSecurityState.model_validate(record.canonical_payload)


def _postcommit_snapshot(store, *, task_id: str, scope_digest: str):
    task_record = store.get_task_fact(task_id)
    assert task_record is not None
    task = task_record.task_fact
    service = SecurityStateService(store)
    snapshot, _ = service.read_snapshot_with_revoked(
        scope_digest,
        scope=SecurityStateScope(
            principal_id=task.principal_id,
            runtime="langgraph",
            runtime_binding_id=f"binding:{task.principal_id}",
            trace_id=_TRACE_ID,
            session_id=None,
            scope_digest=scope_digest,
        ),
        task_fact_head=task,
        evaluation_clock=EvaluationClock(
            evaluated_at="2026-08-16T00:00:03+00:00",
            clock_version="gate-a-test-clock",
        ),
        policy_revision="gate-a-test-policy",
        policy_digest=canonical_sha256({"fixture": "gate-a"}),
        plan=RequiredCheckPlan(
            plan_id="gate-a:int-pr-01:postcommit",
            impact="high",
            required_domains=["task", "source", "dataflow", "behavior"],
            optional_domains=["capability", "memory", "runtime_outcome"],
            required_capabilities=[],
            semantic_resolvable_dimensions=[],
            reason_codes=["gate-a:int-pr-01"],
        ),
    )
    return snapshot


def test_visible_source_refs_legacy_wire_compatibility_none_vs_empty() -> None:
    base = _high_impact_event(
        task_id="task_wire_fixture",
        event_id="evt_gate_a_wire",
        call_id="call_gate_a_wire",
    )
    omitted = GuardEvent.model_validate(base)

    explicit_none_payload = copy.deepcopy(base)
    explicit_none_payload["security_context"]["visible_source_refs"] = None
    explicit_none = GuardEvent.model_validate(explicit_none_payload)

    explicit_empty_payload = copy.deepcopy(base)
    explicit_empty_payload["security_context"]["visible_source_refs"] = []
    explicit_empty = GuardEvent.model_validate(explicit_empty_payload)

    # Optional capability omitted/None preserves the pre-Gate-A wire shape.
    assert "visible_source_refs" not in omitted.security_context.model_dump(mode="json")
    assert "visible_source_refs" not in explicit_none.security_context.model_dump(
        mode="json"
    )
    assert canonical_request_dump(omitted) == canonical_request_dump(explicit_none)

    # An explicit [] is a complete, proven-empty visible set and must survive.
    assert explicit_empty.security_context.visible_source_refs == ()
    assert (
        explicit_empty.security_context.model_dump(mode="json")["visible_source_refs"]
        == []
    )
    assert canonical_request_dump(explicit_empty) != canonical_request_dump(omitted)


def test_http_none_degrades_but_explicit_empty_is_complete() -> None:
    audits: dict[str, Any] = {}
    contexts: dict[str, tuple[Any, dict[str, Any]]] = {}
    for label, refs in (("none", _OMITTED), ("empty", [])):
        client, store = _client_and_store()
        task = _create_task(client)
        event = _high_impact_event(
            task_id=task["task_id"],
            event_id=f"evt_gate_a_{label}",
            call_id=f"call_gate_a_{label}",
            visible_source_refs=refs,
        )
        _post_evaluate(client, event)
        audit = store.get_policy_evaluation_by_event_id(event["event_id"])
        assert audit is not None
        audits[label] = audit
        contexts[label] = (store, task)

    missing_id = "degradation:evt_gate_a_none:ct-fact:visible_set_unavailable"
    assert missing_id in _decision_v21_payload(audits["none"])["degradation_ids"]
    missing_ct = audits["none"].evidence["ct_transient_facts"]["payload"]
    assert missing_ct["projection_eligible"] is False
    assert missing_ct["projection_id"] is None
    assert missing_ct["overlay_digest"].startswith("sha256:")
    missing_store, missing_task = contexts["none"]
    missing_registration = SecurityStateService(
        missing_store
    ).store_access.get_projection(
        missing_task["scope_digest"],
        "runtime_observation",
        "ct-facts:evt_gate_a_none",
        1,
        PROJECTOR_VERSION,
    )
    assert missing_registration is None

    empty_evidence = _decision_v21_payload(audits["empty"])
    assert missing_id not in empty_evidence["degradation_ids"]
    empty_ct = audits["empty"].evidence["ct_transient_facts"]["payload"]
    assert empty_ct["projection_eligible"] is True
    assert empty_ct["bundle"]["degradations"] == []
    assert empty_ct["overlay_digest"].startswith("sha256:")


def test_enabled_ct_bundle_failure_is_required_degradation_without_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        CtProjectionService,
        "build_transient_bundle",
        lambda self, event, materials: None,
    )
    client, store = _client_and_store()
    task = _create_task(client)
    event = _high_impact_event(
        task_id=task["task_id"],
        event_id="evt_gate_a_bundle_failure",
        call_id="call_gate_a_bundle_failure",
        visible_source_refs=[],
    )

    _post_evaluate(client, event)
    audit = store.get_policy_evaluation_by_event_id(event["event_id"])
    assert audit is not None
    decision_v21 = _decision_v21_payload(audit)
    assert decision_v21["v21_fast_disposition"] == "DEFER"
    assert (
        "gate-a:ct-overlay-unavailable:evt_gate_a_bundle_failure"
        in decision_v21["degradation_ids"]
    )
    assert "ct_transient_facts" not in audit.evidence


def test_unconsumed_ct_bundle_cannot_be_committed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = evaluation_module.AssessmentTransientFacts.model_validate

    def reject_mapping(cls, value, *args, **kwargs):
        del cls, value, args, kwargs
        raise ValueError("injected Core DTO mapping failure")

    monkeypatch.setattr(
        evaluation_module.AssessmentTransientFacts,
        "model_validate",
        classmethod(reject_mapping),
    )
    client, store = _client_and_store()
    task = _create_task(client)
    event = _high_impact_event(
        task_id=task["task_id"],
        event_id="evt_gate_a_mapping_failure",
        call_id="call_gate_a_mapping_failure",
        visible_source_refs=[],
    )

    try:
        _post_evaluate(client, event)
    finally:
        # Keep teardown deterministic even if the request assertion fails.
        monkeypatch.setattr(
            evaluation_module.AssessmentTransientFacts,
            "model_validate",
            original,
        )
    audit = store.get_policy_evaluation_by_event_id(event["event_id"])
    assert audit is not None
    decision_v21 = _decision_v21_payload(audit)
    assert decision_v21["v21_fast_disposition"] == "DEFER"
    assert (
        "gate-a:ct-overlay-unavailable:evt_gate_a_mapping_failure"
        in decision_v21["degradation_ids"]
    )
    assert "ct_transient_facts" not in audit.evidence


def test_core_overlay_failure_cannot_commit_unconsumed_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_overlay(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise ValueError("injected overlay identity conflict")

    monkeypatch.setattr(shadow_module, "build_assessment_overlay", fail_overlay)
    client, store = _client_and_store()
    task = _create_task(client)
    event = _high_impact_event(
        task_id=task["task_id"],
        event_id="evt_gate_a_overlay_failure",
        call_id="call_gate_a_overlay_failure",
        visible_source_refs=[],
    )

    _post_evaluate(client, event)
    audit = store.get_policy_evaluation_by_event_id(event["event_id"])
    assert audit is not None
    decision_v21 = _decision_v21_payload(audit)
    assert decision_v21["v21_fast_disposition"] == "DEFER"
    assert any(
        item.startswith("v21-08-shadow-degrade:evt_gate_a_overlay_failure")
        for item in decision_v21["degradation_ids"]
    )
    assert "ct_transient_facts" not in audit.evidence


def _evaluate_verified_chain(client: TestClient, store):
    task = _create_task(client)
    result_event = _tool_result_event(
        task_id=task["task_id"],
        event_id="evt_gate_a_result",
        call_id="call_gate_a_result",
    )
    _post_evaluate(client, result_event)
    _post_evaluate(
        client,
        _model_output_event(
            task_id=task["task_id"],
            event_id="evt_gate_a_model_output",
            visible_source_refs=["action:call_gate_a_result"],
        ),
    )
    # Historical state before the high-impact request contains only committed
    # prior events. The current action and its direct influence edge must not
    # appear until the request's authoritative audit commit has succeeded.
    pre_action_state = _online_state(store, task["scope_digest"])
    assert pre_action_state.recent_actions == []
    assert not any(
        flow.target_ref == "action:call_gate_a_high_action"
        for flow in pre_action_state.relevant_flows
    )
    action_event = _high_impact_event(
        task_id=task["task_id"],
        event_id="evt_gate_a_high_action",
        call_id="call_gate_a_high_action",
        # Runtime knows the producer call ID; the server must resolve this alias
        # through the unique committed returned_by edge in the task scope.
        visible_source_refs=["action:call_gate_a_result"],
    )
    response = _post_evaluate(client, action_event)
    return task, response


def _run_verified_chain(*, ct_enabled: bool):
    client, store = _client_and_store(ct_enabled=ct_enabled)
    task, response = _evaluate_verified_chain(client, store)
    return client, store, task, response


def test_http_verified_tool_result_lineage_reaches_b2_shadow_only(
    tmp_path: Path,
) -> None:
    client, store, task, response = _run_verified_chain(ct_enabled=True)
    _, _, _, legacy_response = _run_verified_chain(ct_enabled=False)

    # Gate A remains shadow-only: the public legacy response is unchanged.
    assert _stable_response_dump(response) == _stable_response_dump(legacy_response)

    audit = store.get_policy_evaluation_by_event_id("evt_gate_a_high_action")
    assert audit is not None
    ct_payload = audit.evidence["ct_transient_facts"]["payload"]
    assert ct_payload["projection_eligible"] is True
    bundle = TransientSecurityFacts.model_validate(ct_payload["bundle"])

    # The audit binds the complete assessment overlay, not only projection facts.
    assert ct_payload["overlay_digest"] == bundle.overlay_digest
    assert bundle.overlay_digest == compute_overlay_digest(bundle)
    assert bundle.overlay_digest.startswith("sha256:")
    assert bundle.current_action is not None
    assert bundle.current_action.impact == "high"

    scope_digest = task["scope_digest"]
    state = _online_state(store, scope_digest)
    returned_by = next(
        flow
        for flow in state.relevant_flows
        if flow.relation == "returned_by"
        and flow.source_ref == "action:call_gate_a_result"
    )
    tool_result_ref = returned_by.target_ref
    source = next(
        source for source in state.source_index if source.source_id == tool_result_ref
    )
    assert source.source_type == "tool_result"
    assert source.trust == "untrusted"
    assert "UNTRUSTED" in source.taints
    assert tool_result_ref in bundle.current_action.data_refs

    model_influence = next(
        flow
        for flow in state.relevant_flows
        if flow.source_ref == tool_result_ref
        and flow.target_ref == "model_output:evt_gate_a_model_output"
        and flow.relation == "influenced_by"
    )
    assert model_influence.strength == "possible"
    assert "UNTRUSTED" in model_influence.taints

    influence = next(
        flow
        for flow in state.relevant_flows
        if flow.source_ref == tool_result_ref
        and flow.target_ref == "action:call_gate_a_high_action"
        and flow.relation == "influenced_by"
    )
    assert influence.strength == "possible"
    assert influence.origin == "semantic_inferred"
    assert "UNTRUSTED" in influence.taints

    # Recreate the exact behavior input from committed source/flow facts plus
    # the current-event action candidate. B2 generated here must be the signal
    # persisted by the real HTTP shadow pipeline.
    assert state.recent_actions == []
    behavior_state = state.model_copy(
        update={"recent_actions": [bundle.current_action]}, deep=True
    )
    b2_signals = [
        signal
        for signal in generate_behavior_signals(behavior_state)
        if signal.category == "behavior:B2"
    ]
    assert len(b2_signals) == 1
    decision_v21 = _decision_v21_payload(audit)
    assert b2_signals[0].signal_id in decision_v21["signal_ids"]
    assert influence.flow_id in decision_v21["flow_path_refs"]
    assert decision_v21["mode"] == "shadow"
    assert decision_v21["v21_fast_disposition"] == "DEFER"
    assert decision_v21["divergence_category"] is None
    assert decision_v21["coverage"]["dataflow"]["status"] == "partial"
    assert decision_v21["coverage"]["behavior"]["status"] == "complete"

    # Public read APIs must return the same high-risk policy record with all
    # three Gate A envelopes; integrity verification remains valid.
    window_response = client.get(
        f"/v1/audit/window?trace_id={_TRACE_ID}", headers=_CONTROL_HEADERS
    )
    assert window_response.status_code == 200, window_response.text
    window_events = window_response.json()["events"]
    window_high = next(
        item for item in window_events if item["audit_id"] == audit.audit_id
    )
    assert {
        "decision_v21",
        "state_delta_v21",
        "ct_transient_facts",
    } <= set(window_high["evidence"])

    trace_response = client.get(f"/v1/traces/{_TRACE_ID}", headers=_CONTROL_HEADERS)
    assert trace_response.status_code == 200, trace_response.text
    trace_high = next(
        item
        for item in trace_response.json()["audit_events"]
        if item["audit_id"] == audit.audit_id
    )
    assert {
        "decision_v21",
        "state_delta_v21",
        "ct_transient_facts",
    } <= set(trace_high["evidence"])

    integrity_response = client.get("/v1/audit/integrity", headers=_CONTROL_HEADERS)
    assert integrity_response.status_code == 200, integrity_response.text
    assert integrity_response.json()["valid"] is True

    # Feed the very same persisted policy_evaluation into the existing offline
    # divergence tool; this is not a synthetic DecisionEvidence-only fixture.
    divergence_input = tmp_path / "gate-a-audit.jsonl"
    divergence_input.write_text(
        json.dumps(audit.model_dump(mode="json"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    divergence_output = tmp_path / "divergence"
    divergence_result = subprocess.run(
        [
            sys.executable,
            str(
                Path(__file__).resolve().parents[1]
                / "scripts"
                / "v21-shadow-divergence.py"
            ),
            "--input",
            str(divergence_input),
            "--output-dir",
            str(divergence_output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert divergence_result.returncode == 0, divergence_result.stderr
    divergence_report = json.loads(
        (divergence_output / "divergence.json").read_text(encoding="utf-8")
    )
    assert divergence_report["ok"] is True
    assert divergence_report["totals"]["with_envelope"] == 1
    assert divergence_report["modes"] == {"shadow": 1}
    assert divergence_report["anomalies"] == []

    # The pre-decision candidate is never projected as historical action state.
    state_service = SecurityStateService(store)
    registration = state_service.store_access.get_projection(
        scope_digest,
        "runtime_observation",
        "ct-facts:evt_gate_a_high_action",
        1,
        PROJECTOR_VERSION,
    )
    assert registration is not None
    assert registration.delta_payload["action_additions"] == []
    assert _online_state(store, scope_digest).recent_actions == []

    # A fresh postcommit Snapshot exposes the projected source/flow/taint.
    snapshot = _postcommit_snapshot(
        store, task_id=task["task_id"], scope_digest=scope_digest
    )
    assert any(item.source_id == tool_result_ref for item in snapshot.sources)
    assert any(flow.flow_id == model_influence.flow_id for flow in snapshot.flows)
    snapshot_edge = next(
        flow for flow in snapshot.flows if flow.flow_id == influence.flow_id
    )
    assert "UNTRUSTED" in snapshot_edge.taints


def test_http_forged_visible_ref_emits_no_edge_or_b2() -> None:
    client, store = _client_and_store()
    task = _create_task(client)
    _post_evaluate(
        client,
        _tool_result_event(
            task_id=task["task_id"],
            event_id="evt_gate_a_forged_seed",
            call_id="call_gate_a_real_result",
        ),
    )
    forged_event = _high_impact_event(
        task_id=task["task_id"],
        event_id="evt_gate_a_forged_action",
        call_id="call_gate_a_forged_action",
        visible_source_refs=["action:call_gate_a_does_not_exist"],
    )
    _post_evaluate(client, forged_event)

    audit = store.get_policy_evaluation_by_event_id(forged_event["event_id"])
    assert audit is not None
    decision_v21 = _decision_v21_payload(audit)
    assert not any(
        str(signal_id).startswith("v21-07-signal:")
        for signal_id in decision_v21["signal_ids"]
    )
    assert (
        "degradation:evt_gate_a_forged_action:ct-fact:visible_set_unavailable"
        in decision_v21["degradation_ids"]
    )

    scope_digest = task["scope_digest"]
    state = _online_state(store, scope_digest)
    assert not any(
        flow.target_ref == "action:call_gate_a_forged_action"
        for flow in state.relevant_flows
    )
    registration = SecurityStateService(store).store_access.get_projection(
        scope_digest,
        "runtime_observation",
        "ct-facts:evt_gate_a_forged_action",
        1,
        PROJECTOR_VERSION,
    )
    assert registration is None


def test_postgres_verified_chain_survives_store_reopen() -> None:
    """The Gate A chain has storage parity and restart-safe readback."""

    database_url = get_test_database_url(dotenv_path=_test_dotenv_path())
    reset_control_plane_schema(database_url)
    store = PostgresControlPlaneStore(database_url)
    try:
        store.initialize()
        add_adapter_credential(store)
        client = TestClient(create_app(store=store, settings=_settings()))
        task, response = _evaluate_verified_chain(client, store)
        assert response["decision"]["decision"] in {"allow", "ask", "deny"}

        audit = store.get_policy_evaluation_by_event_id("evt_gate_a_high_action")
        assert audit is not None
        assert {
            "decision_v21",
            "state_delta_v21",
            "ct_transient_facts",
        } <= set(audit.evidence)
        ct_payload = audit.evidence["ct_transient_facts"]["payload"]
        bundle = TransientSecurityFacts.model_validate(ct_payload["bundle"])
        assert ct_payload["overlay_digest"] == bundle.overlay_digest
        assert bundle.overlay_digest == compute_overlay_digest(bundle)

        scope_digest = task["scope_digest"]
        registration = SecurityStateService(store).store_access.get_projection(
            scope_digest,
            "runtime_observation",
            "ct-facts:evt_gate_a_high_action",
            1,
            PROJECTOR_VERSION,
        )
        assert registration is not None
        assert registration.delta_payload["action_additions"] == []
        first_snapshot = _postcommit_snapshot(
            store, task_id=task["task_id"], scope_digest=scope_digest
        )
        assert any(
            source.source_type == "tool_result" and "UNTRUSTED" in source.taints
            for source in first_snapshot.sources
        )
        assert any(
            flow.relation == "influenced_by" and "UNTRUSTED" in flow.taints
            for flow in first_snapshot.flows
        )

        # New store instance: read the authoritative audit, projection record,
        # online state, and rebuilt Snapshot without relying on process memory.
        restarted = PostgresControlPlaneStore(database_url)
        restarted.initialize()
        persisted_audit = restarted.get_policy_evaluation_by_event_id(
            "evt_gate_a_high_action"
        )
        assert persisted_audit is not None
        persisted_ct = persisted_audit.evidence["ct_transient_facts"]["payload"]
        assert persisted_ct["bundle_digest"] == ct_payload["bundle_digest"]
        assert persisted_ct["overlay_digest"] == ct_payload["overlay_digest"]

        persisted_registration = SecurityStateService(
            restarted
        ).store_access.get_projection(
            scope_digest,
            "runtime_observation",
            "ct-facts:evt_gate_a_high_action",
            1,
            PROJECTOR_VERSION,
        )
        assert persisted_registration is not None
        assert persisted_registration.delta_digest == registration.delta_digest
        persisted_state = _online_state(restarted, scope_digest)
        assert persisted_state.recent_actions == []
        restarted_snapshot = _postcommit_snapshot(
            restarted,
            task_id=task["task_id"],
            scope_digest=scope_digest,
        )
        assert restarted_snapshot.snapshot_digest == first_snapshot.snapshot_digest
        assert restarted.verify_audit_integrity().valid is True
    finally:
        reset_control_plane_schema(database_url)


def test_flag_rollback_stops_new_overlay_and_preserves_committed_history() -> None:
    """Turning both flags off is non-destructive and restores legacy-only writes."""

    store = memory_store_with_adapter()
    enabled_client = TestClient(create_app(store=store, settings=_settings()))
    task = _create_task(enabled_client)
    enabled_event = _tool_result_event(
        task_id=task["task_id"],
        event_id="evt_gate_a_before_rollback",
        call_id="call_gate_a_before_rollback",
    )
    enabled_response = _post_evaluate(enabled_client, enabled_event)
    historical_audit = store.get_policy_evaluation_by_event_id(
        enabled_event["event_id"]
    )
    assert historical_audit is not None
    assert "ct_transient_facts" in historical_audit.evidence
    scope_digest = task["scope_digest"]
    before_rollback = store.get_security_state(scope_digest)
    assert before_rollback is not None

    disabled_client = TestClient(
        create_app(
            store=store,
            settings=_settings(
                ct_enabled=False,
                shadow_enabled=False,
                shadow_secret=None,
            ),
        )
    )
    disabled_event = _tool_result_event(
        task_id=task["task_id"],
        event_id="evt_gate_a_after_rollback",
        # Keep the evaluated action content identical; only the idempotency
        # event key changes so this is a true flag A/B response comparison.
        call_id="call_gate_a_before_rollback",
    )
    disabled_response = _post_evaluate(disabled_client, disabled_event)
    assert _stable_response_dump(disabled_response) == _stable_response_dump(
        enabled_response
    )

    new_audit = store.get_policy_evaluation_by_event_id(disabled_event["event_id"])
    assert new_audit is not None
    assert not {
        "decision_v21",
        "state_delta_v21",
        "ct_transient_facts",
    } & set(new_audit.evidence)
    assert (
        SecurityStateService(store).store_access.get_projection(
            scope_digest,
            "runtime_observation",
            "ct-facts:evt_gate_a_after_rollback",
            1,
            PROJECTOR_VERSION,
        )
        is None
    )

    # Old authoritative evidence and projected facts remain queryable; the
    # rollback neither deletes history nor rewrites/clears the state record.
    persisted_old = store.get_policy_evaluation_by_event_id(enabled_event["event_id"])
    assert persisted_old == historical_audit
    after_rollback = store.get_security_state(scope_digest)
    assert after_rollback == before_rollback
    window = disabled_client.get(
        f"/v1/audit/window?trace_id={_TRACE_ID}", headers=_CONTROL_HEADERS
    )
    assert window.status_code == 200, window.text
    assert historical_audit.audit_id in {
        item["audit_id"] for item in window.json()["events"]
    }


@pytest.mark.parametrize(
    (
        "case",
        "shadow_enabled",
        "shadow_secret",
        "ct_enabled",
        "expected_envelopes",
    ),
    (
        ("v21_off_ct_on", False, _SHADOW_SECRET, True, set()),
        (
            "v21_bad_secret_ct_on",
            True,
            "gate-a-invalid-secret-must-not-leak",
            True,
            set(),
        ),
        (
            "v21_on_ct_off",
            True,
            _SHADOW_SECRET,
            False,
            {"decision_v21", "state_delta_v21"},
        ),
        (
            "all_on",
            True,
            _SHADOW_SECRET,
            True,
            {"decision_v21", "state_delta_v21", "ct_transient_facts"},
        ),
    ),
)
def test_gate_matrix_and_secret_non_disclosure(
    case: str,
    shadow_enabled: bool,
    shadow_secret: str,
    ct_enabled: bool,
    expected_envelopes: set[str],
) -> None:
    store = memory_store_with_adapter()
    settings = _settings(
        ct_enabled=ct_enabled,
        shadow_enabled=shadow_enabled,
        shadow_secret=shadow_secret,
    )
    client = TestClient(create_app(store=store, settings=settings))
    task = _create_task(client)
    event = _tool_result_event(
        task_id=task["task_id"],
        event_id=f"evt_gate_a_matrix_{case}",
        call_id=f"call_gate_a_matrix_{case}",
    )
    _post_evaluate(client, event)

    audit = store.get_policy_evaluation_by_event_id(event["event_id"])
    assert audit is not None
    envelope_keys = {
        "decision_v21",
        "state_delta_v21",
        "ct_transient_facts",
    }
    assert set(audit.evidence) & envelope_keys == expected_envelopes

    # Configuration material must never enter request, decision, or CT evidence.
    rendered = json.dumps(
        audit.model_dump(mode="json"), ensure_ascii=False, sort_keys=True
    )
    assert shadow_secret not in rendered
