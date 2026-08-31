"""Product Active runtime binding wiring and TaskFact scope integrity tests.

This suite is intentionally limited to the identity boundary that must precede
the Product selector.  Loading an activation still leaves evaluate behind the
pre-selector fuse; these tests exercise Task Ingress through its public HTTP
route and the V2 pipeline directly so no decision authority is introduced.
"""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from agentguard_core import (
    GuardEvent,
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
)
from agentguard_core.authority import SecurityStateScope, scope_digest_projection
from fastapi.testclient import TestClient

from guard_api.auth import ApiAuthError, AuthContext
from guard_api.main import create_app
from guard_api.models import TaskCreateRequest
from guard_api.services.policy import PolicyService
from guard_api.services.product_activation import load_frozen_product_activation
from guard_api.services.runtime_binding import (
    PRODUCT_TASK_IDENTITY_MISMATCH,
    PRODUCT_TASK_SCOPE_INVALID,
    RuntimeBindingResolver,
)
from guard_api.services.task_ingress import TaskIngressService
from guard_api.services.v21_pipeline import (
    V21OfficialEvaluationUnavailableError,
    V21PipelineService,
)
from guard_api.settings import GuardApiSettings
from guard_api.security_state import SecurityStateService
from guard_api.storage.base import TaskFactRecord
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.product_activation import (
    TEST_PRODUCT_ACTIVATION_SECRET_B64,
    ProductActivationFixture,
    build_test_product_activation,
    write_test_product_activation,
)

pytestmark = pytest.mark.integration

_CONTROL_HEADERS = {"Authorization": "Bearer control-secret"}
_TASK_SCOPE_KEY_ID = "product-binding-task-key"
_TASK_SCOPE_KEY = b"product-binding-task-scope-secret-material-01"
_TASK_SCOPE_KEY_B64 = base64.urlsafe_b64encode(_TASK_SCOPE_KEY).decode("ascii")
_SHADOW_SECRET_B64 = base64.urlsafe_b64encode(
    b"product-binding-independent-shadow-secret-01"
).decode("ascii")
_SESSION_ID = "session:product-binding"


def _settings(path: Path, fixture: ProductActivationFixture) -> GuardApiSettings:
    return GuardApiSettings(
        storage_backend="memory",
        control_token="control-secret",
        v21_mode="active",
        v21_product_activation_path=str(path),
        v21_product_activation_server_secret=TEST_PRODUCT_ACTIVATION_SECRET_B64,
        v21_product_activation_signer_key_id=fixture.signer_key_id,
        v21_shadow_server_secret=_SHADOW_SECRET_B64,
        task_scope_active_key_id=_TASK_SCOPE_KEY_ID,
        task_scope_keys=json.dumps({_TASK_SCOPE_KEY_ID: _TASK_SCOPE_KEY_B64}),
        rte05_strong_binding_enabled=True,
    )


def _product_context(
    tmp_path: Path,
) -> tuple[
    ProductActivationFixture,
    GuardApiSettings,
    MemoryControlPlaneStore,
]:
    fixture = build_test_product_activation(now=datetime.now(timezone.utc))
    path = tmp_path / "product-activation.json"
    write_test_product_activation(path, fixture)
    return fixture, _settings(path, fixture), MemoryControlPlaneStore()


def _task_payload(
    *,
    runtime_binding_id: str | None,
    task_text: str = "prepare the Product Active binding fixture",
    runtime: str = "langgraph",
    session_id: str | None = _SESSION_ID,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "task_text": task_text,
        "runtime": runtime,
        "trace_id": "trace:product-binding-task",
        "session_id": session_id,
        "action_constraints": [],
        "resource_constraints": [],
        "destination_constraints": [],
    }
    if runtime_binding_id is not None:
        payload["runtime_binding_id"] = runtime_binding_id
    return payload


def _create_product_task(
    tmp_path: Path,
) -> tuple[
    ProductActivationFixture,
    GuardApiSettings,
    MemoryControlPlaneStore,
    dict[str, object],
]:
    fixture, settings, store = _product_context(tmp_path)
    entry = fixture.bundle.runtime_entry("langgraph")
    with TestClient(create_app(store=store, settings=settings)) as client:
        response = client.post(
            "/v1/tasks",
            json=_task_payload(runtime_binding_id=entry.runtime_binding_id),
            headers=_CONTROL_HEADERS,
        )
    assert response.status_code == 200, response.text
    return fixture, settings, store, response.json()


def _resolver(settings: GuardApiSettings) -> RuntimeBindingResolver:
    activation = load_frozen_product_activation(settings)
    assert activation is not None
    return RuntimeBindingResolver(product_activation=activation)


def _pipeline(
    store: MemoryControlPlaneStore,
    settings: GuardApiSettings,
) -> V21PipelineService:
    state_service = SecurityStateService(store)
    return V21PipelineService(
        settings=settings,
        store=store,
        state_service=state_service,
        policy_service=PolicyService(store=store),
        runtime_binding_resolver=_resolver(settings),
    )


def _auth(
    fixture: ProductActivationFixture,
    *,
    principal_id: str | None = None,
    runtime: str | None = None,
    agent_id: str | None = None,
) -> AuthContext:
    entry = fixture.bundle.runtime_entry("langgraph")
    return AuthContext(
        principal_type="component",
        principal_id=principal_id or entry.principal_id,
        role="adapter",
        scopes=["event:evaluate"],
        auth_method="bearer",
        runtime=runtime or entry.runtime,
        agent_id=agent_id or entry.agent_id,
    )


def _event(
    task_id: str,
    *,
    session_id: str | None = _SESSION_ID,
) -> GuardEvent:
    return GuardEvent(
        event_id="evt_product_binding_pipeline",
        event_type="tool_call_proposed",
        runtime="langgraph",
        trace_id="trace:product-binding-evaluate",
        timestamp=datetime.now(timezone.utc).isoformat(),
        pre_execution=True,
        security_context=SecurityContext(
            agent_id="main",
            user_task="exercise Product Active binding",
            session_id=session_id,
        ),
        payload=ToolCallPayload(
            tool=ToolDescriptor(
                name="safe_product_tool",
                call_id="call:product-binding",
            ),
            arguments={},
            derived_resources=[],
        ),
        metadata={"task_id": task_id},
    )


def test_product_control_post_and_put_use_signed_subject_and_binding(
    tmp_path: Path,
) -> None:
    fixture, settings, store = _product_context(tmp_path)
    entry = fixture.bundle.runtime_entry("langgraph")
    app = create_app(store=store, settings=settings)

    with TestClient(app) as client:
        created = client.post(
            "/v1/tasks",
            json=_task_payload(runtime_binding_id=entry.runtime_binding_id),
            headers=_CONTROL_HEADERS,
        )
        assert created.status_code == 200, created.text
        task_id = created.json()["task_id"]

        revised = client.put(
            f"/v1/tasks/{task_id}",
            json={
                **_task_payload(
                    runtime_binding_id=entry.runtime_binding_id,
                    task_text="revised Product Active binding fixture",
                ),
                "expected_revision": 1,
            },
            headers=_CONTROL_HEADERS,
        )

    assert revised.status_code == 200, revised.text
    assert revised.json()["revision"] == 2
    revisions = store.list_task_fact_revisions(task_id)
    assert [record.task_fact.revision for record in revisions] == [1, 2]
    assert all(
        record.task_fact.principal_id == entry.principal_id for record in revisions
    )

    scope = SecurityStateScope(
        principal_id=entry.principal_id,
        runtime=entry.runtime,
        runtime_binding_id=entry.runtime_binding_id,
        trace_id="trace:product-binding-task",
        session_id=_SESSION_ID,
        scope_digest="",
    )
    expected_scope_digest = scope_digest_projection(
        scope,
        server_key=settings.task_scope_signing_key(),
    )
    assert created.json()["scope_digest"] == expected_scope_digest
    assert revised.json()["scope_digest"] == expected_scope_digest
    assert revisions[-1].task_fact.scope_digest == expected_scope_digest
    # The actor is the control credential, but the TaskFact subject and binding
    # are bounded by the signed activation entry, never by cred_control.
    assert entry.principal_id != "cred_control"
    assert entry.runtime_binding_id != "binding:control:cred_control"


@pytest.mark.parametrize(
    "claimed_binding",
    [
        "binding:control:cred_control",
        "binding:attacker-forged",
    ],
)
def test_product_control_rejects_legacy_or_forged_binding_without_task_write(
    tmp_path: Path,
    claimed_binding: str,
) -> None:
    fixture, settings, store = _product_context(tmp_path)
    assert (
        claimed_binding != fixture.bundle.runtime_entry("langgraph").runtime_binding_id
    )

    with TestClient(create_app(store=store, settings=settings)) as client:
        response = client.post(
            "/v1/tasks",
            json=_task_payload(runtime_binding_id=claimed_binding),
            headers=_CONTROL_HEADERS,
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "RUNTIME_IDENTITY_MISMATCH"
    assert store.task_facts == {}


def test_product_task_ingress_rejects_nested_activation_mutation_without_write(
    tmp_path: Path,
) -> None:
    fixture, settings, store = _product_context(tmp_path)
    activation = load_frozen_product_activation(settings)
    assert activation is not None
    resolver = RuntimeBindingResolver(product_activation=activation)
    entry = activation.bundle.runtimes[0]
    activation.bundle.runtimes[0] = entry.model_copy(
        update={"runtime_binding_id": "binding:attacker-mutated"}
    )
    service = TaskIngressService(
        store=store,
        settings=settings,
        runtime_binding_resolver=resolver,
    )
    request = TaskCreateRequest(
        **_task_payload(
            runtime_binding_id=fixture.bundle.runtime_entry(
                "langgraph"
            ).runtime_binding_id
        )
    )
    control = AuthContext(
        principal_type="cli",
        principal_id="cred_control",
        role="control",
        scopes=["task:write"],
        auth_method="bearer",
    )

    with pytest.raises(ApiAuthError) as raised:
        service.create_task(request, control)

    assert raised.value.status_code == 503
    assert raised.value.code == "V21_PRODUCT_ACTIVATION_NOT_CURRENT"
    assert store.task_facts == {}


def test_product_revision_cannot_migrate_the_signed_scope(tmp_path: Path) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    entry = fixture.bundle.runtime_entry("langgraph")

    with TestClient(create_app(store=store, settings=settings)) as client:
        response = client.put(
            f"/v1/tasks/{created['task_id']}",
            json={
                **_task_payload(
                    runtime_binding_id=entry.runtime_binding_id,
                    session_id="session:scope-migration",
                ),
                "expected_revision": 1,
            },
            headers=_CONTROL_HEADERS,
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == PRODUCT_TASK_IDENTITY_MISMATCH
    assert len(store.list_task_fact_revisions(str(created["task_id"]))) == 1


def test_product_revision_rejects_a_tampered_authority_head(tmp_path: Path) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    task_id = str(created["task_id"])
    original = store.get_task_fact(task_id)
    assert original is not None
    tampered_fact = original.task_fact.model_copy(
        update={
            "revision": 2,
            "task_summary": "tampered without recomputing task_digest",
        }
    )
    store.create_task_fact(
        TaskFactRecord(
            task_fact=tampered_fact,
            canonical_payload=tampered_fact.model_dump(mode="json"),
            request_digest="sha256:" + "e" * 64,
            expected_revision=1,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    entry = fixture.bundle.runtime_entry("langgraph")

    with TestClient(create_app(store=store, settings=settings)) as client:
        response = client.put(
            f"/v1/tasks/{task_id}",
            json={
                **_task_payload(
                    runtime_binding_id=entry.runtime_binding_id,
                    task_text="legitimate revision after tamper",
                ),
                "expected_revision": 2,
            },
            headers=_CONTROL_HEADERS,
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == PRODUCT_TASK_SCOPE_INVALID
    assert len(store.list_task_fact_revisions(task_id)) == 2


def test_product_revision_preserves_the_head_scope_key_across_rotation(
    tmp_path: Path,
) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    rotated_key_id = "product-binding-rotated-key"
    rotated_key = base64.urlsafe_b64encode(
        b"product-binding-rotated-secret-material-02"
    ).decode("ascii")
    rotated_settings = replace(
        settings,
        task_scope_active_key_id=rotated_key_id,
        task_scope_keys=json.dumps(
            {
                _TASK_SCOPE_KEY_ID: _TASK_SCOPE_KEY_B64,
                rotated_key_id: rotated_key,
            }
        ),
    )
    entry = fixture.bundle.runtime_entry("langgraph")

    with TestClient(create_app(store=store, settings=rotated_settings)) as client:
        response = client.put(
            f"/v1/tasks/{created['task_id']}",
            json={
                **_task_payload(
                    runtime_binding_id=entry.runtime_binding_id,
                    task_text="revision after task scope key rotation",
                ),
                "expected_revision": 1,
            },
            headers=_CONTROL_HEADERS,
        )

    assert response.status_code == 200, response.text
    revisions = store.list_task_fact_revisions(str(created["task_id"]))
    assert [item.task_fact.scope_key_id for item in revisions] == [
        _TASK_SCOPE_KEY_ID,
        _TASK_SCOPE_KEY_ID,
    ]
    assert revisions[1].task_fact.scope_digest == revisions[0].task_fact.scope_digest


@pytest.mark.parametrize(
    "claimed_binding",
    [
        "binding:control:cred_control",
        "binding:attacker-forged",
    ],
)
def test_product_control_rejects_legacy_or_forged_binding_without_revision_write(
    tmp_path: Path,
    claimed_binding: str,
) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    assert (
        claimed_binding != fixture.bundle.runtime_entry("langgraph").runtime_binding_id
    )
    task_id = str(created["task_id"])

    with TestClient(create_app(store=store, settings=settings)) as client:
        response = client.put(
            f"/v1/tasks/{task_id}",
            json={
                **_task_payload(runtime_binding_id=claimed_binding),
                "expected_revision": 1,
            },
            headers=_CONTROL_HEADERS,
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "RUNTIME_IDENTITY_MISMATCH"
    assert [
        record.task_fact.revision for record in store.list_task_fact_revisions(task_id)
    ] == [1]


def test_product_pipeline_uses_exact_signed_scope_and_action_ir(tmp_path: Path) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    entry = fixture.bundle.runtime_entry("langgraph")
    task_id = str(created["task_id"])
    scope_digest = str(created["scope_digest"])
    # The next batch will make missing-state handling strictly read-only.  Seed
    # an exact ready row here so this identity test remains valid on both sides
    # of that change and does not assert the legacy ensure_ready behavior.
    SecurityStateService(store).ensure_ready(scope_digest)

    materials = _pipeline(store, settings).run_phase_a(
        _event(task_id),
        auth_context=_auth(fixture),
    )

    assert materials is not None
    assert materials.snapshot is not None
    assert materials.action_ir is not None
    assert materials.scope_digest == scope_digest
    assert materials.snapshot.scope.principal_id == entry.principal_id
    assert materials.snapshot.scope.runtime == entry.runtime
    assert materials.snapshot.scope.runtime_binding_id == entry.runtime_binding_id
    assert materials.action_ir.principal_id == entry.principal_id
    assert materials.action_ir.runtime_binding_id == entry.runtime_binding_id
    assert materials.action_ir.scope_digest == scope_digest


def test_product_pipeline_wrong_auth_fails_before_security_state_write(
    tmp_path: Path,
) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    scope_digest = str(created["scope_digest"])

    with pytest.raises(V21OfficialEvaluationUnavailableError):
        _pipeline(store, settings).run_phase_a(
            _event(str(created["task_id"])),
            auth_context=_auth(fixture, principal_id="principal:wrong"),
        )

    assert store.get_security_state(scope_digest) is None


def test_product_pipeline_session_mismatch_fails_before_security_state_write(
    tmp_path: Path,
) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    scope_digest = str(created["scope_digest"])

    with pytest.raises(V21OfficialEvaluationUnavailableError):
        _pipeline(store, settings).run_phase_a(
            _event(str(created["task_id"]), session_id="session:wrong"),
            auth_context=_auth(fixture),
        )

    assert store.get_security_state(scope_digest) is None


def test_product_pipeline_scope_hmac_mismatch_fails_before_security_state_write(
    tmp_path: Path,
) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    task_id = str(created["task_id"])
    original = store.get_task_fact(task_id)
    assert original is not None
    tampered_digest = "hmac-sha256:" + "0" * 64
    assert tampered_digest != original.task_fact.scope_digest
    tampered_fact = original.task_fact.model_copy(
        update={
            "revision": original.task_fact.revision + 1,
            "scope_digest": tampered_digest,
        }
    )
    store.create_task_fact(
        TaskFactRecord(
            task_fact=tampered_fact,
            canonical_payload=tampered_fact.model_dump(mode="json"),
            request_digest="sha256:" + "f" * 64,
            expected_revision=original.task_fact.revision,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError):
        _pipeline(store, settings).run_phase_a(
            _event(task_id),
            auth_context=_auth(fixture),
        )

    assert store.get_security_state(tampered_digest) is None
    assert store.get_security_state(str(created["scope_digest"])) is None


def test_product_phase_b_rejects_same_content_new_task_revision(
    tmp_path: Path,
) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    task_id = str(created["task_id"])
    scope_digest = str(created["scope_digest"])
    SecurityStateService(store).ensure_ready(scope_digest)
    pipeline = _pipeline(store, settings)
    event = _event(task_id)
    materials = pipeline.run_phase_a(event, auth_context=_auth(fixture))
    assert materials is not None
    original = store.get_task_fact(task_id)
    assert original is not None
    advanced = original.task_fact.model_copy(update={"revision": 2})
    # revision is deliberately not part of task_digest; Phase B must still
    # detect the identity drift rather than finalize the stale assessment.
    assert advanced.task_digest == original.task_fact.task_digest
    store.create_task_fact(
        TaskFactRecord(
            task_fact=advanced,
            canonical_payload=advanced.model_dump(mode="json"),
            request_digest="sha256:" + "d" * 64,
            expected_revision=1,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )

    outcome = pipeline.build_phase_b(event, materials)

    assert outcome is not None
    assert outcome.revalidation.status == "stale"
    assert "v21-09:stale_task_digest" in outcome.revalidation.reason_codes
    assert outcome.raw_v21_decision is None


def test_product_phase_b_rechecks_task_content_integrity(tmp_path: Path) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    task_id = str(created["task_id"])
    scope_digest = str(created["scope_digest"])
    SecurityStateService(store).ensure_ready(scope_digest)
    pipeline = _pipeline(store, settings)
    event = _event(task_id)
    materials = pipeline.run_phase_a(event, auth_context=_auth(fixture))
    assert materials is not None
    original = store.get_task_fact(task_id)
    assert original is not None
    tampered_fact = original.task_fact.model_copy(
        update={"task_summary": "tampered between Phase A and Phase B"}
    )
    store.task_facts[task_id] = [
        TaskFactRecord(
            task_fact=tampered_fact,
            canonical_payload=tampered_fact.model_dump(mode="json"),
            request_digest=original.request_digest,
            expected_revision=original.expected_revision,
            created_at=original.created_at,
        )
    ]

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        pipeline.build_phase_b(event, materials)

    assert raised.value.code == PRODUCT_TASK_SCOPE_INVALID


def test_product_split_phase_rejects_same_id_event_drift(tmp_path: Path) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    scope_digest = str(created["scope_digest"])
    SecurityStateService(store).ensure_ready(scope_digest)
    pipeline = _pipeline(store, settings)
    event = _event(str(created["task_id"]))
    auth_context = _auth(fixture)
    prepared = pipeline.prepare_phase_a(event, auth_context=auth_context)
    assert prepared is not None
    drifted = event.model_copy(
        update={
            "security_context": event.security_context.model_copy(
                update={"session_id": "session:split-phase-drift"}
            )
        }
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError):
        pipeline.finish_phase_a(
            drifted,
            prepared,
            auth_context=auth_context,
        )


def test_product_finish_rejects_mutated_prepared_snapshot(tmp_path: Path) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    scope_digest = str(created["scope_digest"])
    SecurityStateService(store).ensure_ready(scope_digest)
    pipeline = _pipeline(store, settings)
    event = _event(str(created["task_id"]))
    auth_context = _auth(fixture)
    prepared = pipeline.prepare_phase_a(event, auth_context=auth_context)
    assert prepared is not None
    assert prepared.snapshot is not None
    assert prepared.snapshot.task is not None
    prepared.snapshot.task.task_summary = "mutated after the authoritative read"

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        pipeline.finish_phase_a(
            event,
            prepared,
            auth_context=auth_context,
        )

    assert raised.value.code == PRODUCT_TASK_SCOPE_INVALID


def test_product_phase_b_rejects_mutated_materials_snapshot(tmp_path: Path) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    scope_digest = str(created["scope_digest"])
    SecurityStateService(store).ensure_ready(scope_digest)
    pipeline = _pipeline(store, settings)
    event = _event(str(created["task_id"]))
    materials = pipeline.run_phase_a(event, auth_context=_auth(fixture))
    assert materials is not None
    assert materials.snapshot is not None
    assert materials.snapshot.task is not None
    materials.snapshot.task.task_summary = "mutated after assessment"

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        pipeline.build_phase_b(event, materials)

    assert raised.value.code == PRODUCT_TASK_SCOPE_INVALID


def test_product_phase_b_rejects_mutated_action_ir(tmp_path: Path) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    scope_digest = str(created["scope_digest"])
    SecurityStateService(store).ensure_ready(scope_digest)
    pipeline = _pipeline(store, settings)
    event = _event(str(created["task_id"]))
    materials = pipeline.run_phase_a(event, auth_context=_auth(fixture))
    assert materials is not None
    assert materials.action_ir is not None
    materials.action_ir.runtime_binding_id = "binding:mutated-after-assessment"

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        pipeline.build_phase_b(event, materials)

    assert raised.value.code == PRODUCT_TASK_SCOPE_INVALID


def test_product_phase_b_rechecks_mutated_auth_identity(tmp_path: Path) -> None:
    fixture, settings, store, created = _create_product_task(tmp_path)
    scope_digest = str(created["scope_digest"])
    SecurityStateService(store).ensure_ready(scope_digest)
    pipeline = _pipeline(store, settings)
    event = _event(str(created["task_id"]))
    auth_context = _auth(fixture)
    materials = pipeline.run_phase_a(event, auth_context=auth_context)
    assert materials is not None
    auth_context.principal_id = "principal:mutated-after-phase-a"

    with pytest.raises(V21OfficialEvaluationUnavailableError):
        pipeline.build_phase_b(event, materials)
