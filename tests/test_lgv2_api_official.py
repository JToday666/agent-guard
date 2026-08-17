"""LangGraph competition authority integration at the Guard API boundary."""

from __future__ import annotations

import base64

from agentguard_core import (
    build_competition_activation_manifest,
)
from agentguard_core.actions.canonical_json import canonical_sha256

from guard_api.auth import AuthContext
from guard_api.security_state import SecurityStateService
from guard_api.services import (
    ApprovalService,
    AuditService,
    EvaluationService,
    FrozenCompetitionActivation,
    PolicyService,
    V21PipelineService,
    V21ShadowService,
    load_frozen_competition_activation,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.test_v21_09_pipeline import (
    _TASK_ID,
    _commit_task_fact,
    _event,
)

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


def _stack(*, with_task: bool) -> tuple[EvaluationService, MemoryControlPlaneStore]:
    settings = _settings()
    store = MemoryControlPlaneStore()
    if with_task:
        _commit_task_fact(store)
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
