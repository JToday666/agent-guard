"""Actual Product HTTP approvals with deterministic IDs; synthetic candidate.

The model is controlled locally. No Provider, production approval or final
candidate qualification is claimed. Approval resolution uses launch/session/CSRF.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

import pytest
from langchain_core.messages import AIMessage

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.authority.models import EvaluationClock, SecurityStateScope
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    OnlineSecurityState,
    rebuild_state,
    state_digest,
)
from agentguard_langgraph_adapter.native_langgraph import build_native_product_graph
from guard_api import models as api_models
from guard_api.security_state import SecurityStateService
from guard_api.security_state.rebuild import _committed_from_projection
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.native_product_runtime import HttpFixtureModel
from tests.test_langgraph_native_graph_http import _automated_test_operator
from tests.test_langgraph_native_model_http import native_model_http  # noqa: F401
from tests.test_product_security_state_readiness import _plan

pytestmark = pytest.mark.e2e

FIRST_APPROVAL = "app_z_approval_arrived_first"
SECOND_APPROVAL = "app_a_approval_arrived_second"


def _assert_strict_read_and_full_rebuild(http, binding):
    store = http.store
    task = store.get_task_fact(http.task_id).task_fact
    scope = SecurityStateScope(
        principal_id=binding.principal_id,
        runtime=binding.runtime,
        runtime_binding_id=binding.runtime_binding_id,
        trace_id=http.trace_id,
        session_id=http.session_id,
        scope_digest=binding.scope_digest,
    )
    before = deepcopy(store.get_security_state(binding.scope_digest))
    snapshot, _, _ = SecurityStateService(store).read_ready_snapshot_with_revoked(
        binding.scope_digest,
        scope=scope,
        task_fact_head=task,
        evaluation_clock=EvaluationClock(
            evaluated_at=datetime.now(timezone.utc).isoformat(),
            clock_version="approval-order-test",
        ),
        policy_revision=binding.policy_revision,
        policy_digest=canonical_sha256(
            store.get_policy_snapshot().model_dump(mode="json")
        ),
        plan=_plan(),
        authoritative_head_revision=task.revision,
    )
    assert store.get_security_state(binding.scope_digest) == before
    assert snapshot.state_version == before.state_version
    current = OnlineSecurityState.model_validate(before.canonical_payload)
    rows = store.list_rebuild_inputs(binding.scope_digest, limit=1024)
    rebuilt = rebuild_state(
        [_committed_from_projection(row) for row in rows],
        projector_version=PROJECTOR_VERSION,
    )
    assert current.active_grants == rebuilt.active_grants
    assert state_digest(current) == state_digest(rebuilt)


@pytest.mark.parametrize("failure", [None, "registration", "reconciliation"])
def test_product_reverse_approval_ids_are_ready_before_consumption_and_recover_once(
    native_model_http,  # noqa: F811
    monkeypatch,
    failure,
):
    http, adapter, _, _ = native_model_http
    original_id = api_models.new_id
    approval_ids = iter((FIRST_APPROVAL, SECOND_APPROVAL))

    def next_id(prefix):
        return next(approval_ids) if prefix == "app" else original_id(prefix)

    monkeypatch.setattr(api_models, "new_id", next_id)
    attempts = []
    injected = []
    verified = []
    read_errors = []
    original_register = MemoryControlPlaneStore.register_approval_grant
    original_reconcile = SecurityStateService.reconcile_projection_history

    def register(store, binding, grant):
        if store is http.store:
            attempts.append((binding.approval_id, grant.grant_id))
            assert all(
                record.action_id != binding.action_id
                for record in store.grant_consumption_records.values()
            )
            if (
                failure == "registration"
                and binding.approval_id == SECOND_APPROVAL
                and not injected
            ):
                injected.append(failure)
                raise OSError("synthetic grant registration unavailable")
            # This assertion runs before a grant becomes consumable: a later
            # model/evaluate reconciliation cannot hide writer-order drift.
            try:
                _assert_strict_read_and_full_rebuild(http, binding)
            except Exception as error:
                read_errors.append(
                    (
                        type(error).__name__,
                        getattr(error, "name", None),
                        getattr(error, "condition", None),
                    )
                )
                raise
            verified.append(binding.approval_id)
        return original_register(store, binding, grant)

    def reconcile(service, scope_digest, **kwargs):
        binding = http.store.get_enforcement_binding(SECOND_APPROVAL)
        approval = http.store.get_approval(SECOND_APPROVAL)
        if (
            failure == "reconciliation"
            and not injected
            and binding is not None
            and binding.grant_id is None
            and approval is not None
            and approval.status == "resolved"
            and binding.scope_digest == scope_digest
        ):
            injected.append(failure)
            raise OSError("synthetic grant reconciliation unavailable")
        return original_reconcile(service, scope_digest, **kwargs)

    monkeypatch.setattr(MemoryControlPlaneStore, "register_approval_grant", register)
    monkeypatch.setattr(SecurityStateService, "reconcile_projection_history", reconcile)
    model = HttpFixtureModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "write",
                        "args": {
                            "path": "fixture.txt",
                            "content": "approved ordered write",
                        },
                        "id": "ordered_write",
                    }
                ],
            ),
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "edit",
                        "args": {
                            "path": "fixture.txt",
                            "edits": [
                                {
                                    "oldText": "approved ordered write",
                                    "newText": "approved ordered edit",
                                }
                            ],
                        },
                        "id": "ordered_edit",
                    }
                ],
            ),
            AIMessage(content="Both approved actions completed."),
        ]
    )
    graph = build_native_product_graph(
        adapter=adapter,
        model=model,
        tools=http.tools,
        provider="controlled-local-contract",
        model_name="non-candidate-http-fixture",
    )
    graph._executor._approval_timeout = 5.0
    security = dict(http.event()["security_context"])
    security["task_id"] = http.task_id
    with _automated_test_operator(http) as resolutions:
        result = graph.invoke(
            sources=[
                {
                    "role": "user",
                    "content": security["user_task"],
                    "source_id": "approval-order-task",
                    "source_type": "user",
                    "source_trust": "trusted",
                }
            ],
            security=security,
            trace_id=http.trace_id,
        )
    assert not result.blocked, (
        result.error_code,
        read_errors,
        [request.status_code for request in http.requests],
    )
    assert result.tool_invocations == 2 and result.model_calls == 3
    assert read_errors == []
    assert (http.root / "fixture.txt").read_text() == "approved ordered edit"
    assert [item["approval_id"] for item in resolutions] == [
        FIRST_APPROVAL,
        SECOND_APPROVAL,
    ]
    assert FIRST_APPROVAL > SECOND_APPROVAL
    assert set(verified) == {FIRST_APPROVAL, SECOND_APPROVAL}
    assert injected == ([] if failure is None else [failure])
    for approval_id in (FIRST_APPROVAL, SECOND_APPROVAL):
        approval = http.store.get_approval(approval_id)
        assert (
            approval.decision == "allow_once" and approval.resolution_source == "human"
        )
        binding = http.store.get_enforcement_binding(approval_id)
        assert binding.grant_id is not None
        _assert_strict_read_and_full_rebuild(http, binding)
        requests = http.requests_for(
            f"/v1/approvals/{approval_id}/execution-leases/consume"
        )
        assert requests[-1].status_code == 200
        assert all(request.body == requests[0].body for request in requests)
        assert all(
            request.activation_ack_header == requests[0].activation_ack_header
            for request in requests
        )
        assert (
            len({grant_id for owner, grant_id in attempts if owner == approval_id}) == 1
        )
        if approval_id == SECOND_APPROVAL and failure is not None:
            assert requests[0].status_code == 503
        rows = http.store.list_rebuild_inputs(binding.scope_digest, limit=1024)
        assert (
            len(
                [
                    row
                    for row in rows
                    if row.source_record_type == "approval"
                    and row.source_record_id == approval_id
                ]
            )
            == 1
        )
    assert len(http.store.capability_grants) == 2
    assert (
        len(http.store.grant_consumption_records)
        == len(http.store.execution_lease_records)
        == 2
    )
