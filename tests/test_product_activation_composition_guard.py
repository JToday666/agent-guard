"""Fail-closed Product evaluation composition contracts."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Literal

import pytest

from guard_api.security_state import SecurityStateService
from guard_api.services import ApprovalService, AuditService, EvaluationService
from guard_api.services.policy import PolicyService
from guard_api.services.product_activation import ProductActivationAuthorityService
from guard_api.services.runtime_binding import RuntimeBindingResolver
from guard_api.services.v21_pipeline import (
    V21OfficialEvaluationUnavailableError,
    V21PipelineService,
)
from tests.support.product_evaluation import create_product_evaluation_harness

pytestmark = pytest.mark.integration

Composition = Literal[
    "pipeline_missing",
    "pipeline_off",
    "pipeline_shadow",
    "pipeline_non_product",
    "authority_mismatch",
]


def _evaluation_write_image(store) -> object:
    return deepcopy(
        {
            "audit_events": store.audit_events,
            "audit_events_by_id": store.audit_events_by_id,
            "audit_ingested_at_by_id": store.audit_ingested_at_by_id,
            "provenance_nodes": store.provenance_nodes,
            "provenance_edges": store.provenance_edges,
            "approvals": store.approvals,
            "enforcement_bindings": store.enforcement_bindings,
            "memory_changes": store.memory_changes,
            "action_critic_reviews": store.action_critic_reviews,
            "security_states": store.security_states,
            "projection_records": store.projection_records,
        }
    )


@pytest.mark.parametrize(
    "composition",
    [
        "pipeline_missing",
        "pipeline_off",
        "pipeline_shadow",
        "pipeline_non_product",
        "authority_mismatch",
    ],
)
def test_product_authority_rejects_invalid_pipeline_composition_before_first_write(
    tmp_path: Path,
    composition: Composition,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    activation = harness.pipeline.product_activation
    authority = harness.evaluation.product_activation_authority
    assert activation is not None
    assert authority is not None

    policy_service = PolicyService(store=harness.store)
    settings = harness.settings
    resolver = RuntimeBindingResolver(product_activation=activation)
    pipeline: V21PipelineService | None = harness.pipeline
    evaluation_authority = authority

    if composition == "pipeline_missing":
        pipeline = None
    elif composition in {"pipeline_off", "pipeline_shadow"}:
        settings = replace(
            harness.settings,
            v21_mode="off" if composition == "pipeline_off" else "shadow",
        )
        pipeline = V21PipelineService(
            settings=settings,
            store=harness.store,
            state_service=SecurityStateService(harness.store),
            policy_service=policy_service,
            runtime_binding_resolver=resolver,
            product_activation_authority=authority,
        )
    elif composition == "pipeline_non_product":
        pipeline = V21PipelineService(
            settings=settings,
            store=harness.store,
            state_service=SecurityStateService(harness.store),
            policy_service=policy_service,
            runtime_binding_resolver=RuntimeBindingResolver(),
            product_activation_authority=authority,
        )
    else:
        evaluation_authority = ProductActivationAuthorityService(
            activation=activation,
            store=harness.store,
            server_secret=harness.fixture.server_secret,
        )
        assert evaluation_authority is not authority

    evaluation = EvaluationService(
        policy_service=policy_service,
        audit_service=AuditService(store=harness.store),
        approval_service=ApprovalService(store=harness.store, settings=settings),
        v21_pipeline=pipeline,
        product_activation_authority=evaluation_authority,
    )
    event = harness.event(event_id=f"evt:product-composition:{composition}")
    before = _evaluation_write_image(harness.store)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        evaluation.evaluate(
            event,
            auth_context=harness.auth_context,
            activation_ack_token=harness.activation_ack_token,
        )

    assert raised.value.code == "V21_PRODUCT_SELECTOR_UNAVAILABLE"
    assert _evaluation_write_image(harness.store) == before
