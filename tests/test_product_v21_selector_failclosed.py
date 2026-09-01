"""Fail-closed Product selector service contracts.

These tests pin the availability boundary around the internal Product Active
selector.  The public composition root remains protected by the pre-selector
fuse until activation ACK/freshness is wired in the following batch.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

import pytest

from agentguard_core import (
    ApprovalIntent,
    GuardDecision,
    GuardEngine,
    GuardEvent,
    PolicyBundle,
    V21AuthoritySelectionError,
)

from guard_api.security_state import SecurityStateService
from guard_api.services import ApprovalService, AuditService, EvaluationService
from guard_api.services.policy import PolicyService
from guard_api.services.runtime_binding import RuntimeBindingResolver
from guard_api.services.v21_pipeline import (
    V21OfficialEvaluationUnavailableError,
    V21PipelineService,
)
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.product_evaluation import create_product_evaluation_harness
from tests.test_product_v21_service_selector import _stack

pytestmark = pytest.mark.integration

_SELECTOR_UNAVAILABLE = "V21_PRODUCT_SELECTOR_UNAVAILABLE"


def _write_image(store: MemoryControlPlaneStore) -> dict[str, Any]:
    """Capture every evaluation-owned mutable container for zero-write checks."""

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


def test_core_selector_error_maps_to_stable_product_503_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    event = harness.event(event_id="evt:product-selector:core-error")
    before = _write_image(harness.store)

    def fail_selector(**_: Any) -> Any:
        raise V21AuthoritySelectionError("v21-product:raw_v21_unavailable")

    monkeypatch.setattr(
        "guard_api.services.evaluation.select_product_v21_authority",
        fail_selector,
    )

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        harness.evaluation.evaluate(event, auth_context=harness.auth_context)

    assert raised.value.code == _SELECTOR_UNAVAILABLE
    assert _write_image(harness.store) == before


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_releasable_ask_without_allow_once_becomes_forbidden_without_release_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime: Literal["langgraph", "openclaw"],
) -> None:
    stack = _stack(tmp_path, runtime)
    event = stack.event(
        "tool_call_proposed",
        event_id=f"evt:product-selector:{runtime}:missing-allow-once",
        payload={
            "tool": {
                "name": "read_file",
                "call_id": f"call:product-selector-{runtime}-missing-allow-once",
            },
            "arguments": {"path": "/docs/public.txt"},
            "derived_resources": [],
        },
    )
    original = GuardEngine.evaluate_with_results

    def force_unreleasable_ask(
        self: GuardEngine,
        candidate: GuardEvent,
        policies: PolicyBundle | None = None,
    ) -> tuple[GuardDecision, list[Any]]:
        decision, detections = original(self, candidate, policies)
        return (
            decision.model_copy(
                update={
                    "decision_id": "dec:current:ask-without-allow-once",
                    "decision": "ask",
                    "risk_score": 50,
                    "severity": "medium",
                    "categories": ["forced-current:ask"],
                    "rule_hits": [],
                    "reason": "forced current ASK without allow_once",
                    "approval_intent": ApprovalIntent(
                        options=["deny"],
                        resource="action:unreleasable",
                    ),
                }
            ),
            detections,
        )

    monkeypatch.setattr(
        GuardEngine,
        "evaluate_with_results",
        force_unreleasable_ask,
    )

    response = stack.evaluation.evaluate(event, auth_context=stack.auth_context)

    assert response.decision.decision == "ask"
    assert response.decision.approval_intent is None
    assert response.approval_release_directive is not None
    assert response.approval_release_directive.mode == "forbidden"
    assert response.decision_authority is not None
    assert response.decision_authority.approval_release == "forbidden"
    assert response.approval is None
    assert response.enforcement_binding is None
    assert stack.store.approvals == {}
    assert stack.store.enforcement_bindings == {}


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_equal_ask_current_deny_only_intent_cannot_gain_product_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime: Literal["langgraph", "openclaw"],
) -> None:
    stack = _stack(tmp_path, runtime)
    event = stack.event(
        "tool_call_proposed",
        event_id=f"evt:product-selector:{runtime}:equal-ask-deny-only",
        payload={
            "tool": {
                "name": "read_file",
                "call_id": f"call:product-selector-{runtime}-equal-ask-deny-only",
            },
            "arguments": {"path": "/docs/public.txt"},
            "derived_resources": [],
        },
    )
    original = GuardEngine.evaluate_with_results

    def force_current_deny_only_ask(
        self: GuardEngine,
        candidate: GuardEvent,
        policies: PolicyBundle | None = None,
    ) -> tuple[GuardDecision, list[Any]]:
        decision, detections = original(self, candidate, policies)
        return (
            decision.model_copy(
                update={
                    "decision_id": "dec:current:equal-ask-deny-only",
                    "decision": "ask",
                    "risk_score": 50,
                    "severity": "medium",
                    "categories": ["forced-current:ask"],
                    "rule_hits": [],
                    "reason": "forced current equal-rank deny-only ASK",
                    "approval_intent": ApprovalIntent(
                        options=["deny"],
                        resource="action:equal-ask-deny-only",
                    ),
                }
            ),
            detections,
        )

    monkeypatch.setattr(
        GuardEngine,
        "evaluate_with_results",
        force_current_deny_only_ask,
    )
    monkeypatch.setattr(
        "agentguard_core.decisions.shadow.evaluate_fusion",
        lambda **_: ("DEFER", ["test:force-equal-rank-v21-ask"]),
    )

    response = stack.evaluation.evaluate(event, auth_context=stack.auth_context)

    assert response.decision.decision == "ask"
    assert response.decision.approval_intent is None
    assert response.approval_release_directive is not None
    assert response.approval_release_directive.mode == "forbidden"
    assert response.decision_authority is not None
    assert response.decision_authority.approval_release == "forbidden"
    assert response.approval is None
    assert response.enforcement_binding is None
    assert stack.store.approvals == {}
    assert stack.store.enforcement_bindings == {}


def test_product_activation_with_non_active_pipeline_fails_closed_without_writes(
    tmp_path: Path,
) -> None:
    harness = create_product_evaluation_harness(tmp_path)
    shadow_settings = replace(harness.settings, v21_mode="shadow")
    # Reuse the already verified activation to exercise a direct service
    # composition that bypasses startup configuration validation.  The public
    # loader correctly rejects this mode mismatch before construction.
    activation = harness.pipeline.product_activation
    assert activation is not None
    resolver = RuntimeBindingResolver(product_activation=activation)
    policy_service = PolicyService(store=harness.store)
    pipeline = V21PipelineService(
        settings=shadow_settings,
        store=harness.store,
        state_service=SecurityStateService(harness.store),
        policy_service=policy_service,
        runtime_binding_resolver=resolver,
    )
    evaluation = EvaluationService(
        policy_service=policy_service,
        audit_service=AuditService(store=harness.store),
        approval_service=ApprovalService(
            store=harness.store,
            settings=shadow_settings,
        ),
        v21_pipeline=pipeline,
    )
    event = harness.event(event_id="evt:product-selector:non-active-pipeline")
    before = _write_image(harness.store)

    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        evaluation.evaluate(event, auth_context=harness.auth_context)

    assert raised.value.code == _SELECTOR_UNAVAILABLE
    assert _write_image(harness.store) == before
