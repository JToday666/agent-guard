"""Fault injection at the Product catalog/transaction boundary; no Host claim."""

from __future__ import annotations

import pytest
from agentguard_core import ToolResult, ToolResultPayload

from guard_api.services.v21_pipeline import V21OfficialEvaluationUnavailableError
from tests.test_product_phase_b_authority_fence import (
    _assert_no_evaluation_effects,
    _evaluate,
    _memory_store_image,
    _stack,
)
from tests.test_product_runtime_binding_wiring import _event

pytestmark = pytest.mark.integration


class _CatalogFault:
    """Only inject catalog availability; real catalog semantics have own tests."""

    content_digest = "sha256:" + "c" * 64
    failed = False

    def verify_current(self, *, activation, activation_ack=None):
        if self.failed:
            raise ValueError("injected catalog drift")
        if activation_ack is not None:
            assert activation_ack.activation_ref_digest == activation.activation_ref_digest

    def resolve(self, event, *, activation, activation_ack=None):
        self.verify_current(activation=activation, activation_ack=activation_ack)
        return None


@pytest.mark.parametrize("when", ["assessment", "phase_b", "precommit"])
def test_catalog_drift_is_zero_write_and_never_falls_back(
    tmp_path, monkeypatch: pytest.MonkeyPatch, when: str
) -> None:
    fixture, store, pipeline, evaluation, task_id, _ = _stack(tmp_path)
    event = _event(task_id)
    before = _memory_store_image(store)
    catalog = _CatalogFault()
    monkeypatch.setattr(pipeline, "_product_tool_catalog", catalog)
    if when == "assessment":
        catalog.failed = True
    else:
        method = "_finish_phase_a" if when == "phase_b" else "build_phase_b"
        original = getattr(pipeline, method)

        def fail_after_materials(*args, **kwargs):
            result = original(*args, **kwargs)
            catalog.failed = True
            return result

        monkeypatch.setattr(pipeline, method, fail_after_materials)
    with pytest.raises(V21OfficialEvaluationUnavailableError) as caught:
        _evaluate(evaluation, event, fixture, store)
    assert caught.value.code in {
        "V21_PRODUCT_ACTION_CONTENT_UNAVAILABLE",
        "V21_PRODUCT_TOOL_CATALOG_UNAVAILABLE",
    }
    _assert_no_evaluation_effects(
        store, event_id=event.event_id, expected_store_image=before
    )


def test_catalog_change_cannot_reuse_an_old_product_decision(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture, store, pipeline, evaluation, task_id, _ = _stack(tmp_path)
    catalog = _CatalogFault()
    monkeypatch.setattr(pipeline, "_product_tool_catalog", catalog)
    event = _event(task_id)
    event = event.model_copy(
        update={
            "event_type": "tool_result_produced",
            "pre_execution": False,
            "payload": ToolResultPayload(
                tool=event.payload.tool,
                result=ToolResult(content_preview="fixture observation"),
            ),
        }
    )
    first = _evaluate(evaluation, event, fixture, store)
    before = _memory_store_image(store)
    catalog.content_digest = "sha256:" + "d" * 64
    with pytest.raises(V21OfficialEvaluationUnavailableError):
        _evaluate(evaluation, event, fixture, store)
    assert _memory_store_image(store) == before
    assert store.get_audit_event(first.policy_audit_id) is not None
