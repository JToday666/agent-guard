"""Required receipt acknowledgement, compatibility and bounded diagnostics."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from agentguard_langgraph_adapter import (
    AgentGuardLangGraphConfig,
    AuditEvent,
    ReceiptSubmissionResult,
    runtime_receipt_preflight_error,
    runtime_receipts_required,
    submit_runtime_receipt,
    submit_runtime_receipt_result,
)

pytestmark = pytest.mark.unit


class _Guard:
    def __init__(self, response: Any = None, **config: Any) -> None:
        self.config = AgentGuardLangGraphConfig(**config)
        self.response = response
        self.submissions: list[AuditEvent] = []

    def submit_audit_event(self, receipt: AuditEvent) -> Any:
        self.submissions.append(receipt)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _receipt() -> AuditEvent:
    return AuditEvent(
        audit_id="audit_submission",
        trace_id="trace_submission",
        summary="Runtime receipt submission fixture",
        reason="Test the acknowledgement boundary",
    )


def _decision(**fields: Any) -> SimpleNamespace:
    return SimpleNamespace(policy_audit_id="audit_policy_submission", **fields)


def test_default_configuration_keeps_best_effort_compatibility() -> None:
    guard = _Guard({"ok": True})
    assert guard.config.runtime_receipt_mode == "best_effort"
    assert not runtime_receipts_required(guard)
    assert submit_runtime_receipt(guard, _receipt()) is None
    assert len(guard.submissions) == 1


@pytest.mark.parametrize("mode", ["off", "disabled", "fail_open", "", None])
def test_configuration_rejects_unknown_receipt_modes(mode: Any) -> None:
    with pytest.raises(ValueError, match="runtime_receipt_mode must be one of"):
        AgentGuardLangGraphConfig(runtime_receipt_mode=mode)


def test_configuration_normalizes_supported_receipt_modes() -> None:
    config = AgentGuardLangGraphConfig(runtime_receipt_mode=" REQUIRED ")  # type: ignore[arg-type]
    assert config.runtime_receipt_mode == "required"


@pytest.mark.parametrize(
    "config",
    [{"defense_enabled": False}, {"api_mode": "legacy"}],
)
def test_disabled_submission_is_distinct_and_does_not_send(
    config: dict[str, Any],
) -> None:
    if config.get("api_mode") == "legacy":
        with pytest.warns(DeprecationWarning):
            guard = _Guard({"ok": True}, **config)
    else:
        guard = _Guard({"ok": True}, **config)
    assert submit_runtime_receipt_result(guard, _receipt()) == ReceiptSubmissionResult(
        status="disabled"
    )
    assert submit_runtime_receipt(guard, _receipt()) is None
    assert not guard.submissions


def test_required_disabled_submission_fails_without_sending() -> None:
    guard = _Guard({"ok": True}, defense_enabled=False, runtime_receipt_mode="required")
    result = submit_runtime_receipt_result(guard, _receipt())
    assert result.status == "failed"
    assert result.audit_id is None
    assert result.error and "disabled" in result.error
    assert not guard.submissions


@pytest.mark.parametrize("required", [False, True])
def test_correlated_positive_acknowledgement_records_exactly_once(
    required: bool,
) -> None:
    guard = _Guard({"ok": True, "audit_id": "audit_submission"})
    result = submit_runtime_receipt_result(guard, _receipt(), required=required)
    assert result == ReceiptSubmissionResult(
        status="recorded", audit_id="audit_submission"
    )
    assert len(guard.submissions) == 1


@pytest.mark.parametrize(
    "response",
    [None, [], "ok", {}, {"ok": 1}, {"ok": "true"}, {"ok": False}],
)
@pytest.mark.parametrize("required", [False, True])
def test_invalid_responses_fail_without_retry(response: Any, required: bool) -> None:
    guard = _Guard(response)
    result = submit_runtime_receipt_result(guard, _receipt(), required=required)
    assert result.status == "failed"
    assert result.error
    assert result.audit_id is None
    assert len(guard.submissions) == 1


@pytest.mark.parametrize("audit_id", [None, "", False, "audit_other"])
def test_required_response_needs_exact_receipt_correlation(audit_id: Any) -> None:
    guard = _Guard({"ok": True, "audit_id": audit_id})
    result = submit_runtime_receipt_result(guard, _receipt(), required=True)
    assert result.status == "failed"
    assert result.error and "audit_id" in result.error
    assert len(guard.submissions) == 1


def test_required_configuration_cannot_be_overridden_by_call_default() -> None:
    guard = _Guard({"ok": True}, runtime_receipt_mode="required")
    assert submit_runtime_receipt_result(guard, _receipt()).status == "failed"
    assert submit_runtime_receipt(guard, _receipt()) is not None
    assert len(guard.submissions) == 2


@pytest.mark.parametrize("skipped", ["defense_off", True, False, None, ""])
def test_skipped_response_never_claims_recorded(skipped: Any) -> None:
    guard = _Guard({"ok": True, "audit_id": "audit_submission", "skipped": skipped})
    assert submit_runtime_receipt_result(guard, _receipt()).status == "disabled"
    result = submit_runtime_receipt_result(guard, _receipt(), required=True)
    assert result.status == "failed"
    assert result.error and "skipped" in result.error
    assert len(guard.submissions) == 2


@pytest.mark.parametrize("raises", [False, True])
def test_submission_errors_are_bounded_and_redact_credentials(raises: bool) -> None:
    lease = "lease-v1:" + "a" * 64
    hmac = "hmac-sha256:" + "b" * 64
    token = "fixture-adapter-secret"
    detail = (
        f"start unavailable: {lease} {hmac} {token} Bearer fixture-secret " + "x" * 900
    )
    guard = _Guard(
        RuntimeError(detail) if raises else {"ok": False, "error": detail}, token=token
    )
    result = submit_runtime_receipt_result(guard, _receipt(), required=True)
    assert result.status == "failed"
    assert result.error and len(result.error) <= 500
    assert "Runtime receipt submission failed: start unavailable" in result.error
    assert "[redacted]" in result.error
    assert lease not in result.error
    assert hmac not in result.error
    assert token not in result.error
    assert "fixture-secret" not in result.error
    assert len(guard.submissions) == 1


def test_config_or_durable_directive_requires_receipts() -> None:
    assert runtime_receipts_required(_Guard(runtime_receipt_mode="required"))
    guard = _Guard()
    directive = {"receipt_requirement": "required_durable"}
    assert runtime_receipts_required(
        guard, _decision(approval_release_directive=directive)
    )
    assert runtime_receipts_required(guard, {"approval_release_directive": directive})
    assert not runtime_receipts_required(guard, _decision())


@pytest.mark.parametrize(
    "authority,expected",
    [
        ({"source": "v21", "mode": "active", "selection_basis": "profile_all"}, True),
        ({"source": "v21", "mode": "shadow", "selection_basis": "profile_all"}, False),
        (
            {"source": "current", "mode": "active", "selection_basis": "profile_all"},
            False,
        ),
        (
            {"source": "v21", "mode": "active", "selection_basis": "path_allowlist"},
            False,
        ),
    ],
)
def test_only_complete_product_active_authority_requires_receipts(
    authority: dict[str, str], expected: bool
) -> None:
    for value in (authority, SimpleNamespace(**authority)):
        assert (
            runtime_receipts_required(_Guard(), _decision(decision_authority=value))
            is expected
        )


def test_preflight_required_prerequisites_and_captured_requirement() -> None:
    guard = _Guard()
    assert runtime_receipt_preflight_error(guard, _decision(), required=True) is None
    assert not guard.submissions
    guard.config.defense_enabled = False
    assert runtime_receipt_preflight_error(guard, _decision()) is None
    error = runtime_receipt_preflight_error(guard, _decision(), required=True)
    assert error and "disabled" in error
    guard.config.defense_enabled = True
    for audit_id in (None, "", " ", False):
        error = runtime_receipt_preflight_error(
            guard, SimpleNamespace(policy_audit_id=audit_id), required=True
        )
        assert error and "policy_audit_id" in error
    guard.submit_audit_event = None  # type: ignore[method-assign, assignment]
    error = runtime_receipt_preflight_error(guard, _decision(), required=True)
    assert error and "not callable" in error
    assert not guard.submissions


def test_preflight_implicitly_honors_product_active_authority() -> None:
    guard = _Guard(defense_enabled=False)
    decision = _decision(
        decision_authority={
            "source": "v21",
            "mode": "active",
            "selection_basis": "profile_all",
        }
    )
    error = runtime_receipt_preflight_error(guard, decision)
    assert error and "disabled" in error
