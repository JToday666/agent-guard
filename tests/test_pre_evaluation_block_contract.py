"""Core-only contract tests for fail-closed pre-evaluation observations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, get_args

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError

from agentguard_core import (
    AuditEvent,
    PreEvaluationBlockDiagnostic,
    PreEvaluationBlockFailureCode,
)
from agentguard_core.decisions import (
    PreEvaluationBlockDiagnostic as DecisionsPreEvaluationBlockDiagnostic,
)

pytestmark = pytest.mark.contract

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/pre_evaluation_block_diagnostic_v1.schema.json"
SCHEMA_ID = (
    "https://agentguard.dev/schemas/" "pre_evaluation_block_diagnostic_v1.schema.json"
)
FAILURE_CODES = get_args(PreEvaluationBlockFailureCode)
DIGESTS = {character: f"sha256:{character * 64}" for character in "123456789a"}


def _payload(
    failure_code: str = "guard_api_unavailable",
) -> dict[str, Any]:
    return {
        "audit_id": "audit_execution_blocked_event_pre_eval_1",
        "schema_version": "0.4",
        "record_type": "runtime_observation",
        "trace_id": "trace_pre_eval_1",
        "case_id": "case_pre_eval_1",
        "runtime": "openclaw",
        "timestamp": "2026-09-01T08:00:00+08:00",
        "stage": "pre_evaluation_blocked",
        "event_type": "execution_blocked",
        "attack_type": None,
        "is_malicious": None,
        "summary": "OpenClaw blocked a side effect before Guard evaluation",
        "decision": None,
        "risk_score": None,
        "severity": None,
        "blocked": True,
        "resource_targets": [],
        "rule_hits": [],
        "reason": failure_code,
        "links": {
            "event_id": "event_pre_eval_1",
            "action_id": "call_pre_eval_1",
            "activation_ref_digest": DIGESTS["1"],
        },
        "latency_ms": None,
        "metadata": {
            "agent_id": "main",
            "runtime_version": "2026.7.1-2",
            "plugin_version": "0.1.0-rc.1",
            "runtime_binding_id": "binding:openclaw:main",
            "profile_id": "agentguard-openclaw-v2-restricted",
            "profile_digest": DIGESTS["2"],
            "activation_ref_digest": DIGESTS["1"],
            "capability_digest": DIGESTS["3"],
            "host_inventory_digest": DIGESTS["4"],
            "plugin_inventory_digest": DIGESTS["5"],
            "plugin_order_inventory_digest": DIGESTS["6"],
            "tool_inventory_digest": DIGESTS["7"],
            "action_digest": DIGESTS["8"],
            "failure_code": failure_code,
        },
        "evidence": {
            "authority_stage": "pre_evaluation_blocked",
            "execution_state": "not_invoked",
            "required_durable_spool": True,
            "tool_replay_permitted": False,
            "failure_code": failure_code,
        },
    }


def _schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _validator() -> Draft202012Validator:
    return Draft202012Validator(_schema(), format_checker=FormatChecker())


def _general_audit_validator() -> Draft202012Validator:
    schema = json.loads(
        (ROOT / "schemas/audit_event.schema.json").read_text(encoding="utf-8")
    )
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _generated_public_schema() -> dict[str, Any]:
    generated = PreEvaluationBlockDiagnostic.model_json_schema(mode="validation")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_ID,
        **generated,
    }


def _set_path(payload: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    target = payload
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def _delete_path(payload: dict[str, Any], path: tuple[str, ...]) -> None:
    target = payload
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]


@pytest.mark.parametrize("failure_code", FAILURE_CODES)
def test_all_failure_codes_round_trip_as_non_authority_observations(
    failure_code: str,
) -> None:
    diagnostic = PreEvaluationBlockDiagnostic.model_validate(_payload(failure_code))
    dumped = diagnostic.model_dump(mode="json")

    assert isinstance(diagnostic, AuditEvent)
    assert DecisionsPreEvaluationBlockDiagnostic is PreEvaluationBlockDiagnostic
    assert dumped["timestamp"] == "2026-09-01T00:00:00+00:00"
    assert dumped["decision"] is None
    assert dumped["evidence"]["execution_state"] == "not_invoked"
    assert dumped["evidence"]["tool_replay_permitted"] is False
    _validator().validate(dumped)
    _general_audit_validator().validate(dumped)


def test_public_schema_is_the_exact_generated_validation_contract() -> None:
    schema = _schema()

    Draft202012Validator.check_schema(schema)
    assert schema == _generated_public_schema()
    assert set(FAILURE_CODES) == {
        "activation_authority_unavailable",
        "guard_api_unavailable",
        "wrong_binding",
        "wrong_profile",
    }


@pytest.mark.parametrize(
    "path",
    [
        ("reason",),
        ("metadata", "failure_code"),
        ("evidence", "failure_code"),
    ],
)
def test_failure_code_drift_is_rejected_by_model_and_schema(
    path: tuple[str, ...],
) -> None:
    payload = _payload()
    _set_path(payload, path, "wrong_binding")

    with pytest.raises(ValidationError, match="failure codes must match"):
        PreEvaluationBlockDiagnostic.model_validate(payload)
    assert not _validator().is_valid(payload)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("runtime",), "langgraph"),
        (("metadata", "runtime_version"), "latest"),
        (("metadata", "plugin_version"), "0.1.0"),
        (("summary",), "blocked"),
        (("decision",), "deny"),
        (("risk_score",), 0),
        (("severity",), "high"),
        (("latency_ms",), 0),
        (("blocked",), False),
        (("blocked",), 1),
        (("attack_type",), "prompt_injection"),
        (("is_malicious",), True),
        (("resource_targets",), ["file:///secret"]),
        (("rule_hits",), ["rule:invented"]),
        (("evidence", "authority_stage"), "approval_released"),
        (("evidence", "execution_state"), "unknown"),
        (("evidence", "required_durable_spool"), False),
        (("evidence", "required_durable_spool"), 1),
        (("evidence", "tool_replay_permitted"), True),
        (("evidence", "tool_replay_permitted"), 0),
    ],
)
def test_fixed_non_authority_shape_rejects_semantic_drift(
    path: tuple[str, ...],
    value: Any,
) -> None:
    payload = _payload()
    _set_path(payload, path, value)

    with pytest.raises(ValidationError):
        PreEvaluationBlockDiagnostic.model_validate(payload)
    assert not _validator().is_valid(payload)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("links", "event_id"), ""),
        (("links", "action_id"), "a" * 161),
        (("metadata", "agent_id"), "a" * 129),
        (("metadata", "runtime_binding_id"), "b" * 257),
        (("metadata", "profile_digest"), "not-a-digest"),
        (("metadata", "action_digest"), f"sha256:{'A' * 64}"),
    ],
)
def test_identity_and_digest_boundaries_are_strict(
    path: tuple[str, ...],
    value: str,
) -> None:
    payload = _payload()
    _set_path(payload, path, value)

    with pytest.raises(ValidationError):
        PreEvaluationBlockDiagnostic.model_validate(payload)
    assert not _validator().is_valid(payload)


@pytest.mark.parametrize(
    "path",
    [
        ("schema_version",),
        ("record_type",),
        ("runtime",),
        ("stage",),
        ("event_type",),
        ("blocked",),
        ("decision",),
        ("links", "action_id"),
        ("metadata", "capability_digest"),
        ("evidence", "execution_state"),
    ],
)
def test_canonical_wire_fields_are_required(path: tuple[str, ...]) -> None:
    payload = _payload()
    _delete_path(payload, path)

    with pytest.raises(ValidationError):
        PreEvaluationBlockDiagnostic.model_validate(payload)
    assert not _validator().is_valid(payload)


@pytest.mark.parametrize(
    "path",
    [
        ("unexpected",),
        ("activation_ack",),
        ("links", "lease_id"),
        ("metadata", "approval_id"),
        ("evidence", "release_directive"),
    ],
)
def test_authority_or_unknown_field_injection_is_rejected(
    path: tuple[str, ...],
) -> None:
    payload = _payload()
    _set_path(payload, path, "injected")

    with pytest.raises(ValidationError):
        PreEvaluationBlockDiagnostic.model_validate(payload)
    assert not _validator().is_valid(payload)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("audit_id",), "audit_execution_blocked_other_event"),
        (("links", "activation_ref_digest"), DIGESTS["9"]),
    ],
)
def test_dynamic_identity_relations_are_model_authoritative(
    path: tuple[str, ...],
    value: str,
) -> None:
    payload = _payload()
    _set_path(payload, path, value)

    with pytest.raises(ValidationError):
        PreEvaluationBlockDiagnostic.model_validate(payload)
    assert _validator().is_valid(payload)


@pytest.mark.parametrize(
    "timestamp",
    ["not-a-time", "2026-09-01T00:00:00"],
)
def test_timestamp_must_be_rfc3339_with_timezone(timestamp: str) -> None:
    payload = _payload()
    payload["timestamp"] = timestamp

    with pytest.raises(ValidationError):
        PreEvaluationBlockDiagnostic.model_validate(payload)
    assert not _validator().is_valid(payload)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("trace_id",), f"hmac-sha256:{'a' * 64}"),
        (("links", "action_id"), f"lease-v1:{'b' * 64}"),
        (("metadata", "runtime_binding_id"), f"hmac-sha256:{'c' * 64}"),
    ],
)
def test_full_record_secret_scan_has_no_exempt_leaf(
    path: tuple[str, ...],
    value: str,
) -> None:
    payload = _payload()
    _set_path(payload, path, value)

    with pytest.raises(ValidationError, match="cannot contain runtime secrets"):
        PreEvaluationBlockDiagnostic.model_validate(payload)
    assert _validator().is_valid(payload)


def test_diagnostic_and_nested_objects_are_frozen() -> None:
    diagnostic = PreEvaluationBlockDiagnostic.model_validate(_payload())

    with pytest.raises(ValidationError, match="frozen"):
        diagnostic.blocked = False
    with pytest.raises(ValidationError, match="frozen"):
        diagnostic.metadata.profile_id = "mutated"
    assert diagnostic.resource_targets == ()
    assert diagnostic.rule_hits == ()
