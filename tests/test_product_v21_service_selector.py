"""Product Active selector wiring through the real ``EvaluationService``.

The runtime-neutral Core selector has its own exhaustive contract suite.  This
module proves that the production service feeds it fenced Phase-A/Phase-B
materials and commits the resulting schema-2 authority, release directive,
approval and (where supported) C3 binding without falling back to ``current``.

The public composition root intentionally remains covered by the pre-selector
fuse until the activation-ack/freshness batch removes it atomically.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import pytest

from agentguard_core import (
    GuardDecision,
    GuardEngine,
    GuardEvent,
    PolicyBundle,
    ProductDecisionAuthorityEvidenceV1,
    legacy_approval_release_projection,
)
from agentguard_core.actions import ActionConstraint
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions.product import PRODUCT_EVENT_TYPES
from agentguard_core.decisions.shadow import compute_assessment_digest

from guard_api.auth import AuthContext
from guard_api.models import (
    ADAPTER_CREDENTIAL_SCOPES,
    CredentialRecord,
    TaskCreateRequest,
)
from guard_api.security_state import SecurityStateService
from guard_api.services import ApprovalService, AuditService, EvaluationService
from guard_api.services.competition import parse_decision_authority_evidence_payload
from guard_api.services.policy import PolicyService
from guard_api.services.product_activation import load_frozen_product_activation
from guard_api.services.runtime_binding import RuntimeBindingResolver
from guard_api.services.task_ingress import TaskIngressService
from guard_api.services.v21_pipeline import V21PipelineService
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.product_activation import (
    TEST_PRODUCT_ACTIVATION_SECRET_B64,
    ProductActivationFixture,
    build_test_product_activation,
    product_runtime_status_for_activation,
    write_test_product_activation,
)

pytestmark = pytest.mark.integration

Runtime = Literal["langgraph", "openclaw"]

_TASK_SCOPE_KEY_ID = "product-selector-service-task-key"
_TASK_SCOPE_KEY_B64 = base64.urlsafe_b64encode(
    b"product-selector-service-task-secret-01"
).decode("ascii")
_SHADOW_SECRET_B64 = base64.urlsafe_b64encode(
    b"product-selector-service-shadow-secret-01"
).decode("ascii")
_SESSION_ID = "session:product-selector-service"
_TRACE_ID = "trace:product-selector-service"


def _safe_payload(event_type: str) -> dict[str, Any]:
    payloads: dict[str, dict[str, Any]] = {
        "tool_call_proposed": {
            "tool": {
                "name": "safe_product_tool",
                "call_id": "call:product-selector-safe",
            },
            "arguments": {},
            "derived_resources": [],
        },
        "context_assembled": {
            "sources": [],
            "will_enter_context": True,
            "sanitized": True,
        },
        "model_input_prepared": {
            "phase": "input",
            "content_preview": "safe model input",
            "contains_instruction_like_text": False,
            "contains_sensitive_data": False,
            "sanitized": True,
        },
        "model_output_produced": {
            "phase": "output",
            "content_preview": "safe model output",
            "contains_instruction_like_text": False,
            "contains_sensitive_data": False,
            "sanitized": True,
        },
        "tool_result_produced": {
            "tool": {
                "name": "safe_product_tool",
                "call_id": "call:product-selector-result",
            },
            "result": {
                "content_preview": "safe tool result",
                "content_type": "text/plain",
                "size_bytes": 16,
            },
            "will_enter_context": False,
            "will_persist": False,
            "sanitized": True,
            "contains_sensitive_data": False,
            "contains_instruction_like_text": False,
        },
        "memory_write_proposed": {
            "memory": {
                "namespace": "product-selector",
                "key": "safe-key",
                "value_preview": "safe value",
                "source_trust": "trusted",
                "operation": "write",
            },
            "will_persist": True,
            "requires_approval": False,
        },
        "message_send_proposed": {
            "channel": "test",
            "recipient": "recipient:internal",
            "content_preview": "safe message",
        },
    }
    return payloads[event_type]


@dataclass(frozen=True, slots=True)
class _ProductServiceStack:
    fixture: ProductActivationFixture
    store: MemoryControlPlaneStore
    evaluation: EvaluationService
    auth_context: AuthContext
    task_id: str
    scope_digest: str
    runtime: Runtime

    def event(
        self,
        event_type: str,
        *,
        event_id: str | None = None,
        payload: dict[str, Any] | None = None,
        source_trust: str = "trusted",
        user_task: str = "exercise the Product Active selector",
    ) -> GuardEvent:
        return GuardEvent.model_validate(
            {
                "schema_version": "0.3",
                "event_id": event_id
                or f"evt:product-selector:{self.runtime}:{event_type}",
                "event_type": event_type,
                "runtime": self.runtime,
                "trace_id": _TRACE_ID,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "pre_execution": event_type
                not in {"model_output_produced", "tool_result_produced"},
                "security_context": {
                    "agent_id": "main",
                    "session_id": _SESSION_ID,
                    "user_task": user_task,
                    "source_type": "user",
                    "source_trust": source_trust,
                },
                "payload": payload or _safe_payload(event_type),
                "metadata": {"task_id": self.task_id},
            }
        )


def _settings(
    activation_path: Path,
    fixture: ProductActivationFixture,
) -> GuardApiSettings:
    return GuardApiSettings(
        storage_backend="memory",
        control_token="control-secret",
        v21_mode="active",
        v21_product_activation_path=str(activation_path),
        v21_product_activation_server_secret=TEST_PRODUCT_ACTIVATION_SECRET_B64,
        v21_product_activation_signer_key_id=fixture.signer_key_id,
        v21_shadow_server_secret=_SHADOW_SECRET_B64,
        task_scope_active_key_id=_TASK_SCOPE_KEY_ID,
        task_scope_keys=json.dumps({_TASK_SCOPE_KEY_ID: _TASK_SCOPE_KEY_B64}),
        rte05_strong_binding_enabled=True,
    )


def _stack(
    tmp_path: Path,
    runtime: Runtime,
    *,
    action_types: list[str] | None = None,
) -> _ProductServiceStack:
    policy = PolicyBundle()
    fixture = build_test_product_activation(
        now=datetime.now(timezone.utc),
        policy_digest=canonical_sha256(policy.model_dump(mode="json")),
    )
    activation_path = write_test_product_activation(
        tmp_path / f"product-selector-{runtime}.json",
        fixture,
    )
    settings = _settings(activation_path, fixture)
    store = MemoryControlPlaneStore()
    store.save_policy_snapshot(
        policy,
        expected_revision=0,
        updated_by="product-selector-service-test",
    )
    for observed_runtime in ("langgraph", "openclaw"):
        store.save_product_runtime_status(
            product_runtime_status_for_activation(fixture, observed_runtime)
        )

    entry = fixture.bundle.runtime_entry(runtime)
    raw_token = f"product-selector-service-token:{runtime}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    credential_id = f"cred_product_selector_service_{runtime}"
    store.create_credential(
        CredentialRecord(
            credential_id=credential_id,
            token_hash=token_hash,
            principal_type="component",
            principal_id=entry.principal_id,
            role="adapter",
            scopes=list(ADAPTER_CREDENTIAL_SCOPES),
            runtime=entry.runtime,
            agent_id=entry.agent_id,
        )
    )

    activation = load_frozen_product_activation(settings)
    assert activation is not None
    resolver = RuntimeBindingResolver(product_activation=activation)
    created = TaskIngressService(
        store=store,
        settings=settings,
        runtime_binding_resolver=resolver,
    ).create_task(
        TaskCreateRequest(
            task_text="exercise the Product Active selector",
            runtime=entry.runtime,
            trace_id=_TRACE_ID,
            session_id=_SESSION_ID,
            runtime_binding_id=entry.runtime_binding_id,
            # A non-empty compiled constraint makes the authoritative task
            # coverage complete.  Individual event authorization is still
            # assessed by the production pipeline and safety floor.
            action_constraints=[
                ActionConstraint(action_types=action_types or ["tool_call"])
            ],
            resource_constraints=[],
            destination_constraints=[],
        ),
        AuthContext(
            principal_type="cli",
            principal_id="cred_control",
            role="control",
            scopes=["task:write"],
            auth_method="bearer",
        ),
    )
    SecurityStateService(store).ensure_ready(created.scope_digest)

    policy_service = PolicyService(store=store)
    pipeline = V21PipelineService(
        settings=settings,
        store=store,
        state_service=SecurityStateService(store),
        policy_service=policy_service,
        runtime_binding_resolver=resolver,
    )
    evaluation = EvaluationService(
        policy_service=policy_service,
        audit_service=AuditService(store=store),
        approval_service=ApprovalService(store=store, settings=settings),
        v21_pipeline=pipeline,
    )
    auth_context = AuthContext(
        principal_type="component",
        principal_id=entry.principal_id,
        role="adapter",
        scopes=list(ADAPTER_CREDENTIAL_SCOPES),
        auth_method="bearer",
        credential_id=credential_id,
        credential_token_hash=token_hash,
        runtime=entry.runtime,
        agent_id=entry.agent_id,
    )
    return _ProductServiceStack(
        fixture=fixture,
        store=store,
        evaluation=evaluation,
        auth_context=auth_context,
        task_id=created.task_id,
        scope_digest=created.scope_digest,
        runtime=runtime,
    )


def _authority_evidence(
    stack: _ProductServiceStack,
    event: GuardEvent,
) -> ProductDecisionAuthorityEvidenceV1:
    audit = stack.store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None and audit.evidence is not None
    parsed = parse_decision_authority_evidence_payload(
        {"decision_authority": audit.evidence["decision_authority"]}
    )
    assert isinstance(parsed, ProductDecisionAuthorityEvidenceV1)
    return parsed


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("event_type", PRODUCT_EVENT_TYPES)
def test_all_product_events_commit_v2_active_profile_all_without_current_fallback(
    tmp_path: Path,
    runtime: Runtime,
    event_type: str,
) -> None:
    stack = _stack(tmp_path, runtime)
    event = stack.event(event_type)

    response = stack.evaluation.evaluate(event, auth_context=stack.auth_context)

    authority = response.decision_authority
    assert authority is not None
    assert authority.source == "v21"
    assert authority.mode == "active"
    assert authority.selection_basis == "profile_all"
    assert authority.matched_path_ids == []
    assert response.decision.decision_id.startswith("dec:v21-product:")
    assert response.approval_release_directive is not None
    evidence = _authority_evidence(stack, event)
    assert evidence.schema_version == "2.0"
    assert evidence.persistence_requirement == "critical_no_drop"
    assert evidence.runtime == runtime
    assert evidence.event_type == event_type
    assert evidence.event_id == event.event_id
    assert evidence.selected_decision == response.decision
    assert evidence.decision_authority == authority
    assert evidence.approval_release_directive == (response.approval_release_directive)


def test_product_service_commits_a_true_raw_v21_allow(tmp_path: Path) -> None:
    stack = _stack(tmp_path, "langgraph")
    event = stack.event(
        "tool_call_proposed",
        event_id="evt:product-selector:raw-v21-allow",
        source_trust="trusted",
        user_task=(
            "Summarize the quarterly results already present in the conversation."
        ),
        payload={
            "tool": {
                "name": "read_file",
                "call_id": "call:product-selector-raw-v21-allow",
            },
            "arguments": {"path": "/docs/quarterly-results.txt"},
            "derived_resources": [],
        },
    )

    response = stack.evaluation.evaluate(event, auth_context=stack.auth_context)
    evidence = _authority_evidence(stack, event)

    assert evidence.current_decision.decision == "allow"
    assert evidence.raw_v21_decision.decision == "allow"
    assert response.decision.decision == "allow"
    assert response.decision.decision_id.startswith("dec:v21-product:")
    assert response.decision_authority is not None
    assert response.decision_authority.source == "v21"
    assert response.approval_release_directive is not None
    assert response.approval_release_directive.mode == "not_applicable"
    assert response.approval is None
    assert response.enforcement_binding is None


@pytest.mark.parametrize(
    (
        "runtime",
        "expected_mode",
        "expected_profile",
        "expected_action_binding",
        "expected_legacy_projection",
        "expect_c3_binding",
    ),
    [
        (
            "langgraph",
            "strong_binding",
            "C3",
            "exact",
            "strong_binding_required",
            True,
        ),
        (
            "openclaw",
            "restricted_allow_once",
            "C1",
            "best_effort_host",
            "forbidden",
            False,
        ),
    ],
)
def test_product_ask_commits_runtime_specific_release_and_exact_carrier_parity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime: Runtime,
    expected_mode: str,
    expected_profile: str,
    expected_action_binding: str,
    expected_legacy_projection: str,
    expect_c3_binding: bool,
) -> None:
    stack = _stack(tmp_path, runtime)
    # Keep the V2 assessment fully real and complete while deterministically
    # exercising the legacy safety-floor ASK branch.  The Product Core then
    # derives the runtime-specific release directive from production inputs.
    _force_current_decision(monkeypatch, "ask")
    event = stack.event(
        "tool_call_proposed",
        event_id=f"evt:product-selector:{runtime}:ask",
        source_trust="trusted",
        user_task=(
            "Summarize the quarterly results already present in the conversation."
        ),
        payload={
            "tool": {
                "name": "read_file",
                "call_id": f"call:product-selector-{runtime}-ask",
            },
            "arguments": {"path": "/docs/quarterly-results.txt"},
            "derived_resources": [],
        },
    )

    response = stack.evaluation.evaluate(event, auth_context=stack.auth_context)

    assert response.decision.decision == "ask"
    assert response.approval is not None
    directive = response.approval_release_directive
    authority = response.decision_authority
    assert directive is not None and authority is not None
    assert directive.mode == expected_mode
    assert directive.required_runtime_profile == expected_profile
    assert directive.action_binding == expected_action_binding
    assert directive.human_only is True
    assert directive.single_use is True
    assert directive.receipt_requirement == "required_durable"
    assert legacy_approval_release_projection(directive) == (expected_legacy_projection)
    assert authority.approval_release == expected_legacy_projection
    assert (response.enforcement_binding is not None) is expect_c3_binding

    audit = stack.store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None and audit.evidence is not None
    raw_authority = audit.evidence["decision_authority"]
    assert raw_authority["schema_version"] == "2.0"
    evidence = _authority_evidence(stack, event)
    assert evidence.selected_decision == response.decision
    assert evidence.decision_authority == authority
    assert evidence.approval_release_directive == directive
    approval = stack.store.get_approval(response.approval.approval_id)
    assert approval is not None
    assert approval.evidence["decision_authority"] == authority.model_dump(mode="json")
    assert approval.evidence["approval_release_directive"] == directive.model_dump(
        mode="json"
    )
    if runtime == "openclaw":
        assert stack.store.enforcement_bindings == {}
    else:
        assert response.enforcement_binding is not None
        assert response.enforcement_binding.runtime_binding_id == (
            stack.fixture.bundle.runtime_entry("langgraph").runtime_binding_id
        )


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize(
    ("event_type", "action_type"),
    [
        ("memory_write_proposed", "memory_write"),
        ("message_send_proposed", "message_send"),
    ],
)
def test_product_side_effect_ask_release_applies_to_memory_and_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime: Runtime,
    event_type: str,
    action_type: str,
) -> None:
    stack = _stack(tmp_path, runtime, action_types=[action_type])
    _force_current_decision(monkeypatch, "ask")
    _force_complete_v21_allow(monkeypatch)
    event = stack.event(
        event_type,
        event_id=f"evt:product-selector:{runtime}:{event_type}:ask",
        payload=_safe_payload(event_type),
    )

    response = stack.evaluation.evaluate(event, auth_context=stack.auth_context)
    evidence = _authority_evidence(stack, event)

    assert evidence.raw_v21_decision.decision == "allow"
    assert response.decision.decision == "ask"
    assert response.approval is not None
    assert response.approval_release_directive is not None
    assert response.approval_release_directive.mode == (
        "strong_binding" if runtime == "langgraph" else "restricted_allow_once"
    )
    assert response.approval_release_directive.required_runtime_profile == (
        "C3" if runtime == "langgraph" else "C1"
    )
    assert response.approval_release_directive.action_binding == (
        "exact" if runtime == "langgraph" else "best_effort_host"
    )
    assert legacy_approval_release_projection(response.approval_release_directive) == (
        "strong_binding_required" if runtime == "langgraph" else "forbidden"
    )
    assert (response.enforcement_binding is not None) is (runtime == "langgraph")
    if runtime == "openclaw":
        assert stack.store.enforcement_bindings == {}


def _force_current_decision(
    monkeypatch: pytest.MonkeyPatch,
    forced: Literal["allow", "ask", "deny"],
) -> None:
    original = GuardEngine.evaluate_with_results

    def force(
        self: GuardEngine,
        event: GuardEvent,
        policies: PolicyBundle | None = None,
    ) -> tuple[GuardDecision, list[Any]]:
        decision, detections = original(self, event, policies)
        risk_score = {"allow": 0, "ask": 50, "deny": 100}[forced]
        severity = {"allow": "low", "ask": "medium", "deny": "critical"}[forced]
        forced_decision = decision.model_copy(
            update={
                "decision_id": f"dec:forced-current:{forced}",
                "decision": forced,
                "risk_score": risk_score,
                "severity": severity,
                "categories": [f"forced-current:{forced}"],
                "rule_hits": [],
                "reason": f"forced current {forced}",
                "approval_intent": None,
            }
        )
        return forced_decision, detections

    monkeypatch.setattr(GuardEngine, "evaluate_with_results", force)


def _force_complete_v21_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep real Phase A inputs/ActionIR while making coverage fully reviewable."""

    from guard_api.services import v21_pipeline as pipeline_module

    original = pipeline_module.shadow_assess_with_coverage

    def force(*args: Any, **kwargs: Any):
        outcome = original(*args, **kwargs)
        assert outcome.action_ir is not None
        assert outcome.assessment.authority.status == "authorized"
        coverage = outcome.coverage.model_copy(
            update={
                domain: getattr(outcome.coverage, domain).model_copy(
                    update={"status": "complete", "reason_codes": []}
                )
                for domain in (
                    "task",
                    "source",
                    "capability",
                    "behavior",
                    "dataflow",
                    "memory",
                    "runtime_outcome",
                )
            }
        )
        pending = outcome.assessment.model_copy(
            update={
                "disposition": "CLEAR_ALLOW",
                "degradations": [],
                "flow": outcome.assessment.flow.model_copy(
                    update={
                        "status": "safe",
                        "taints": [],
                        "external_sink": False,
                        "path_refs": [],
                        "evidence_refs": [],
                    }
                ),
                "reason_codes": [],
                "assessment_digest": "",
            }
        )
        assessment = pending.model_copy(
            update={"assessment_digest": compute_assessment_digest(pending)}
        )
        return replace(outcome, assessment=assessment, coverage=coverage)

    monkeypatch.setattr(pipeline_module, "shadow_assess_with_coverage", force)


def test_current_deny_floor_remains_v2_authority_not_current_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack = _stack(tmp_path, "langgraph")
    _force_current_decision(monkeypatch, "deny")
    event = stack.event(
        "tool_call_proposed",
        event_id="evt:product-selector:legacy-deny-floor",
        payload={
            "tool": {
                "name": "read_file",
                "call_id": "call:product-selector-legacy-deny-floor",
            },
            "arguments": {"path": "/docs/public.txt"},
            "derived_resources": [],
        },
    )

    response = stack.evaluation.evaluate(event, auth_context=stack.auth_context)
    evidence = _authority_evidence(stack, event)

    assert evidence.current_decision.decision == "deny"
    assert evidence.raw_v21_decision.decision == "allow"
    assert response.decision.decision == "deny"
    assert response.decision.decision_id != evidence.current_decision.decision_id
    assert response.decision.decision_id.startswith("dec:v21-product:")
    assert response.decision_authority is not None
    assert response.decision_authority.source == "v21"
    assert response.decision_authority.legacy_floor_applied is True
