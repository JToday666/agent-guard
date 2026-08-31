"""Server-owned legacy/Product runtime binding resolution tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

import pytest
from agentguard_core import GuardEvent, SecurityContext, ToolCallPayload, ToolDescriptor

from guard_api.auth import AuthContext
from guard_api.services.product_activation import FrozenProductActivation
from guard_api.services.runtime_binding import (
    LEGACY_RUNTIME_IDENTITY_MISMATCH,
    PRODUCT_ACTIVATION_NOT_CURRENT,
    PRODUCT_RUNTIME_IDENTITY_MISMATCH,
    RuntimeBindingResolutionError,
    RuntimeBindingResolver,
)
from guard_api.storage.integrity import canonical_sha256
from tests.support.product_activation import (
    ProductActivationFixture,
    build_test_product_activation,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)


def _frozen(fixture: ProductActivationFixture) -> FrozenProductActivation:
    return FrozenProductActivation(
        bundle=fixture.bundle,
        source_path="/test/product-activation.json",
        content_digest=canonical_sha256(fixture.bundle.model_dump(mode="json")),
    )


def _auth(
    *,
    runtime: str | None = "langgraph",
    principal_id: str = "principal:lg",
    agent_id: str | None = "main",
    role: str = "adapter",
) -> AuthContext:
    return AuthContext(
        principal_type="component" if runtime is not None else "cli",
        principal_id=principal_id,
        role=role,
        scopes=["event:evaluate"] if runtime is not None else ["task:write"],
        auth_method="bearer",
        runtime=runtime,
        agent_id=agent_id,
    )


def _event(*, runtime: str = "langgraph", agent_id: str = "main") -> GuardEvent:
    return GuardEvent(
        event_type="tool_call_proposed",
        runtime=runtime,
        trace_id="trace_binding_resolver",
        timestamp=_NOW.isoformat(),
        pre_execution=True,
        security_context=SecurityContext(agent_id=agent_id),
        payload=ToolCallPayload(
            tool=ToolDescriptor(
                name="send_email",
                category="message",
                kind="email_send",
                call_id="call_binding_resolver",
            ),
            arguments={"to": "safe@example.test"},
        ),
    )


def _assert_code(code: str, call) -> None:
    with pytest.raises(RuntimeBindingResolutionError) as exc:
        call()
    assert exc.value.code == code
    assert str(exc.value) == code


def test_legacy_task_derivation_preserves_runtime_and_control_forms() -> None:
    resolver = RuntimeBindingResolver()

    runtime_bound = resolver.resolve_task_ingress(
        _auth(),
        runtime="langgraph",
        claimed_runtime_binding_id="binding:principal:lg",
    )
    assert runtime_bound.runtime_binding_id == "binding:principal:lg"
    assert runtime_bound.principal_id == "principal:lg"
    assert runtime_bound.agent_id == "main"
    assert runtime_bound.actor_principal_id == "principal:lg"
    assert runtime_bound.activation_ref_digest is None
    assert runtime_bound.source == "legacy_derived"

    control = resolver.resolve_task_ingress(
        _auth(
            runtime=None,
            principal_id="cred_control",
            agent_id=None,
            role="control",
        ),
        runtime="openclaw",
    )
    assert control.runtime == "openclaw"
    assert control.principal_id == "cred_control"
    assert control.agent_id is None
    assert control.runtime_binding_id == "binding:control:cred_control"
    assert control.actor_principal_id == "cred_control"
    assert control.activation_ref_digest is None
    assert control.source == "legacy_derived"


def test_legacy_claim_and_runtime_are_comparison_only() -> None:
    resolver = RuntimeBindingResolver()
    auth = _auth()

    _assert_code(
        LEGACY_RUNTIME_IDENTITY_MISMATCH,
        lambda: resolver.resolve_task_ingress(auth, runtime="openclaw"),
    )
    _assert_code(
        LEGACY_RUNTIME_IDENTITY_MISMATCH,
        lambda: resolver.resolve_task_ingress(
            auth,
            runtime="langgraph",
            claimed_runtime_binding_id="binding:caller-controlled",
        ),
    )


def test_legacy_evaluation_reconstructs_the_existing_task_principal_form() -> None:
    resolved = RuntimeBindingResolver().resolve_evaluation(
        _auth(principal_id="different-auth-principal"),
        event=_event(),
        task_principal_id="persisted-task-principal",
    )

    assert resolved.runtime == "langgraph"
    assert resolved.principal_id == "persisted-task-principal"
    assert resolved.agent_id == "main"
    assert resolved.runtime_binding_id == "binding:persisted-task-principal"
    assert resolved.actor_principal_id == "different-auth-principal"
    assert resolved.activation_ref_digest is None
    assert resolved.source == "legacy_derived"


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_product_control_selects_only_the_signed_runtime_subject(runtime: str) -> None:
    fixture = build_test_product_activation(now=_NOW)
    resolver = RuntimeBindingResolver(
        product_activation=_frozen(fixture),
        clock=lambda: _NOW,
    )
    entry = fixture.bundle.runtime_entry(runtime)  # type: ignore[arg-type]

    resolved = resolver.resolve_task_ingress(
        _auth(
            runtime=None,
            principal_id="cred_control",
            agent_id=None,
            role="control",
        ),
        runtime=runtime,
        claimed_runtime_binding_id=entry.runtime_binding_id,
    )

    assert resolved.runtime == entry.runtime
    assert resolved.principal_id == entry.principal_id
    assert resolved.agent_id == entry.agent_id
    assert resolved.runtime_binding_id == entry.runtime_binding_id
    assert resolved.actor_principal_id == "cred_control"
    assert resolved.activation_ref_digest == fixture.bundle.activation_ref_digest
    assert resolved.source == "product_activation"


def test_product_runtime_credential_is_matched_by_authenticated_tuple() -> None:
    fixture = build_test_product_activation(now=_NOW)
    resolver = RuntimeBindingResolver(
        product_activation=_frozen(fixture),
        clock=lambda: _NOW,
    )
    entry = fixture.bundle.runtime_entry("langgraph")

    resolved = resolver.resolve_task_ingress(
        _auth(),
        runtime="langgraph",
        claimed_runtime_binding_id=entry.runtime_binding_id,
    )
    assert resolved.runtime_binding_id == "binding:langgraph:main"
    assert resolved.runtime_binding_id != f"binding:{entry.principal_id}"

    mismatches = (
        (_auth(runtime="openclaw", principal_id="principal:oc"), "langgraph"),
        (_auth(principal_id="principal:other"), "langgraph"),
        (_auth(agent_id="other"), "langgraph"),
    )
    for auth_context, runtime in mismatches:
        _assert_code(
            PRODUCT_RUNTIME_IDENTITY_MISMATCH,
            lambda auth_context=auth_context, runtime=runtime: (
                resolver.resolve_task_ingress(auth_context, runtime=runtime)
            ),
        )


def test_product_claim_never_becomes_the_resolved_binding() -> None:
    fixture = build_test_product_activation(now=_NOW)
    resolver = RuntimeBindingResolver(
        product_activation=_frozen(fixture),
        clock=lambda: _NOW,
    )

    _assert_code(
        LEGACY_RUNTIME_IDENTITY_MISMATCH,
        lambda: resolver.resolve_task_ingress(
            _auth(),
            runtime="langgraph",
            claimed_runtime_binding_id="binding:caller-controlled",
        ),
    )


def test_product_rejects_non_control_identity_without_runtime() -> None:
    fixture = build_test_product_activation(now=_NOW)
    resolver = RuntimeBindingResolver(
        product_activation=_frozen(fixture),
        clock=lambda: _NOW,
    )

    _assert_code(
        PRODUCT_RUNTIME_IDENTITY_MISMATCH,
        lambda: resolver.resolve_task_ingress(
            _auth(runtime=None, agent_id=None, role="adapter"),
            runtime="langgraph",
        ),
    )


def test_product_validity_is_checked_on_every_resolution() -> None:
    fixture = build_test_product_activation(now=_NOW)
    observed = [_NOW]
    resolver = RuntimeBindingResolver(
        product_activation=_frozen(fixture),
        clock=lambda: observed[0],
    )

    assert resolver.product_active is True
    assert (
        resolver.resolve_task_ingress(_auth(), runtime="langgraph").source
        == "product_activation"
    )
    observed[0] = _NOW + timedelta(days=2)
    _assert_code(
        PRODUCT_ACTIVATION_NOT_CURRENT,
        lambda: resolver.resolve_task_ingress(_auth(), runtime="langgraph"),
    )


def test_product_nested_bundle_mutation_is_rejected_after_verification() -> None:
    fixture = build_test_product_activation(now=_NOW)
    resolver = RuntimeBindingResolver(
        product_activation=_frozen(fixture),
        clock=lambda: _NOW,
    )
    original = fixture.bundle.runtimes[0]
    fixture.bundle.runtimes[0] = original.model_copy(
        update={"runtime_binding_id": "binding:attacker-replaced"}
    )

    _assert_code(
        PRODUCT_ACTIVATION_NOT_CURRENT,
        lambda: resolver.resolve_task_ingress(_auth(), runtime="langgraph"),
    )


def test_product_evaluation_reconstructs_only_the_exact_signed_identity() -> None:
    fixture = build_test_product_activation(now=_NOW)
    resolver = RuntimeBindingResolver(
        product_activation=_frozen(fixture),
        clock=lambda: _NOW,
    )
    entry = fixture.bundle.runtime_entry("langgraph")

    resolved = resolver.resolve_evaluation(
        _auth(),
        event=_event(),
        task_principal_id="principal:lg",
    )
    assert resolved.runtime == entry.runtime
    assert resolved.principal_id == entry.principal_id
    assert resolved.agent_id == entry.agent_id
    assert resolved.runtime_binding_id == entry.runtime_binding_id
    assert resolved.actor_principal_id == "principal:lg"
    assert resolved.activation_ref_digest == fixture.bundle.activation_ref_digest
    assert resolved.source == "product_activation"


@pytest.mark.parametrize(
    ("auth_context", "event", "task_principal_id"),
    [
        (None, _event(), "principal:lg"),
        (_auth(runtime=None, agent_id=None, role="control"), _event(), "principal:lg"),
        (_auth(principal_id="principal:other"), _event(), "principal:lg"),
        (_auth(agent_id="other"), _event(), "principal:lg"),
        (_auth(), _event(runtime="openclaw"), "principal:lg"),
        (_auth(), _event(agent_id="other"), "principal:lg"),
        (_auth(), _event(), "principal:other"),
    ],
)
def test_product_evaluation_rejects_any_auth_event_or_task_drift(
    auth_context: AuthContext | None,
    event: GuardEvent,
    task_principal_id: str,
) -> None:
    fixture = build_test_product_activation(now=_NOW)
    resolver = RuntimeBindingResolver(
        product_activation=_frozen(fixture),
        clock=lambda: _NOW,
    )

    _assert_code(
        PRODUCT_RUNTIME_IDENTITY_MISMATCH,
        lambda: resolver.resolve_evaluation(
            auth_context,
            event=event,
            task_principal_id=task_principal_id,
        ),
    )


def test_product_evaluation_requires_explicit_event_agent_identity() -> None:
    fixture = build_test_product_activation(now=_NOW)
    resolver = RuntimeBindingResolver(
        product_activation=_frozen(fixture),
        clock=lambda: _NOW,
    )
    event = _event().model_copy(update={"security_context": SecurityContext()})

    _assert_code(
        PRODUCT_RUNTIME_IDENTITY_MISMATCH,
        lambda: resolver.resolve_evaluation(
            _auth(),
            event=event,
            task_principal_id="principal:lg",
        ),
    )


def test_resolver_and_result_are_immutable() -> None:
    resolver = RuntimeBindingResolver()
    resolved = resolver.resolve_task_ingress(_auth(), runtime="langgraph")

    assert resolver.product_active is False
    resolver.revalidate(resolved)
    with pytest.raises(FrozenInstanceError):
        resolver.product_activation = _frozen(  # type: ignore[misc]
            build_test_product_activation(now=_NOW)
        )
    with pytest.raises(FrozenInstanceError):
        resolved.runtime_binding_id = "binding:mutated"  # type: ignore[misc]


def test_product_revalidate_checks_window_and_exact_signed_entry() -> None:
    fixture = build_test_product_activation(now=_NOW)
    observed = [_NOW]
    resolver = RuntimeBindingResolver(
        product_activation=_frozen(fixture),
        clock=lambda: observed[0],
    )
    resolved = resolver.resolve_evaluation(
        _auth(),
        event=_event(),
        task_principal_id="principal:lg",
    )

    resolver.revalidate(resolved)
    for drifted in (
        replace(resolved, runtime_binding_id="binding:drift"),
        replace(resolved, activation_ref_digest="sha256:" + "0" * 64),
        replace(resolved, source="legacy_derived"),
    ):
        _assert_code(
            PRODUCT_RUNTIME_IDENTITY_MISMATCH,
            lambda drifted=drifted: resolver.revalidate(drifted),
        )

    observed[0] = _NOW + timedelta(days=2)
    _assert_code(
        PRODUCT_ACTIVATION_NOT_CURRENT,
        lambda: resolver.revalidate(resolved),
    )
