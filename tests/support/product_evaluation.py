"""Internal Product Active evaluation harness shared by replay acceptance tests."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from agentguard_core import (
    GuardEvent,
    PolicyBundle,
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
)
from agentguard_core.actions import ActionConstraint
from agentguard_core.actions.canonical_json import canonical_sha256

from guard_api.auth import AuthContext
from guard_api.models import (
    ADAPTER_CREDENTIAL_SCOPES,
    CredentialRecord,
    TaskCreateRequest,
)
from guard_api.security_state import SecurityStateService
from guard_api.services import ApprovalService, AuditService, EvaluationService
from guard_api.services.policy import PolicyService
from guard_api.services.product_activation import load_frozen_product_activation
from guard_api.services.runtime_binding import RuntimeBindingResolver
from guard_api.services.task_ingress import TaskIngressService
from guard_api.services.v21_pipeline import V21PipelineService
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore

from .product_activation import (
    TEST_PRODUCT_ACTIVATION_SECRET_B64,
    ProductActivationFixture,
    build_test_product_activation,
    product_runtime_status_for_activation,
    write_test_product_activation,
)

PRODUCT_REPLAY_SESSION_ID = "session:product-replay"
PRODUCT_REPLAY_CREDENTIAL_ID = "cred_product_replay_langgraph"
PRODUCT_REPLAY_RAW_TOKEN = "product-replay-adapter-secret"
PRODUCT_REPLAY_TOKEN_HASH = hashlib.sha256(
    PRODUCT_REPLAY_RAW_TOKEN.encode("utf-8")
).hexdigest()

_TASK_SCOPE_KEY_ID = "product-replay-task-key"
_TASK_SCOPE_KEY_B64 = base64.urlsafe_b64encode(
    b"product-replay-task-scope-secret-material-01"
).decode("ascii")
_SHADOW_SECRET_B64 = base64.urlsafe_b64encode(
    b"product-replay-independent-shadow-secret-01"
).decode("ascii")

ProductReplayRuntime = Literal["langgraph", "openclaw"]


@dataclass(frozen=True, slots=True)
class ProductEvaluationHarness:
    fixture: ProductActivationFixture
    settings: GuardApiSettings
    store: MemoryControlPlaneStore
    pipeline: V21PipelineService
    audit_service: AuditService
    evaluation: EvaluationService
    task_id: str
    scope_digest: str
    auth_context: AuthContext
    runtime: ProductReplayRuntime

    def event(
        self,
        *,
        event_id: str = "evt:product-replay",
        call_id: str = "call:product-replay",
    ) -> GuardEvent:
        return GuardEvent(
            event_id=event_id,
            event_type="tool_call_proposed",
            runtime=self.runtime,
            trace_id="trace:product-replay",
            timestamp=datetime.now(timezone.utc).isoformat(),
            pre_execution=True,
            security_context=SecurityContext(
                agent_id="main",
                user_task="verify authority-aware exact Product replay",
                session_id=PRODUCT_REPLAY_SESSION_ID,
            ),
            payload=ToolCallPayload(
                tool=ToolDescriptor(
                    name="product_replay_safe_tool",
                    call_id=call_id,
                ),
                arguments={"fixture": "safe"},
                derived_resources=[],
            ),
            metadata={"task_id": self.task_id},
        )


def product_replay_settings(
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


def create_product_evaluation_harness(
    tmp_path: Path,
    *,
    runtime: ProductReplayRuntime = "langgraph",
) -> ProductEvaluationHarness:
    """Create one fully signed in-memory Product authority environment."""

    policy = PolicyBundle()
    fixture = build_test_product_activation(
        now=datetime.now(timezone.utc),
        policy_digest=canonical_sha256(policy.model_dump(mode="json")),
    )
    activation_path = tmp_path / f"product-replay-activation-{runtime}.json"
    write_test_product_activation(activation_path, fixture)
    settings = product_replay_settings(activation_path, fixture)
    store = MemoryControlPlaneStore()
    store.save_policy_snapshot(policy, expected_revision=0, updated_by="replay-test")
    for observed_runtime in ("langgraph", "openclaw"):
        store.save_product_runtime_status(
            product_runtime_status_for_activation(fixture, observed_runtime)
        )

    entry = fixture.bundle.runtime_entry(runtime)
    credential_id = (
        PRODUCT_REPLAY_CREDENTIAL_ID
        if runtime == "langgraph"
        else "cred_product_replay_openclaw"
    )
    store.create_credential(
        CredentialRecord(
            credential_id=credential_id,
            token_hash=PRODUCT_REPLAY_TOKEN_HASH,
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
    task = TaskIngressService(
        store=store,
        settings=settings,
        runtime_binding_resolver=resolver,
    ).create_task(
        TaskCreateRequest(
            task_text="verify authority-aware exact Product replay",
            runtime=entry.runtime,
            trace_id="trace:product-replay-task",
            session_id=PRODUCT_REPLAY_SESSION_ID,
            runtime_binding_id=entry.runtime_binding_id,
            action_constraints=[ActionConstraint(action_types=["tool_call"])],
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
    SecurityStateService(store).ensure_ready(task.scope_digest)
    policy_service = PolicyService(store=store)
    pipeline = V21PipelineService(
        settings=settings,
        store=store,
        state_service=SecurityStateService(store),
        policy_service=policy_service,
        runtime_binding_resolver=resolver,
    )
    audit_service = AuditService(store=store)
    evaluation = EvaluationService(
        policy_service=policy_service,
        audit_service=audit_service,
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
        credential_token_hash=PRODUCT_REPLAY_TOKEN_HASH,
        runtime=entry.runtime,
        agent_id=entry.agent_id,
    )
    return ProductEvaluationHarness(
        fixture=fixture,
        settings=settings,
        store=store,
        pipeline=pipeline,
        audit_service=audit_service,
        evaluation=evaluation,
        task_id=task.task_id,
        scope_digest=task.scope_digest,
        auth_context=auth_context,
        runtime=runtime,
    )


__all__ = [
    "PRODUCT_REPLAY_CREDENTIAL_ID",
    "PRODUCT_REPLAY_RAW_TOKEN",
    "PRODUCT_REPLAY_SESSION_ID",
    "PRODUCT_REPLAY_TOKEN_HASH",
    "ProductEvaluationHarness",
    "ProductReplayRuntime",
    "create_product_evaluation_harness",
    "product_replay_settings",
]
