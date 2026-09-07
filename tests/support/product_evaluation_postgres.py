"""PostgreSQL Product Active evaluation harness for exact replay tests."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from agentguard_core import (
    GuardEvent,
    PolicyBundle,
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
)
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions import ActionConstraint

from guard_api.auth import AuthContext
from guard_api.models import (
    ADAPTER_CREDENTIAL_SCOPES,
    CredentialRecord,
    TaskCreateRequest,
)
from guard_api.security_state import SecurityStateService
from guard_api.services import ApprovalService, AuditService, EvaluationService
from guard_api.services.policy import PolicyService
from guard_api.services.product_activation import (
    ProductActivationAuthorityService,
    load_frozen_product_activation,
)
from guard_api.services.runtime_binding import RuntimeBindingResolver
from guard_api.services.task_ingress import TaskIngressService
from guard_api.services.v21_pipeline import V21PipelineService
from guard_api.settings import GuardApiSettings
from guard_api.storage.postgres import PostgresControlPlaneStore

from .postgres import get_test_database_url, reset_control_plane_schema
from .product_activation import (
    ProductActivationFixture,
    build_test_product_activation,
    product_activation_ack_for_status,
    product_runtime_status_for_activation,
    write_test_product_activation,
)
from .product_evaluation import (
    PRODUCT_REPLAY_CREDENTIAL_ID,
    PRODUCT_REPLAY_SESSION_ID,
    PRODUCT_REPLAY_TOKEN_HASH,
    product_replay_settings,
)

PRODUCT_REPLAY_TRACE_ID = "trace:product-replay-postgres"


@dataclass(frozen=True, slots=True)
class ProductPostgresEvaluationHarness:
    """One isolated, signed Product environment backed by PostgreSQL."""

    fixture: ProductActivationFixture
    settings: GuardApiSettings
    store: PostgresControlPlaneStore
    writer: PostgresControlPlaneStore
    pipeline: V21PipelineService
    audit_service: AuditService
    evaluation: EvaluationService
    task_id: str
    scope_digest: str
    auth_context: AuthContext
    activation_ack_token: str

    def evaluate(self, event: GuardEvent):
        return self.evaluation.evaluate(
            event,
            auth_context=self.auth_context,
            activation_ack_token=self.activation_ack_token,
        )

    def event(
        self,
        *,
        event_id: str = "evt:product-replay-postgres",
        call_id: str = "call:product-replay-postgres",
    ) -> GuardEvent:
        return GuardEvent(
            event_id=event_id,
            event_type="tool_call_proposed",
            runtime="langgraph",
            trace_id=PRODUCT_REPLAY_TRACE_ID,
            timestamp=datetime.now(timezone.utc).isoformat(),
            pre_execution=True,
            security_context=SecurityContext(
                agent_id="main",
                user_task="verify PostgreSQL Product exact replay",
                session_id=PRODUCT_REPLAY_SESSION_ID,
            ),
            payload=ToolCallPayload(
                tool=ToolDescriptor(
                    name="product_replay_postgres_safe_tool",
                    call_id=call_id,
                ),
                arguments={"fixture": "safe"},
                derived_resources=[],
            ),
            metadata={"task_id": self.task_id},
        )


@contextmanager
def create_product_postgres_evaluation_harness(
    tmp_path: Path,
    *,
    action_constraints: list[ActionConstraint] | None = None,
) -> Iterator[ProductPostgresEvaluationHarness]:
    """Create and tear down a PostgreSQL Product replay environment."""

    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    store = PostgresControlPlaneStore(database_url)
    writer = PostgresControlPlaneStore(database_url)
    store.initialize()

    policy = PolicyBundle()
    fixture = build_test_product_activation(
        now=datetime.now(timezone.utc),
        policy_digest=canonical_sha256(policy.model_dump(mode="json")),
    )
    activation_path = tmp_path / "product-replay-postgres-activation.json"
    write_test_product_activation(activation_path, fixture)
    settings = product_replay_settings(activation_path, fixture)
    settings.storage_backend = "postgres"
    settings.database_url = database_url

    store.save_policy_snapshot(
        policy,
        expected_revision=0,
        updated_by="product-replay-postgres-test",
    )
    activation_ack_tokens: dict[str, str] = {}
    for runtime in ("langgraph", "openclaw"):
        status = product_runtime_status_for_activation(fixture, runtime)
        ack = product_activation_ack_for_status(fixture, status)
        store.save_product_runtime_status(status, activation_ack=ack)
        activation_ack_tokens[runtime] = ack.ack_token

    entry = fixture.bundle.runtime_entry("langgraph")
    store.create_credential(
        CredentialRecord(
            credential_id=PRODUCT_REPLAY_CREDENTIAL_ID,
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
    product_authority = ProductActivationAuthorityService(
        activation=activation,
        store=store,
        server_secret=fixture.server_secret,
    )
    task = TaskIngressService(
        store=store,
        settings=settings,
        runtime_binding_resolver=resolver,
    ).create_task(
        TaskCreateRequest(
            task_text="verify PostgreSQL Product exact replay",
            runtime="langgraph",
            trace_id="trace:product-replay-postgres-task",
            session_id=PRODUCT_REPLAY_SESSION_ID,
            runtime_binding_id=entry.runtime_binding_id,
            action_constraints=action_constraints or [],
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
        product_activation_authority=product_authority,
    )
    audit_service = AuditService(store=store)
    evaluation = EvaluationService(
        policy_service=policy_service,
        audit_service=audit_service,
        approval_service=ApprovalService(store=store, settings=settings),
        v21_pipeline=pipeline,
        product_activation_authority=product_authority,
    )
    auth_context = AuthContext(
        principal_type="component",
        principal_id=entry.principal_id,
        role="adapter",
        scopes=list(ADAPTER_CREDENTIAL_SCOPES),
        auth_method="bearer",
        credential_id=PRODUCT_REPLAY_CREDENTIAL_ID,
        credential_token_hash=PRODUCT_REPLAY_TOKEN_HASH,
        runtime=entry.runtime,
        agent_id=entry.agent_id,
    )
    try:
        yield ProductPostgresEvaluationHarness(
            fixture=fixture,
            settings=settings,
            store=store,
            writer=writer,
            pipeline=pipeline,
            audit_service=audit_service,
            evaluation=evaluation,
            task_id=task.task_id,
            scope_digest=task.scope_digest,
            auth_context=auth_context,
            activation_ack_token=activation_ack_tokens["langgraph"],
        )
    finally:
        reset_control_plane_schema(database_url)


__all__ = [
    "PRODUCT_REPLAY_TRACE_ID",
    "ProductPostgresEvaluationHarness",
    "create_product_postgres_evaluation_harness",
]
