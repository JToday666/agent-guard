"""RTE-05 Freeze Gate 冻结不变量 guard 测试（防漂移）。

核对记录：`docs/AgentGuard_Runtime_Enforcement_Contract_v1_Final/08_RTE-05_Freeze_Gate_核对记录.md`。
本文件只断言"已冻结语义"本身，任何实现漂移（域分离标签、投影白名单、
human-only 投影、双花 CAS）都会在此变红：

- authorization_fingerprint 域分离标签/前缀/确定性/secret 依赖（01 §9）；
- ActionIR 冻结纪律（extra=forbid、action_id 派生规则，builder.py L512-517）；
- 投影白名单与模型声明 frozenset 一致（01 §29 白名单纪律）；
- 仅 resolution_source='human' 可投影可消费 grant（02 §12 / 04 §12）；
- GrantConsumption 双花冲突 + 同键重试幂等（02 §12 单事务 CAS）。
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from agentguard_core import (
    GuardEvent,
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
)
from agentguard_core.actions.builder import build_action_ir
from agentguard_core.actions.fingerprints import (
    AUTHORIZATION_DOMAIN_TAG,
    audit_fingerprint,
    audit_projection,
    authorization_fingerprint,
    authorization_projection,
)
from agentguard_core.actions.models import ActionIR
from agentguard_core.security_context.projection import (
    ConsumptionIntent,
    consumption_intent_digest,
)
from agentguard_core.security_context.projection.capability import (
    ApprovalGrantProjection,
    CapabilityProjectionError,
    GrantPolicyContext,
    compile_approval_to_grant,
)
from guard_api.security_state.lease_service import (
    GrantConsumptionConflictError,
    LeaseService,
    derive_lease_token_key,
)
from guard_api.storage.memory import MemoryControlPlaneStore

SERVER_SECRET = b"freeze-gate-fixture-secret"
OTHER_SECRET = b"freeze-gate-other-secret"
SCOPE_DIGEST = "sha256:" + "ab" * 32
PRINCIPAL_ID = "principal:freeze-gate"
FINGERPRINT_A = "hmac-sha256:" + "11" * 32
FINGERPRINT_B = "hmac-sha256:" + "22" * 32


def _event(*, call_id: str = "call_freeze_gate_1") -> GuardEvent:
    return GuardEvent(
        event_id="evt_freeze_gate_1",
        event_type="tool_call_proposed",
        runtime="openclaw",
        trace_id="trace_freeze_gate_1",
        timestamp="2026-08-15T00:00:00+00:00",
        security_context=SecurityContext(
            agent_id="main", user_task="freeze gate fixture"
        ),
        payload=ToolCallPayload(
            tool=ToolDescriptor(
                name="read_file",
                category="file",
                kind="file_read",
                call_id=call_id,
            ),
            arguments={"path": "/docs/public.txt"},
        ),
        metadata={},
    )


# ---------------------------------------------------------------------------
# 1.2 authorization_fingerprint 算法/版本冻结（01 §9）
# ---------------------------------------------------------------------------


def test_authorization_domain_tag_is_frozen() -> None:
    # 域分离标签承载版本号（v1）；变更即换标签，不得静默复用。
    assert AUTHORIZATION_DOMAIN_TAG == "agentguard/v21/action-ir/v1"


def test_authorization_fingerprint_prefix_determinism_and_secret_dependency() -> None:
    ir = build_action_ir(_event(), server_secret=SERVER_SECRET)
    first = authorization_fingerprint(SERVER_SECRET, ir)
    second = authorization_fingerprint(SERVER_SECRET, ir)
    assert first.startswith("hmac-sha256:")
    assert first == second, "fingerprint must be deterministic"
    assert authorization_fingerprint(OTHER_SECRET, ir) != first
    # audit_fingerprint 非 keyed、前缀不同、与 server secret 无关。
    audit = audit_fingerprint(ir)
    assert audit.startswith("sha256:")
    assert audit == audit_fingerprint(ir)


def test_projection_whitelists_match_declared_frozensets() -> None:
    ir = build_action_ir(_event(), server_secret=SERVER_SECRET)
    assert set(authorization_projection(ir).keys()) == set(
        ActionIR.authorization_fingerprint_fields()
    )
    assert set(audit_projection(ir).keys()) == set(
        ActionIR.audit_fingerprint_fields()
    )
    # 白名单字面量冻结：任何键增删都必须显式改动本断言。
    assert ActionIR.authorization_fingerprint_fields() == frozenset(
        {
            "schema_version",
            "principal_id",
            "task_id",
            "task_revision",
            "action_type",
            "resources",
            "destinations",
            "security_arguments",
            "effects",
            "runtime_binding_id",
            "scope_digest",
            "argument_digest",
        }
    )
    assert ActionIR.audit_fingerprint_fields() == frozenset(
        {
            "schema_version",
            "event_id",
            "action_id",
            "trace_id",
            "tool_name",
            "action_type",
            "impact",
            "resource_ids",
            "destination_ids",
            "argument_digest",
            "normalizer_version",
        }
    )


# ---------------------------------------------------------------------------
# 1.1 ActionIR action_id 冻结纪律（01 §9；builder.py L512-517）
# ---------------------------------------------------------------------------


def test_action_ir_rejects_unknown_fields_and_requires_action_id() -> None:
    ir = build_action_ir(_event(), server_secret=SERVER_SECRET)
    payload = ir.model_dump(mode="json")
    payload["unknown_frozen_field"] = "x"
    with pytest.raises(PydanticValidationError):
        ActionIR.model_validate(payload)
    payload.pop("unknown_frozen_field")
    payload.pop("action_id")
    with pytest.raises(PydanticValidationError):
        ActionIR.model_validate(payload)


def test_action_id_derivation_rules() -> None:
    # ToolCallPayload：action_id = payload.tool.call_id（权威调用身份）。
    ir_tool = build_action_ir(
        _event(call_id="call_derived_77"), server_secret=SERVER_SECRET
    )
    assert ir_tool.action_id == "call_derived_77"
    # 非 tool payload 回退确定性派生 act_{event_id}。
    from agentguard_core import ContextBuildPayload

    context_event = GuardEvent(
        event_id="evt_ctx_1",
        event_type="context_assembled",
        runtime="openclaw",
        trace_id="trace_freeze_gate_1",
        timestamp="2026-08-15T00:00:00+00:00",
        security_context=SecurityContext(agent_id="main", user_task="fixture"),
        payload=ContextBuildPayload(sources=[], will_enter_context=True, sanitized=False),
        metadata={},
    )
    ir_ctx = build_action_ir(context_event, server_secret=SERVER_SECRET)
    assert ir_ctx.action_id == "act_evt_ctx_1"


# ---------------------------------------------------------------------------
# 1.4 / 1.7 human-only grant 投影（02 §12 / 04 §12）
# ---------------------------------------------------------------------------


def _approval_projection(*, resolution_source: str) -> ApprovalGrantProjection:
    return ApprovalGrantProjection(
        approval_id="approval_freeze_gate_1",
        scope_digest=SCOPE_DIGEST,
        principal_id=PRINCIPAL_ID,
        action_types=["tool.read_file"],
        resource_constraints=[],
        destination_constraints=[],
        argument_constraints=[],
        resolution_source=resolution_source,
        authorization_fingerprint=FINGERPRINT_A,
        policy_revision="rev-1",
    )


def _policy_context() -> GrantPolicyContext:
    return GrantPolicyContext(
        policy_revision="rev-1",
        scope_digest=SCOPE_DIGEST,
        principal_id=PRINCIPAL_ID,
    )


def test_llm_resolution_source_cannot_project_consumable_grant() -> None:
    with pytest.raises(CapabilityProjectionError) as excinfo:
        compile_approval_to_grant(
            _approval_projection(resolution_source="llm"), _policy_context()
        )
    assert excinfo.value.reason_code == "v21-06:llm_reviewer_grant_forbidden"


def test_human_allow_once_projects_single_use_exact_binding_grant() -> None:
    grant = compile_approval_to_grant(
        _approval_projection(resolution_source="human"), _policy_context()
    )
    assert grant.source_type == "human_approval"
    assert grant.usage_limit == 1
    assert grant.remaining_uses == 1
    assert grant.delegable is False
    assert grant.exact_authorization_fingerprint == FINGERPRINT_A
    assert grant.grant_id.startswith("grant:")


def test_human_projection_without_fingerprint_is_rejected() -> None:
    approval = _approval_projection(resolution_source="human")
    approval = approval.model_copy(update={"authorization_fingerprint": ""})
    with pytest.raises(CapabilityProjectionError) as excinfo:
        compile_approval_to_grant(approval, _policy_context())
    assert (
        excinfo.value.reason_code
        == "v21-06:missing_authorization_fingerprint"
    )


# ---------------------------------------------------------------------------
# 1.5 GrantConsumption CAS（02 §12 单事务原子消费）
# ---------------------------------------------------------------------------


def _lease_service() -> LeaseService:
    return LeaseService(
        store=MemoryControlPlaneStore(),
        lease_token_key=derive_lease_token_key("freeze-gate-control-token"),
    )


def _intent(*, action_id: str, fingerprint: str) -> ConsumptionIntent:
    grant_id = "grant:freeze_gate_fixture"
    return ConsumptionIntent(
        grant_id=grant_id,
        scope_digest=SCOPE_DIGEST,
        action_id=action_id,
        authorization_fingerprint=fingerprint,
        approval_id="approval:freeze_gate_1",
        runtime_binding_id="binding:freeze_gate",
        intent_digest=consumption_intent_digest(
            grant_id=grant_id,
            action_id=action_id,
            authorization_fingerprint=fingerprint,
        ),
    )


def test_double_spend_with_different_fingerprint_conflicts_and_replay_is_idempotent() -> None:
    service = _lease_service()
    service.store.seed_capability_grant_runtime(
        grant_id="grant:freeze_gate_fixture",
        scope_digest=SCOPE_DIGEST,
        remaining_uses=1,
        expires_at=None,
        authorization_fingerprint=FINGERPRINT_A,
        status="active",
    )

    first = service.consume_grant_atomic(_intent(action_id="action_1", fingerprint=FINGERPRINT_A))
    assert first.replayed is False

    # 同 (grant_id, action_id) + 异 fingerprint → 双花冲突（CAS 拒绝）。
    with pytest.raises(GrantConsumptionConflictError) as excinfo:
        service.consume_grant_atomic(
            _intent(action_id="action_1", fingerprint=FINGERPRINT_B)
        )
    assert excinfo.value.reason_code == "v21-06:consumption_conflict"

    # 同三元身份重试 → 幂等返回同一 lease（不重复扣减）。
    retry = service.consume_grant_atomic(
        _intent(action_id="action_1", fingerprint=FINGERPRINT_A)
    )
    assert retry.replayed is True
    assert retry.lease.lease_id == first.lease.lease_id
    assert retry.lease_token == first.lease_token
