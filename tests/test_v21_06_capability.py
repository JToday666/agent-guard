"""V21-06 Authority/Capability core 纯函数验收测试（04 §12 可离线部分）。

覆盖九项验收的可离线判定：

1. forged issuer（task producer/authority 伪造 → fail-closed）；
2. scope mismatch（grant 源 scope 与认证 policy context 不一致）；
3. expired（grant 过期 → verdict 不匹配）；
4. revoked（grant 撤销 → verdict 不匹配 + intent 拒绝）；
5. allow_once double-spend（remaining_uses 耗尽 → verdict 拒绝路径）；
6. fingerprint mismatch（human_approval grant 指纹不一致 → 拒绝）；
7. destination mismatch（destination 约束未命中 → 显式 scope mismatch）；
8. LLM reviewer 禁发 V2 grant（resolution_source != "human" 一律拒绝）；
9. receipt 不泄露 token（存储层契约测试覆盖；本文件覆盖 core 侧
   ConsumptionIntent digest 只含三元身份、不含敏感正文）。

外加：grant handler 三纯函数单测、TaskFact→Grant / Approval→Grant
确定性（同输入同输出、grant_id 禁 uuid）。
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentguard_core.actions.models import (
    CANONICALIZATION_VERSION,
    NORMALIZER_VERSION,
    ActionConstraint,
    ActionEffect,
    ActionIR,
    ArgumentConstraint,
    CanonicalArgument,
    CanonicalArguments,
    DestinationConstraint,
    FileResource,
    ResourceConstraint,
    UrlResource,
)
from agentguard_core.authority.models import TaskFact
from agentguard_core.security_context import (
    CapabilityGrant,
    GrantConsumption,
    OnlineSecurityState,
    StateWatermarks,
)
from agentguard_core.security_context.projection import (
    ApprovalGrantProjection,
    AuthorityProjectionError,
    CapabilityProjectionError,
    GrantPolicyContext,
    apply_grant_consumptions,
    apply_grant_revocations,
    apply_grant_upserts,
    build_consumption_intent,
    compile_approval_to_grant,
    compile_task_to_grants,
    compute_authority_verdict,
    consumption_intent_digest,
)

from tests.test_v21_security_state_models import make_grant

SCOPE = "hmac-sha256:v21_06_scope"
OTHER_SCOPE = "hmac-sha256:v21_06_other_scope"
PRINCIPAL = "principal_a"
FINGERPRINT = "hmac-sha256:approval_fingerprint"
OTHER_FINGERPRINT = "hmac-sha256:forged_fingerprint"


def make_policy_context(
    *,
    scope_digest: str = SCOPE,
    principal_id: str = PRINCIPAL,
    expires_at: str | None = None,
) -> GrantPolicyContext:
    return GrantPolicyContext(
        policy_revision="rev_7",
        scope_digest=scope_digest,
        principal_id=principal_id,
        expires_at=expires_at,
    )


def make_task_fact(
    *,
    status: str = "active",
    scope_digest: str = SCOPE,
    principal_id: str = PRINCIPAL,
    action_types: list[str] | None = None,
    resource_constraints: list[ResourceConstraint] | None = None,
    destination_constraints: list[DestinationConstraint] | None = None,
) -> TaskFact:
    return TaskFact(
        task_id="task_1",
        scope_digest=scope_digest,
        scope_key_id="key_1",
        principal_id=principal_id,
        task_summary="整理本周会议纪要",
        task_digest="sha256:task_content_digest",
        revision=3,
        status=status,  # pyright: ignore[reportArgumentType]
        action_constraints=[
            ActionConstraint(op="in", action_types=action_types or ["file.read"])
        ],
        resource_constraints=resource_constraints or [],
        destination_constraints=destination_constraints or [],
        created_sequence=None,
        producer="guard_api_task_ingress",
        evidence_refs=[],
    )


def make_approval_projection(
    *,
    resolution_source: str = "human",
    authorization_fingerprint: str = FINGERPRINT,
    scope_digest: str = SCOPE,
    principal_id: str = PRINCIPAL,
    action_types: list[str] | None = None,
    resource_constraints: list[ResourceConstraint] | None = None,
    destination_constraints: list[DestinationConstraint] | None = None,
    expires_at: str | None = None,
) -> ApprovalGrantProjection:
    return ApprovalGrantProjection(
        approval_id="approval_1",
        scope_digest=scope_digest,
        principal_id=principal_id,
        subject_agent_id="agent_a",
        task_id="task_1",
        action_types=action_types if action_types is not None else ["file.write"],
        resource_constraints=resource_constraints or [],
        destination_constraints=destination_constraints or [],
        argument_constraints=[],
        resolution_source=resolution_source,
        authorization_fingerprint=authorization_fingerprint,
        resolved_sequence=None,
        expires_at=expires_at,
        policy_revision="rev_7",
    )


def make_file_resource(
    *, canonical_id: str = "file:///work/a.txt"
) -> FileResource:
    return FileResource(
        resource_id="res_1",
        canonical_id=canonical_id,
        display_summary="a.txt",
        resolution_status="resolved",
        normalizer_version=NORMALIZER_VERSION,
        normalized_path="/work/a.txt",
        platform="posix",
        case_sensitive=True,
        symlink_resolution="not_applicable",
        final_path="/work/a.txt",
    )


def make_url_resource(*, host: str = "example.com") -> UrlResource:
    return UrlResource(
        resource_id="dest_1",
        canonical_id=f"https://{host}/",
        display_summary=host,
        resolution_status="resolved",
        normalizer_version=NORMALIZER_VERSION,
        scheme="https",
        host_ascii=host,
        port=443,
        normalized_path="/",
        query_keys=[],
        security_query_arguments=[],
        redirect_policy="forbid",
    )


def make_action_ir(
    *,
    action_type: str = "file.write",
    authorization_fingerprint: str = FINGERPRINT,
    scope_digest: str = SCOPE,
    action_id: str = "action_1",
    resources: list | None = None,
    destinations: list | None = None,
) -> ActionIR:
    digest = "sha256:" + "00" * 32
    return ActionIR(
        event_id="event_1",
        action_id=action_id,
        trace_id="trace_1",
        task_id="task_1",
        task_revision=3,
        scope_digest=scope_digest,
        principal_id=PRINCIPAL,
        runtime="openclaw",
        runtime_binding_id="binding_a",
        agent_id="agent_a",
        branch_id=None,
        parent_event_ids=[],
        runtime_sequence=None,
        tool_name=None,
        action_type=action_type,
        effects=ActionEffect(),
        impact="low",
        resources=resources if resources is not None else [],
        destinations=destinations if destinations is not None else [],
        data_refs=[],
        canonical_arguments=CanonicalArguments(
            items=[],
            canonicalization_version=CANONICALIZATION_VERSION,
            argument_digest=digest,
        ),
        argument_digest=digest,
        authorization_fingerprint=authorization_fingerprint,
        audit_fingerprint=digest,
        normalizer_version=NORMALIZER_VERSION,
    )


def state_with_grants(grants: list[CapabilityGrant]) -> OnlineSecurityState:
    state = OnlineSecurityState(
        watermarks=StateWatermarks(
            committed_sequence=None,
            projected_sequence=None,
            runtime_receipt_sequence=None,
            memory_sequence=None,
            gaps=[],
        )
    )
    return apply_grant_upserts(state, grants)


# ---------------------------------------------------------------------------
# 验收 1：forged issuer（TaskFact producer/authority 伪造）
# ---------------------------------------------------------------------------


def test_compile_task_rejects_forged_producer() -> None:
    task = make_task_fact()
    # Literal 校验绕过构造伪造 producer（模拟越权注入的载荷）。
    forged = task.model_construct(**{**task.model_dump(), "producer": "adapter"})
    with pytest.raises(CapabilityProjectionError) as excinfo:
        compile_task_to_grants(forged, make_policy_context())
    assert excinfo.value.reason_code == "v21-06:forged_issuer"


def test_compile_task_rejects_forged_authority() -> None:
    task = make_task_fact()
    forged = task.model_construct(
        **{**task.model_dump(), "authority": "candidate"}
    )
    with pytest.raises(CapabilityProjectionError) as excinfo:
        compile_task_to_grants(forged, make_policy_context())
    assert excinfo.value.reason_code == "v21-06:forged_issuer"


# ---------------------------------------------------------------------------
# 验收 2：scope mismatch（编译期绑定校验）
# ---------------------------------------------------------------------------


def test_compile_task_rejects_scope_mismatch() -> None:
    task = make_task_fact(scope_digest=OTHER_SCOPE)
    with pytest.raises(CapabilityProjectionError) as excinfo:
        compile_task_to_grants(task, make_policy_context())
    assert excinfo.value.reason_code == "v21-06:scope_mismatch"


def test_compile_task_rejects_principal_mismatch() -> None:
    task = make_task_fact(principal_id="principal_evil")
    with pytest.raises(CapabilityProjectionError) as excinfo:
        compile_task_to_grants(task, make_policy_context())
    assert excinfo.value.reason_code == "v21-06:principal_mismatch"


def test_compile_approval_rejects_scope_mismatch() -> None:
    approval = make_approval_projection(scope_digest=OTHER_SCOPE)
    with pytest.raises(CapabilityProjectionError) as excinfo:
        compile_approval_to_grant(approval, make_policy_context())
    assert excinfo.value.reason_code == "v21-06:scope_mismatch"


# ---------------------------------------------------------------------------
# TaskFact → Grant：确定性 / 最小权限 / 状态门控
# ---------------------------------------------------------------------------


def test_compile_task_is_deterministic_and_uuid_free() -> None:
    first = compile_task_to_grants(make_task_fact(), make_policy_context())
    second = compile_task_to_grants(make_task_fact(), make_policy_context())
    assert first == second
    assert len(first) == 1
    grant = first[0]
    # grant_id / grant_digest 确定性派生（禁 uuid）：前缀 + sha256 hex。
    assert grant.grant_id.startswith("grant:")
    assert len(grant.grant_id.removeprefix("grant:")) == 64
    assert grant.grant_digest.startswith("sha256:")
    assert grant.source_type == "task_compiler"
    assert grant.revoked is False
    assert grant.delegable is False


def test_compile_task_multiple_constraints_yield_per_constraint_grants() -> None:
    task = make_task_fact(action_types=["file.read", "notes.write"])
    grants = compile_task_to_grants(task, make_policy_context())
    assert [grant.action_types for grant in grants] == [
        ["file.read", "notes.write"]
    ]
    # 动作类型去重排序后进入确定性身份。
    task_dup = make_task_fact(action_types=["notes.write", "file.read", "file.read"])
    assert compile_task_to_grants(task_dup, make_policy_context()) == grants


def test_compile_task_cancelled_yields_no_grants() -> None:
    for status in ("cancelled", "superseded"):
        assert (
            compile_task_to_grants(
                make_task_fact(status=status), make_policy_context()
            )
            == []
        )


def test_compile_task_rejects_empty_action_constraint() -> None:
    task = make_task_fact()
    forged = task.model_copy(
        update={"action_constraints": [ActionConstraint(op="in", action_types=[])]}
    )
    with pytest.raises(CapabilityProjectionError) as excinfo:
        compile_task_to_grants(forged, make_policy_context())
    assert excinfo.value.reason_code == "v21-06:unsupported_action_constraint"


def test_compile_task_grant_digest_excludes_itself() -> None:
    grant = compile_task_to_grants(make_task_fact(), make_policy_context())[0]
    # grant_digest 白名单投影不包含 grant_digest 自身（否则循环依赖）。
    from agentguard_core.security_context.projection.capability import (
        grant_digest_projection,
    )

    assert "grant_digest" not in grant_digest_projection(grant)


# ---------------------------------------------------------------------------
# 验收 8：LLM reviewer 禁发 V2 grant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source", ["llm", "llm_reviewer", "system", "auto"])
def test_compile_approval_rejects_non_human_source(source: str) -> None:
    approval = make_approval_projection(resolution_source=source)
    with pytest.raises(CapabilityProjectionError) as excinfo:
        compile_approval_to_grant(approval, make_policy_context())
    assert excinfo.value.reason_code == "v21-06:llm_reviewer_grant_forbidden"


def test_compile_approval_human_projects_allow_once_grant() -> None:
    grant = compile_approval_to_grant(
        make_approval_projection(), make_policy_context()
    )
    assert grant.source_type == "human_approval"
    assert grant.source_ref == "approval:approval_1"
    assert grant.usage_limit == 1
    assert grant.remaining_uses == 1
    assert grant.delegable is False
    assert grant.exact_authorization_fingerprint == FINGERPRINT
    assert grant.grant_id.startswith("grant:")
    # 确定性：同输入同输出。
    again = compile_approval_to_grant(
        make_approval_projection(), make_policy_context()
    )
    assert again == grant


def test_compile_approval_requires_fingerprint_and_actions() -> None:
    with pytest.raises(CapabilityProjectionError):
        compile_approval_to_grant(
            make_approval_projection(action_types=[]), make_policy_context()
        )
    no_fingerprint = make_approval_projection().model_copy(
        update={
            "authorization_fingerprint": "",
            "resolution_source": "human",
        }
    )
    with pytest.raises(CapabilityProjectionError) as excinfo:
        compile_approval_to_grant(no_fingerprint, make_policy_context())
    assert (
        excinfo.value.reason_code
        == "v21-06:missing_authorization_fingerprint"
    )


def test_compile_approval_single_use_contract_is_enforced() -> None:
    grant = compile_approval_to_grant(
        make_approval_projection(), make_policy_context()
    )
    # 冻结契约（facts.CapabilityGrant._enforce_approval_single_use）：
    # human_approval grant 不允许 usage_limit != 1 的变体（经校验路径）。
    forged_payload = {
        **grant.model_dump(mode="json"),
        "usage_limit": 2,
        "remaining_uses": 2,
    }
    with pytest.raises(ValidationError):
        CapabilityGrant.model_validate(forged_payload)


# ---------------------------------------------------------------------------
# grant handler 纯函数单测
# ---------------------------------------------------------------------------


def _approval_grant() -> CapabilityGrant:
    return compile_approval_to_grant(
        make_approval_projection(), make_policy_context()
    )


def test_apply_grant_upserts_dedups_by_grant_id_and_appends() -> None:
    grant = _approval_grant()
    state = OnlineSecurityState(
        watermarks=StateWatermarks(
            committed_sequence=None,
            projected_sequence=None,
            runtime_receipt_sequence=None,
            memory_sequence=None,
            gaps=[],
        )
    )
    once = apply_grant_upserts(state, [grant])
    twice = apply_grant_upserts(once, [grant])  # 幂等
    assert len(twice.active_grants) == 1
    # 纯函数：输入不被修改。
    assert state.active_grants == []
    # 同 id 后来者整体替换（upsert 语义），支持 dict 输入。
    updated = grant.model_copy(update={"revoked": True})
    replaced = apply_grant_upserts(twice, [updated.model_dump(mode="json")])
    assert len(replaced.active_grants) == 1
    assert replaced.active_grants[0].revoked is True


def test_apply_grant_revocations_marks_and_appends_ids() -> None:
    grant = _approval_grant()
    state = apply_grant_upserts(
        OnlineSecurityState(
            watermarks=StateWatermarks(
                committed_sequence=None,
                projected_sequence=None,
                runtime_receipt_sequence=None,
                memory_sequence=None,
                gaps=[],
            )
        ),
        [grant],
    )
    revoked = apply_grant_revocations(state, [grant.grant_id, grant.grant_id])
    assert revoked.revoked_grant_ids == [grant.grant_id]  # 去重追加
    assert revoked.active_grants[0].revoked is True
    # 纯函数：原状态不被修改。
    assert state.revoked_grant_ids == []
    assert state.active_grants[0].revoked is False


def test_apply_grant_consumptions_idempotent_and_conflict_closed() -> None:
    consumption = GrantConsumption(
        consumption_id="consumption:fixture",
        grant_id="grant:fixture",
        action_id="action_1",
        authorization_fingerprint=FINGERPRINT,
        sequence=None,
        evidence_refs=[],
    )
    state = OnlineSecurityState(
        watermarks=StateWatermarks(
            committed_sequence=None,
            projected_sequence=None,
            runtime_receipt_sequence=None,
            memory_sequence=None,
            gaps=[],
        )
    )
    once = apply_grant_consumptions(state, [consumption])
    twice = apply_grant_consumptions(once, [consumption])  # 幂等跳过
    assert len(twice.grant_consumptions) == 1
    forged = consumption.model_copy(update={"action_id": "action_evil"})
    with pytest.raises(CapabilityProjectionError) as excinfo:
        apply_grant_consumptions(twice, [forged])
    assert excinfo.value.reason_code == "v21-06:consumption_identity_conflict"


# ---------------------------------------------------------------------------
# compute_authority_verdict：验收 3/4/5/6/7
# ---------------------------------------------------------------------------


def test_verdict_authorized_with_matching_human_grant() -> None:
    grant = _approval_grant()
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state, make_action_ir(), evaluated_at="2026-08-15T00:00:00Z"
    )
    assert verdict.status == "authorized"
    assert verdict.matched_grant_ids == [grant.grant_id]


def test_verdict_expired_grant_rejected() -> None:
    approval = make_approval_projection(expires_at="2026-08-01T00:00:00Z")
    grant = compile_approval_to_grant(approval, make_policy_context())
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state, make_action_ir(), evaluated_at="2026-08-15T00:00:00Z"
    )
    assert verdict.status == "unauthorized"
    assert f"{grant.grant_id}:expired" in verdict.explicit_scope_mismatches


def test_verdict_expiry_unverifiable_without_evaluated_at() -> None:
    approval = make_approval_projection(expires_at="2026-08-01T00:00:00Z")
    grant = compile_approval_to_grant(approval, make_policy_context())
    state = state_with_grants([grant])
    # 有 expires_at 而无 evaluated_at：无法证明有效 → fail-closed。
    verdict = compute_authority_verdict(state, make_action_ir())
    assert verdict.status == "unauthorized"
    assert (
        f"{grant.grant_id}:expiry_unverifiable"
        in verdict.explicit_scope_mismatches
    )


def test_verdict_invalid_evaluated_at_fails_closed() -> None:
    state = state_with_grants([_approval_grant()])
    with pytest.raises(AuthorityProjectionError) as excinfo:
        compute_authority_verdict(
            state, make_action_ir(), evaluated_at="not-a-timestamp"
        )
    assert excinfo.value.reason_code == "v21-06:invalid_evaluated_at"


def test_verdict_revoked_grant_rejected_via_flag_and_id_list() -> None:
    grant = _approval_grant()
    state = apply_grant_revocations(state_with_grants([grant]), [grant.grant_id])
    verdict = compute_authority_verdict(
        state, make_action_ir(), evaluated_at="2026-08-15T00:00:00Z"
    )
    assert verdict.status == "unauthorized"
    assert f"{grant.grant_id}:revoked" in verdict.explicit_scope_mismatches


def test_verdict_uses_exhausted_rejected() -> None:
    grant = _approval_grant().model_copy(update={"remaining_uses": 0})
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state, make_action_ir(), evaluated_at="2026-08-15T00:00:00Z"
    )
    assert verdict.status == "unauthorized"
    assert (
        f"{grant.grant_id}:uses_exhausted" in verdict.explicit_scope_mismatches
    )


def test_verdict_fingerprint_mismatch_rejected() -> None:
    grant = _approval_grant()
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state,
        make_action_ir(authorization_fingerprint=OTHER_FINGERPRINT),
        evaluated_at="2026-08-15T00:00:00Z",
    )
    assert verdict.status == "unauthorized"
    assert (
        f"{grant.grant_id}:fingerprint_mismatch"
        in verdict.explicit_scope_mismatches
    )


def test_verdict_resource_scope_mismatch_explicit() -> None:
    approval = make_approval_projection(
        resource_constraints=[
            ResourceConstraint(
                scheme="file", op="exact", values=["file:///work/b.txt"]
            )
        ]
    )
    grant = compile_approval_to_grant(approval, make_policy_context())
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state,
        make_action_ir(resources=[make_file_resource()]),
        evaluated_at="2026-08-15T00:00:00Z",
    )
    assert verdict.status == "unauthorized"
    assert (
        f"{grant.grant_id}:resource_scope_mismatch"
        in verdict.explicit_scope_mismatches
    )


def test_verdict_destination_scope_mismatch_explicit() -> None:
    approval = make_approval_projection(
        destination_constraints=[
            DestinationConstraint(
                scheme="url", op="domain", values=["trusted.example.org"]
            )
        ]
    )
    grant = compile_approval_to_grant(approval, make_policy_context())
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state,
        make_action_ir(destinations=[make_url_resource(host="evil.example.com")]),
        evaluated_at="2026-08-15T00:00:00Z",
    )
    assert verdict.status == "unauthorized"
    assert (
        f"{grant.grant_id}:destination_scope_mismatch"
        in verdict.explicit_scope_mismatches
    )


def test_verdict_destination_domain_constraint_covers_subdomains() -> None:
    approval = make_approval_projection(
        destination_constraints=[
            DestinationConstraint(
                scheme="url", op="domain", values=["example.com"]
            )
        ]
    )
    grant = compile_approval_to_grant(approval, make_policy_context())
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state,
        make_action_ir(destinations=[make_url_resource(host="api.example.com")]),
        evaluated_at="2026-08-15T00:00:00Z",
    )
    assert verdict.status == "authorized"


def test_verdict_action_type_not_covered_unauthorized() -> None:
    grant = _approval_grant()
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state,
        make_action_ir(action_type="shell.exec"),
        evaluated_at="2026-08-15T00:00:00Z",
    )
    assert verdict.status == "unauthorized"
    assert verdict.missing_capabilities == ["shell.exec"]


def test_verdict_no_grants_unauthorized() -> None:
    state = state_with_grants([])
    verdict = compute_authority_verdict(
        state, make_action_ir(), evaluated_at="2026-08-15T00:00:00Z"
    )
    assert verdict.status == "unauthorized"
    assert verdict.missing_capabilities == ["file.write"]


# ---------------------------------------------------------------------------
# Codex P1-1：verdict 路径 scope_digest 比对（跨 scope state fail-closed）
# ---------------------------------------------------------------------------


def test_verdict_cross_scope_grant_rejected() -> None:
    # 调用方选错/缓存错 state：其他 scope 的 grant 不得用于本动作。
    grant = _approval_grant().model_copy(
        update={"scope_digest": OTHER_SCOPE}
    )
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state, make_action_ir(), evaluated_at="2026-08-15T00:00:00Z"
    )
    assert verdict.status == "unauthorized"
    assert (
        f"{grant.grant_id}:verdict_scope_mismatch"
        in verdict.explicit_scope_mismatches
    )


def test_verdict_cross_scope_state_denied_even_with_matching_constraints() -> None:
    # 跨 scope grant 即便 action/resource/destination 全部命中也必须拒绝；
    # 同 state 中同 scope grant 不受影响（逐 grant 过滤，非全局降级）。
    foreign = _approval_grant().model_copy(
        update={"grant_id": "grant_foreign", "scope_digest": OTHER_SCOPE}
    )
    local = _approval_grant()
    state = state_with_grants([foreign, local])
    verdict = compute_authority_verdict(
        state, make_action_ir(), evaluated_at="2026-08-15T00:00:00Z"
    )
    assert verdict.status == "authorized"
    assert verdict.matched_grant_ids == [local.grant_id]
    assert (
        "grant_foreign:verdict_scope_mismatch"
        in verdict.explicit_scope_mismatches
    )


def test_verdict_same_scope_path_no_regression() -> None:
    grant = _approval_grant()
    assert grant.scope_digest == SCOPE
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state,
        make_action_ir(scope_digest=SCOPE),
        evaluated_at="2026-08-15T00:00:00Z",
    )
    assert verdict.status == "authorized"
    assert verdict.matched_grant_ids == [grant.grant_id]


# ---------------------------------------------------------------------------
# Codex P1-2：verdict 路径 argument_constraints 校验（fail-closed）
# ---------------------------------------------------------------------------


def _policy_grant_with_argument_constraint() -> CapabilityGrant:
    # 无精确 fingerprint 的 system_policy grant（非 human_approval 分支），
    # 携带受限参数约束：/mode 必须等于 "safe"。
    return make_grant(
        scope_digest=SCOPE,
        source_type="system_policy",
        exact_authorization_fingerprint=None,
        action_types=["file.write"],
        expires_at=None,
        argument_constraints=[
            ArgumentConstraint(json_pointer="/mode", op="eq", value="safe")
        ],
    )


def _action_ir_with_argument(value: str) -> ActionIR:
    action = make_action_ir(action_type="file.write")
    return action.model_copy(
        update={
            "canonical_arguments": CanonicalArguments(
                items=[
                    CanonicalArgument(
                        json_pointer="/mode",
                        value=value,
                        security_relevant=True,
                    )
                ],
                canonicalization_version=CANONICALIZATION_VERSION,
                argument_digest=action.argument_digest,
            )
        }
    )


def test_verdict_argument_constraint_violation_rejected() -> None:
    grant = _policy_grant_with_argument_constraint()
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state,
        _action_ir_with_argument("unsafe"),
        evaluated_at="2026-08-15T00:00:00Z",
    )
    assert verdict.status == "unauthorized"
    assert (
        f"{grant.grant_id}:argument_scope_mismatch"
        in verdict.explicit_scope_mismatches
    )


def test_verdict_argument_constraint_satisfied_authorized() -> None:
    grant = _policy_grant_with_argument_constraint()
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state,
        _action_ir_with_argument("safe"),
        evaluated_at="2026-08-15T00:00:00Z",
    )
    assert verdict.status == "authorized"
    assert verdict.matched_grant_ids == [grant.grant_id]


def test_verdict_argument_constraint_unprovable_fails_closed() -> None:
    # 动作未携带对应 security_relevant 规范参数 → 无法证明满足约束 →
    # fail-closed 不匹配（不得因参数缺失而放行）。
    grant = _policy_grant_with_argument_constraint()
    state = state_with_grants([grant])
    verdict = compute_authority_verdict(
        state, make_action_ir(action_type="file.write"),
        evaluated_at="2026-08-15T00:00:00Z",
    )
    assert verdict.status == "unauthorized"
    assert (
        f"{grant.grant_id}:argument_scope_mismatch"
        in verdict.explicit_scope_mismatches
    )


# ---------------------------------------------------------------------------
# build_consumption_intent：确定性 digest + fail-closed 前置校验
# ---------------------------------------------------------------------------


def test_consumption_intent_digest_is_three_tuple_identity() -> None:
    grant = _approval_grant()
    intent = build_consumption_intent(grant, make_action_ir())
    assert intent.intent_digest == consumption_intent_digest(
        grant_id=grant.grant_id,
        action_id="action_1",
        authorization_fingerprint=FINGERPRINT,
    )
    assert intent.approval_id == "approval:approval_1"
    assert intent.runtime_binding_id == "binding_a"
    assert intent.scope_digest == SCOPE
    # 同输入同输出（确定性，禁随机 id）。
    again = build_consumption_intent(grant, make_action_ir())
    assert again == intent


def test_consumption_intent_rejects_non_human_grant() -> None:
    grant = _approval_grant().model_copy(update={"source_type": "task_compiler"})
    with pytest.raises(AuthorityProjectionError) as excinfo:
        build_consumption_intent(grant, make_action_ir())
    assert (
        excinfo.value.reason_code
        == "v21-06:consumption_requires_human_approval"
    )


def test_consumption_intent_rejects_revoked_grant() -> None:
    grant = _approval_grant().model_copy(update={"revoked": True})
    with pytest.raises(AuthorityProjectionError) as excinfo:
        build_consumption_intent(grant, make_action_ir())
    assert excinfo.value.reason_code == "v21-06:grant_revoked"


def test_consumption_intent_rejects_fingerprint_mismatch() -> None:
    grant = _approval_grant()
    with pytest.raises(AuthorityProjectionError) as excinfo:
        build_consumption_intent(
            grant, make_action_ir(authorization_fingerprint=OTHER_FINGERPRINT)
        )
    assert excinfo.value.reason_code == "v21-06:fingerprint_mismatch"


def test_consumption_intent_rejects_scope_mismatch() -> None:
    grant = _approval_grant()
    with pytest.raises(AuthorityProjectionError) as excinfo:
        build_consumption_intent(
            grant, make_action_ir(scope_digest=OTHER_SCOPE)
        )
    assert excinfo.value.reason_code == "v21-06:scope_mismatch"


def test_consumption_intent_rejects_action_type_not_granted() -> None:
    grant = _approval_grant()
    with pytest.raises(AuthorityProjectionError) as excinfo:
        build_consumption_intent(grant, make_action_ir(action_type="shell.exec"))
    assert excinfo.value.reason_code == "v21-06:action_type_not_granted"


def test_consumption_intent_rejects_resource_and_destination_mismatch() -> None:
    approval = make_approval_projection(
        resource_constraints=[
            ResourceConstraint(
                scheme="file", op="exact", values=["file:///work/b.txt"]
            )
        ],
        destination_constraints=[
            DestinationConstraint(
                scheme="url", op="domain", values=["trusted.example.org"]
            )
        ],
    )
    grant = compile_approval_to_grant(approval, make_policy_context())
    with pytest.raises(AuthorityProjectionError) as excinfo:
        build_consumption_intent(
            grant, make_action_ir(resources=[make_file_resource()])
        )
    assert excinfo.value.reason_code == "v21-06:resource_scope_mismatch"
    # 携带满足资源约束的资源，只触发 destination 分支的显式拒绝。
    matching_resource = make_file_resource(canonical_id="file:///work/b.txt")
    with pytest.raises(AuthorityProjectionError) as excinfo:
        build_consumption_intent(
            grant,
            make_action_ir(
                resources=[matching_resource],
                destinations=[make_url_resource(host="evil.com")],
            ),
        )
    assert excinfo.value.reason_code == "v21-06:destination_scope_mismatch"
