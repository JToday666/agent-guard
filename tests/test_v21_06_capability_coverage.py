"""V21-06 capability 域 coverage 判定专门测试（02 §6.3 判定表，F8）。

逐状态参数化（期望表模式，仿 ``test_v21_state_coverage.py``）：

- complete / partial / unknown / stale / not_applicable 五状态；
- ``provider_available["lease_store"]=False`` → unknown 前置分支
  （键缺失视为未报告，不推断为不可用）；
- dirty 域前置分支 → unknown（02 §3：投影失败不得解释为 complete）；
- eviction ``unprovable_domains`` 命中 → partial（02 §5.1）；
- F2 修复后行为：``remaining_uses=None``（无限次，task_compiler 编译
  的 grant 恒为 None）不抛 TypeError 且计为活跃；
- F4 修复后行为：``state.revoked_grant_ids`` 投影命中后同 grant 不再
  计为活跃（与 verdict/matcher 口径对齐）。
"""

from __future__ import annotations

import pytest

from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    COVERAGE_DOMAINS,
    PROJECTOR_VERSION,
    GapContext,
    OnlineSecurityState,
    RequiredHistoryWindow,
    compute_coverage,
)
from agentguard_core.security_context.coverage_context import CoverageContext
from agentguard_core.security_context.eviction import EvictionReport
from agentguard_core.security_context.projection.capability_coverage import (
    CAPABILITY_PROVIDER_KEY,
    capability_coverage,
)
from agentguard_core.signals.models import SequenceRef

from tests.test_v21_security_state_models import make_grant, make_watermarks


def make_state(**overrides: object) -> OnlineSecurityState:
    payload: dict[str, object] = {"watermarks": make_watermarks()}
    payload.update(overrides)
    return OnlineSecurityState(**payload)  # pyright: ignore[reportArgumentType]


def plan(
    capabilities: list[str],
    *,
    capability_required: bool = True,
) -> RequiredCheckPlan:
    required = ["capability"] if capability_required else ["behavior"]
    return RequiredCheckPlan(
        plan_id="v21-06-plan:fixture",
        impact="high",
        required_domains=required,  # pyright: ignore[reportArgumentType]
        optional_domains=[d for d in COVERAGE_DOMAINS if d not in required],
        required_capabilities=capabilities,
        semantic_resolvable_dimensions=[],
        reason_codes=["v21-06:fixture"],
    )


def make_ctx(
    state: OnlineSecurityState, ctx_plan: RequiredCheckPlan, **overrides: object
) -> CoverageContext:
    payload: dict[str, object] = {
        "plan": ctx_plan,
        "watermarks": state.watermarks,
    }
    payload.update(overrides)
    return CoverageContext(**payload)  # pyright: ignore[reportArgumentType]


def capability_window(*, end_sequence: int = 10) -> RequiredHistoryWindow:
    return RequiredHistoryWindow(
        domain="capability",
        start_sequence=1,
        end_sequence=end_sequence,
        sequence_domain="policy",
        producer_binding_id="binding_a",
    )


# ---------------------------------------------------------------------------
# 五状态期望表（02 §6.3）
# ---------------------------------------------------------------------------


def test_capability_complete_when_all_required_covered() -> None:
    state = make_state(
        active_grants=[
            make_grant(action_types=["email.send", "file.read"])
        ]
    )
    coverage = compute_coverage(
        state,
        plan(["email.send", "file.read"]),
        projector_version=PROJECTOR_VERSION,
    )
    assert coverage.capability.status == "complete"
    assert "v21-06:capability_complete" in coverage.capability.reason_codes


def test_capability_complete_without_required_capabilities() -> None:
    # 无 required capability：grant 状态从 state 直读已知（含空集）。
    state = make_state(active_grants=[])
    coverage = compute_coverage(
        state, plan([]), projector_version=PROJECTOR_VERSION
    )
    assert coverage.capability.status == "complete"
    assert (
        "v21-06:capability_state_known" in coverage.capability.reason_codes
    )


def test_capability_partial_when_some_required_uncovered() -> None:
    state = make_state(active_grants=[make_grant(action_types=["email.send"])])
    coverage = compute_coverage(
        state,
        plan(["email.send", "file.read"]),
        projector_version=PROJECTOR_VERSION,
    )
    assert coverage.capability.status == "partial"
    assert (
        "v21-06:required_capability_unresolved"
        in coverage.capability.reason_codes
    )


@pytest.mark.parametrize(
    "action_types",
    [[], ["other.action"]],
    ids=["no_grants", "none_of_required_covered"],
)
def test_capability_unknown_when_grant_state_not_established(
    action_types: list[str],
) -> None:
    # required 非空但无任何活跃 grant 覆盖 → grant 状态无法建立。
    grants = [make_grant(action_types=action_types)] if action_types else []
    state = make_state(active_grants=grants)
    coverage = compute_coverage(
        state, plan(["email.send"]), projector_version=PROJECTOR_VERSION
    )
    assert coverage.capability.status == "unknown"
    assert (
        "v21-06:grant_state_not_established"
        in coverage.capability.reason_codes
    )


def test_capability_stale_when_window_behind_watermark() -> None:
    state = make_state(active_grants=[make_grant(action_types=["email.send"])])
    ctx_plan = plan(["email.send"])
    stale_ctx = make_ctx(
        state,
        ctx_plan,
        gap_context=GapContext(
            required_history_windows=(capability_window(),)
        ),
    )
    # committed（policy 域）水位缺失 → 无法证明新鲜度，fail-closed stale。
    coverage = capability_coverage(state, stale_ctx)
    assert coverage.status == "stale"
    assert "v21-06:grant_watermark_behind" in coverage.reason_codes

    # 水位新鲜（同域同 producer 且 value >= end_sequence）→ 不 stale。
    fresh_state = make_state(
        active_grants=[make_grant(action_types=["email.send"])],
        watermarks=make_watermarks().model_copy(
            update={
                "committed_sequence": SequenceRef(
                    domain="policy",
                    producer_binding_id="binding_a",
                    value=10,
                )
            }
        ),
    )
    fresh_ctx = make_ctx(
        fresh_state,
        ctx_plan,
        gap_context=GapContext(
            required_history_windows=(capability_window(),)
        ),
    )
    fresh = capability_coverage(fresh_state, fresh_ctx)
    assert fresh.status == "complete"


def test_capability_not_applicable_when_not_required() -> None:
    state = make_state(active_grants=[])
    # 总分派层：不在 plan.required_domains → not_applicable。
    coverage = compute_coverage(
        state,
        plan([], capability_required=False),
        projector_version=PROJECTOR_VERSION,
    )
    assert coverage.capability.status == "not_applicable"
    # 域函数自身分支同语义（v21-06 前缀）。
    direct = capability_coverage(
        state, make_ctx(state, plan([], capability_required=False))
    )
    assert direct.status == "not_applicable"
    assert "v21-06:capability_not_required" in direct.reason_codes


# ---------------------------------------------------------------------------
# 前置分支优先级（dirty / lease store / eviction）
# ---------------------------------------------------------------------------


def test_capability_unknown_when_lease_store_unavailable() -> None:
    state = make_state(active_grants=[make_grant(action_types=["email.send"])])
    ctx_plan = plan(["email.send"])
    unavailable_ctx = make_ctx(
        state, ctx_plan, provider_available={CAPABILITY_PROVIDER_KEY: False}
    )
    coverage = capability_coverage(state, unavailable_ctx)
    assert coverage.status == "unknown"
    assert "v21-06:lease_store_unavailable" in coverage.reason_codes

    # 键缺失视为未报告（不推断为不可用）→ 正常判定 complete。
    unreported_ctx = make_ctx(state, ctx_plan, provider_available={})
    assert capability_coverage(state, unreported_ctx).status == "complete"


def test_capability_unknown_when_domain_dirty() -> None:
    # 域函数前置分支：dirty → unknown（总分派层同语义另由
    # test_v21_state_coverage 的 v21-04:dirty_projection 固化）。
    state = make_state(
        active_grants=[make_grant(action_types=["email.send"])],
        dirty_domains=["capability"],
    )
    ctx_plan = plan(["email.send"])
    coverage = capability_coverage(state, make_ctx(state, ctx_plan))
    assert coverage.status == "unknown"
    assert "v21-06:dirty_projection" in coverage.reason_codes


def test_capability_partial_on_unprovable_eviction() -> None:
    state = make_state(active_grants=[make_grant(action_types=["email.send"])])
    ctx_plan = plan(["email.send"])
    ctx = make_ctx(
        state,
        ctx_plan,
        eviction_report=EvictionReport(unprovable_domains=["capability"]),
    )
    coverage = capability_coverage(state, ctx)
    assert coverage.status == "partial"
    assert "v21-06:safety_preserving_eviction" in coverage.reason_codes


# ---------------------------------------------------------------------------
# F2：remaining_uses=None（无限次）不得抛 TypeError 且计为活跃
# ---------------------------------------------------------------------------


def test_grant_with_unlimited_uses_is_active() -> None:
    # task_compiler 编译的 grant remaining_uses 恒为 None（01 §14），
    # 且不受 human_approval 单次使用不变量约束。
    state = make_state(
        active_grants=[
            make_grant(
                source_type="task_compiler",
                action_types=["email.send"],
                remaining_uses=None,
            )
        ]
    )
    coverage = compute_coverage(
        state, plan(["email.send"]), projector_version=PROJECTOR_VERSION
    )
    assert coverage.capability.status == "complete"
    assert "v21-06:capability_complete" in coverage.capability.reason_codes


def test_grant_with_zero_uses_is_not_active() -> None:
    state = make_state(
        active_grants=[
            make_grant(action_types=["email.send"], remaining_uses=0)
        ]
    )
    coverage = compute_coverage(
        state, plan(["email.send"]), projector_version=PROJECTOR_VERSION
    )
    assert coverage.capability.status == "unknown"


# ---------------------------------------------------------------------------
# F4：revoked_grant_ids 投影命中后同 grant 不再计为活跃
# ---------------------------------------------------------------------------


def test_revoked_grant_ids_projection_removes_active_grant() -> None:
    grant = make_grant(grant_id="grant_revoked", action_types=["email.send"])
    # 未投影 revocation：grant 活跃 → complete。
    active_state = make_state(active_grants=[grant])
    active = compute_coverage(
        active_state,
        plan(["email.send"]),
        projector_version=PROJECTOR_VERSION,
    )
    assert active.capability.status == "complete"

    # revocation 投影后（revoked_grant_ids 命中）→ 同 grant 不再活跃。
    revoked_state = make_state(
        active_grants=[grant], revoked_grant_ids=["grant_revoked"]
    )
    revoked = compute_coverage(
        revoked_state,
        plan(["email.send"]),
        projector_version=PROJECTOR_VERSION,
    )
    assert revoked.capability.status == "unknown"
    assert (
        "v21-06:grant_state_not_established"
        in revoked.capability.reason_codes
    )


def test_grant_revoked_flag_still_deactivates() -> None:
    state = make_state(
        active_grants=[
            make_grant(action_types=["email.send"], revoked=True)
        ]
    )
    coverage = compute_coverage(
        state, plan(["email.send"]), projector_version=PROJECTOR_VERSION
    )
    assert coverage.capability.status == "unknown"
