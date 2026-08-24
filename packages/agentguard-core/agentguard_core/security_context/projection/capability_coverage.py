"""V21-06 capability 域 coverage 判定纯函数（02 §6.3，Phase 2 集成补齐）。

V21-06 分支只交付了 handler（``capability.py``）与判定
（``authority_verdict.py``），未单独提供 capability 域 coverage 函数；
按集成 PR 约定依 02 §6.3 判定表在本模块补齐，签名符合
``coverage_context.DomainCoverageFn``。

C3 冻结约束：判定消费 ``CoverageContext`` 完整上下文 —— ``plan``
（required 判定 + ``required_capabilities``）、``provider_available``
（lease store 可用性，C5/D1：lease 权威存储在 guard-api 独立表）、
``dirty_domains`` / ``eviction_report``（fail-closed 降级）、
``gap_context.required_history_windows`` + ``watermarks``（stale 判定，
02 §5 跨域比较禁止）。

判定优先级：

1. 不在 ``plan.required_domains`` → ``not_applicable``；
2. 域 dirty → ``unknown``（02 §3：不得把投影失败解释为 complete）；
3. lease store 显式不可用 → ``unknown``（``provider_available`` 键缺失
   视为未报告，不推断为不可用）；
4. ``eviction_report.unprovable_domains`` 命中 → ``partial``（02 §5.1）;
5. required history window 落后 policy 水位 → ``stale``；
6. grant/revocation/consumption 状态覆盖 ``required_capabilities``
   （全部覆盖 → complete；部分覆盖 → partial；完全无活跃 grant →
   unknown）。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...decisions.evidence import DomainCoverage
from ...signals.models import CoverageStatus, SequenceDomain
from ..facts import StateWatermarks
from ..projector import PROJECTOR_VERSION
from ..state import OnlineSecurityState

if TYPE_CHECKING:
    # 仅类型注解消费：避免 coverage_context ↔ projection 导入环
    # （Phase 2 装配时 coverage_context 模块级导入本模块）。
    from ..coverage_context import CoverageContext

__all__ = [
    "CAPABILITY_PROVIDER_KEY",
    "capability_coverage",
]

#: ``CoverageContext.provider_available`` 的 provider 标识约定：
#: lease store（权威 ExecutionLease/GrantConsumption 存储，01 §31）。
CAPABILITY_PROVIDER_KEY = "lease_store"

_REASON_PREFIX = "v21-06"


def _watermark_for(watermarks: StateWatermarks, sequence_domain: SequenceDomain):
    """序列域 → 对应状态水位（跨域比较禁止，02 §5）。"""
    if sequence_domain == "policy":
        return watermarks.committed_sequence
    if sequence_domain == "memory":
        return watermarks.memory_sequence
    if sequence_domain == "receipt":
        return watermarks.runtime_receipt_sequence
    return watermarks.projected_sequence


def _window_stale(ctx: CoverageContext) -> bool:
    """capability 域 required history window 落后水位 → stale。

    窗口指定 ``sequence_domain`` + ``producer_binding_id``，只与同域
    同 producer 的水位比较（02 §5）；水位缺失或不可比均视为落后
    （无法证明新鲜度，fail-closed）。
    """
    if ctx.gap_context is None:
        return False
    stale = False
    for window in ctx.gap_context.required_history_windows:
        if window.domain != "capability":
            continue
        watermark = _watermark_for(ctx.watermarks, window.sequence_domain)
        if watermark is None:
            stale = True
            continue
        if (
            watermark.domain != window.sequence_domain
            or watermark.producer_binding_id != window.producer_binding_id
        ):
            stale = True
            continue
        if watermark.value < window.end_sequence:
            stale = True
    return stale


def _grant_is_active(grant, revoked_ids: frozenset[str]) -> bool:
    """活跃 grant 判定（与 verdict/matcher 口径对齐，authority_verdict）。

    - 撤销：grant 自身 ``revoked`` 标记或 ``state.revoked_grant_ids``
      投影命中（revocation 经 grant_revocations 容器投影）→ 不活跃；
    - 用量：``remaining_uses is None`` 表示无限次（task_compiler 编译
      的 grant 恒为 None，01 §14），视为有用量；否则须 > 0。
    """
    if grant.grant_id in revoked_ids or grant.revoked:
        return False
    return grant.remaining_uses is None or grant.remaining_uses > 0


def capability_coverage(
    state: OnlineSecurityState, ctx: CoverageContext
) -> DomainCoverage:
    """capability 域五状态判定（02 §6.3 判定表）。

    - complete：required capabilities 均被活跃 grant 覆盖，
      grant/revocation/consumption 状态已知；无 required capabilities
      时 grant 状态从 state 直读已知（含空集）亦判 complete；
    - partial：部分 required capability 无活跃 grant 覆盖；
    - stale：grant revision / consumption watermark 落后 required
      history window；
    - unknown：lease store 不可用、域 dirty，或 required capabilities
      非空但 state 无任何活跃 grant（grant 状态无法建立）；
    - not_applicable：policy 明确该动作无需 capability。
    """
    domain = "capability"
    as_of = ctx.watermarks.projected_sequence

    def result(status: CoverageStatus, reason_codes: list[str]) -> DomainCoverage:
        return DomainCoverage(
            domain=domain,
            status=status,
            as_of_sequence=as_of,
            projector_version=PROJECTOR_VERSION,
            reason_codes=reason_codes,
        )

    if domain not in ctx.plan.required_domains:
        return result("not_applicable", [f"{_REASON_PREFIX}:capability_not_required"])
    if domain in state.dirty_domains:
        return result("unknown", [f"{_REASON_PREFIX}:dirty_projection"])
    if ctx.provider_available.get(CAPABILITY_PROVIDER_KEY, True) is False:
        return result("unknown", [f"{_REASON_PREFIX}:lease_store_unavailable"])
    if (
        ctx.eviction_report is not None
        and domain in ctx.eviction_report.unprovable_domains
    ):
        return result("partial", [f"{_REASON_PREFIX}:safety_preserving_eviction"])
    if _window_stale(ctx):
        return result("stale", [f"{_REASON_PREFIX}:grant_watermark_behind"])

    required = list(ctx.plan.required_capabilities)
    if not required:
        # 无 required capability：grant/revocation/consumption 状态从
        # state 直读已知（含空集），判 complete（02 §6.3「state 已知」）。
        return result("complete", [f"{_REASON_PREFIX}:capability_state_known"])

    revoked_ids = frozenset(state.revoked_grant_ids)
    active = [
        grant for grant in state.active_grants if _grant_is_active(grant, revoked_ids)
    ]
    if not active:
        return result("unknown", [f"{_REASON_PREFIX}:grant_state_not_established"])

    covered_actions = {
        action_type for grant in active for action_type in grant.action_types
    }
    missing = [cap for cap in required if cap not in covered_actions]
    if len(missing) == len(required):
        return result("unknown", [f"{_REASON_PREFIX}:grant_state_not_established"])
    if missing:
        return result("partial", [f"{_REASON_PREFIX}:required_capability_unresolved"])
    return result("complete", [f"{_REASON_PREFIX}:capability_complete"])
