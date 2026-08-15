"""V21-07 B1-B6 行为模式 matcher（Phase 1 纯新增，零接线）。

02_状态投影_Provenance_Authority.md §14 冻结的六个 Minimal 行为模式：

- **B1** sensitive read → external egress；
- **B2** untrusted tool result → high-impact action；
- **B3** credential read → network/API/email；
- **B4** memory write/retrieve → future action；
- **B5** privilege escalation / action scope expansion；
- **B6** action budget / frequency anomaly。

冻结纪律：

- **behavior signal 不单独决定 deny**（02 §14 末句）：本模块只产出
  ``BehaviorMatch`` 证据与 ``SecuritySignal``，最终 deny/allow 由
  Fusion 阶段结合 policy/authority/flow 判定；signal 不携带 decision；
- **branch/parent refs 优先于纯 sequence**（04 §13）：关联前驱动作时
  优先级 ``parent_event_ids → branch_id → runtime_sequence``，见
  ``predecessor_link_kind`` / ``select_predecessor``；
- 纯函数确定性：无 IO、无随机、无时钟；同输入同输出。B1-B5 端到端
  真实链验收属 Phase 2（集成 PR），本模块用构造夹具独立验收（C6）。
"""

from __future__ import annotations

from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict

from ...actions.canonical_json import canonical_sha256
from ...signals.models import ImpactClass, SecuritySignal, TaintLabel
from ..facts import CapabilityGrant, RecentActionFact
from ..state import OnlineSecurityState, compare_sequence_refs

__all__ = [
    "B6_ANOMALY_COUNT_THRESHOLD",
    "LINK_KIND_PRIORITY",
    "BehaviorMatch",
    "BehaviorPatternId",
    "LinkKind",
    "generate_behavior_signals",
    "match_b1",
    "match_b2",
    "match_b3",
    "match_b4",
    "match_b5",
    "match_b6",
    "predecessor_link_kind",
    "select_predecessor",
]

BehaviorPatternId = Literal["B1", "B2", "B3", "B4", "B5", "B6"]

#: 前驱关联优先级（04 §13）：数值小者优先。
LinkKind = Literal["parent_event_ids", "branch_id", "runtime_sequence"]
LINK_KIND_PRIORITY: dict[LinkKind, int] = {
    "parent_event_ids": 0,
    "branch_id": 1,
    "runtime_sequence": 2,
}

#: B6 频率/预算异常的计数阈值（behavior_aggregates.count 达到即告警）。
B6_ANOMALY_COUNT_THRESHOLD: int = 20

#: 高影响动作集合（B2/B4 与 coverage 共用口径）。
_HIGH_IMPACTS = {"high", "critical"}

#: B2 影响链允许的 flow relation（02 §10 数据/因果边）。
_INFLUENCE_RELATIONS = {
    "influenced_by",
    "derived_from",
    "received_from",
    "returned_by",
}

#: B3 外发目的地的确定性前缀（network/API/email）。
_EXTERNAL_DESTINATION_PREFIXES = ("network:", "api:", "email:")

#: signal 不单独 deny 的显式纪律标签（02 §14 末句）。
_SIGNAL_ONLY_TAG = "v21-07:signal-only-no-standalone-deny"


class BehaviorMatch(BaseModel):
    """单个 B1-B6 模式命中证据（确定性、无 decision 语义）。

    - ``subject_refs``：命中主体（动作/事件 id）；
    - ``fact_refs``：证据事实 id（flow/source/memory/grant/aggregate）；
    - ``link_kind``：前驱关联依据（04 §13 优先级），无动作间关联为
      ``None``；
    - ``reason_codes``：命中理由码（``v21-07:`` 前缀）。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern_id: BehaviorPatternId
    subject_refs: tuple[str, ...]
    fact_refs: tuple[str, ...]
    link_kind: LinkKind | None = None
    reason_codes: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# 前驱关联（04 §13：branch/parent refs 优先于纯 sequence）
# ---------------------------------------------------------------------------


def predecessor_link_kind(
    successor: RecentActionFact, predecessor: RecentActionFact
) -> LinkKind | None:
    """判定 predecessor 是否为 successor 的前驱及关联依据。

    优先级（04 §13）：

    1. ``predecessor.event_id ∈ successor.parent_event_ids`` →
       ``parent_event_ids``（显式因果，最强）；
    2. 同非空 ``branch_id`` → ``branch_id``；
    3. 同 ``domain + producer_binding_id`` 的 ``runtime_sequence`` 且
       predecessor ≤ successor → ``runtime_sequence``（最弱，保守序）；
       跨域/跨 producer 的整数**不可比较**（02 §5）→ 不建立关联
       （fail-closed，不推断先后）。

    均不满足返回 ``None``。
    """
    if predecessor.event_id in successor.parent_event_ids:
        return "parent_event_ids"
    if (
        successor.branch_id is not None
        and predecessor.branch_id is not None
        and successor.branch_id == predecessor.branch_id
    ):
        return "branch_id"
    successor_seq = successor.runtime_sequence
    predecessor_seq = predecessor.runtime_sequence
    if successor_seq is None or predecessor_seq is None:
        return None
    if (
        successor_seq.domain != predecessor_seq.domain
        or successor_seq.producer_binding_id != predecessor_seq.producer_binding_id
    ):
        # 跨域整数比较被 02 §5 禁止：fail-closed，不建立顺序关联。
        return None
    if compare_sequence_refs(predecessor_seq, successor_seq) <= 0:
        return "runtime_sequence"
    return None


def select_predecessor(
    successor: RecentActionFact, candidates: list[RecentActionFact]
) -> tuple[RecentActionFact, LinkKind] | None:
    """在候选中选出最优前驱（优先级高者胜；同级按 event_id 确定性取胜）。

    优先级：``parent_event_ids → branch_id → runtime_sequence``
    （04 §13：branch/parent refs 优先于纯 sequence）。
    """
    best: tuple[RecentActionFact, LinkKind] | None = None
    best_rank: tuple[int, str] | None = None
    for candidate in candidates:
        if candidate.action_id == successor.action_id:
            continue
        kind = predecessor_link_kind(successor, candidate)
        if kind is None:
            continue
        rank = (LINK_KIND_PRIORITY[kind], candidate.event_id)
        if best_rank is None or rank < best_rank:
            best_rank = rank
            best = (candidate, kind)
    return best


def _ref_points_to_action(ref: str, action: RecentActionFact) -> bool:
    """flow target/source ref 是否指向动作（裸 id / event_id / 前缀形式）。"""
    return ref in {
        action.action_id,
        action.event_id,
        f"action:{action.action_id}",
    }


def _has_taint(taints: list[TaintLabel], label: TaintLabel) -> bool:
    return label in taints


def _max_impact_of(
    state: OnlineSecurityState, action_ids: set[str]
) -> ImpactClass | None:
    """命中动作中的最高 impact（signal 分级输入；无命中动作为 None）。"""
    order: dict[ImpactClass, int] = {
        "low": 0,
        "moderate": 1,
        "high": 2,
        "critical": 3,
    }
    best: ImpactClass | None = None
    for action in state.recent_actions:
        if action.action_id in action_ids:
            if best is None or order[action.impact] > order[best]:
                best = action.impact
    return best


# ---------------------------------------------------------------------------
# B1 — sensitive read → external egress
# ---------------------------------------------------------------------------


def match_b1(state: OnlineSecurityState) -> list[BehaviorMatch]:
    """B1：SENSITIVE taint 读取 → 外部出口。

    命中规则（查 relevant_flows relation + taint SENSITIVE）：

    1. ``sent_to`` flow 本身携带 ``SENSITIVE`` taint → 直接命中；
    2. 链式命中：SENSITIVE 读取 flow（``read_from`` / ``derived_from``）
       的 source/target 被 ``sent_to`` 外发 flow 的 source_ref 衔接。
    """
    matches: list[BehaviorMatch] = []
    flows = state.relevant_flows
    sensitive_reads = [
        flow
        for flow in flows
        if _has_taint(flow.taints, "SENSITIVE")
        and flow.relation in {"read_from", "derived_from"}
    ]
    for flow in flows:
        if flow.relation == "sent_to" and _has_taint(flow.taints, "SENSITIVE"):
            matches.append(
                BehaviorMatch(
                    pattern_id="B1",
                    subject_refs=(flow.target_ref,),
                    fact_refs=(flow.flow_id,),
                    reason_codes=("v21-07:b1_sensitive_direct_egress",),
                )
            )
    for egress in flows:
        if egress.relation != "sent_to":
            continue
        linked = [
            read.flow_id
            for read in sensitive_reads
            if egress.source_ref in {read.source_ref, read.target_ref}
        ]
        if linked:
            matches.append(
                BehaviorMatch(
                    pattern_id="B1",
                    subject_refs=(egress.target_ref,),
                    fact_refs=(egress.flow_id, *tuple(sorted(linked))),
                    reason_codes=("v21-07:b1_sensitive_read_to_egress",),
                )
            )
    return matches


# ---------------------------------------------------------------------------
# B2 — untrusted tool_result → high-impact action
# ---------------------------------------------------------------------------


def match_b2(state: OnlineSecurityState) -> list[BehaviorMatch]:
    """B2：untrusted tool_result → 高影响动作。

    命中规则（查 source_index trust + action impact）：untrusted 的
    ``tool_result`` source 经影响类 flow 或 producer 动作关联到
    high/critical impact 动作；前驱动作按 04 §13 优先级选路
    （parent_event_ids → branch_id → runtime_sequence）。
    """
    untrusted_sources = [
        source
        for source in state.source_index
        if source.source_type == "tool_result"
        and (
            source.trust == "untrusted"
            or set(source.taints)
            & {"UNTRUSTED", "EXTERNAL_INSTRUCTION", "PERSISTENT_UNTRUSTED"}
        )
    ]
    high_actions = [
        action for action in state.recent_actions if action.impact in _HIGH_IMPACTS
    ]
    matches: list[BehaviorMatch] = []
    for source in untrusted_sources:
        influence_flows = [
            flow
            for flow in state.relevant_flows
            if flow.source_ref == source.source_id
            and flow.relation in _INFLUENCE_RELATIONS
        ]
        if not influence_flows:
            continue
        producer_actions = [
            action
            for action in state.recent_actions
            if source.source_id in action.data_refs
            or source.source_id in action.resource_ids
        ]
        for action in high_actions:
            direct_flow = any(
                _ref_points_to_action(flow.target_ref, action)
                for flow in influence_flows
            )
            linked = select_predecessor(action, producer_actions)
            if not direct_flow and linked is None:
                continue
            matches.append(
                BehaviorMatch(
                    pattern_id="B2",
                    subject_refs=(action.action_id,),
                    fact_refs=(
                        source.source_id,
                        *tuple(sorted(flow.flow_id for flow in influence_flows)),
                    ),
                    link_kind=linked[1] if linked is not None else None,
                    reason_codes=("v21-07:b2_untrusted_tool_result_to_high_impact",),
                )
            )
    return matches


# ---------------------------------------------------------------------------
# B3 — credential read → network/API/email
# ---------------------------------------------------------------------------


def _is_external_destination(destination: str) -> bool:
    return destination.startswith(_EXTERNAL_DESTINATION_PREFIXES)


def match_b3(state: OnlineSecurityState) -> list[BehaviorMatch]:
    """B3：credential 读取 → network/API/email。

    命中规则（查 taint CREDENTIAL + destination）：

    1. ``sent_to`` flow 携带 ``CREDENTIAL`` taint → 直接命中；
    2. 状态内存在 CREDENTIAL 事实（flow taint 或 sticky summary）且
       近期动作的 destination 为 network/API/email（或 effects 显示
       外部通信/数据出口）→ 命中；凭据读取动作与外发动作间的前驱
       关联按 04 §13 优先级选路。
    """
    credential_flows = [
        flow for flow in state.relevant_flows if _has_taint(flow.taints, "CREDENTIAL")
    ]
    matches: list[BehaviorMatch] = []
    for flow in credential_flows:
        if flow.relation == "sent_to":
            matches.append(
                BehaviorMatch(
                    pattern_id="B3",
                    subject_refs=(flow.target_ref,),
                    fact_refs=(flow.flow_id,),
                    reason_codes=("v21-07:b3_credential_direct_egress",),
                )
            )

    credential_present = bool(credential_flows) or any(
        _has_taint(summary.taints, "CREDENTIAL")
        for summary in state.sticky_taint_summaries
    )
    if not credential_present:
        return matches

    credential_read_actions = [
        action
        for action in state.recent_actions
        if any(
            flow.relation in {"read_from", "derived_from"}
            and _ref_points_to_action(flow.target_ref, action)
            for flow in credential_flows
        )
    ]
    for action in state.recent_actions:
        egress = any(
            _is_external_destination(destination)
            for destination in action.destination_ids
        ) or (
            action.effects.external_communication
            or action.effects.data_egress
            or action.effects.network_access
        )
        if not egress:
            continue
        linked = select_predecessor(action, credential_read_actions)
        matches.append(
            BehaviorMatch(
                pattern_id="B3",
                subject_refs=(action.action_id,),
                fact_refs=tuple(sorted(flow.flow_id for flow in credential_flows)),
                link_kind=linked[1] if linked is not None else None,
                reason_codes=("v21-07:b3_credential_read_to_external_sink",),
            )
        )
    return matches


# ---------------------------------------------------------------------------
# B4 — memory write/retrieve → future action
# ---------------------------------------------------------------------------


def match_b4(state: OnlineSecurityState) -> list[BehaviorMatch]:
    """B4：memory write/retrieve → 后续动作。

    命中规则（查 memory_index + recent_actions 关联）：tainted /
    quarantined memory 经 ``loaded_from_memory`` flow 或 ``data_refs``
    关联到后续动作；写/取回动作与后续动作的前驱关联按 04 §13
    优先级选路（parent_event_ids → branch_id → runtime_sequence）。
    """
    risky_memories = [
        memory
        for memory in state.memory_index
        if memory.trust_state in {"tainted", "quarantined"} or memory.taints
    ]
    if not risky_memories:
        return []

    memory_ids = {memory.memory_id for memory in risky_memories}
    memory_write_actions = [
        action
        for action in state.recent_actions
        if action.effects.persistence
        or any(ref in memory_ids for ref in action.data_refs)
    ]
    write_action_ids = {
        a.action_id for a in memory_write_actions if a.effects.persistence
    }
    matches: list[BehaviorMatch] = []
    for action in state.recent_actions:
        if action.action_id in write_action_ids:
            continue  # 持久化写入动作自身不是「后续动作」
        flow_linked = [
            flow.flow_id
            for flow in state.relevant_flows
            if flow.relation == "loaded_from_memory"
            and flow.source_ref in memory_ids
            and _ref_points_to_action(flow.target_ref, action)
        ]
        ref_linked = sorted(ref for ref in action.data_refs if ref in memory_ids)
        if not flow_linked and not ref_linked:
            continue
        linked = select_predecessor(action, memory_write_actions)
        fact_refs = tuple(
            dict.fromkeys(
                [
                    *sorted(memory_ids),
                    *sorted(flow_linked),
                    *ref_linked,
                ]
            )
        )
        matches.append(
            BehaviorMatch(
                pattern_id="B4",
                subject_refs=(action.action_id,),
                fact_refs=fact_refs,
                link_kind=linked[1] if linked is not None else None,
                reason_codes=("v21-07:b4_memory_to_future_action",),
            )
        )
    return matches


# ---------------------------------------------------------------------------
# B5 — privilege escalation / scope expansion
# ---------------------------------------------------------------------------


def _grant_active(state: OnlineSecurityState, grant: CapabilityGrant) -> bool:
    return not grant.revoked and grant.grant_id not in state.revoked_grant_ids


def match_b5(state: OnlineSecurityState) -> list[BehaviorMatch]:
    """B5：privilege escalation / action scope expansion。

    命中规则（查 active_grants 的 action_types 扩展）：同 principal +
    task 的 grant 组内，按 ``issued_sequence`` 排序（仅同 domain +
    producer 可比；不可比的 grant 对 fail-closed 跳过，不推断先后），
    后发 grant 的 ``action_types`` 超出所有更早 grant 的并集 →
    scope expansion。
    """
    active = [grant for grant in state.active_grants if _grant_active(state, grant)]
    groups: dict[tuple[str, str | None], list[CapabilityGrant]] = {}
    for grant in active:
        groups.setdefault((grant.subject_principal_id, grant.task_id), []).append(grant)

    matches: list[BehaviorMatch] = []
    for group_key in sorted(groups, key=lambda key: (key[0], key[1] or "")):
        grants = [grant for grant in groups[group_key] if grant.issued_sequence]
        for candidate in grants:
            assert candidate.issued_sequence is not None
            earlier_types: set[str] = set()
            comparable_earlier: list[CapabilityGrant] = []
            for other in grants:
                if other.grant_id == candidate.grant_id:
                    continue
                assert other.issued_sequence is not None
                candidate_seq = candidate.issued_sequence
                other_seq = other.issued_sequence
                if (
                    candidate_seq.domain != other_seq.domain
                    or candidate_seq.producer_binding_id
                    != other_seq.producer_binding_id
                ):
                    continue  # 跨域不可比：fail-closed，不建立先后
                if compare_sequence_refs(other_seq, candidate_seq) < 0:
                    comparable_earlier.append(other)
                    earlier_types.update(other.action_types)
            if not comparable_earlier:
                continue
            new_types = sorted(set(candidate.action_types) - earlier_types)
            if new_types:
                matches.append(
                    BehaviorMatch(
                        pattern_id="B5",
                        subject_refs=(candidate.grant_id,),
                        fact_refs=tuple(
                            sorted(grant.grant_id for grant in comparable_earlier)
                        ),
                        reason_codes=(
                            "v21-07:b5_scope_expansion:" + ",".join(new_types),
                        ),
                    )
                )
    return matches


# ---------------------------------------------------------------------------
# B6 — budget/frequency anomaly
# ---------------------------------------------------------------------------


def match_b6(state: OnlineSecurityState) -> list[BehaviorMatch]:
    """B6：action budget / frequency anomaly。

    命中规则（查 behavior_aggregates count 阈值）：任一 aggregate 的
    ``count`` 达到 ``B6_ANOMALY_COUNT_THRESHOLD`` 即命中；聚合本身由
    ``apply_behavior_aggregate_upserts`` 增量维护，本 matcher 只读。
    """
    matches: list[BehaviorMatch] = []
    for aggregate in state.behavior_aggregates:
        if aggregate.count >= B6_ANOMALY_COUNT_THRESHOLD:
            matches.append(
                BehaviorMatch(
                    pattern_id="B6",
                    subject_refs=(aggregate.aggregate_id,),
                    fact_refs=(aggregate.aggregate_id,),
                    reason_codes=(
                        f"v21-07:b6_frequency_anomaly:"
                        f"{aggregate.pattern_id}:count={aggregate.count}",
                    ),
                )
            )
    return matches


# ---------------------------------------------------------------------------
# behavior signal 生成（signal 不单独决定 deny，02 §14 末句）
# ---------------------------------------------------------------------------

_Matcher = Callable[[OnlineSecurityState], list[BehaviorMatch]]

_MATCHERS: tuple[tuple[BehaviorPatternId, _Matcher], ...] = (
    ("B1", match_b1),
    ("B2", match_b2),
    ("B3", match_b3),
    ("B4", match_b4),
    ("B5", match_b5),
    ("B6", match_b6),
)


def generate_behavior_signals(
    state: OnlineSecurityState,
) -> list[SecuritySignal]:
    """汇总 B1-B6 命中产出 behavior signal（每模式至多一条，确定性序）。

    **纪律（02 §14 末句）：behavior signal 只生成 signal，不单独决定
    deny。** 本函数输出不携带 decision；是否 deny 必须由 Fusion 阶段
    结合 policy/authority/flow 证据判定。signal 通过
    ``tags`` 携带 ``v21-07:signal-only-no-standalone-deny`` 显式标记。
    """
    signals: list[SecuritySignal] = []
    for pattern_id, matcher in _MATCHERS:
        matches = matcher(state)
        if not matches:
            continue
        subject_refs = sorted({ref for match in matches for ref in match.subject_refs})
        fact_refs = sorted({ref for match in matches for ref in match.fact_refs})
        impact = _max_impact_of(state, set(subject_refs)) or "moderate"
        signal_id = "v21-07-signal:" + canonical_sha256(
            {
                "pattern_id": pattern_id,
                "subject_refs": subject_refs,
                "fact_refs": fact_refs,
            }
        )
        link_kinds = sorted(
            {match.link_kind for match in matches if match.link_kind is not None}
        )
        signals.append(
            SecuritySignal(
                signal_id=signal_id,
                detector_id="v21-07.behavior_matchers",
                category=f"behavior:{pattern_id}",
                scope="sequence",
                impact=impact,
                confidence="medium",
                evidence_group=f"v21-07:{pattern_id.lower()}",
                reason_codes=[
                    reason for match in matches for reason in match.reason_codes
                ],
                evidence_refs=[],
                facts=[],
                tags=[
                    f"behavior:{pattern_id.lower()}",
                    _SIGNAL_ONLY_TAG,
                    *(f"link:{kind}" for kind in link_kinds),
                ],
            )
        )
    return signals
