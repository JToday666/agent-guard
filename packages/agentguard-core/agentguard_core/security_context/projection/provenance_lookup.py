"""V21-05 bounded relevant subgraph lookup（02 §8）。

Minimal provenance 查询目标不是「遍历全局 20 跳路径」，而是**当前
Action 的 bounded relevant subgraph**：

```text
file:credential → read_from artifact:x → derived_from message:y
    → sent_to email:external
```

冻结纪律（C8）：

- 三重预算 —— ``max_depth``（hop 数）、``max_breadth``（单节点邻接
  flow 上限）、``node_budget``（访问节点总量）——任一超限立即停止并
  返回 ``truncated=True``；**截断不得静默**，消费方必须把 dataflow
  coverage 降 partial/unknown（reason_code
  ``v21-05:flow_lookup_truncated``，见 ``provenance_coverage``）；
- 临时邻接索引只在函数栈内构建（局部 dict），不写入
  ``OnlineSecurityState`` 任何字段，state digest 零影响；
- 输入 flow 另有硬上限 ``MAX_LOOKUP_INPUT_FLOWS``。超过上限时在
  排序、复制或建索引前整组拒绝并返回 ``truncated=True``，避免 sticky
  历史图把单次 assessment 的 CPU/内存成本重新变成无界；
- 遍历确定性：邻接表按 ``flow_id`` 排序展开，结果按 ``flow_id`` 排序
  返回，同 state 重复查询结果逐字节一致（T-Replay 友好）。
"""

from __future__ import annotations

from collections import deque

from ..facts import FlowFact
from ..state import OnlineSecurityState

__all__ = [
    "DEFAULT_LOOKUP_MAX_BREADTH",
    "DEFAULT_LOOKUP_MAX_DEPTH",
    "DEFAULT_LOOKUP_NODE_BUDGET",
    "MAX_LOOKUP_INPUT_FLOWS",
    "bounded_relevant_flow_lookup",
    "bounded_relevant_flow_lookup_many",
]

#: 默认预算常量（02 §8 bounded 要求；模块级集中配置）。
DEFAULT_LOOKUP_MAX_DEPTH: int = 4
DEFAULT_LOOKUP_MAX_BREADTH: int = 32
DEFAULT_LOOKUP_NODE_BUDGET: int = 256

#: 单次 lookup 允许建索引的硬上限。取 node × breadth 的最坏边界邻接
#: 数；调用方可以收紧 depth/breadth/node，但不得放宽该输入上限。
MAX_LOOKUP_INPUT_FLOWS: int = DEFAULT_LOOKUP_NODE_BUDGET * DEFAULT_LOOKUP_MAX_BREADTH


def _build_adjacency(
    flows: list[FlowFact],
) -> tuple[dict[str, list[FlowFact]], dict[str, list[FlowFact]]]:
    """函数栈内临时邻接索引（不入 state，digest 零影响）。

    返回 (按 source_ref 索引, 按 target_ref 索引)；每个桶内按
    ``flow_id`` 排序保证展开顺序确定性。
    """
    by_source: dict[str, list[FlowFact]] = {}
    by_target: dict[str, list[FlowFact]] = {}
    for flow in sorted(flows, key=lambda item: item.flow_id):
        by_source.setdefault(flow.source_ref, []).append(flow)
        by_target.setdefault(flow.target_ref, []).append(flow)
    return by_source, by_target


def bounded_relevant_flow_lookup(
    state: OnlineSecurityState,
    *,
    target_ref: str,
    max_depth: int = DEFAULT_LOOKUP_MAX_DEPTH,
    max_breadth: int = DEFAULT_LOOKUP_MAX_BREADTH,
    node_budget: int = DEFAULT_LOOKUP_NODE_BUDGET,
) -> tuple[list[FlowFact], bool]:
    """从 ``target_ref`` 出发沿 FlowFact 的 source/target 引用做有界遍历。

    返回 ``(flows, truncated)``：

    - ``flows``：相关子图内的 flow（按 ``flow_id`` 排序去重）；
    - ``truncated``：任一预算（depth/breadth/node）触顶即为 True ——
      depth 触顶时仍有未展开 frontier、单节点邻接超过
      ``max_breadth``、或访问节点数达到 ``node_budget``。

    遍历语义：节点 = flow 的 source_ref/target_ref 字符串；边 = 一条
    FlowFact 连接其两端引用（双向可达，provenance 需要向上溯源与
    向下追 sink 两个方向）。访问到的节点关联的 flow 计入结果（即使
    对端节点已访问 —— 该 flow 仍属于相关子图）。
    """
    return bounded_relevant_flow_lookup_many(
        state,
        target_refs=(target_ref,),
        max_depth=max_depth,
        max_breadth=max_breadth,
        node_budget=node_budget,
    )


def bounded_relevant_flow_lookup_many(
    state: OnlineSecurityState,
    *,
    target_refs: list[str] | tuple[str, ...] | set[str] | frozenset[str],
    max_depth: int = DEFAULT_LOOKUP_MAX_DEPTH,
    max_breadth: int = DEFAULT_LOOKUP_MAX_BREADTH,
    node_budget: int = DEFAULT_LOOKUP_NODE_BUDGET,
) -> tuple[list[FlowFact], bool]:
    """Multi-root variant sharing one global depth/breadth/node budget.

    Gate A seeds the lookup with the current action plus its normalized sinks.
    Roots and adjacency are sorted, so caller collection order cannot affect the
    returned graph or truncation result. Inputs exceeding the hard flow cap or
    root node budget are rejected before an adjacency/index allocation.
    """
    if max_depth < 0 or max_breadth < 0 or node_budget < 0:
        raise ValueError("lookup budgets must be non-negative")
    if len(state.relevant_flows) > MAX_LOOKUP_INPUT_FLOWS:
        return [], True
    if len(target_refs) > node_budget:
        return [], True
    roots = sorted(set(target_refs))
    if len(roots) > node_budget:
        return [], True
    if not roots:
        return [], False

    by_source, by_target = _build_adjacency(list(state.relevant_flows))

    collected: dict[str, FlowFact] = {}
    truncated = False
    visited: set[str] = set(roots)

    # BFS：(node, depth)；depth = 距 target_ref 的 hop 数。
    frontier: deque[tuple[str, int]] = deque((root, 0) for root in roots)
    while frontier:
        node, depth = frontier.popleft()
        adjacent = [
            *by_source.get(node, []),
            *by_target.get(node, []),
        ]
        adjacent.sort(key=lambda flow: flow.flow_id)

        expand = adjacent
        if len(adjacent) > max_breadth:
            # 单节点邻接超宽：只展开前 max_breadth 条，截断显式上报。
            expand = adjacent[:max_breadth]
            truncated = True

        for flow in expand:
            neighbor = flow.target_ref if flow.source_ref == node else flow.source_ref
            if neighbor in visited:
                # Both endpoints were already admitted within the node/depth
                # budgets, so the connecting edge belongs to the bounded graph.
                collected[flow.flow_id] = flow
                continue
            if depth + 1 > max_depth:
                # The edge itself would expose an endpoint beyond max_depth;
                # reject it rather than returning an off-by-one subgraph.
                truncated = True
                continue
            if len(visited) >= node_budget:
                # Do not collect an edge whose peer node cannot be admitted.
                truncated = True
                continue
            visited.add(neighbor)
            collected[flow.flow_id] = flow
            frontier.append((neighbor, depth + 1))

    flows = [collected[flow_id] for flow_id in sorted(collected)]
    return flows, truncated
