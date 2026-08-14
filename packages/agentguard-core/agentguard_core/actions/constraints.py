"""Constraint DSL evaluation for V21-02 (01 §8, L345-373).

Capability 匹配语言的最小求值器：

- 每类约束一个 ``matches_*`` 纯函数，op 语义表驱动；
- 未知 op 一律返回 ``False``（fail-closed），不抛异常也不放行；
- ``security_relevant=False`` 的规范参数对 ``ArgumentConstraint`` 不可见；
- 禁止任意解释器、eval、regex、glob：只使用等值/成员/前缀/区间比较。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .models import (
    ActionConstraint,
    ArgumentConstraint,
    CanonicalArguments,
    CanonicalResource,
    DestinationConstraint,
    ResourceConstraint,
)

__all__ = [
    "matches_action",
    "matches_argument",
    "matches_destination",
    "matches_resource",
]


def matches_action(constraint: ActionConstraint, action_type: str) -> bool:
    """动作类型约束：``action_type`` 是否在允许集合内。"""
    if constraint.op != "in":
        return False
    return action_type in constraint.action_types


def _argument_eq(value: Any, expected: Any) -> bool:
    # 无隐式协变：精确类型匹配前置判断（bool 是 int 子类，
    # ``True == 1`` 不得进入授权匹配；int/float 亦不互等）。
    if type(value) is not type(expected):
        return False
    return value == expected


def _argument_in(value: Any, expected: Any) -> bool:
    if not isinstance(expected, list):
        return False
    return any(_argument_eq(value, candidate) for candidate in expected)


def _argument_prefix(value: Any, expected: Any) -> bool:
    if not isinstance(value, str) or not isinstance(expected, str):
        return False
    return value.startswith(expected)


def _argument_range(value: Any, expected: Any) -> bool:
    if (
        not isinstance(expected, list)
        or len(expected) != 2
        or isinstance(value, bool)
        or not isinstance(value, (int, float))
    ):
        return False
    low, high = expected
    for bound in (low, high):
        if isinstance(bound, bool) or not isinstance(bound, (int, float)):
            return False
    return low <= value <= high


_ARGUMENT_OPS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": _argument_eq,
    "in": _argument_in,
    "prefix": _argument_prefix,
    "range": _argument_range,
}


def matches_argument(
    constraint: ArgumentConstraint, arguments: CanonicalArguments
) -> bool:
    """规范参数约束：只对 ``security_relevant=True`` 的条目可见。

    未知 op → 表查找失败 → ``False``（fail-closed）。
    """
    evaluator = _ARGUMENT_OPS.get(constraint.op)
    if evaluator is None:
        return False
    for item in arguments.items:
        if not item.security_relevant:
            continue
        if item.json_pointer != constraint.json_pointer:
            continue
        if evaluator(item.value, constraint.value):
            return True
    return False


def _resource_matches_identity(
    resource: CanonicalResource, op: str, values: list[str]
) -> bool:
    # 只有已解析到最终 identity 的资源才能证明明确授权。partial/unresolved
    # 必须交由 Runtime 二次检查，不能用词法 canonical_id 命中 capability。
    if resource.resolution_status != "resolved":
        return False
    identity = resource.canonical_id
    if op == "exact":
        return identity in values
    if op == "in":
        return identity in values
    if op == "prefix":
        return any(identity.startswith(value) for value in values)
    return False


def matches_resource(
    constraint: ResourceConstraint, resources: list[CanonicalResource]
) -> bool:
    """资源约束：``scheme`` 匹配资源 kind，再按 op 比对 canonical identity。"""
    for resource in resources:
        if resource.kind != constraint.scheme:
            continue
        if _resource_matches_identity(resource, constraint.op, constraint.values):
            return True
    return False


def _destination_identifier(destination: CanonicalResource) -> str:
    """destination 的匹配标识：url/api 用 host_ascii，email 用 domain_ascii。"""
    kind = destination.kind
    if kind in {"url", "api"}:
        return getattr(destination, "host_ascii")
    if kind == "email":
        return getattr(destination, "domain_ascii")
    return destination.canonical_id


def _destination_matches_identifier(identifier: str, op: str, values: list[str]) -> bool:
    # destination 匹配标识（host_ascii/domain_ascii）恒为小写 ASCII：
    # 约束值统一 casefold 后再比，避免约束侧大写导致静默不匹配。
    if op == "exact":
        return identifier in [value.casefold() for value in values]
    if op == "in":
        return identifier in [value.casefold() for value in values]
    if op == "prefix":
        return any(identifier.startswith(value.casefold()) for value in values)
    if op == "domain":
        for value in values:
            lowered = value.casefold()
            if identifier == lowered or identifier.endswith(f".{lowered}"):
                return True
        return False
    return False


def matches_destination(
    constraint: DestinationConstraint, destinations: list[CanonicalResource]
) -> bool:
    """外部目标约束：``domain`` op 覆盖目标域及其全部子域。"""
    for destination in destinations:
        if destination.kind != constraint.scheme:
            continue
        if destination.resolution_status != "resolved":
            continue
        identifier = _destination_identifier(destination)
        if _destination_matches_identifier(
            identifier, constraint.op, constraint.values
        ):
            return True
    return False
