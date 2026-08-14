"""SequenceRef 顺序比较入口（02 §5 可比性约束）。

``SequenceRef.domain + producer_binding_id`` 决定可比较的顺序域；跨域或
跨 producer 直接用整数大小推断先后被 02 §5 禁止，fail-closed 抛
``SequenceComparisonError``。本模块直接转调 core 冻结实现，不在
guard-api 侧复制比较逻辑。
"""

from __future__ import annotations

from agentguard_core.security_context import (
    SequenceComparisonError,
    compare_sequence_refs,
)
from agentguard_core.signals.models import SequenceRef

__all__ = ["SequenceComparisonError", "compare_sequence_ref_order"]


def compare_sequence_ref_order(left: SequenceRef, right: SequenceRef) -> int:
    """同域同 producer 的 SequenceRef 比较：返回 ``-1 / 0 / 1``。

    跨域或跨 producer 比较 fail-closed 抛 ``SequenceComparisonError``
    （reason_code 前缀 ``v21-04:``）。
    """

    return compare_sequence_refs(left, right)
