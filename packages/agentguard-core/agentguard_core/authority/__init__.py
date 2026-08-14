"""V2.1 authority scaffold (V21-03: Authenticated Task Ingress).

纯新增模块组：Authenticated Task Ingress 的冻结模型
（SecurityStateScope/EvaluationClock/TaskFact）与确定性
TaskAuthorizationCompiler 最小版。判定路径（``engine.py`` /
``decisions/*``）不引用本包；顶层 ``agentguard_core/__init__.py``
不在 V21-03 本期范围内改动。
"""

from __future__ import annotations

from .compiler import (
    COMPILER_VERSION,
    DERIVED_AUTHORITY_MARKER,
    CompiledTaskAuthority,
    TaskAuthorityError,
    compile_task_authority,
    compiled_task_authority_projection,
)
from .models import (
    EvaluationClock,
    SecurityStateScope,
    TaskFact,
    scope_digest_projection,
    task_digest_projection,
)

__all__ = [
    "COMPILER_VERSION",
    "DERIVED_AUTHORITY_MARKER",
    "CompiledTaskAuthority",
    "EvaluationClock",
    "SecurityStateScope",
    "TaskAuthorityError",
    "TaskFact",
    "compile_task_authority",
    "compiled_task_authority_projection",
    "scope_digest_projection",
    "task_digest_projection",
]
