"""投影失败异常元组的共享定义（projector.py 与 rebuild.py 复用）。

V21-05/06/07 接线后，apply/rebuild 重放路径可能抛出的 fail-closed
异常不止 V21-04 的 ``ProjectionError``：三路 typed handler 各自抛
``ProvenanceProjectionError`` / ``CapabilityProjectionError`` /
``BehaviorProjectionError``（``ValueError`` 直接子类，互不继承）。

增量投影（``projector.py``）与 bounded rebuild（``rebuild.py``）必须
捕获**同一**异常元组，否则 rebuild 失败路径会漏接分支异常、绕过
全域 dirty + 结构化 alert 的 fail-closed 语义（02 §3.1）。本模块是
该元组的唯一定义点，两处导入复用，禁止各自维护副本。
"""

from __future__ import annotations

from agentguard_core.security_context import ProjectionError
from agentguard_core.security_context.projection import (
    BehaviorProjectionError,
    CapabilityProjectionError,
    ProvenanceProjectionError,
)

__all__ = ["PROJECTION_FAILURE_EXCEPTIONS", "ProjectionFailureException"]

#: 元组成员联合类型：四类异常均携带 ``reason_code``，收紧后
#: ``except PROJECTION_FAILURE_EXCEPTIONS as exc`` 的静态类型可直接
#: 访问结构化字段（pyright 不降为 ``Exception``）。
ProjectionFailureException = (
    ProjectionError
    | ProvenanceProjectionError
    | CapabilityProjectionError
    | BehaviorProjectionError
)

#: 投影 apply / rebuild 重放阶段可能抛出的全部 fail-closed 异常
#: （V21-04 入口校验 + V21-05/06/07 接线后 typed handler 分支异常）。
#: 分支异常携带 ``dirty_domains``（V21-05）：优先用于置脏相关域。
PROJECTION_FAILURE_EXCEPTIONS: tuple[
    type[ProjectionFailureException], ...
] = (
    ProjectionError,
    ProvenanceProjectionError,
    CapabilityProjectionError,
    BehaviorProjectionError,
)
