"""V21-04 服务层数据类：投影编排结果与结构化 security alert。

冻结语义对齐 02_状态投影_Provenance_Authority.md §3/§4：

- projector failure / digest conflict → state dirty + security alert，
  **不静默覆盖**、不吞错（原始错误经 ``SecurityStateProjectError`` 上抛，
  alert 随异常返回给调用方）；
- alert 只承载结构化诊断信息，不做任何判定，判定路径零改动。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

#: 编排结果状态：透传 core ``ApplyOutcome`` 语义并区分幂等重放。
ProjectApplyOutcome = Literal[
    "applied", "replayed_noop", "needs_rebuild", "conflict"
]


@dataclass(frozen=True, slots=True)
class SecurityAlert:
    """结构化 security alert（返回给调用方，不改任何判定）。

    ``reason_code`` 统一使用 ``v21-04:`` 前缀；``message`` 不得包含
    task 正文、server key 或任何敏感内容（与 core ProjectionError 纪律一致）。
    """

    reason_code: str
    message: str
    scope_digest: str
    domains: tuple[str, ...] = ()


class SecurityStateProjectError(RuntimeError):
    """投影/apply/CAS 编排失败：携带结构化 alert，不吞原始错误。

    ``alert`` 是返回给调用方的结构化诊断；``__cause__`` 保留底层
    ProjectionError / 存储冲突异常（raise ... from exc）。
    """

    def __init__(self, alert: SecurityAlert) -> None:
        super().__init__(f"{alert.reason_code}: {alert.message}")
        self.alert = alert
        self.reason_code = alert.reason_code


@dataclass(frozen=True, slots=True)
class ProjectApplyResult:
    """``project_and_apply`` 的编排结果。

    ``outcome`` 透传 core apply 三分支 + 幂等重放；``state_version``
    是编排后的当前 state version；``alert`` 非空仅出现在 conflict 分支
    （失败分支经 ``SecurityStateProjectError`` 上抛，不产生本结果）。
    """

    outcome: ProjectApplyOutcome
    state_version: int
    reason_codes: tuple[str, ...] = ()
    alert: SecurityAlert | None = None
