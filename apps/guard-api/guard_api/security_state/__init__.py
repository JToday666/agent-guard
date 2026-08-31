"""V21-04 guard-api 安全状态编排包（State Projection / Snapshot）。

顶层包：V21-08 T4 起由 main 注册 service 门面供 shadow 旁路只读
消费；不新增 HTTP 路由。模块分工（07 §3 六文件口径 +
service 门面）：

- ``ordering``：SequenceRef 同域同 producer 比较入口（转调 core）；
- ``models``：服务层数据类（ApplyResult 透传、security alert 结构）；
- ``store``：ControlPlaneStore 新方法薄封装 + per-scope 锁注册表；
- ``projector``：commit → project → 幂等写入 → CAS 编排；
- ``rebuild``：bounded rebuild（crash/replay 恢复 + 截断 fail-closed）；
- ``snapshot_builder``：兼容路径 repair-capable snapshot + Product strict
  ready-only snapshot；
- ``service``：对外 API 门面（read_snapshot / project_committed /
  read_ready_snapshot_with_revoked / ensure_ready）。
"""

from .models import (
    ProjectApplyOutcome,
    ProjectApplyResult,
    SecurityAlert,
    SecurityStateNotReadyError,
    SecurityStateProjectError,
)
from .ordering import SequenceComparisonError, compare_sequence_ref_order
from .projector import CommittedVerifier, SecurityStateProjector
from .rebuild import DEFAULT_REBUILD_LIMIT, rebuild
from .service import SecurityStateService
from .snapshot_builder import get_snapshot
from .store import SecurityStateStoreAccess, empty_online_state

__all__ = [
    "DEFAULT_REBUILD_LIMIT",
    "CommittedVerifier",
    "ProjectApplyOutcome",
    "ProjectApplyResult",
    "SecurityAlert",
    "SecurityStateNotReadyError",
    "SecurityStateProjectError",
    "SecurityStateProjector",
    "SecurityStateService",
    "SecurityStateStoreAccess",
    "SequenceComparisonError",
    "compare_sequence_ref_order",
    "empty_online_state",
    "get_snapshot",
    "rebuild",
]
