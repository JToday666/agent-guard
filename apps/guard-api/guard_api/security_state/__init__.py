"""V21-04 guard-api 安全状态编排包（State Projection / Snapshot）。

纯新增顶层包：本期不接线 evaluation 编排 / main / routers（接线属
V21-08），不新增 HTTP 路由与环境变量。模块分工（07 §3 六文件口径 +
service 门面）：

- ``ordering``：SequenceRef 同域同 producer 比较入口（转调 core）；
- ``models``：服务层数据类（ApplyResult 透传、security alert 结构）；
- ``store``：ControlPlaneStore 新方法薄封装 + per-scope 锁注册表；
- ``projector``：commit → project → 幂等写入 → CAS 编排；
- ``rebuild``：bounded rebuild（crash/replay 恢复 + 截断 fail-closed）；
- ``snapshot_builder``：dirty/缺态先 rebuild 再出不可变快照；
- ``service``：对外 API 门面（read_snapshot / project_committed /
  ensure_ready）。
"""

from .models import (
    ProjectApplyOutcome,
    ProjectApplyResult,
    SecurityAlert,
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
