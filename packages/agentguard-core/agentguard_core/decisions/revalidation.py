"""V21-09 CAS revalidation 纯函数（03 §12 Semantic Revalidation / CAS）。

契约依据：

- 03 §12（L439-467）：``Read Snapshot V → assess → assessment_digest →
  transaction 外调用 LLM → judgment return → compare 五元组 → re-read /
  validate current state version → 若相关 state/policy/task 已变化：
  judgment stale，作废并 reassess/ASK → finalize``。禁止
  ``BEGIN transaction → LLM → COMMIT``；Semantic 期间不持长锁。
- ``12_决策记录_V21-09前置.md`` D8：revalidate 返回 stale 时
  divergence 归受控类目 ``degraded_stale_judgment``（见
  ``decisions/divergence.py``），stale reason code 沿用
  ``v21-09:stale_*`` 前缀纪律（与 V21-08 ``v21-08:`` 前缀一致）。

两个纯函数入口：

- ``revalidate_assessment``：Phase B 短事务内的 CAS 校验——assessment
  五元组锚点（``assessment_digest`` 自洽完整性 + ``task_digest`` /
  ``policy_digest`` / ``snapshot_digest``）与 state version 逐项比对
  当前权威值；任一项漂移 → ``stale`` + 对应 reason code。
- ``validate_semantic_binding``：``SemanticJudgment`` 的五 digest
  binding（01 §26）与 assessment 逐项比对 + 调用方注入参考时间的过期
  判定；binding 不符或过期 → ``False``（03 §14 DEFER 保持 ASK）。

纯函数纪律（01 §29）：不读 wall-clock（过期判定使用调用方注入的
``reference_time``，保证 replay 同输入同输出）、不生成 uuid、无 IO；
stale/invalid 一律 fail-closed，绝不放行。
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..semantic.models import SemanticJudgment
from .evidence import FastAssessment
from .shadow import compute_assessment_digest

__all__ = [
    "STALE_ASSESSMENT_DIGEST_REASON",
    "STALE_POLICY_DIGEST_REASON",
    "STALE_SNAPSHOT_DIGEST_REASON",
    "STALE_STATE_VERSION_REASON",
    "STALE_TASK_DIGEST_REASON",
    "RevalidationResult",
    "revalidate_assessment",
    "validate_semantic_binding",
]

#: revalidation stale reason codes（``v21-09:stale_*`` 前缀，D8 纪律）。
STALE_ASSESSMENT_DIGEST_REASON = "v21-09:stale_assessment_digest"
STALE_STATE_VERSION_REASON = "v21-09:stale_state_version"
STALE_TASK_DIGEST_REASON = "v21-09:stale_task_digest"
STALE_POLICY_DIGEST_REASON = "v21-09:stale_policy_digest"
STALE_SNAPSHOT_DIGEST_REASON = "v21-09:stale_snapshot_digest"


class RevalidationResult(BaseModel):
    """五元组 / state version revalidate 的确定性结论。

    ``status == "stale"`` 时 ``reason_codes`` 逐项登记漂移来源
    （fail-closed：调用方按 D8 口径放弃 V21-09 权威提交、记
    ``degraded_stale_judgment``，legacy 官方决策不受影响）。
    """

    model_config = ConfigDict(extra="forbid")

    status: Literal["valid", "stale"]
    reason_codes: list[str] = Field(default_factory=list)


def revalidate_assessment(
    assessment: FastAssessment,
    *,
    assessment_state_version: int,
    current_state_version: int,
    current_task_digest: str | None,
    current_policy_digest: str,
    current_snapshot_digest: str,
) -> RevalidationResult:
    """五元组 + state version 逐项比对（03 §12，纯函数确定性）。

    逐项检查（任一漂移即 ``stale``，reason codes 按检查顺序登记）：

    1. ``assessment_digest`` 自洽完整性：按 D1 口径重算白名单摘要，
       与 assessment 自带值比对（防评估产物被篡改/漂移）；
    2. state version CAS：``assessment_state_version``（Phase A 读取
       snapshot V 时的版本，由编排层传入）与 ``current_state_version``
       （re-read，03 §12 L462）相等；
    3. ``task_digest`` / ``policy_digest`` / ``snapshot_digest`` 与当前
       权威值逐项相等（``task_digest`` 可空，None 与 None 视为相等）。

    ``authorization_fingerprint`` 的漂移由 ``task_digest`` /
    ``snapshot_digest`` 比对覆盖（fingerprint 派生自 event + scope +
    task 身份，task 修订必改 ``task_digest``）；semantic judgment 侧的
    五 digest binding 完整比对见 ``validate_semantic_binding``。
    """
    reason_codes: list[str] = []

    if compute_assessment_digest(assessment) != assessment.assessment_digest:
        reason_codes.append(STALE_ASSESSMENT_DIGEST_REASON)
    if assessment_state_version != current_state_version:
        reason_codes.append(STALE_STATE_VERSION_REASON)
    if assessment.task_digest != current_task_digest:
        reason_codes.append(STALE_TASK_DIGEST_REASON)
    if assessment.policy_digest != current_policy_digest:
        reason_codes.append(STALE_POLICY_DIGEST_REASON)
    if assessment.snapshot_digest != current_snapshot_digest:
        reason_codes.append(STALE_SNAPSHOT_DIGEST_REASON)

    if reason_codes:
        return RevalidationResult(status="stale", reason_codes=reason_codes)
    return RevalidationResult(status="valid", reason_codes=[])


def _normalize_instant(value: str) -> str:
    """RFC 3339 UTC 时间串的最小规范化（``Z`` → ``+00:00``）。

    只做字符串规范化以便确定性字典序比较，不解析时钟（01 §29 纪律）；
    调用方必须保证 ``expires_at`` 与 ``reference_time`` 均为 UTC 口径。
    """
    if value.endswith("Z"):
        return value[:-1] + "+00:00"
    return value


def validate_semantic_binding(
    assessment: FastAssessment,
    judgment: SemanticJudgment,
    *,
    reference_time: str | None = None,
) -> bool:
    """五 digest binding 比对（03 §12 compare 节，纯函数）。

    逐项相等才视为 binding 有效：``assessment_digest`` /
    ``authorization_fingerprint`` / ``task_digest`` / ``policy_digest`` /
    ``snapshot_digest``。``reference_time`` 提供时附加过期判定：
    ``expires_at`` 早于参考时间即失效（03 §13 hard deadline 语义）。

    V21-09 semantic 恒 None（D1），本函数以纯函数形态预留
    03 §14 ``semantic binding invalid or stale → ASK`` 分支；任何
    binding 不符一律 ``False``（fail-closed）。
    """
    if judgment.assessment_digest != assessment.assessment_digest:
        return False
    if judgment.authorization_fingerprint != assessment.authorization_fingerprint:
        return False
    if judgment.task_digest != assessment.task_digest:
        return False
    if judgment.policy_digest != assessment.policy_digest:
        return False
    if judgment.snapshot_digest != assessment.snapshot_digest:
        return False
    if reference_time is not None and (
        _normalize_instant(judgment.expires_at)
        < _normalize_instant(reference_time)
    ):
        return False
    return True
