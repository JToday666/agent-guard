"""SemanticJudgment 冻结模型（01 §26，L1003-1041 逐字对齐）。

V21-09 scaffold（structure-only）：只落冻结字段与 digest 白名单声明，
不实现 provider/调用链（V21-13 职责）；纯模型无 IO，Core 不引入网络
IO 纪律（07 §2 ``semantic/models.py  # no network I/O in Core``）。

确定性纪律（01 §29）：不声明 uuid / wall-clock 默认工厂——
``judgment_id`` / ``created_at`` / ``expires_at`` / ``semantic_digest``
全部由调用方（V21-13 provider 编排层）确定性提供。

冻结语义（03 §11）：Semantic Judge 只允许输出
``aligned / misaligned / uncertain``，**不允许输出 allow/deny**；
``reported_confidence`` 只是模型自报等级，不是概率。
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from ..signals.models import EvidenceRef

__all__ = ["SemanticJudgment"]


class SemanticJudgment(BaseModel):
    """V2.1 Semantic Judge 判定记录（01 §26 字段逐字冻结）。

    五 digest binding（``assessment_digest`` /
    ``authorization_fingerprint`` / ``task_digest`` / ``policy_digest`` /
    ``snapshot_digest``）把本判定锚定到产出它的评估上下文，供
    03 §12 CAS revalidation 逐项比对（见
    ``decisions/revalidation.py::validate_semantic_binding``）；任一
    binding 漂移或判定过期即 stale/invalid，DEFER 保持 ASK。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2.1"] = "2.1"

    judgment_id: str
    verdict: Literal["aligned", "misaligned", "uncertain"]
    reported_confidence: Literal["low", "medium", "high"]

    reason_codes: list[str]
    evidence_refs: list[EvidenceRef]

    assessment_digest: str
    authorization_fingerprint: str
    task_digest: str | None
    policy_digest: str
    snapshot_digest: str

    provider: str
    model: str
    prompt_version: str
    created_at: str
    expires_at: str

    degraded: bool
    semantic_digest: str

    @classmethod
    def digest_fields(cls) -> frozenset[str]:
        """参与安全摘要的字段白名单（01 §29, L1164-1184）。

        只声明白名单，``semantic_digest`` 的实际计算属 V21-13
        provider 职责。禁入字段：``semantic_digest`` 自身（不进入自身
        摘要输入）、``judgment_id``（身份不入摘要，同
        ``FastAssessment.assessment_id`` 口径）、``created_at`` /
        ``expires_at``（03 §13：TTL 只是补充失效机制，不是主要一致性
        机制，不入安全摘要）。
        """
        return frozenset(
            {
                "schema_version",
                "verdict",
                "reported_confidence",
                "reason_codes",
                "evidence_refs",
                "assessment_digest",
                "authorization_fingerprint",
                "task_digest",
                "policy_digest",
                "snapshot_digest",
                "provider",
                "model",
                "prompt_version",
                "degraded",
            }
        )
