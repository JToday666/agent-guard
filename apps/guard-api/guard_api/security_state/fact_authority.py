"""CT-PR-01 Fact Authority Matrix：adapter claim → verified descriptor（ct-fam-1，无接线）。

冻结出处（docs/AgentGuard_Context_Isolation_Taint_Tracking_Final_RC/）：

- 02 章 §3 冻结矩阵、§5 Claim Monotonicity、§6 Verified Source
  Algorithm（伪代码）、§7 Initial Taint Rules、§11 Determinism
  Contract（T-NoClaimUpgrade / T-NoSanitizeClaim）、§12 版本、
  §13 Failure Contract、§14 DoD；
- 01 章 §13 ``VerifiedSourceDescriptor`` 字段逐字冻结；
- 机器冻结文件 ``context_taint_contract_freeze.yaml`` 的
  ``source_defaults`` / ``claim_rules`` / ``declassification`` 三节
  （parity 由 ``tests/test_ct_fact_authority.py`` 固化）。

本模块纪律（CT-PR-01 DoD，零接线）：

- 纯函数：无 state mutation、不写 store、无 I/O、不产
  ``SecurityStateDeltaV21``、不返回 ``GuardDecision``；
- Adapter claim 只能保守增加风险，不能单独降低风险（CT-F0-07）；
- ``sanitized=True`` 永不减 taint（T-NoSanitizeClaim）；
- 任何失败路径 fail-closed（对齐 ``EvaluationDegradation`` 先例），
  不 raise、不 fail-open。

reason_code 清单（verify_source_claim）：
``authenticated_owner_upgrade`` / ``producer_attribution_mismatch`` /
``trusted_claim_ignored`` / ``sanitized_claim_ignored`` /
``model_judgment_only`` / ``memory_inherit_pending_apply_memory_inheritance`` /
``source_type_unknown`` / ``source_default_missing``。
reason_code 清单（apply_memory_inheritance）：
``memory_fact_missing`` / ``memory_inherited_from_fact`` /
``memory_trust_state_<trust_state>`` /
``memory_trust_state_unrecognized`` / ``memory_clean_with_taints_conflict``。
"""

from __future__ import annotations

import types
import typing
from typing import Literal

from pydantic import BaseModel, ConfigDict

from agentguard_core.security_context.facts import MemoryFact, SourceFact
from agentguard_core.signals.models import EvidenceRef, FactAuthority, TaintLabel

#: 02 章 §12 版本：影响 fact 语义的变化必须 bump。
FACT_AUTHORITY_VERSION = "ct-fam-1"

#: memory 源三字段哨兵（YAML ``source_defaults.memory``）：不在 core
#: ``FactAuthority`` Literal 内，本模块以并集局部表达，不改 packages/。
MEMORY_INHERIT = "inherit_memory_fact"

MemoryInheritAuthority = FactAuthority | Literal["inherit_memory_fact"]
MemoryInheritTaints = tuple[TaintLabel, ...] | Literal["inherit_memory_fact"]

#: 01 §13 VerifiedSourceDescriptor.trust 冻结三值。
TrustLevel = Literal["trusted", "untrusted", "unknown"]

#: 默认表 trust 字段：memory 源为哨兵（YAML source_defaults.memory）。
MemoryInheritTrust = TrustLevel | Literal["inherit_memory_fact"]

#: 冻结 taint 标签顺序（YAML ``taint_labels``）：保证 ``initial_taints`` 确定性
#: 排序（02 §11 T-FactReplay）；CT-PR-02b 起公开导出（fact_builder 写侧复用
#: 保序去重），原名 ``_TAINT_ORDER``、无兼容别名，消费方应使用 ``TAINT_ORDER``。
TAINT_ORDER: tuple[TaintLabel, ...] = (
    "UNTRUSTED",
    "EXTERNAL_INSTRUCTION",
    "SENSITIVE",
    "CREDENTIAL",
    "PERSISTENT_UNTRUSTED",
)

#: SourceFact.source_type 的 11 值 Literal（只读 core 类型，02 §6
#: normalize 步骤的对齐依据）。
_SOURCE_TYPE_VALUES = frozenset(
    typing.get_args(SourceFact.model_fields["source_type"].annotation)
)


class SourceDefaultProfile(BaseModel):
    """冻结 YAML ``source_defaults`` 单源默认项（逐值 parity）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trust: MemoryInheritTrust
    fact_authority: MemoryInheritAuthority
    initial_taints: MemoryInheritTaints


class SourceClaim(BaseModel):
    """Adapter 提交的来源声明（最小集，仅承载 02 §6 算法所需输入）。

    ``claimed_trust`` / ``sanitized`` 等只是 claim：server 按 02 §5
    Claim Monotonicity 保守处理，永不因 claim 单独降风险或清 taint。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str
    scope_digest: str
    raw_source_type: str
    claimed_trust: Literal["trusted", "untrusted", "unknown"] = "unknown"
    sanitized: bool = False
    instruction_like: bool = False
    server_sensitive_evidence: bool = False
    server_credential_evidence: bool = False
    producer: str = "adapter_unattributed"


class ProducerIdentity(BaseModel):
    """认证身份（02 §6 authenticated owner 升级分支的最小输入）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    runtime_authenticated: bool = False
    principal_authenticated: bool = False
    producer_id: str | None = None

    @property
    def is_authenticated_owner(self) -> bool:
        """runtime + principal 双认证且身份可归属（02 §3 矩阵行 4）。

        空串 producer_id 不构成可归属身份。
        """
        return (
            self.runtime_authenticated
            and self.principal_authenticated
            and bool(self.producer_id)
        )


def _freeze_profiles(raw: dict[str, dict[str, object]]) -> types.MappingProxyType:
    profiles = {
        name: SourceDefaultProfile(
            trust=typing.cast(MemoryInheritTrust, entry["trust"]),
            fact_authority=typing.cast(MemoryInheritAuthority, entry["fact_authority"]),
            initial_taints=typing.cast(
                MemoryInheritTaints,
                (
                    tuple(entry["initial_taints"])
                    if isinstance(entry["initial_taints"], list)
                    else entry["initial_taints"]
                ),
            ),
        )
        for name, entry in raw.items()
    }
    return types.MappingProxyType(profiles)


#: 8 源默认表（02 §3 冻结矩阵 + YAML ``source_defaults``，import 期
#: 一次构建；parity 断言在 tests/test_ct_fact_authority.py）。
SOURCE_DEFAULTS: types.MappingProxyType = _freeze_profiles(
    {
        "web": {
            "trust": "untrusted",
            "fact_authority": "untrusted_claim",
            "initial_taints": ("UNTRUSTED",),
        },
        "email": {
            "trust": "untrusted",
            "fact_authority": "untrusted_claim",
            "initial_taints": ("UNTRUSTED",),
        },
        "rag": {
            "trust": "untrusted",
            "fact_authority": "untrusted_claim",
            "initial_taints": ("UNTRUSTED",),
        },
        "tool_result": {
            "trust": "untrusted",
            "fact_authority": "untrusted_claim",
            "initial_taints": ("UNTRUSTED",),
        },
        "mcp": {
            "trust": "untrusted",
            "fact_authority": "untrusted_claim",
            "initial_taints": ("UNTRUSTED",),
        },
        "model": {
            "trust": "unknown",
            "fact_authority": "model_judgment",
            "initial_taints": (),
        },
        "memory": {
            "trust": MEMORY_INHERIT,
            "fact_authority": MEMORY_INHERIT,
            "initial_taints": MEMORY_INHERIT,
        },
        "file": {
            "trust": "unknown",
            "fact_authority": "untrusted_claim",
            "initial_taints": (),
        },
    }
)

#: YAML ``claim_rules`` 四布尔（02 §5 Claim Monotonicity）。
CLAIM_RULES: types.MappingProxyType = types.MappingProxyType(
    {
        "risk_increasing_claims_may_be_accepted_conservatively": True,
        "trust_increasing_claim_requires_server_verification": True,
        "sanitized_claim_can_remove_taint": False,
        "model_output_can_create_capability": False,
    }
)

#: YAML ``declassification`` 节全键镜像（02 §5 / CT-F0-02）。
DECLASSIFICATION_RULES: types.MappingProxyType = types.MappingProxyType(
    {
        "producer": "trusted_declassifier",
        "adapter_sanitized_is_declassification": False,
        "llm_summary_is_declassification": False,
        "protected_labels": ("CREDENTIAL", "PERSISTENT_UNTRUSTED"),
        "protected_removal_requires_registry_permission": True,
    }
)


class VerifiedSourceDescriptor(BaseModel):
    """01 章 §13 TARGET-FROZEN 字段逐字对齐（+ memory 继承待决标识）。

    ``memory_inherit_pending=True`` 表示 memory 源的 trust/authority/
    taints 三字段尚为哨兵占位，须由 ``apply_memory_inheritance`` 解析；
    JSON 可序列化（tuple 字段序列化为数组）。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    source_id: str
    scope_digest: str
    source_type: str
    trust: Literal["trusted", "untrusted", "unknown"]
    verification_state: Literal["verified", "unverified", "not_applicable"]
    fact_authority: FactAuthority
    producer: str
    initial_taints: tuple[TaintLabel, ...] = ()
    reason_codes: tuple[str, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()
    memory_inherit_pending: bool = False


def normalize_source_type(raw: str) -> tuple[str, bool]:
    """归一到 SourceFact 11 值 Literal（02 §6 第一步）。

    返回 ``(source_type, unknown)``：已知值原样返回、``unknown=False``；
    未知值归一 ``"other"`` 并 ``unknown=True``，由调用方 fail-closed
    （对齐 ``EvaluationDegradation`` 先例：降级而非异常/放行）。
    """
    candidate = raw.strip().lower()
    if candidate in _SOURCE_TYPE_VALUES:
        return candidate, False
    return "other", True


def _accumulate_risk_increasing_taints(claim: SourceClaim) -> tuple[TaintLabel, ...]:
    """risk-increasing claim 保守累积（02 §5 / §6，确定性保序）。

    只增不减：claimed untrusted → UNTRUSTED；instruction_like →
    EXTERNAL_INSTRUCTION；server sensitive/credential evidence →
    SENSITIVE / CREDENTIAL+SENSITIVE。
    """
    taints: set[TaintLabel] = set()
    if claim.claimed_trust == "untrusted":
        taints.add("UNTRUSTED")
    if claim.instruction_like:
        taints.add("EXTERNAL_INSTRUCTION")
    if claim.server_sensitive_evidence:
        taints.add("SENSITIVE")
    if claim.server_credential_evidence:
        taints.update(("CREDENTIAL", "SENSITIVE"))
    return tuple(label for label in TAINT_ORDER if label in taints)


def verify_source_claim(
    *,
    claim: SourceClaim,
    producer_identity: ProducerIdentity,
) -> VerifiedSourceDescriptor:
    """纯函数：adapter claim → verified descriptor（02 §6 算法顺序）。

    顺序：默认表查表 → authenticated owner 升级（仅
    trusted/trusted_claim/verified；CT-Q-01 禁止 authoritative；升级
    额外要求归因一致 claim.producer == producer_identity.producer_id）
    → risk-increasing claim 保守接受 → sanitized 与 claimed trusted 恒
    忽略（CT-F0-07，仅记 reason_code）→ model 源恒 model_judgment +
    trust=unknown。memory 源早退前同样执行 risk-increasing 累积（结果
    写入 pending descriptor，由 apply_memory_inheritance 的 ∪ 并集继
    承）。policy 信任升级 v1 不实现。任何路径不 raise：
    未知 source_type → fail-closed descriptor + reason_code
    ``source_type_unknown``；属于 11 值 Literal 但不在 8 源默认表内
    的 source_type（如 runtime/user）→ fail-closed descriptor +
    reason_code ``source_default_missing``。
    """
    source_type, unknown = normalize_source_type(claim.raw_source_type)

    if source_type == "memory":
        # risk-increasing 输入不得在早退时丢弃（02 §5 Claim
        # Monotonicity）：claimed untrusted / instruction_like / server
        # evidence 照常规累积；claimed trusted 与 sanitized 仍恒忽略
        # （CT-F0-07，不记额外 reason_code）。trust/authority/taints
        # 继承字段由 apply_memory_inheritance 用权威 MemoryFact 解析。
        memory_taints = _accumulate_risk_increasing_taints(claim)
        return VerifiedSourceDescriptor(
            source_id=claim.source_id,
            scope_digest=claim.scope_digest,
            source_type=source_type,
            trust="unknown",
            verification_state="unverified",
            fact_authority="untrusted_claim",
            producer=claim.producer,
            initial_taints=memory_taints,
            reason_codes=("memory_inherit_pending_apply_memory_inheritance",),
            memory_inherit_pending=True,
        )

    if unknown or source_type not in SOURCE_DEFAULTS:
        # fail-closed：未知类型、或 11 值 Literal 内但 v1 无默认表的
        # 类型（runtime/user，policy 信任升级未实现）均不 raise、不
        # fail-open（02 §13 Failure Contract）。
        reason_code = "source_type_unknown" if unknown else "source_default_missing"
        return VerifiedSourceDescriptor(
            source_id=claim.source_id,
            scope_digest=claim.scope_digest,
            source_type=source_type,
            trust="unknown",
            verification_state="unverified",
            fact_authority="untrusted_claim",
            producer=claim.producer,
            initial_taints=(),
            reason_codes=(reason_code,),
        )

    profile = typing.cast(SourceDefaultProfile, SOURCE_DEFAULTS[source_type])
    # memory 哨兵分支已提前返回，此处 trust 必为冻结三值之一。
    trust: TrustLevel = typing.cast(TrustLevel, profile.trust)
    authority = typing.cast(FactAuthority, profile.fact_authority)
    verification: Literal["verified", "unverified", "not_applicable"] = "unverified"
    reason_codes: list[str] = []
    taints: set[TaintLabel] = set()
    if profile.initial_taints != MEMORY_INHERIT:
        taints.update(profile.initial_taints)

    # authenticated owner 升级：仅身份信任（trusted/trusted_claim/
    # verified），且归因必须一致——adapter 可控的 claim.producer 与
    # 服务端认证的 producer_id 不一致时不升级（防身份冒认）。model
    # 源豁免：LLM 输出永不因身份升级（02 §8.3 +
    # claim_rules.model_output_can_create_capability=false）。
    owner_upgraded = False
    if producer_identity.is_authenticated_owner and source_type != "model":
        if claim.producer == producer_identity.producer_id:
            trust = "trusted"
            authority = "trusted_claim"
            verification = "verified"
            owner_upgraded = True
            reason_codes.append("authenticated_owner_upgrade")
        else:
            reason_codes.append("producer_attribution_mismatch")

    # risk-increasing claims 保守接受（02 §5 / §6）。
    taints.update(
        label
        for label in _accumulate_risk_increasing_taints(claim)
        if label not in taints
    )
    if claim.claimed_trust == "untrusted":
        trust = "untrusted"

    # sanitized=True 与 claimed trusted 恒忽略（CT-F0-07 /
    # T-NoSanitizeClaim / T-NoClaimUpgrade）：仅记 reason_code。
    if claim.sanitized:
        reason_codes.append("sanitized_claim_ignored")
    if claim.claimed_trust == "trusted" and not owner_upgraded:
        reason_codes.append("trusted_claim_ignored")

    # model 源恒 model_judgment + trust=unknown（02 §8.3）。
    if source_type == "model":
        trust = "unknown"
        authority = "model_judgment"
        reason_codes.append("model_judgment_only")

    ordered_taints: tuple[TaintLabel, ...] = tuple(
        label for label in TAINT_ORDER if label in taints
    )
    return VerifiedSourceDescriptor(
        source_id=claim.source_id,
        scope_digest=claim.scope_digest,
        source_type=source_type,
        trust=trust,
        verification_state=verification,
        fact_authority=authority,
        producer=claim.producer,
        initial_taints=ordered_taints,
        reason_codes=tuple(reason_codes),
    )


#: MemoryFact.trust_state → descriptor trust 映射（02 §7 Memory「继承
#: 权威 MemoryFact」）：clean→trusted / tainted→untrusted /
#: quarantined、unknown→unknown（fail-closed，不得当作可信）。
_MEMORY_TRUST_MAP: dict[str, Literal["trusted", "untrusted", "unknown"]] = {
    "clean": "trusted",
    "tainted": "untrusted",
    "quarantined": "unknown",
    "unknown": "unknown",
}


def apply_memory_inheritance(
    descriptor: VerifiedSourceDescriptor,
    memory_fact: MemoryFact | None,
) -> VerifiedSourceDescriptor:
    """独立纯函数：解析 memory 源的继承三字段（02 §7）。

    - 有权威 ``MemoryFact``：trust 按 ``_MEMORY_TRUST_MAP`` 映射（表外
      trust_state 按 unknown fail-closed + reason_code
      ``memory_trust_state_unrecognized``，不 raise）；tainted/
      quarantined 追加 ``UNTRUSTED``；taints 为 descriptor 既有
      taints ∪ MemoryFact.taints（按冻结顺序去重）；clean →
      trusted_claim，其余 → untrusted_claim（fail-closed）；
      verification_state=verified（继承自服务端 MemoryFact 记录）。
      矛盾收紧：trust_state=clean 但 taints 非空时降为
      unknown/untrusted_claim + reason_code
      ``memory_clean_with_taints_conflict``（ALLOW ≠ TRUST，CT-Q-08）。
    - 无 ``MemoryFact``：fail-closed unknown + reason_code
      ``memory_fact_missing``（02 §13；不 raise）。

    非 memory 源直接原样返回（不触发继承语义）。
    """
    if not descriptor.memory_inherit_pending:
        return descriptor

    if memory_fact is None:
        return descriptor.model_copy(
            update={
                "verification_state": "not_applicable",
                "reason_codes": descriptor.reason_codes + ("memory_fact_missing",),
                "memory_inherit_pending": False,
            }
        )

    extra_reason_codes: list[str] = []
    trust = _MEMORY_TRUST_MAP.get(memory_fact.trust_state)
    if trust is None:
        # 表外 trust_state：fail-closed 不 raise（02 §13）。
        trust = "unknown"
        extra_reason_codes.append("memory_trust_state_unrecognized")
    if memory_fact.trust_state == "clean" and memory_fact.taints:
        # clean 与非空 taints 矛盾：收紧为 fail-closed（CT-Q-08）。
        trust = "unknown"
        extra_reason_codes.append("memory_clean_with_taints_conflict")
    authority: FactAuthority = (
        "trusted_claim" if trust == "trusted" else "untrusted_claim"
    )
    taints: set[TaintLabel] = set(descriptor.initial_taints)
    taints.update(memory_fact.taints)
    if memory_fact.trust_state in {"tainted", "quarantined"}:
        taints.add("UNTRUSTED")
    ordered_taints = tuple(label for label in TAINT_ORDER if label in taints)
    reason_codes = descriptor.reason_codes + (
        "memory_inherited_from_fact",
        f"memory_trust_state_{memory_fact.trust_state}",
        *extra_reason_codes,
    )
    return descriptor.model_copy(
        update={
            "trust": trust,
            "verification_state": "verified",
            "fact_authority": authority,
            "initial_taints": ordered_taints,
            "reason_codes": reason_codes,
            "memory_inherit_pending": False,
        }
    )
