"""V2.1 frozen ActionIR models (V21-02: ActionIR + Canonicalization).

字段逐字冻结自
``docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/01_F1字段与契约冻结.md``：

- ActionEffect §6, L215-230；
- CanonicalArguments §7.1, L236-252；
- CanonicalResource §7.2, L254-342（8 变体 discriminated union，``kind`` 判别）；
- Constraint DSL §8, L345-373；
- ActionIR §9, L376-412；指纹白名单 §9, L414-447。

本模块为纯新增 scaffold：不引入 DB/HTTP，不被判定路径
（``engine.py`` / ``decisions/policy.py``）引用。
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..signals.models import ImpactClass

__all__ = [
    "CANONICALIZATION_VERSION",
    "NORMALIZER_VERSION",
    "ActionConstraint",
    "ActionEffect",
    "ActionIR",
    "ApiResource",
    "ArgumentConstraint",
    "CanonicalArgument",
    "CanonicalArguments",
    "CanonicalResource",
    "CanonicalScalar",
    "ConstraintOp",
    "DestinationConstraint",
    "EmailResource",
    "FileResource",
    "MemoryResource",
    "OtherResource",
    "ProcessResource",
    "ResourceBase",
    "ResourceConstraint",
    "ToolResource",
    "UrlResource",
]

# 规范化/摘要算法版本常量：任何规范化行为变化必须升级版本，而不是静默改变
# 既有 digest 语义（01 §29）。
NORMALIZER_VERSION = "v21-02-normalizer-2"
CANONICALIZATION_VERSION = "v21-02-jcs-subset-2"


# ---------------------------------------------------------------------------
# ActionEffect (01 §6, L215-230)
# ---------------------------------------------------------------------------


class ActionEffect(BaseModel):
    """多维动作副作用画像。

    冻结语义：不允许退回单枚举 ``side_effect``；每个维度独立可判定，
    ``reversible`` 为三态（True/False/未知 None）。
    """

    model_config = ConfigDict(extra="forbid")

    mutates_state: bool = False
    external_communication: bool = False
    persistence: bool = False
    privilege_use: bool = False
    destructive: bool = False
    reversible: bool | None = None
    data_egress: bool = False
    code_execution: bool = False
    network_access: bool = False


# ---------------------------------------------------------------------------
# CanonicalArguments (01 §7.1, L236-252)
# ---------------------------------------------------------------------------

CanonicalScalar = str | int | float | bool | None


class CanonicalArgument(BaseModel):
    """单个规范参数；``strict`` 校验禁止隐式协变（``"123" != 123``）。

    集合语义参数按 ``json_pointer`` 排序；授权 matcher 只能读取
    ``security_relevant=True`` 的规范参数（01 §7.1, L252）。
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    json_pointer: str
    value: CanonicalScalar | list[CanonicalScalar]
    security_relevant: bool


class CanonicalArguments(BaseModel):
    """规范参数集合 + canonical digest（items 按 ``json_pointer`` 排序）。"""

    model_config = ConfigDict(extra="forbid")

    items: list[CanonicalArgument]
    canonicalization_version: str
    argument_digest: str


# ---------------------------------------------------------------------------
# CanonicalResource discriminated union (01 §7.2, L254-342)
# ---------------------------------------------------------------------------


class ResourceBase(BaseModel):
    """资源规范化基类；``resolution_status`` 冻结为 resolved/partial/unresolved。

    冻结语义（01 §7.2, L337）：``unresolved`` 资源不能用于证明“明确授权”；
    授权针对最终 canonical/resolved identity。
    """

    model_config = ConfigDict(extra="forbid")

    resource_id: str
    canonical_id: str
    display_summary: str
    resolution_status: Literal["resolved", "partial", "unresolved"]
    normalizer_version: str


class FileResource(ResourceBase):
    kind: Literal["file"] = "file"
    normalized_path: str
    platform: Literal["windows", "posix", "unknown"]
    case_sensitive: bool | None
    symlink_resolution: Literal["resolved", "not_resolved", "not_applicable"]
    final_path: str | None


class UrlResource(ResourceBase):
    kind: Literal["url"] = "url"
    scheme: Literal["http", "https"]
    host_ascii: str
    port: int
    normalized_path: str
    query_keys: list[str]
    security_query_arguments: list[CanonicalArgument]
    redirect_policy: Literal["forbid", "same_authority_only", "runtime_recheck"]


class ApiResource(ResourceBase):
    kind: Literal["api"] = "api"
    scheme: Literal["http", "https"]
    host_ascii: str
    port: int
    normalized_path: str
    query_keys: list[str]
    security_query_arguments: list[CanonicalArgument]
    redirect_policy: Literal["forbid", "same_authority_only", "runtime_recheck"]
    method: str


class EmailResource(ResourceBase):
    kind: Literal["email"] = "email"
    normalized_address: str
    domain_ascii: str


class MemoryResource(ResourceBase):
    kind: Literal["memory"] = "memory"
    memory_id: str
    namespace: str | None


class ProcessResource(ResourceBase):
    kind: Literal["process"] = "process"
    executable: str
    interpreter: str | None


class ToolResource(ResourceBase):
    kind: Literal["tool"] = "tool"
    tool_name: str
    tool_schema_digest: str | None
    provider_binding_id: str | None


class OtherResource(ResourceBase):
    kind: Literal["other"] = "other"
    type_name: str
    stable_identifier: str | None


CanonicalResource = Annotated[
    FileResource
    | UrlResource
    | ApiResource
    | EmailResource
    | MemoryResource
    | ProcessResource
    | ToolResource
    | OtherResource,
    Field(discriminator="kind"),
]


# ---------------------------------------------------------------------------
# Constraint DSL (01 §8, L345-373)
# ---------------------------------------------------------------------------

ConstraintOp = Literal["eq", "in", "prefix", "range"]


class ActionConstraint(BaseModel):
    """动作类型约束；第一版 DSL 禁止任意解释器、eval 与不受控 regex。"""

    model_config = ConfigDict(extra="forbid")

    op: Literal["in"] = "in"
    action_types: list[str]


class ArgumentConstraint(BaseModel):
    """规范参数约束；只对 ``security_relevant=True`` 的参数可见。"""

    model_config = ConfigDict(extra="forbid")

    json_pointer: str
    op: ConstraintOp
    value: str | int | float | bool | list[str] | list[int]


class ResourceConstraint(BaseModel):
    """资源约束；``scheme`` 取资源 kind（file/url/api/email/memory/...）。"""

    model_config = ConfigDict(extra="forbid")

    scheme: str
    op: Literal["exact", "prefix", "in"]
    values: list[str]


class DestinationConstraint(BaseModel):
    """外部目标约束；``domain`` op 匹配 host/domain 及其子域。"""

    model_config = ConfigDict(extra="forbid")

    scheme: str
    op: Literal["exact", "domain", "prefix", "in"]
    values: list[str]


# ---------------------------------------------------------------------------
# ActionIR (01 §9, L376-412)
# ---------------------------------------------------------------------------


class ActionIR(BaseModel):
    """V2.1 最终动作中间表示；字段逐字冻结自 01 §9。

    指纹白名单遵循 01 §29：每种安全摘要只允许白名单字段参与，禁止
    “整个 model_dump 随模型增长自动进入摘要”。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2.1"] = "2.1"

    event_id: str
    action_id: str
    trace_id: str
    task_id: str | None
    task_revision: int | None
    scope_digest: str

    principal_id: str
    runtime: str
    runtime_binding_id: str
    agent_id: str
    branch_id: str | None
    parent_event_ids: list[str]
    runtime_sequence: int | None

    tool_name: str | None
    action_type: str
    effects: ActionEffect
    impact: ImpactClass

    resources: list[CanonicalResource]
    destinations: list[CanonicalResource]
    data_refs: list[str]
    canonical_arguments: CanonicalArguments
    argument_digest: str

    authorization_fingerprint: str
    audit_fingerprint: str

    normalizer_version: str

    @classmethod
    def authorization_fingerprint_fields(cls) -> frozenset[str]:
        """authorization_fingerprint 参与字段白名单（01 §9, L414-444）。

        键名与 ``fingerprints.authorization_projection`` 的实际投影键
        一一对应（契约测试断言两者相等）。参与：subject/principal、
        task_id/revision、action_type、final canonical resources/
        destinations、security-relevant arguments（投影键
        ``security_arguments``）、effect、runtime binding、scope_digest、
        argument_digest。
        排除：latency、random decision id、created_at、provider request id、
        display text、unordered debug metadata（靠只投影白名单天然排除；
        resource 投影另剔除 ``display_summary`` 与事件级 ``resource_id``）。
        """
        return frozenset(
            {
                "schema_version",
                "principal_id",
                "task_id",
                "task_revision",
                "action_type",
                "resources",
                "destinations",
                "security_arguments",
                "effects",
                "runtime_binding_id",
                "scope_digest",
                "argument_digest",
            }
        )

    @classmethod
    def audit_fingerprint_fields(cls) -> frozenset[str]:
        """audit_fingerprint 参与字段白名单（01 §9, L445-447）。

        键名与 ``fingerprints.audit_projection`` 的实际投影键一一对应
        （契约测试断言两者相等）；resource/destination 只投影
        canonical identity（``resource_ids``/``destination_ids``）。

        仅脱敏/摘要字段：可公开到 Audit/Dashboard，只用于关联和解释，
        不能承担授权安全语义。
        """
        return frozenset(
            {
                "schema_version",
                "event_id",
                "action_id",
                "trace_id",
                "tool_name",
                "action_type",
                "impact",
                "resource_ids",
                "destination_ids",
                "argument_digest",
                "normalizer_version",
            }
        )
