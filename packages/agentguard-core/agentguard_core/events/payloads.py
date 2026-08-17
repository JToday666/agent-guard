"""GuardEvent payload models."""

from __future__ import annotations

from typing import Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)

from ..ids import new_id


class SecurityContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    user_task: str = ""
    source_type: str = "user"
    source_trust: str = "trusted"
    channel: str | None = None
    sender_id: str | None = None
    # 会话身份字段：OpenClaw 插件与 LangGraph adapter 已作为会话关联信息发送，
    # 收入正式契约以避免它们停留在 extra 通道（为 extra=forbid 翻转做准备）。
    conversation_id: str | None = None
    session_key: str | None = None
    session_id: str | None = None
    run_id: str | None = None
    agent_id: str = "main"
    current_step: str = "before_tool"
    model_intent: str | None = None
    # Gate A current-event provenance ingress.  ``None`` means the Runtime
    # cannot prove the visible set, while an explicit empty tuple means it
    # proved that the set is empty.  The wrap serializer below preserves the
    # legacy wire shape on every supported Pydantic >=2.9 release; field-level
    # ``exclude_if`` is newer than the package's declared minimum.
    visible_source_refs: tuple[str, ...] | None = None
    context_sources: list[dict[str, Any]] = Field(default_factory=list)
    derived_paths: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_serializer(mode="wrap")
    def _serialize_optional_visible_refs(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        serialized = handler(self)
        if self.visible_source_refs is None:
            serialized.pop("visible_source_refs", None)
        return serialized


class ToolDescriptor(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    category: str = "tool"
    kind: str | None = None
    input_kind: str | None = None
    call_id: str = Field(default_factory=lambda: new_id("call"))

    def model_post_init(self, __context: Any) -> None:
        if self.kind is None:
            self.kind = self.name


class DerivedResource(BaseModel):
    model_config = ConfigDict(extra="allow")

    resource_type: str
    operation: str
    target: str
    data_classification: str | None = None
    direction: str


class ToolCallPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    tool: ToolDescriptor
    arguments: dict[str, Any] = Field(default_factory=dict)
    derived_resources: list[DerivedResource] = Field(default_factory=list)


class ContextSource(BaseModel):
    model_config = ConfigDict(extra="allow")

    source_id: str
    source_type: str
    source_trust: str = "trusted"
    summary: str = ""
    contains_instruction_like_text: bool = False
    contains_sensitive_data: bool = False
    # CT-PR-04 additive binding fields.  They remain optional so legacy
    # producers retain their canonical request shape; when isolation is
    # required the server accepts a source only if all bindings are present.
    content_digest: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    role: str | None = Field(default=None, min_length=1, max_length=32)
    sequence_index: int | None = Field(default=None, ge=0)


class ContextBuildPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    sources: list[ContextSource] = Field(default_factory=list)
    will_enter_context: bool = True
    sanitized: bool = False


class ModelCallPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    phase: Literal["input", "output"]
    content_preview: str = ""
    provider: str | None = None
    model: str | None = None
    contains_instruction_like_text: bool = False
    contains_sensitive_data: bool = False
    sanitized: bool = False
    tool_plan: list[dict[str, Any]] = Field(default_factory=list)
    # CT-PR-04 runtime receipt of the exact plan used to rebuild this input.
    # All-or-none validation is performed by the LangGraph adapter before the
    # event is emitted; optional defaults preserve legacy producers.
    context_plan_id: str | None = Field(default=None, min_length=1, max_length=256)
    context_plan_digest: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    context_ref: str | None = Field(default=None, min_length=1, max_length=256)
    visible_source_refs: tuple[str, ...] | None = None

    @model_validator(mode="after")
    def validate_context_plan_identity(self) -> Self:
        identity = (
            self.context_plan_id,
            self.context_plan_digest,
            self.context_ref,
            self.visible_source_refs,
        )
        if any(value is not None for value in identity) and not all(
            value is not None for value in identity
        ):
            raise ValueError("context plan model-input identity must be complete")
        if self.visible_source_refs is not None:
            if any(not ref or len(ref) > 512 for ref in self.visible_source_refs):
                raise ValueError("visible_source_refs must contain bounded non-empty refs")
            if len(self.visible_source_refs) != len(set(self.visible_source_refs)):
                raise ValueError("visible_source_refs must be unique")
        return self


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    content_preview: str = ""
    content_type: str = "text/plain"
    size_bytes: int = Field(default=0, ge=0)


class ToolResultPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    tool: ToolDescriptor
    result: ToolResult
    will_enter_context: bool = False
    will_persist: bool = False
    sanitized: bool = False
    contains_sensitive_data: bool = False
    contains_instruction_like_text: bool = False
    derived_resources: list[DerivedResource] = Field(default_factory=list)


class MemoryRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    namespace: str
    key: str
    value_preview: str = ""
    source_trust: str = "trusted"
    operation: str = "write"


class MemoryEventPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    memory: MemoryRecord
    will_persist: bool = True
    requires_approval: bool = False
    # 来源工具调用 ID：LangGraph adapter 的 memory_write_proposed 事件用它把
    # 记忆写入动作关联回触发它的工具调用（稳定 action_id）。
    action_id: str | None = None


class MessageSendPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    channel: str
    recipient: str
    content_preview: str = ""
    contains_sensitive_data: bool = False
    sanitized: bool = False
    derived_resources: list[DerivedResource] = Field(default_factory=list)


GuardPayload = (
    ContextBuildPayload
    | ModelCallPayload
    | ToolResultPayload
    | MemoryEventPayload
    | MessageSendPayload
    | ToolCallPayload
)

GuardEventType = Literal[
    "tool_call_proposed",
    "context_assembled",
    "model_input_prepared",
    "model_output_produced",
    "tool_result_produced",
    "memory_write_proposed",
    "message_send_proposed",
]
