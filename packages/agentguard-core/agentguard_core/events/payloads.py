"""GuardEvent payload models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

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
    context_sources: list[dict[str, Any]] = Field(default_factory=list)
    derived_paths: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


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
