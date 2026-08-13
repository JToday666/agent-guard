"""生产端契约对齐测试：adapter 事件 wire 形状对 extra=forbid 语义的前置证明。

PR-3 范围：以「extra=forbid 语义」逐层断言 adapter 构造的事件 wire dict 键集合
全部落在 core 契约声明字段内（键 ⊆ 声明字段），为后续 PR-4 真正翻转
extra="forbid" 提供前置保证。当前 core 模型仍是 extra="allow"，故通过手工
键集合比对实现同等语义，不改动模型配置。
"""

import sys
from pathlib import Path
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from agentguard_langgraph_adapter.config import AgentGuardLangGraphConfig  # noqa: E402
from agentguard_langgraph_adapter.core_client import _guard_api_v03_event  # noqa: E402
from agentguard_langgraph_adapter.langgraph_adapter import (  # noqa: E402
    LangGraphAdapter,
)
from agentguard_core import GuardEvent  # noqa: E402
from agentguard_core.events.payloads import (  # noqa: E402
    ContextBuildPayload,
    ContextSource,
    DerivedResource,
    MemoryEventPayload,
    MemoryRecord,
    SecurityContext,
    ToolDescriptor,
    ToolResult,
    ToolResultPayload,
)

# core 契约声明的键集合（extra=forbid 语义的基准）。
GUARD_EVENT_FIELDS = set(GuardEvent.model_fields)
SECURITY_CONTEXT_FIELDS = set(SecurityContext.model_fields)
TOOL_DESCRIPTOR_FIELDS = set(ToolDescriptor.model_fields)
DERIVED_RESOURCE_FIELDS = set(DerivedResource.model_fields)
CONTEXT_SOURCE_FIELDS = set(ContextSource.model_fields)
TOOL_RESULT_FIELDS = set(ToolResult.model_fields)
MEMORY_RECORD_FIELDS = set(MemoryRecord.model_fields)
PAYLOAD_FIELDS_BY_EVENT_TYPE: dict[str, set[str]] = {
    "tool_call_proposed": {"tool", "arguments", "derived_resources"},
    "context_assembled": set(ContextBuildPayload.model_fields),
    "tool_result_produced": set(ToolResultPayload.model_fields),
    "memory_write_proposed": set(MemoryEventPayload.model_fields),
}


def _assert_keys_within(label: str, data: Any, allowed: set[str]) -> dict[str, Any]:
    assert isinstance(data, dict), f"{label} 应为 dict，实际为 {type(data)!r}"
    extra = set(data) - allowed
    assert not extra, f"{label} 携带契约外字段: {sorted(extra)}"
    return data


def assert_guard_event_contract(wire: dict[str, Any]) -> None:
    """以 extra=forbid 语义逐层校验 wire dict，并用 core 模型复验可解析性。"""
    _assert_keys_within("GuardEvent 顶层", wire, GUARD_EVENT_FIELDS)
    context = _assert_keys_within(
        "security_context", wire["security_context"], SECURITY_CONTEXT_FIELDS
    )
    event_type = wire["event_type"]
    payload_allowed = PAYLOAD_FIELDS_BY_EVENT_TYPE[event_type]
    payload = _assert_keys_within("payload", wire["payload"], payload_allowed)

    for index, resource in enumerate(payload.get("derived_resources", [])):
        _assert_keys_within(
            f"payload.derived_resources[{index}]", resource, DERIVED_RESOURCE_FIELDS
        )
    if "tool" in payload:
        _assert_keys_within("payload.tool", payload["tool"], TOOL_DESCRIPTOR_FIELDS)
    if "result" in payload:
        _assert_keys_within("payload.result", payload["result"], TOOL_RESULT_FIELDS)
    if "sources" in payload:
        for index, source in enumerate(payload["sources"]):
            _assert_keys_within(
                f"payload.sources[{index}]", source, CONTEXT_SOURCE_FIELDS
            )
    if "memory" in payload:
        _assert_keys_within("payload.memory", payload["memory"], MEMORY_RECORD_FIELDS)
    assert isinstance(context, dict)

    # core 模型必须能解析该 wire（含正式字段增补后的会话身份/action_id 字段）。
    parsed = GuardEvent.model_validate(wire)
    assert parsed.event_type == event_type


def _build_adapter() -> LangGraphAdapter:
    return LangGraphAdapter(
        config=AgentGuardLangGraphConfig(api_mode="guard-api-v0.3"),
        core_client=None,
    )


def test_adapter_tool_call_event_satisfies_extra_forbid_contract() -> None:
    adapter = _build_adapter()
    event = adapter.build_tool_call_event(
        tool_name="rag_retrieve",
        arguments={"dataset": "support", "question_id": "q1"},
        security={
            "user_task": "Answer from support knowledge.",
            "source_trust": "untrusted",
        },
        trace_id="trace_contract_tool_call",
        call_id="call_contract",
    )

    wire = _guard_api_v03_event(event.model_dump())
    assert_guard_event_contract(wire)
    assert wire["payload"]["tool"]["call_id"] == "call_contract"


def test_adapter_memory_write_event_satisfies_extra_forbid_contract() -> None:
    adapter = _build_adapter()
    event = adapter.build_memory_write_event(
        arguments={
            "namespace": "user_preferences",
            "key": "style",
            "value": "concise",
            "_source_tool_call_id": "call_src_001",
        },
        security={
            "user_task": "Persist a user preference.",
            "source_trust": "trusted",
        },
        trace_id="trace_contract_memory",
    )

    wire = event.model_dump()
    assert_guard_event_contract(wire)
    # action_id 已是 MemoryEventPayload 正式字段，随 payload 传递。
    assert wire["payload"]["action_id"] == "call_src_001"


def test_adapter_context_event_satisfies_extra_forbid_contract() -> None:
    adapter = _build_adapter()
    event = adapter.build_context_event(
        sources=[{"source_id": "doc_1", "summary": "harmless summary"}],
        security={
            "user_task": "Assemble context.",
            "source_trust": "untrusted",
        },
        trace_id="trace_contract_context",
    )

    wire = event.model_dump()
    assert_guard_event_contract(wire)


def test_adapter_tool_result_event_satisfies_extra_forbid_contract() -> None:
    adapter = _build_adapter()
    event = adapter.build_tool_result_event(
        tool_name="rag_retrieve",
        arguments={"dataset": "support", "question_id": "q1"},
        result={"contexts": ["harmless context"]},
        security={
            "user_task": "Answer from support knowledge.",
            "source_trust": "untrusted",
        },
        trace_id="trace_contract_tool_result",
        call_id="call_contract_result",
    )

    wire = event.model_dump()
    assert_guard_event_contract(wire)
