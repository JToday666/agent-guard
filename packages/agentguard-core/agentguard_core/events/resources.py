"""Resource derivation helpers for GuardEvent payloads."""

from __future__ import annotations

from typing import Any

from .contracts import GuardEvent
from .payloads import (
    ContextBuildPayload,
    DerivedResource,
    MemoryEventPayload,
    MessageSendPayload,
    ModelCallPayload,
    ToolCallPayload,
    ToolResultPayload,
)


def derive_resources(event: GuardEvent) -> list[DerivedResource]:
    resources = _canonical_resources(event)
    derived_resources = getattr(event.payload, "derived_resources", [])
    if derived_resources:
        resources.extend(derived_resources)
    return _dedupe_resources(resources)


def _canonical_resources(event: GuardEvent) -> list[DerivedResource]:
    if isinstance(event.payload, MessageSendPayload):
        return [
            DerivedResource(
                resource_type="message",
                operation="send",
                target=event.payload.recipient,
                data_classification="sensitive" if event.payload.contains_sensitive_data else None,
                direction="outbound",
            )
        ]
    if isinstance(event.payload, MemoryEventPayload):
        return [
            DerivedResource(
                resource_type="memory",
                operation=event.payload.memory.operation,
                target=f"{event.payload.memory.namespace}/{event.payload.memory.key}",
                data_classification=None,
                direction="persistent",
            )
        ]
    if isinstance(event.payload, ToolResultPayload):
        return [
            DerivedResource(
                resource_type="tool_result",
                operation="persist" if event.payload.will_persist else "context",
                target=event.payload.tool.call_id,
                data_classification="sensitive" if event.payload.contains_sensitive_data else None,
                direction="inbound",
            )
        ]
    if isinstance(event.payload, ContextBuildPayload):
        return [
            DerivedResource(
                resource_type="context_source",
                operation="assemble",
                target=source.source_id,
                data_classification="sensitive" if source.contains_sensitive_data else None,
                direction="inbound",
            )
            for source in event.payload.sources
        ]
    if isinstance(event.payload, ModelCallPayload):
        return [
            DerivedResource(
                resource_type="model",
                operation=event.payload.phase,
                target=event.payload.model or event.payload.provider or "model",
                data_classification="sensitive" if event.payload.contains_sensitive_data else None,
                direction="model",
            )
        ]
    if not isinstance(event.payload, ToolCallPayload):
        return []

    tool = event.payload.tool.name
    args: dict[str, Any] = event.payload.arguments
    if tool == "read_file":
        return [
            DerivedResource(
                resource_type="file",
                operation="read",
                target=str(args.get("path") or ""),
                data_classification=None,
                direction="local",
            )
        ]
    if tool == "write_file":
        return [
            DerivedResource(
                resource_type="file",
                operation="write",
                target=str(args.get("path") or ""),
                data_classification=None,
                direction="local",
            )
        ]
    if tool == "send_email":
        return [
            DerivedResource(
                resource_type="message",
                operation="send",
                target=str(args.get("to") or ""),
                data_classification=None,
                direction="outbound",
            )
        ]
    if tool == "call_api":
        return [
            DerivedResource(
                resource_type="api",
                operation=str(args.get("method") or "GET").upper(),
                target=str(args.get("url") or ""),
                data_classification=None,
                direction="outbound",
            )
        ]
    if tool == "code_exec":
        return [
            DerivedResource(
                resource_type="process",
                operation="execute",
                target=tool_argument_text(args, "command", "cmd", "code"),
                data_classification=None,
                direction="local",
            )
        ]
    if tool == "memory_write":
        namespace = str(args.get("namespace") or "")
        key = str(args.get("key") or "")
        return [
            DerivedResource(
                resource_type="memory",
                operation="write",
                target="/".join(item for item in [namespace, key] if item),
                data_classification=None,
                direction="persistent",
            )
        ]
    return []


def _dedupe_resources(resources: list[DerivedResource]) -> list[DerivedResource]:
    deduped: list[DerivedResource] = []
    seen: set[tuple[str, str, str, str]] = set()
    for resource in resources:
        key = (resource.resource_type, resource.operation, resource.target, resource.direction)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(resource)
    return deduped


def tool_argument_text(arguments: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = arguments.get(key)
        if value is not None:
            return str(value)
    return ""
