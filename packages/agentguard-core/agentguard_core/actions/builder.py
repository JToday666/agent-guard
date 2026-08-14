"""ActionIR builder for V21-02: GuardEvent → ActionIR 编排层。

编排顺序（不 import 判定路径 ``engine`` / ``decisions/policy``）：

1. payload 类型分派：工具名 → 资源类型映射以常量表在本文件内实现
   （read_file→file、send_email→email、call_api→api、exec-like→process、
   memory_write→memory 等，先例参考 ``events/resources.py::derive_resources``）；
2. ``ActionEffect`` 表驱动推导 → ``ImpactClass`` 由 effect 位推导；
3. 参数规范化（``normalize``）与资源规范化（``canonical_resources``）；
4. 指纹计算（``fingerprints``）。

V21-03 前置字段（task_id/task_revision/principal/runtime binding/
scope_digest）缺省时，用确定性 claim 级占位 + reason_code 标记：
reason_code 以 ``v21-02:`` 前缀写入 ``ActionIR.data_refs``。V21-03 的
Task Authority / Capability Registry 接入点即为替换这些占位的入口。
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..decisions.models import GuardDecision
from ..events.contracts import GuardEvent
from ..events.payloads import (
    ContextBuildPayload,
    MemoryEventPayload,
    MessageSendPayload,
    ModelCallPayload,
    ToolCallPayload,
    ToolResultPayload,
)
from ..events.resources import is_exec_like_tool
from ..signals.models import EvaluationDegradation, ImpactClass
from .canonical_json import canonical_json_bytes
from .canonical_resources import (
    RESOURCE_NORMALIZERS,
    ResourceNormalizationInput,
    SymlinkResolver,
)
from .fingerprints import audit_fingerprint, authorization_fingerprint
from .models import NORMALIZER_VERSION, ActionEffect, ActionIR, CanonicalResource
from .normalize import normalize_arguments

__all__ = ["ShadowEvaluation", "build_action_ir", "build_shadow_evaluation"]

# 外部目标 kind：进入 ActionIR.destinations；其余进入 resources。
_DESTINATION_KINDS = frozenset({"url", "api", "email"})

# 工具名 → (资源 kind, 目标参数候选键)。不 import 判定路径，先例参考
# events/resources.py::derive_resources 的工具映射。
_TOOL_RESOURCE_MAP: Mapping[str, tuple[str, tuple[str, ...]]] = {
    "read_file": ("file", ("path", "file", "file_path")),
    "write_file": ("file", ("path", "file", "file_path")),
    "delete_file": ("file", ("path", "file", "file_path")),
    "create_file": ("file", ("path", "file", "file_path")),
    "send_email": ("email", ("to", "recipient", "address")),
    "call_api": ("api", ("url", "endpoint", "uri")),
    "http_request": ("api", ("url", "endpoint", "uri")),
    "browse_url": ("url", ("url", "link", "target")),
    "browser_extract_text": ("url", ("url", "link", "target")),
    "memory_write": ("memory", ("key", "memory_id")),
    "memory_read": ("memory", ("key", "memory_id")),
}

# event_type → action_type。
_ACTION_TYPE_BY_EVENT: Mapping[str, str] = {
    "tool_call_proposed": "tool_call",
    "context_assembled": "context_build",
    "model_input_prepared": "model_call",
    "model_output_produced": "model_call",
    "tool_result_produced": "tool_result",
    "memory_write_proposed": "memory_write",
    "message_send_proposed": "message_send",
}

# context_source 等其他派生资源的有界上限。
_MAX_DERIVED_RESOURCES = 16
REASON_DERIVED_RESOURCE_LIMIT = "resources.derived_limit_exceeded"
REASON_RESOURCE_TARGET_MISSING = "resources.target_missing"


@dataclass(frozen=True)
class ShadowEvaluation:
    """Shadow 模式评估结果：legacy 判定为主，ActionIR 只做旁路记录。

    ``degradation`` 记录 ActionIR 构建侧的结构化降级（例如 builder 异常）；
    构建失败时 ``action_ir`` 为 None，legacy ``decision`` 不受影响。
    """

    decision: GuardDecision
    action_ir: ActionIR | None
    degradation: EvaluationDegradation | None


# ---------------------------------------------------------------------------
# ActionEffect / ImpactClass 推导
# ---------------------------------------------------------------------------


def _effects_for_tool(tool: Any) -> ActionEffect:
    name = str(getattr(tool, "name", "") or "").lower()
    if is_exec_like_tool(tool):
        return ActionEffect(
            code_execution=True,
            mutates_state=True,
            privilege_use=True,
            reversible=False,
        )
    kind, _ = _TOOL_RESOURCE_MAP.get(name, (None, ()))
    if kind == "file":
        if name.startswith("read"):
            return ActionEffect()
        return ActionEffect(mutates_state=True, persistence=True, reversible=True)
    if kind == "email":
        return ActionEffect(
            external_communication=True, data_egress=True, network_access=True
        )
    if kind in {"api", "url"}:
        return ActionEffect(network_access=True, external_communication=True)
    if kind == "memory":
        return ActionEffect(mutates_state=True, persistence=True, reversible=True)
    # 未画像工具：保守假设会变更状态，交由策略层处置。
    return ActionEffect(mutates_state=True)


def _effects_for_event(event: GuardEvent) -> ActionEffect:
    payload = event.payload
    if isinstance(payload, ToolCallPayload):
        return _effects_for_tool(payload.tool)
    if isinstance(payload, MemoryEventPayload):
        return ActionEffect(mutates_state=True, persistence=True, reversible=True)
    if isinstance(payload, MessageSendPayload):
        return ActionEffect(
            external_communication=True, data_egress=True, network_access=True
        )
    if isinstance(payload, ModelCallPayload):
        return ActionEffect(
            external_communication=True, data_egress=True, network_access=True
        )
    # ContextBuildPayload / ToolResultPayload：观察类事件，无副作用位。
    return ActionEffect()


def _impact_for_effects(effects: ActionEffect) -> ImpactClass:
    """ImpactClass 由 effect 位推导（确定性、无外部输入）。"""
    if effects.destructive:
        return "critical"
    if (
        effects.code_execution
        or effects.privilege_use
        or (effects.data_egress and effects.external_communication)
    ):
        return "high"
    if (
        effects.mutates_state
        or effects.persistence
        or effects.network_access
        or effects.external_communication
        or effects.data_egress
    ):
        return "moderate"
    return "low"


# ---------------------------------------------------------------------------
# payload 分派 → canonical resources/destinations
# ---------------------------------------------------------------------------


def _first_argument_value(arguments: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = arguments.get(key)
        if value is not None and str(value):
            return str(value)
    return ""


def _normalize_one(
    event: GuardEvent,
    *,
    kind: str,
    target: str,
    index: int,
    reason_codes: list[str],
    method: str | None = None,
    memory_namespace: str | None = None,
    tool_name: str | None = None,
    resolver: SymlinkResolver | None = None,
) -> CanonicalResource:
    normalizer = RESOURCE_NORMALIZERS.get(kind, RESOURCE_NORMALIZERS["other"])
    return normalizer(
        ResourceNormalizationInput(
            resource_id=f"{event.event_id}:res:{index}",
            target=target,
            method=method,
            memory_namespace=memory_namespace,
            tool_name=tool_name,
            resolver=resolver,
        )
    )


def _tool_call_resources(
    event: GuardEvent,
    payload: ToolCallPayload,
    *,
    reason_codes: list[str],
    resolver: SymlinkResolver | None,
) -> list[CanonicalResource]:
    tool_name = payload.tool.name
    arguments = payload.arguments
    lowered = tool_name.lower()

    if is_exec_like_tool(payload.tool):
        kind, target = "process", _first_argument_value(
            arguments, ("command", "cmd", "code")
        )
        method = None
        namespace = None
    else:
        mapped = _TOOL_RESOURCE_MAP.get(lowered)
        if mapped is not None:
            kind, keys = mapped
            target = _first_argument_value(arguments, keys)
        else:
            kind, target = "tool", tool_name
        method = None
        if kind == "api":
            method = str(arguments.get("method") or "") or None
        namespace = str(arguments.get("namespace") or "") or None

    if kind != "tool" and not target:
        reason_codes.append(REASON_RESOURCE_TARGET_MISSING)
        kind = "tool"  # 无目标时退回工具自身 identity，fail-closed。

    return [
        _normalize_one(
            event,
            kind=kind,
            target=target,
            index=0,
            reason_codes=reason_codes,
            method=method,
            memory_namespace=namespace,
            tool_name=tool_name,
            resolver=resolver,
        )
    ]


def _payload_resources(
    event: GuardEvent,
    *,
    reason_codes: list[str],
    resolver: SymlinkResolver | None,
) -> list[CanonicalResource]:
    payload = event.payload
    if isinstance(payload, ToolCallPayload):
        return _tool_call_resources(
            event, payload, reason_codes=reason_codes, resolver=resolver
        )
    if isinstance(payload, MessageSendPayload):
        return [
            _normalize_one(
                event,
                kind="email",
                target=payload.recipient,
                index=0,
                reason_codes=reason_codes,
                resolver=resolver,
            )
        ]
    if isinstance(payload, MemoryEventPayload):
        return [
            _normalize_one(
                event,
                kind="memory",
                target=payload.memory.key,
                index=0,
                reason_codes=reason_codes,
                memory_namespace=payload.memory.namespace,
                resolver=resolver,
            )
        ]
    if isinstance(payload, ToolResultPayload):
        return [
            _normalize_one(
                event,
                kind="other",
                target=f"tool_result:{payload.tool.call_id}",
                index=0,
                reason_codes=reason_codes,
                resolver=resolver,
            )
        ]
    if isinstance(payload, ModelCallPayload):
        return [
            _normalize_one(
                event,
                kind="other",
                target=f"model:{payload.model or payload.provider or 'model'}",
                index=0,
                reason_codes=reason_codes,
                resolver=resolver,
            )
        ]
    if isinstance(payload, ContextBuildPayload):
        targets = list(event.security_context.derived_paths) or [
            source.source_id for source in payload.sources
        ]
        if len(targets) > _MAX_DERIVED_RESOURCES:
            targets = targets[:_MAX_DERIVED_RESOURCES]
            reason_codes.append(REASON_DERIVED_RESOURCE_LIMIT)
        return [
            _normalize_one(
                event,
                kind="other",
                target=target,
                index=index,
                reason_codes=reason_codes,
                resolver=resolver,
            )
            for index, target in enumerate(targets)
        ]
    return []


# ---------------------------------------------------------------------------
# build_action_ir
# ---------------------------------------------------------------------------


def build_action_ir(
    event: GuardEvent,
    *,
    server_secret: bytes,
    task_id: str | None = None,
    task_revision: int | None = None,
    scope_digest: str | None = None,
    principal_id: str | None = None,
    runtime_binding_id: str | None = None,
    resolver: SymlinkResolver | None = None,
) -> ActionIR:
    """把 GuardEvent 编排为确定性 ActionIR。

    V21-03 前置字段缺省时使用确定性 claim 级占位 + reason_code 标记；
    V21-03 接入点：Task Authority API（task_id/task_revision/scope_digest）
    与 Runtime Binding Registry（principal_id/runtime_binding_id）。
    """
    reason_codes: list[str] = []
    agent_id = event.security_context.agent_id

    if task_id is None:
        reason_codes.append("claim.task_id")
    if task_revision is None:
        reason_codes.append("claim.task_revision")
    if principal_id is None:
        principal_id = f"principal:claim:{agent_id}"
        reason_codes.append("claim.principal_id")
    if runtime_binding_id is None:
        runtime_binding_id = f"binding:claim:{event.runtime}:{agent_id}"
        reason_codes.append("claim.runtime_binding_id")
    if scope_digest is None:
        scope_digest = "sha256:" + hashlib.sha256(
            canonical_json_bytes(
                {
                    "claim": "scope_digest",
                    "runtime": event.runtime,
                    "agent_id": agent_id,
                }
            )
        ).hexdigest()
        reason_codes.append("claim.scope_digest")

    payload = event.payload
    tool_name = (
        payload.tool.name
        if isinstance(payload, (ToolCallPayload, ToolResultPayload))
        else None
    )
    action_type = _ACTION_TYPE_BY_EVENT.get(event.event_type, event.event_type)
    effects = _effects_for_event(event)
    impact = _impact_for_effects(effects)

    normalized_arguments = normalize_arguments(
        payload.arguments if isinstance(payload, ToolCallPayload) else {}
    )
    reason_codes.extend(normalized_arguments.reason_codes)

    produced = _payload_resources(
        event, reason_codes=reason_codes, resolver=resolver
    )
    resources = [item for item in produced if item.kind not in _DESTINATION_KINDS]
    destinations = [item for item in produced if item.kind in _DESTINATION_KINDS]

    data_refs = [f"event:{event.event_id}", f"trace:{event.trace_id}"]
    data_refs.extend(f"v21-02:{code}" for code in reason_codes)

    metadata = event.metadata
    parent_event_ids = (
        [str(item) for item in metadata.get("parent_event_ids", [])]
        if isinstance(metadata.get("parent_event_ids"), list)
        else []
    )
    runtime_sequence = (
        int(metadata["runtime_sequence"])
        if isinstance(metadata.get("runtime_sequence"), int)
        else None
    )
    branch_id = (
        str(metadata["branch_id"])
        if isinstance(metadata.get("branch_id"), str)
        else None
    )

    placeholder = ActionIR(
        event_id=event.event_id,
        action_id=f"act_{event.event_id}",
        trace_id=event.trace_id,
        task_id=task_id,
        task_revision=task_revision,
        scope_digest=scope_digest,
        principal_id=principal_id,
        runtime=event.runtime,
        runtime_binding_id=runtime_binding_id,
        agent_id=agent_id,
        branch_id=branch_id,
        parent_event_ids=parent_event_ids,
        runtime_sequence=runtime_sequence,
        tool_name=tool_name,
        action_type=action_type,
        effects=effects,
        impact=impact,
        resources=resources,
        destinations=destinations,
        data_refs=data_refs,
        canonical_arguments=normalized_arguments.canonical,
        argument_digest=normalized_arguments.canonical.argument_digest,
        authorization_fingerprint="",
        audit_fingerprint="",
        normalizer_version=NORMALIZER_VERSION,
    )
    return placeholder.model_copy(
        update={
            "authorization_fingerprint": authorization_fingerprint(
                server_secret, placeholder
            ),
            "audit_fingerprint": audit_fingerprint(placeholder),
        }
    )


def build_shadow_evaluation(
    event: GuardEvent,
    *,
    decision: GuardDecision,
    server_secret: bytes,
    task_id: str | None = None,
    task_revision: int | None = None,
    scope_digest: str | None = None,
    principal_id: str | None = None,
    runtime_binding_id: str | None = None,
    resolver: SymlinkResolver | None = None,
) -> ShadowEvaluation:
    """Shadow 编排：legacy ``decision`` 为主，ActionIR 旁路构建。

    builder 异常被 try/except 吸收，失败时产出带结构化
    ``EvaluationDegradation`` 的结果（``action_ir=None``），绝不外抛；
    legacy 判定不受 ActionIR 构建成败影响。
    """
    try:
        action_ir: ActionIR | None = build_action_ir(
            event,
            server_secret=server_secret,
            task_id=task_id,
            task_revision=task_revision,
            scope_digest=scope_digest,
            principal_id=principal_id,
            runtime_binding_id=runtime_binding_id,
            resolver=resolver,
        )
        degradation = None
    except Exception as exc:  # noqa: BLE001 - 旁路构建失败必须收敛，不外抛。
        action_ir = None
        degradation = EvaluationDegradation(
            degradation_id=f"actionir-degrade:{event.event_id}",
            component_id="v21-02-action-ir-builder",
            domain=None,
            required_for_action=False,
            failure_kind="unavailable",
            reason_codes=[
                "action_ir.build_failed",
                f"action_ir.build_failed:{type(exc).__name__}",
            ],
            evidence_refs=[],
        )
    return ShadowEvaluation(
        decision=decision, action_ir=action_ir, degradation=degradation
    )
