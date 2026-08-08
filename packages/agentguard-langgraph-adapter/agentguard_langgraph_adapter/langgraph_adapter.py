"""LangGraph adapter for AgentGuard Core decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .config import AgentGuardLangGraphConfig
from .core_client import (
    AgentGuardCoreClient,
    CoreClientError,
    CoreClientProtocol,
    FakeDenyCoreClient,
)
from .event_models import (
    AuditEvent,
    DerivedResource,
    PolicyDecision,
    RuntimeGuardEvent,
    RuleHit,
    SecurityContext,
    ToolCallEvent,
    ToolDescriptor,
    ToolExecutionResult,
    new_id,
)

TOOL_METADATA = {
    "read_file": ("file", "file_read", "read"),
    "write_file": ("file", "file_write", "write"),
    "send_email": ("message", "email_send", "send"),
    "call_api": ("api", "http_request", "request"),
    "code_exec": ("code", "command_exec", "execute"),
    "memory_write": ("memory", "memory_write", "write"),
    "memory_read": ("memory", "memory_read", "read"),
    "memory_search": ("memory", "memory_search", "search"),
    "browser_start": ("browser", "browser_session", "open"),
    "browser_navigate": ("browser", "browser_navigation", "open"),
    "browser_input": ("browser", "browser_input", "input"),
    "browser_click": ("browser", "browser_click", "click"),
    "browser_extract_text": ("browser", "browser_extract", "extract"),
    "browser_inspect": ("browser", "browser_inspect", "inspect"),
    "mcp_call": ("mcp", "mcp_tool_call", "call"),
    "rag_retrieve": ("rag", "rag_retrieve", "retrieve"),
    "rag_answer": ("rag", "rag_answer", "answer"),
}
TRUSTED_SOURCE_TRUST = {"trusted", "verified", "sanitized", "clean"}


@dataclass(slots=True)
class LangGraphAdapter:
    config: Any = field(default_factory=AgentGuardLangGraphConfig)
    core_client: CoreClientProtocol | None = None

    def __post_init__(self) -> None:
        if self.core_client is None:
            self.core_client = AgentGuardCoreClient(self.config)

    @classmethod
    def with_fake_deny_core(cls, config: Any | None = None) -> "LangGraphAdapter":
        return cls(
            config=config or AgentGuardLangGraphConfig(defense_enabled=True),
            core_client=FakeDenyCoreClient(),
        )

    def evaluate_before_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ) -> tuple[ToolCallEvent, PolicyDecision]:
        event = self.build_tool_call_event(
            tool_name=tool_name,
            arguments=arguments,
            security=security,
            trace_id=trace_id,
            call_id=call_id,
        )
        if not self.config.defense_enabled:
            return event, PolicyDecision(
                decision_id="dec_defense_off",
                decision="allow",
                risk_score=0,
                severity="low",
                rule_hits=[],
                reason="Defense is disabled for this benchmark run.",
                safe_message=None,
                latency_ms=0,
            )

        try:
            assert self.core_client is not None
            raw_decision = self.core_client.evaluate_tool_call(event.model_dump())
            decision = PolicyDecision.model_validate(raw_decision)
        except Exception as exc:
            if self.config.fail_closed:
                decision = PolicyDecision(
                    decision_id="dec_fail_closed",
                    decision="deny",
                    risk_score=100,
                    severity="high",
                    rule_hits=[
                        RuleHit(
                            rule_id="AGENTGUARD_FAIL_CLOSED",
                            rule_name="AgentGuard Fail Closed",
                            severity="high",
                            evidence=[str(exc)],
                        )
                    ],
                    reason=f"Core unavailable or invalid; fail_closed blocked the tool call: {exc}",
                    safe_message="The tool call was blocked because AgentGuard Core was unavailable.",
                    latency_ms=None,
                )
            else:
                decision = PolicyDecision(
                    decision_id="dec_fail_open_debug",
                    decision="allow",
                    risk_score=0,
                    severity="low",
                    rule_hits=[],
                    reason=f"Core unavailable; fail_closed=false allowed local debug execution: {exc}",
                    safe_message=None,
                    latency_ms=None,
                )
        return event, decision

    def evaluate_guard_event(
        self, event: RuntimeGuardEvent | dict[str, Any]
    ) -> PolicyDecision:
        if not self.config.defense_enabled:
            return _allow_decision("Defense is disabled for this benchmark run.")
        try:
            assert self.core_client is not None
            if not hasattr(self.core_client, "evaluate_guard_event"):
                return _allow_decision(
                    "Core client does not implement runtime guard events; "
                    "allowed for explicit compatibility clients."
                )
            raw_decision = self.core_client.evaluate_guard_event(_event_dump(event))
            return PolicyDecision.model_validate(raw_decision)
        except Exception as exc:
            return _failure_decision(exc, fail_closed=self.config.fail_closed)

    def evaluate_context(
        self,
        *,
        sources: list[Any],
        security: dict[str, Any],
        trace_id: str,
        will_enter_context: bool = True,
        sanitized: bool = False,
    ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
        event = self.build_context_event(
            sources=sources,
            security=security,
            trace_id=trace_id,
            will_enter_context=will_enter_context,
            sanitized=sanitized,
        )
        return event, self.evaluate_guard_event(event)

    def evaluate_model_input(
        self,
        *,
        content: Any,
        security: dict[str, Any],
        trace_id: str,
        provider: str | None = None,
        model: str | None = None,
        sanitized: bool = False,
        tool_plan: list[dict[str, Any]] | None = None,
    ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
        event = self.build_model_event(
            phase="input",
            content=content,
            security=security,
            trace_id=trace_id,
            provider=provider,
            model=model,
            sanitized=sanitized,
            tool_plan=tool_plan,
        )
        return event, self.evaluate_guard_event(event)

    def evaluate_model_output(
        self,
        *,
        content: Any,
        security: dict[str, Any],
        trace_id: str,
        provider: str | None = None,
        model: str | None = None,
        sanitized: bool = False,
    ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
        event = self.build_model_event(
            phase="output",
            content=content,
            security=security,
            trace_id=trace_id,
            provider=provider,
            model=model,
            sanitized=sanitized,
        )
        return event, self.evaluate_guard_event(event)

    def evaluate_tool_result(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any,
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
        will_enter_context: bool = True,
        will_persist: bool = False,
        sanitized: bool = False,
    ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
        event = self.build_tool_result_event(
            tool_name=tool_name,
            arguments=arguments,
            result=result,
            security=security,
            trace_id=trace_id,
            call_id=call_id,
            will_enter_context=will_enter_context,
            will_persist=will_persist,
            sanitized=sanitized,
        )
        return event, self.evaluate_guard_event(event)

    def evaluate_memory_write(
        self,
        *,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
    ) -> tuple[RuntimeGuardEvent, PolicyDecision]:
        event = self.build_memory_write_event(
            arguments=arguments, security=security, trace_id=trace_id
        )
        return event, self.evaluate_guard_event(event)

    def build_tool_call_event(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ) -> ToolCallEvent:
        category, kind, _ = TOOL_METADATA.get(tool_name, ("tool", tool_name, "execute"))
        resources = derive_resources(tool_name, arguments)
        security_metadata = (
            security.get("metadata", {})
            if isinstance(security.get("metadata"), dict)
            else {}
        )
        event_metadata = {
            "adapter": "agentguard_langgraph_bench",
            **mcp_hijacking_metadata(arguments, security_metadata),
        }
        if "compatibility" in security_metadata:
            event_metadata["compatibility"] = security_metadata["compatibility"]
        context = SecurityContext.model_validate(
            {
                "user_task": security.get("user_task") or security.get("payload") or "",
                "source_type": security.get("source_type", "dataset"),
                "source_trust": security.get("source_trust", "untrusted"),
                "current_step": "before_tool",
                "model_intent": security.get("model_intent"),
                "derived_paths": [
                    item.target for item in resources if item.resource_type == "file"
                ],
                "metadata": {
                    **security_metadata,
                    **mcp_hijacking_metadata(arguments, security_metadata),
                },
            }
        )
        return ToolCallEvent(
            runtime=self.config.runtime,
            trace_id=trace_id,
            case_id=security.get("case_id"),
            attack_type=security.get("attack_type"),
            is_malicious=security.get("is_malicious"),
            security_context=context,
            tool=ToolDescriptor(
                name=tool_name,
                category=category,
                kind=kind,
                call_id=call_id or new_id("call"),
            ),
            arguments=arguments,
            derived_resources=resources,
            metadata=event_metadata,
        )

    def build_context_event(
        self,
        *,
        sources: list[Any],
        security: dict[str, Any],
        trace_id: str,
        will_enter_context: bool = True,
        sanitized: bool = False,
    ) -> RuntimeGuardEvent:
        context = _security_context(
            security,
            current_step="context_assembled",
            runtime=self.config.runtime,
            agent_id=_config_agent_id(self.config),
        )
        return RuntimeGuardEvent(
            event_type="context_assembled",
            runtime=self.config.runtime,
            trace_id=trace_id,
            case_id=security.get("case_id"),
            attack_type=security.get("attack_type"),
            is_malicious=security.get("is_malicious"),
            pre_execution=True,
            security_context=context,
            payload={
                "sources": [
                    _context_source_payload(source, index, context)
                    for index, source in enumerate(sources)
                ],
                "will_enter_context": will_enter_context,
                "sanitized": sanitized,
            },
            metadata={
                "adapter": "agentguard_langgraph_adapter",
                "hook": "context_assembled",
            },
        )

    def build_model_event(
        self,
        *,
        phase: str,
        content: Any,
        security: dict[str, Any],
        trace_id: str,
        provider: str | None = None,
        model: str | None = None,
        sanitized: bool = False,
        tool_plan: list[dict[str, Any]] | None = None,
    ) -> RuntimeGuardEvent:
        normalized_phase = "output" if phase == "output" else "input"
        current_step = (
            "model_output_produced"
            if normalized_phase == "output"
            else "model_input_prepared"
        )
        context = _security_context(
            security,
            current_step=current_step,
            runtime=self.config.runtime,
            agent_id=_config_agent_id(self.config),
        )
        preview = _preview(content)
        return RuntimeGuardEvent(
            event_type=current_step,
            runtime=self.config.runtime,
            trace_id=trace_id,
            case_id=security.get("case_id"),
            attack_type=security.get("attack_type"),
            is_malicious=security.get("is_malicious"),
            pre_execution=normalized_phase == "input",
            security_context=context,
            payload={
                "phase": normalized_phase,
                "content_preview": preview,
                "provider": provider,
                "model": model,
                "contains_instruction_like_text": _contains_instruction_like_text(
                    preview
                ),
                "contains_sensitive_data": _contains_sensitive_text(preview),
                "sanitized": sanitized,
                "tool_plan": tool_plan or [],
            },
            metadata={"adapter": "agentguard_langgraph_adapter", "hook": current_step},
        )

    def build_tool_result_event(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any,
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
        will_enter_context: bool = True,
        will_persist: bool = False,
        sanitized: bool = False,
    ) -> RuntimeGuardEvent:
        context = _security_context(
            security,
            current_step="tool_result_produced",
            runtime=self.config.runtime,
            agent_id=_config_agent_id(self.config),
            resources=derive_resources(tool_name, arguments),
        )
        preview = _preview(result)
        return RuntimeGuardEvent(
            event_type="tool_result_produced",
            runtime=self.config.runtime,
            trace_id=trace_id,
            case_id=security.get("case_id"),
            attack_type=security.get("attack_type"),
            is_malicious=security.get("is_malicious"),
            pre_execution=False,
            security_context=context,
            payload={
                "tool": {
                    "name": tool_name,
                    "category": TOOL_METADATA.get(
                        tool_name, ("tool", tool_name, "execute")
                    )[0],
                    "kind": TOOL_METADATA.get(
                        tool_name, ("tool", tool_name, "execute")
                    )[1],
                    "call_id": call_id or new_id("call"),
                },
                "result": {
                    "content_preview": preview,
                    "content_type": _content_type(result),
                    "size_bytes": len(preview.encode("utf-8")),
                },
                "will_enter_context": will_enter_context,
                "will_persist": will_persist,
                "sanitized": sanitized,
                "contains_sensitive_data": _contains_sensitive_text(preview),
                "contains_instruction_like_text": _contains_instruction_like_text(
                    preview
                ),
                "derived_resources": [
                    resource.model_dump()
                    for resource in derive_resources(tool_name, arguments)
                ],
            },
            metadata={
                "adapter": "agentguard_langgraph_adapter",
                "hook": "tool_result_produced",
            },
        )

    def build_memory_write_event(
        self,
        *,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
    ) -> RuntimeGuardEvent:
        namespace = str(arguments.get("namespace") or "memory")
        key = str(arguments.get("key") or arguments.get("id") or "memory")
        value = _preview(
            arguments.get("value")
            or arguments.get("value_preview")
            or arguments.get("content")
            or arguments.get("text")
        )
        source_trust = str(
            arguments.get("source_trust") or security.get("source_trust") or "untrusted"
        )
        context = _security_context(
            {**security, "source_trust": source_trust},
            current_step="memory_write_proposed",
            runtime=self.config.runtime,
            agent_id=_config_agent_id(self.config),
        )
        return RuntimeGuardEvent(
            event_type="memory_write_proposed",
            runtime=self.config.runtime,
            trace_id=trace_id,
            case_id=security.get("case_id"),
            attack_type=security.get("attack_type"),
            is_malicious=security.get("is_malicious"),
            pre_execution=True,
            security_context=context,
            payload={
                "memory": {
                    "namespace": namespace,
                    "key": key,
                    "value_preview": value,
                    "source_trust": source_trust,
                    "operation": "write",
                },
                "will_persist": True,
                "requires_approval": bool(arguments.get("requires_approval"))
                or source_trust.lower() not in TRUSTED_SOURCE_TRUST,
            },
            metadata={
                "adapter": "agentguard_langgraph_adapter",
                "hook": "memory_write_proposed",
            },
        )

    def build_audit_event(
        self,
        event: ToolCallEvent | RuntimeGuardEvent | dict[str, Any],
        decision: PolicyDecision,
    ) -> AuditEvent:
        """构造 AuditEvent 0.4 形态（契约 §8/§9）。

        Guard API 模式下策略审计由 evaluate writer 唯一写入，本方法产物不再
        经 POST /v1/audit/events 重复提交（§12.1）；仅 legacy Core 路径和本地
        结果载体仍使用该形态。
        """
        event_dict = _event_dump(event)
        targets = _resource_targets(event_dict)
        rule_ids = [hit.rule_id for hit in decision.rule_hits]
        summary_target = targets[0] if targets else "no derived resource"
        raw_security_context = event_dict.get("security_context")
        security_context = (
            raw_security_context if isinstance(raw_security_context, dict) else {}
        )
        raw_payload = event_dict.get("payload")
        payload = raw_payload if isinstance(raw_payload, dict) else event_dict
        tool_name = _tool_name_from_payload(payload)
        event_type = str(event_dict.get("event_type") or "runtime_event")
        # 契约 §8 口径：工具前置评估统一使用 before_tool_call 阶段名。
        if event_type == "tool_call_proposed":
            stage = "before_tool_call"
        else:
            stage = str(security_context.get("current_step") or event_type)
        event_id = str(event_dict.get("event_id") or "")
        links: dict[str, str] = {
            "event_id": event_id,
            "decision_id": decision.decision_id,
        }
        action_id = _action_id_from_payload(payload)
        if action_id:
            links["action_id"] = action_id
        approval_id = _approval_id_from_decision(decision)
        if approval_id:
            links["approval_id"] = approval_id
        return AuditEvent(
            trace_id=str(event_dict.get("trace_id") or new_id("trace")),
            case_id=event_dict.get("case_id"),
            runtime=str(event_dict.get("runtime") or self.config.runtime),
            attack_type=event_dict.get("attack_type"),
            is_malicious=event_dict.get("is_malicious"),
            stage=stage,
            event_type=event_type,
            summary=_audit_summary(
                event_type=event_type,
                tool_name=tool_name,
                summary_target=summary_target,
            ),
            decision=decision.decision,
            risk_score=decision.risk_score,
            severity=decision.severity,
            blocked=decision.blocked,
            resource_targets=targets,
            rule_hits=rule_ids,
            reason=decision.reason,
            links=links,
            latency_ms=decision.latency_ms,
            evidence=_policy_evaluation_evidence(
                event_dict, decision, payload, security_context
            ),
        )

    def submit_audit_event(self, audit_event: AuditEvent) -> dict[str, Any]:
        if not self.config.defense_enabled:
            return {"ok": True, "skipped": "defense_off"}
        try:
            assert self.core_client is not None
            return self.core_client.submit_audit_event(audit_event.model_dump())
        except CoreClientError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def wait_for_approval(
        self, approval_id: str, timeout: float | None = None
    ) -> dict[str, Any]:
        if not self.config.defense_enabled:
            return {"status": "resolved", "decision": "allow_once"}
        try:
            assert self.core_client is not None
            try:
                return self.core_client.wait_for_approval(approval_id, timeout=timeout)
            except TypeError:
                return self.core_client.wait_for_approval(approval_id)
        except CoreClientError as exc:
            return {
                "status": "error",
                "decision": "deny" if self.config.fail_closed else None,
                "error": str(exc),
            }
        except Exception as exc:
            return {
                "status": "error",
                "decision": "deny" if self.config.fail_closed else None,
                "error": str(exc),
            }


def _allow_decision(reason: str) -> PolicyDecision:
    return PolicyDecision(
        decision_id="dec_defense_off",
        decision="allow",
        risk_score=0,
        severity="low",
        rule_hits=[],
        reason=reason,
        safe_message=None,
        latency_ms=0,
    )


def _failure_decision(exc: Exception, *, fail_closed: bool) -> PolicyDecision:
    if fail_closed:
        return PolicyDecision(
            decision_id="dec_fail_closed",
            decision="deny",
            risk_score=100,
            severity="high",
            rule_hits=[
                RuleHit(
                    rule_id="AGENTGUARD_FAIL_CLOSED",
                    rule_name="AgentGuard Fail Closed",
                    severity="high",
                    evidence=[str(exc)],
                )
            ],
            reason=f"Core unavailable or invalid; fail_closed blocked the runtime event: {exc}",
            safe_message="The runtime event was blocked because AgentGuard Core was unavailable.",
            latency_ms=None,
        )
    return PolicyDecision(
        decision_id="dec_fail_open_debug",
        decision="allow",
        risk_score=0,
        severity="low",
        rule_hits=[],
        reason=f"Core unavailable; fail_closed=false allowed local debug execution: {exc}",
        safe_message=None,
        latency_ms=None,
    )


def _event_dump(
    event: RuntimeGuardEvent | ToolCallEvent | dict[str, Any],
) -> dict[str, Any]:
    if isinstance(event, dict):
        return event
    return event.model_dump()


def _config_agent_id(config: Any) -> str:
    return str(getattr(config, "agent_id", None) or "langgraph_demo")


def _security_context(
    security: dict[str, Any],
    *,
    current_step: str,
    runtime: str,
    agent_id: str,
    resources: list[DerivedResource] | None = None,
) -> SecurityContext:
    metadata = (
        security.get("metadata", {})
        if isinstance(security.get("metadata"), dict)
        else {}
    )
    return SecurityContext.model_validate(
        {
            "user_task": security.get("user_task") or security.get("payload") or "",
            "source_type": security.get("source_type", "dataset"),
            "source_trust": security.get("source_trust", "untrusted"),
            "current_step": current_step,
            "model_intent": security.get("model_intent"),
            "run_id": security.get("run_id"),
            "agent_id": security.get("agent_id") or agent_id,
            "derived_paths": [
                item.target for item in resources or [] if item.resource_type == "file"
            ],
            "metadata": {"runtime": runtime, **metadata},
        }
    )


def _context_source_payload(
    source: Any, index: int, context: SecurityContext
) -> dict[str, Any]:
    if isinstance(source, dict):
        summary = _preview(
            source.get("summary")
            or source.get("content")
            or source.get("text")
            or source
        )
        source_id = str(
            source.get("source_id")
            or source.get("id")
            or f"langgraph:context:{index + 1}"
        )
        source_type = str(source.get("source_type") or context.source_type)
        source_trust = str(source.get("source_trust") or context.source_trust)
    else:
        summary = _preview(source)
        source_id = f"langgraph:context:{index + 1}"
        source_type = context.source_type
        source_trust = context.source_trust
    return {
        "source_id": source_id,
        "source_type": source_type,
        "source_trust": source_trust,
        "summary": summary,
        "contains_instruction_like_text": _contains_instruction_like_text(summary),
        "contains_sensitive_data": _contains_sensitive_text(summary),
    }


def _resource_targets(event: dict[str, Any]) -> list[str]:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else event
    targets: list[str] = []
    resources = payload.get("derived_resources") if isinstance(payload, dict) else []
    if isinstance(resources, list):
        for item in resources:
            if isinstance(item, dict) and item.get("target"):
                targets.append(str(item["target"]))
    memory = payload.get("memory") if isinstance(payload, dict) else None
    if isinstance(memory, dict):
        targets.append(
            f"{memory.get('namespace', 'memory')}/{memory.get('key', 'memory')}"
        )
    recipient = payload.get("recipient") if isinstance(payload, dict) else None
    if recipient:
        targets.append(str(recipient))
    if not targets and isinstance(payload, dict):
        tool = payload.get("tool")
        if isinstance(tool, dict) and tool.get("call_id"):
            targets.append(str(tool["call_id"]))
    return targets


def _tool_name_from_payload(payload: dict[str, Any]) -> str | None:
    tool = payload.get("tool")
    if isinstance(tool, dict) and tool.get("name"):
        return str(tool["name"])
    return None


def _action_id_from_payload(payload: dict[str, Any]) -> str | None:
    tool = payload.get("tool")
    if isinstance(tool, dict) and tool.get("call_id"):
        return str(tool["call_id"])
    return None


def _approval_id_from_decision(decision: PolicyDecision) -> str | None:
    approval = decision.approval
    if isinstance(approval, dict):
        value = approval.get("approval_id") or approval.get("id")
        return str(value) if value else None
    return None


# 契约 §21.2 冻结边界：内容预览 2000 字符，普通摘要/reason/规则 evidence 500 字符。
_CONTENT_PREVIEW_LIMIT = 2000
_SUMMARY_TEXT_LIMIT = 500
_CONTEXT_SOURCES_LIMIT = 20
_NORMALIZED_RESOURCES_LIMIT = 50
_RULE_HITS_LIMIT = 100


def _bounded_text(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    return str(value)[:limit]


def _policy_evaluation_evidence(
    event_dict: dict[str, Any],
    decision: PolicyDecision,
    payload: dict[str, Any],
    security_context: dict[str, Any],
) -> dict[str, Any]:
    """构造 policy_evaluation 的有界 evidence（契约 §8.3/§9）。

    adapter 不持有策略快照，`policy` 保持 null；服务端脱敏与预算约束由
    Guard API writer 负责，此处仅提供有界投影。
    """
    return {
        "guard_event": _guard_event_projection(event_dict, payload, security_context),
        "guard_decision": _guard_decision_projection(decision),
        "policy": None,
        "intervention": _policy_intervention(decision),
        "execution": {
            "status": "unknown",
            "receipt_recorded": False,
            "invoked_at": None,
            "completed_at": None,
            "error": None,
            "tool_result_entered_context": None,
            "persisted": None,
        },
        "side_effects": {
            "measurement_status": "unknown",
            "count": None,
            "summary": None,
        },
        "result": {
            "disposition": "unknown",
            "summary": None,
            "sanitized": None,
        },
        "approval": _approval_evidence(decision),
    }


def _guard_event_projection(
    event_dict: dict[str, Any],
    payload: dict[str, Any],
    security_context: dict[str, Any],
) -> dict[str, Any]:
    source: dict[str, Any] = {
        "type": str(security_context.get("source_type") or ""),
        "trust_level": str(security_context.get("source_trust") or ""),
    }
    sender_id = security_context.get("sender_id")
    if sender_id:
        source["source_id"] = str(sender_id)
    raw_context_sources = security_context.get("context_sources")
    context_sources = (
        list(raw_context_sources)
        if isinstance(raw_context_sources, list)
        else []
    )[:_CONTEXT_SOURCES_LIMIT]
    tool = payload.get("tool")
    tool_projection: dict[str, Any] | None = None
    if isinstance(tool, dict) and tool.get("name"):
        tool_projection = {
            "name": str(tool.get("name")),
            "category": str(tool.get("category") or ""),
            "call_id": str(tool.get("call_id") or ""),
            "arguments": payload.get("arguments") or {},
        }
    raw_resources = payload.get("derived_resources")
    resources = raw_resources if isinstance(raw_resources, list) else []
    normalized_resources = [
        {
            "type": str(item.get("resource_type") or ""),
            "operation": str(item.get("operation") or ""),
            "target": str(item.get("target") or ""),
            "sensitivity": item.get("data_classification"),
            "direction": str(item.get("direction") or ""),
        }
        for item in resources
        if isinstance(item, dict)
    ][:_NORMALIZED_RESOURCES_LIMIT]
    return {
        "event_id": str(event_dict.get("event_id") or ""),
        "event_type": str(event_dict.get("event_type") or ""),
        "user_task": _bounded_text(
            str(security_context.get("user_task") or ""), _CONTENT_PREVIEW_LIMIT
        ),
        "source": source,
        "context_sources": context_sources,
        "model_intent": _bounded_text(
            security_context.get("model_intent"), _CONTENT_PREVIEW_LIMIT
        ),
        "tool": tool_projection,
        "normalized_resources": normalized_resources,
    }


def _guard_decision_projection(decision: PolicyDecision) -> dict[str, Any]:
    return {
        "decision_id": decision.decision_id,
        "decision": decision.decision,
        "risk_score": decision.risk_score,
        "severity": decision.severity,
        "categories": [],
        "rule_hits": [
            {
                "rule_id": hit.rule_id,
                "rule_name": hit.rule_name,
                "severity": hit.severity,
                "decision": decision.decision,
                "reason": _bounded_text(decision.reason, _SUMMARY_TEXT_LIMIT),
                "evidence": [
                    str(item)[:_SUMMARY_TEXT_LIMIT] for item in hit.evidence
                ],
            }
            for hit in decision.rule_hits[:_RULE_HITS_LIMIT]
        ],
        "reason": _bounded_text(decision.reason, _SUMMARY_TEXT_LIMIT),
        "risk_breakdown": None,
    }


def _policy_intervention(decision: PolicyDecision) -> dict[str, Any]:
    if decision.decision == "allow":
        return {
            "type": "none",
            "reason": "The action was allowed without intervention.",
        }
    if decision.decision == "deny":
        reason = "策略已拒绝，尚未收到 Adapter 执行回执"
    else:
        reason = "策略要求审批，尚未收到 Adapter 执行回执"
    return {"type": "unknown", "reason": reason}


def _approval_evidence(decision: PolicyDecision) -> dict[str, Any]:
    approval_id = _approval_id_from_decision(decision)
    if approval_id is not None:
        return {
            "approval_id": approval_id,
            "status": "pending",
            "decision": None,
            "resolved_at": None,
        }
    return {
        "approval_id": None,
        "status": "not_required",
        "decision": None,
        "resolved_at": None,
    }


def _audit_summary(
    *, event_type: str, tool_name: str | None, summary_target: str
) -> str:
    if event_type == "tool_call_proposed":
        return f"Agent attempted to call {tool_name or 'tool'} on {summary_target}"
    if event_type == "tool_result_produced":
        return f"AgentGuard evaluated result from {tool_name or 'tool'} before context admission."
    if event_type == "memory_write_proposed":
        return f"Agent attempted a persistent memory write to {summary_target}."
    if event_type == "context_assembled":
        return "AgentGuard evaluated assembled model context."
    if event_type in {"model_input_prepared", "model_output_produced"}:
        return f"AgentGuard evaluated {event_type.replace('_', ' ')}."
    return f"AgentGuard evaluated {event_type}."


def _preview(value: Any, limit: int = 2000) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    else:
        try:
            import json

            text = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except Exception:
            text = repr(value)
    return text[:limit]


def _content_type(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return "application/json"
    return "text/plain"


def _contains_instruction_like_text(value: str) -> bool:
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in (
            "ignore previous",
            "ignore all prior",
            "disregard previous",
            "override",
            "persist this rule",
            "remember this rule",
            "store this rule",
            "save this rule",
            "remember this instruction",
            "store this instruction",
            "save this instruction",
            "from now on",
            "next time",
            "for all future",
            "future tasks",
            "future runs",
            "future requests",
            "future reports",
            "always send",
            "send reports externally",
            "route future reports",
            "never mention",
            "never reveal",
            "never tell",
            "developer message",
            "system message",
            "ignore developer instructions",
            "identityverify",
            "market-segment-submit",
            "support-profile-confirm",
            "managed-device support profile",
            "lead-verification-relax",
            "reduce verification controls",
            "weaken verification",
        )
    )


def _contains_sensitive_text(value: str) -> bool:
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in (
            "token=",
            "secret",
            "credential",
            "api key",
            "password",
            "private key",
        )
    )


def classify_resource(target: str) -> str:
    lowered = target.lower()
    if any(
        marker in lowered
        for marker in (".env", "token", "secret", "private", "key", "credential")
    ):
        return "secret"
    if "config" in lowered:
        return "confidential"
    return "public"


def derive_resources(
    tool_name: str, arguments: dict[str, Any]
) -> list[DerivedResource]:
    if tool_name == "read_file":
        target = str(arguments.get("path", ""))
        return [
            DerivedResource(
                resource_type="file",
                operation="read",
                target=target,
                data_classification=classify_resource(target),
                direction="local",
            )
        ]
    if tool_name == "write_file":
        target = str(arguments.get("path", ""))
        return [
            DerivedResource(
                resource_type="file",
                operation="write",
                target=target,
                data_classification=classify_resource(target),
                direction="local",
            )
        ]
    if tool_name == "send_email":
        target = str(arguments.get("to", ""))
        return [
            DerivedResource(
                resource_type="message",
                operation="send",
                target=target,
                data_classification=None,
                direction="outbound",
            )
        ]
    if tool_name == "call_api":
        target = str(arguments.get("url", ""))
        return [
            DerivedResource(
                resource_type="api",
                operation=str(arguments.get("method", "GET")).upper(),
                target=target,
                data_classification=None,
                direction="outbound",
            )
        ]
    if tool_name == "code_exec":
        target = str(arguments.get("command") or arguments.get("code") or "")
        return [
            DerivedResource(
                resource_type="process",
                operation="execute",
                target=target,
                data_classification=None,
                direction="local",
            )
        ]
    if tool_name in {"memory_write", "memory_read", "memory_search"}:
        namespace = str(arguments.get("namespace") or "memory")
        key = str(arguments.get("key") or arguments.get("query") or "memory")
        operation = (
            "write"
            if tool_name == "memory_write"
            else ("read" if tool_name == "memory_read" else "search")
        )
        return [
            DerivedResource(
                resource_type="memory",
                operation=operation,
                target=f"{namespace}:{key}",
                data_classification=(
                    "persistent_memory" if operation == "write" else "memory"
                ),
                direction="persistent" if operation == "write" else "local",
            )
        ]
    if tool_name.startswith("browser_"):
        target = str(
            arguments.get("url")
            or arguments.get("selector")
            or arguments.get("text")
            or arguments.get("session_id")
            or "browser"
        )
        return [
            DerivedResource(
                resource_type="browser",
                operation=tool_name.removeprefix("browser_"),
                target=target,
                data_classification=None,
                direction="runtime",
            )
        ]
    if tool_name == "mcp_call":
        server = str(arguments.get("server") or "mcp")
        tool = str(arguments.get("tool") or "unknown")
        return [
            DerivedResource(
                resource_type="mcp",
                operation="call",
                target=f"{server}.{tool}",
                data_classification=None,
                direction="tool",
            )
        ]
    if tool_name.startswith("rag_"):
        target = str(
            arguments.get("question_id")
            or arguments.get("dataset")
            or arguments.get("question")
            or "rag"
        )
        return [
            DerivedResource(
                resource_type="rag",
                operation=tool_name.removeprefix("rag_"),
                target=target,
                data_classification=None,
                direction="context",
            )
        ]
    return []


def mcp_hijacking_metadata(
    arguments: dict[str, Any], case_metadata: dict[str, Any] | None = None
) -> dict[str, Any]:
    if not isinstance(arguments, dict) or "hijacking" not in arguments:
        case_metadata = case_metadata or {}
        hijacking = (
            case_metadata.get("hijacking") if isinstance(case_metadata, dict) else None
        )
    else:
        hijacking = arguments.get("hijacking")
    if not isinstance(hijacking, dict):
        return {}
    config = _normalize_hijacking_payload(hijacking)
    metadata = {
        "hijacking_mode": config["mode"],
        "target_server": config["target_server"],
        "target_tool": config["target_tool"],
        "hijacked_server": config["hijacked_server"],
        "hijacked_tool": config["hijacked_tool"],
        "argument_mutation": config["argument_mutation"],
        "injected_return_markers": config["injected_return_markers"],
        "required_dependency": config["required_dependency"],
        "dependency_type": config["dependency_type"],
        "mcpsafety_evaluator": config["source_evaluator"],
    }
    descriptor = arguments.get("descriptor") if isinstance(arguments, dict) else None
    if isinstance(descriptor, dict):
        metadata.update(
            {
                "descriptor_view": arguments.get("catalog_view") or "unknown",
                "descriptor_hash": descriptor.get("descriptor_hash"),
                "descriptor_permissions": descriptor.get("permissions") or [],
                "descriptor_trust_level": descriptor.get("trust_level"),
                "descriptor_version": descriptor.get("version"),
            }
        )
    return metadata


def _normalize_hijacking_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": _string_first(payload, "mode", "hijacking_mode") or "tool_shadowing",
        "target_server": _string_first(payload, "targetServer", "target_server"),
        "target_tool": _string_first(payload, "targetTool", "target_tool"),
        "hijacked_server": _string_first(
            payload, "hijackedServer", "hijackToServer", "hijacked_server"
        ),
        "hijacked_tool": _string_first(
            payload,
            "hijackedTool",
            "hijackToTool",
            "maliciousTool",
            "malicious_tool",
            "hijacked_tool",
        ),
        "argument_mutation": _dict_first(
            payload,
            "argumentMutation",
            "argument_mutation",
            "maliciousArguments",
            "malicious_arguments",
        ),
        "injected_return_markers": _list_first(
            payload,
            "injectedReturnMarkers",
            "injected_return_markers",
            "returnMarkers",
            "return_markers",
        ),
        "required_dependency": _string_first(
            payload, "requiredDependency", "required_dependency"
        ),
        "dependency_type": _string_first(payload, "dependencyType", "dependency_type"),
        "source_evaluator": _string_first(
            payload, "source_evaluator", "mcpsafety_evaluator"
        ),
    }


def _string_first(payload: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if value is not None:
            return str(value)
    return ""


def _dict_first(payload: dict[str, Any], *keys: str) -> dict[str, Any]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, dict):
            return dict(value)
    return {}


def _list_first(payload: dict[str, Any], *keys: str) -> list[str]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, str) and value:
            return [value]
    return []


def create_guarded_tool_node(
    adapter: LangGraphAdapter,
    tool_registry: Any | None = None,
    *,
    gateway: Any | None = None,
) -> Any:
    from .secure_tool_node import SecureToolNode

    return SecureToolNode(gateway=gateway, adapter=adapter, tool_registry=tool_registry)


def blocked_result(
    *,
    tool_name: str,
    call_id: str,
    event: ToolCallEvent,
    decision: PolicyDecision,
    audit_event: AuditEvent | None = None,
) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_name=tool_name,
        call_id=call_id,
        executed=False,
        blocked=True,
        decision=decision.decision,
        status="blocked",
        result=None,
        safe_message=decision.safe_message
        or "The tool call was blocked by AgentGuard.",
        side_effects=[],
        event=event.model_dump(),
        audit_event=audit_event.model_dump() if audit_event is not None else None,
        block_semantics=(
            "policy_deny" if decision.decision == "deny" else "approval_block"
        ),
        counts_as_effective_block=decision.decision == "deny",
    )
