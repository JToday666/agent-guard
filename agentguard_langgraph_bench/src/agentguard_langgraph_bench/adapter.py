"""LangGraph adapter for AgentGuard Core decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import BenchConfig
from .core_client import AgentGuardCoreClient, CoreClientError, CoreClientProtocol, FakeDenyCoreClient
from .models import (
    AuditEvent,
    DerivedResource,
    PolicyDecision,
    SecurityContext,
    ToolCallEvent,
    ToolDescriptor,
    ToolExecutionResult,
    new_id,
)
from .hijacking import ToolHijackingConfig


TOOL_METADATA = {
    "read_file": ("file", "file_read", "read"),
    "write_file": ("file", "file_write", "write"),
    "send_email": ("message", "email_send", "send"),
    "call_api": ("api", "http_request", "request"),
    "code_exec": ("code", "command_exec", "execute"),
    "memory_write": ("memory", "memory_write", "write"),
    "browser_start": ("browser", "browser_session", "open"),
    "browser_navigate": ("browser", "browser_navigation", "open"),
    "browser_input": ("browser", "browser_input", "input"),
    "browser_click": ("browser", "browser_click", "click"),
    "browser_extract_text": ("browser", "browser_extract", "extract"),
    "mcp_call": ("mcp", "mcp_tool_call", "call"),
    "rag_retrieve": ("rag", "rag_retrieve", "retrieve"),
    "rag_answer": ("rag", "rag_answer", "answer"),
}


@dataclass(slots=True)
class LangGraphAdapter:
    config: BenchConfig
    core_client: CoreClientProtocol | None = None

    def __post_init__(self) -> None:
        if self.core_client is None:
            self.core_client = AgentGuardCoreClient(self.config)

    @classmethod
    def with_fake_deny_core(cls, config: BenchConfig | None = None) -> "LangGraphAdapter":
        return cls(config=config or BenchConfig(defense_enabled=True), core_client=FakeDenyCoreClient())

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
                        {
                            "rule_id": "AGENTGUARD_FAIL_CLOSED",
                            "rule_name": "AgentGuard Fail Closed",
                            "severity": "high",
                            "evidence": [str(exc)],
                        }
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
        context = SecurityContext.model_validate({
            "user_task": security.get("user_task") or security.get("payload") or "",
            "source_type": security.get("source_type", "dataset"),
            "source_trust": security.get("source_trust", "untrusted"),
            "current_step": "before_tool",
            "model_intent": security.get("model_intent"),
            "derived_paths": [item.target for item in resources if item.resource_type == "file"],
            "metadata": {**security.get("metadata", {}), **mcp_hijacking_metadata(arguments, security.get("metadata", {}))},
        })
        return ToolCallEvent(
            runtime=self.config.runtime,
            trace_id=trace_id,
            case_id=security.get("case_id"),
            attack_type=security.get("attack_type"),
            is_malicious=security.get("is_malicious"),
            security_context=context,
            tool=ToolDescriptor(name=tool_name, category=category, kind=kind, call_id=call_id or new_id("call")),
            arguments=arguments,
            derived_resources=resources,
            metadata={"adapter": "agentguard_langgraph_bench", **mcp_hijacking_metadata(arguments, security.get("metadata", {}))},
        )

    def build_audit_event(self, event: ToolCallEvent, decision: PolicyDecision) -> AuditEvent:
        targets = [item.target for item in event.derived_resources]
        rule_ids = [hit.rule_id for hit in decision.rule_hits]
        summary_target = targets[0] if targets else "no derived resource"
        return AuditEvent(
            trace_id=event.trace_id,
            case_id=event.case_id,
            runtime=event.runtime,
            stage="before_tool_call",
            event_type=event.event_type,
            summary=f"Agent attempted to call {event.tool.name} on {summary_target}",
            decision=decision.decision,
            risk_score=decision.risk_score,
            severity=decision.severity,
            blocked=decision.blocked,
            resource_targets=targets,
            rule_hits=rule_ids,
            reason=decision.reason,
            links={"event_id": event.event_id, "decision_id": decision.decision_id},
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


def classify_resource(target: str) -> str:
    lowered = target.lower()
    if any(marker in lowered for marker in (".env", "token", "secret", "private", "key", "credential")):
        return "secret"
    if "config" in lowered:
        return "confidential"
    return "public"


def derive_resources(tool_name: str, arguments: dict[str, Any]) -> list[DerivedResource]:
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
    if tool_name == "memory_write":
        target = str(arguments.get("key") or arguments.get("namespace") or "memory")
        return [
            DerivedResource(
                resource_type="memory",
                operation="write",
                target=target,
                data_classification=None,
                direction="persistent",
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
        target = str(arguments.get("question_id") or arguments.get("dataset") or arguments.get("question") or "rag")
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


def mcp_hijacking_metadata(arguments: dict[str, Any], case_metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(arguments, dict) or "hijacking" not in arguments:
        case_metadata = case_metadata or {}
        hijacking = case_metadata.get("hijacking") if isinstance(case_metadata, dict) else None
    else:
        hijacking = arguments.get("hijacking")
    if not isinstance(hijacking, dict):
        return {}
    config = ToolHijackingConfig.from_payload(hijacking)
    return {
        "hijacking_mode": config.mode,
        "target_server": config.target_server,
        "target_tool": config.target_tool,
        "hijacked_server": config.hijacked_server,
        "hijacked_tool": config.hijacked_tool,
        "argument_mutation": config.argument_mutation,
        "injected_return_markers": config.injected_return_markers,
        "required_dependency": config.required_dependency,
        "dependency_type": config.dependency_type,
        "mcpsafety_evaluator": config.source_evaluator,
    }


def create_guarded_tool_node(adapter: LangGraphAdapter, tool_registry: Any) -> Any:
    from .secure_tool_node import SecureToolNode

    return SecureToolNode(adapter=adapter, tool_registry=tool_registry)


def blocked_result(
    *,
    tool_name: str,
    call_id: str,
    event: ToolCallEvent,
    decision: PolicyDecision,
    audit_event: AuditEvent,
) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_name=tool_name,
        call_id=call_id,
        executed=False,
        blocked=True,
        decision=decision.decision,
        status="blocked",
        result=None,
        safe_message=decision.safe_message or "The tool call was blocked by AgentGuard.",
        side_effects=[],
        event=event.model_dump(),
        audit_event=audit_event.model_dump(),
    )
