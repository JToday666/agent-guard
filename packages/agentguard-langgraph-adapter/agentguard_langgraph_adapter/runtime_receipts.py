"""Deterministic AuditEvent 0.4 receipts for observable runtime facts."""

from __future__ import annotations

from typing import Any, Literal

from .event_models import (
    AuditEvent,
    PolicyDecision,
    RuntimeEnforcementEvidence,
    RuntimeOutcomeKind,
    RuntimeOutcomeReceipt,
    utc_now_iso,
)
from .strong_binding import normalize_approval_resolution

ExecutionStatus = Literal["not_invoked", "executed", "failed", "unknown"]
ResultDisposition = Literal[
    "not_applicable", "passed_through", "modified", "quarantined", "unknown"
]
TraceLifecycleState = Literal[
    "trace_started", "trace_completed", "trace_failed", "trace_cancelled"
]

# 契约 02 §9：execution.error 上限 2000 字符，截断时省略号计入上限，
# 与 OpenClaw 插件 boundedTerminalError 语义一致（RTE-04 CF-07 硬化）。
MAX_TERMINAL_ERROR_CHARS = 2_000


def bounded_terminal_error(error: str | None) -> str | None:
    """将 execution.error 截断到契约上限；None 保持 None。"""
    if error is None:
        return None
    if len(error) <= MAX_TERMINAL_ERROR_CHARS:
        return error
    return f"{error[: MAX_TERMINAL_ERROR_CHARS - 3]}..."


def runtime_receipts_enabled(guard_adapter: Any) -> bool:
    config = getattr(guard_adapter, "config", None)
    mode = getattr(config, "core_api_mode", getattr(config, "api_mode", None))
    defense_enabled = getattr(config, "defense_enabled", True)
    competition_mode = bool(getattr(config, "competition_mode", False))
    competition_rte_mode = getattr(config, "competition_rte_mode", None)
    return bool(
        defense_enabled
        and mode == "guard-api-v0.3"
        and not (competition_mode and competition_rte_mode == "off")
        and callable(getattr(guard_adapter, "submit_audit_event", None))
    )


def submit_runtime_receipt(
    guard_adapter: Any, receipt: AuditEvent | RuntimeOutcomeReceipt
) -> str | None:
    """Submit a receipt and return a bounded diagnostic instead of raising."""

    if not runtime_receipts_enabled(guard_adapter):
        return None
    try:
        response = guard_adapter.submit_audit_event(receipt)
    except Exception as exc:
        return f"Runtime receipt submission failed: {exc}"[:500]
    if isinstance(response, dict) and response.get("ok") is False:
        return f"Runtime receipt submission failed: {response.get('error') or 'unknown error'}"[
            :500
        ]
    return None


def build_tool_started_observation(
    event: Any,
    decision: PolicyDecision,
    *,
    approval_resolution: dict[str, Any] | None = None,
    timestamp: str | None = None,
    enforcement: RuntimeEnforcementEvidence | dict[str, Any] | Any | None = None,
    lease_id: str | None = None,
    consumption_id: str | None = None,
) -> AuditEvent:
    event_data = _event_dump(event)
    occurred_at = timestamp or utc_now_iso()
    links = _policy_links(
        event_data,
        decision,
        approval_resolution,
        lease_id=lease_id,
        consumption_id=consumption_id,
    )
    links["parent_audit_id"] = str(decision.policy_audit_id)
    approval = _approval_evidence(decision, approval_resolution)
    action_name = _action_name(event_data)
    event_id = _event_id(event_data)
    evidence: dict[str, Any] = {
        "intervention": _intervention(decision, approval),
        "execution": {
            "status": "unknown",
            "receipt_recorded": False,
            "invoked_at": occurred_at,
            "completed_at": None,
            "error": None,
            "tool_result_entered_context": None,
            "persisted": None,
        },
        "side_effects": {
            "measurement_status": "not_measured",
            "count": None,
            "summary": "Execution started; final side effects are not yet known.",
        },
        "result": {
            "disposition": "unknown",
            "summary": "Execution has not produced a terminal result.",
            "sanitized": False,
        },
        "approval": approval,
    }
    if enforcement is not None:
        evidence["enforcement"] = _enforcement_dump(enforcement)
    return AuditEvent(
        audit_id=f"audit_observation_started_{event_id}",
        schema_version="0.4",
        record_type="runtime_observation",
        trace_id=_trace_id(event_data),
        case_id=_optional_string(event_data.get("case_id")),
        runtime=str(event_data.get("runtime") or "langgraph"),
        timestamp=occurred_at,
        stage="tool_call_started",
        event_type="tool_call_started",
        attack_type=event_data.get("attack_type"),
        is_malicious=event_data.get("is_malicious"),
        summary=f"Runtime started {action_name}",
        decision=None,
        risk_score=None,
        severity=None,
        blocked=None,
        resource_targets=_resource_targets(event_data),
        rule_hits=[],
        reason="The adapter observed the tool runtime invocation boundary.",
        links=links,
        latency_ms=None,
        metadata={"action_name": action_name, "observation_state": "started"},
        evidence=evidence,
    )


def build_runtime_outcome(
    event: Any,
    decision: PolicyDecision,
    *,
    execution_status: ExecutionStatus,
    approval_resolution: dict[str, Any] | None = None,
    invoked_at: str | None = None,
    completed_at: str | None = None,
    error: str | None = None,
    side_effects: list[dict[str, Any]] | None = None,
    side_effects_measured: bool = False,
    result_disposition: ResultDisposition | None = None,
    result_summary: str | None = None,
    result_sanitized: bool | None = None,
    parent_audit_id: str | None = None,
    intervention_type: str | None = None,
    intervention_reason: str | None = None,
    enforcement: RuntimeEnforcementEvidence | dict[str, Any] | Any | None = None,
    lease_id: str | None = None,
    consumption_id: str | None = None,
) -> AuditEvent:
    event_data = _event_dump(event)
    event_id = _event_id(event_data)
    completed = completed_at or utc_now_iso()
    links = _policy_links(
        event_data,
        decision,
        approval_resolution,
        lease_id=lease_id,
        consumption_id=consumption_id,
    )
    if parent_audit_id:
        links["parent_audit_id"] = parent_audit_id
    approval = _approval_evidence(decision, approval_resolution)
    measured_effects = list(side_effects or [])
    disposition = result_disposition or _default_disposition(execution_status)
    action_name = _action_name(event_data)
    outcome_kind = _outcome_kind(execution_status, disposition, approval)
    evidence: dict[str, Any] = {
        "intervention": (
            {
                "type": intervention_type,
                "reason": intervention_reason
                or "The adapter recorded the runtime outcome.",
            }
            if intervention_type
            else _intervention(decision, approval)
        ),
        "execution": {
            "status": execution_status,
            "receipt_recorded": True,
            "invoked_at": invoked_at,
            "completed_at": completed,
            "error": bounded_terminal_error(error),
            "tool_result_entered_context": (
                True
                if execution_status == "executed" and disposition != "quarantined"
                else (
                    False if execution_status in {"not_invoked", "executed"} else None
                )
            ),
            "persisted": False if execution_status == "not_invoked" else None,
        },
        "side_effects": _side_effect_evidence(
            execution_status,
            measured_effects,
            measured=side_effects_measured,
        ),
        "result": {
            "disposition": disposition,
            "summary": result_summary,
            "sanitized": result_sanitized,
        },
        "approval": approval,
    }
    if enforcement is not None:
        evidence["enforcement"] = _enforcement_dump(enforcement)
    return RuntimeOutcomeReceipt(
        audit_id=f"audit_outcome_{event_id}_{outcome_kind}",
        schema_version="0.4",
        record_type="runtime_outcome",
        trace_id=_trace_id(event_data),
        case_id=_optional_string(event_data.get("case_id")),
        runtime=str(event_data.get("runtime") or "langgraph"),
        timestamp=completed,
        stage="after_tool_call",
        event_type="runtime_outcome",
        attack_type=event_data.get("attack_type"),
        is_malicious=event_data.get("is_malicious"),
        summary=_outcome_summary(action_name, execution_status),
        decision=decision.decision,
        risk_score=decision.risk_score,
        severity=decision.severity,  # pyright: ignore[reportArgumentType]
        blocked=decision.blocked,
        resource_targets=_resource_targets(event_data),
        rule_hits=[hit.rule_id for hit in decision.rule_hits],
        reason=decision.reason,
        links=links,  # pyright: ignore[reportArgumentType]
        latency_ms=None,
        metadata={  # pyright: ignore[reportArgumentType]
            "agent_id": _agent_id(event_data),
            "outcome_kind": outcome_kind,
        },
        evidence=evidence,  # pyright: ignore[reportArgumentType]
    )


def build_trace_lifecycle_observation(
    *,
    trace_id: str,
    state: TraceLifecycleState,
    runtime: str = "langgraph",
    case_id: str | None = None,
    parent_audit_id: str | None = None,
    timestamp: str | None = None,
    reason: str | None = None,
) -> AuditEvent:
    occurred_at = timestamp or utc_now_iso()
    links = {"event_id": f"event_{state}_{trace_id}"}
    if parent_audit_id:
        links["parent_audit_id"] = parent_audit_id
    return AuditEvent(
        audit_id=f"audit_{state}_{trace_id}",
        schema_version="0.4",
        record_type="runtime_observation",
        trace_id=trace_id,
        case_id=case_id,
        runtime=runtime,
        timestamp=occurred_at,
        stage=state,
        event_type=state,
        summary=_lifecycle_summary(state),
        decision=None,
        risk_score=None,
        severity=None,
        blocked=None,
        resource_targets=[],
        rule_hits=[],
        reason=reason or "The adapter recorded an explicit trace lifecycle boundary.",
        links=links,
        latency_ms=None,
        metadata={"lifecycle_state": state.removeprefix("trace_")},
        evidence={
            "intervention": {
                "type": "audit_observation",
                "reason": "Lifecycle observation only.",
            },
            "execution": {
                "status": "unknown",
                "receipt_recorded": False,
                "invoked_at": None,
                "completed_at": occurred_at if state != "trace_started" else None,
                "error": reason if state == "trace_failed" else None,
                "tool_result_entered_context": None,
                "persisted": None,
            },
            "side_effects": {
                "measurement_status": "unknown",
                "count": None,
                "summary": "Not applicable to a trace lifecycle observation.",
            },
            "result": {
                "disposition": "not_applicable",
                "summary": None,
                "sanitized": False,
            },
            "approval": {
                "approval_id": None,
                "status": "not_required",
                "decision": None,
                "resolved_at": None,
            },
        },
    )


def _event_dump(event: Any) -> dict[str, Any]:
    if isinstance(event, dict):
        return dict(event)
    if hasattr(event, "model_dump"):
        dumped = event.model_dump(mode="json")
        return dumped if isinstance(dumped, dict) else {}
    return {}


def _event_id(event: dict[str, Any]) -> str:
    value = event.get("event_id")
    if not isinstance(value, str) or not value:
        raise ValueError("runtime receipt requires event_id")
    return value


def _trace_id(event: dict[str, Any]) -> str:
    value = event.get("trace_id")
    if not isinstance(value, str) or not value:
        raise ValueError("runtime receipt requires trace_id")
    return value


def _agent_id(event: dict[str, Any]) -> str:
    security = event.get("security_context")
    value = security.get("agent_id") if isinstance(security, dict) else None
    if not isinstance(value, str) or not value:
        raise ValueError("runtime receipt requires security_context.agent_id")
    return value


def _policy_links(
    event: dict[str, Any],
    decision: PolicyDecision,
    approval_resolution: dict[str, Any] | None,
    *,
    lease_id: str | None = None,
    consumption_id: str | None = None,
) -> dict[str, str]:
    if not decision.policy_audit_id:
        raise ValueError("runtime receipt requires policy_audit_id")
    links = {
        "event_id": _event_id(event),
        "decision_id": decision.decision_id,
        "policy_audit_id": decision.policy_audit_id,
    }
    if action_id := _action_id(event):
        links["action_id"] = action_id
    if approval_id := _approval_id(decision, approval_resolution):
        links["approval_id"] = approval_id
    if (lease_id is None) != (consumption_id is None):
        raise ValueError("lease_id and consumption_id must be present together")
    if lease_id is not None and consumption_id is not None:
        if not lease_id or not consumption_id:
            raise ValueError("execution lease IDs must be non-empty")
        links["lease_id"] = lease_id
        links["consumption_id"] = consumption_id
    return links


def _enforcement_dump(
    evidence: RuntimeEnforcementEvidence | dict[str, Any] | Any,
) -> dict[str, Any]:
    if isinstance(evidence, RuntimeEnforcementEvidence):
        model = evidence
    elif isinstance(evidence, dict):
        model = RuntimeEnforcementEvidence.model_validate(evidence)
    else:
        as_dict = getattr(evidence, "as_dict", None)
        model_dump = getattr(evidence, "model_dump", None)
        if callable(as_dict):
            model = RuntimeEnforcementEvidence.model_validate(as_dict())
        elif callable(model_dump):
            model = RuntimeEnforcementEvidence.model_validate(model_dump())
        else:
            model = RuntimeEnforcementEvidence.model_validate(evidence)
    return model.model_dump(mode="json")


def _action_id(event: dict[str, Any]) -> str | None:
    value = event.get("action_id")
    if isinstance(value, str) and value:
        return value
    tool = event.get("tool")
    if not isinstance(tool, dict):
        payload = event.get("payload")
        if isinstance(payload, dict):
            value = payload.get("action_id")
            if isinstance(value, str) and value:
                return value
        tool = payload.get("tool") if isinstance(payload, dict) else None
    if isinstance(tool, dict):
        value = tool.get("call_id") or tool.get("tool_call_id")
        if isinstance(value, str) and value:
            return value
    if event.get("event_type") == "message_send_proposed":
        event_id = event.get("event_id")
        if isinstance(event_id, str) and event_id:
            # Mirror agentguard_core.actions.canonical_action_id for message
            # events that do not carry an explicit action ID.
            return f"act_{event_id}"
    return None


def _action_name(event: dict[str, Any]) -> str:
    tool = event.get("tool")
    if not isinstance(tool, dict):
        payload = event.get("payload")
        tool = payload.get("tool") if isinstance(payload, dict) else None
    if isinstance(tool, dict):
        value = tool.get("name")
        if isinstance(value, str) and value:
            return value
    return str(event.get("event_type") or "runtime action")


def _resource_targets(event: dict[str, Any]) -> list[str]:
    resources = event.get("derived_resources")
    if not isinstance(resources, list):
        payload = event.get("payload")
        resources = (
            payload.get("derived_resources") if isinstance(payload, dict) else []
        )
    targets = [
        str(item.get("target"))
        for item in resources or []
        if isinstance(item, dict) and item.get("target")
    ]
    security = event.get("security_context")
    if isinstance(security, dict):
        targets.extend(
            str(item)
            for item in security.get("derived_paths") or []
            if isinstance(item, str) and item
        )
    return list(dict.fromkeys(targets))


def _approval_id(
    decision: PolicyDecision, approval_resolution: dict[str, Any] | None
) -> str | None:
    candidates = [approval_resolution, decision.approval]
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        value = candidate.get("approval_id") or candidate.get("id")
        if value:
            return str(value)
    return None


def _approval_evidence(
    decision: PolicyDecision, resolution: dict[str, Any] | None
) -> dict[str, object]:
    if resolution is not None:
        resolution = normalize_approval_resolution(resolution)
    approval_id = _approval_id(decision, resolution)
    if decision.decision != "ask":
        return {
            "approval_id": None,
            "status": "not_required",
            "decision": None,
            "resolved_at": None,
        }
    status = str((resolution or {}).get("status") or "pending").lower()
    resolution_decision = str((resolution or {}).get("decision") or "").lower()
    if status == "resolved" and resolution_decision in {
        "allow",
        "allow_once",
        "allow_session",
    }:
        normalized_status = "allowed"
    elif status == "resolved" and resolution_decision == "deny":
        normalized_status = "denied"
    elif status in {"expired", "timeout"} or resolution_decision in {
        "expired",
        "timeout",
    }:
        normalized_status = "expired"
    elif status == "pending":
        normalized_status = "pending"
    else:
        normalized_status = "unknown"
    return {
        "approval_id": approval_id,
        "status": normalized_status,
        "decision": (
            "allow_once"
            if resolution_decision in {"allow", "allow_once", "allow_session"}
            else "deny" if resolution_decision == "deny" else None
        ),
        "resolved_at": (resolution or {}).get("resolved_at"),
    }


def _intervention(
    decision: PolicyDecision, approval: dict[str, object]
) -> dict[str, str]:
    if decision.decision == "allow":
        return {
            "type": "none",
            "reason": "The action was allowed without intervention.",
        }
    if decision.decision == "deny":
        return {
            "type": "policy_deny",
            "reason": "Policy denied the action before execution.",
        }
    status = approval.get("status")
    if status == "allowed":
        return {
            "type": "approval_release",
            "reason": "A resolved approval released the action.",
        }
    if status == "denied":
        return {
            "type": "approval_deny",
            "reason": "Approval denied the action before execution.",
        }
    if status == "expired":
        return {
            "type": "approval_expired",
            "reason": "Approval expired before execution.",
        }
    return {
        "type": "approval_not_obtained",
        "reason": "The action did not receive approval.",
    }


def _side_effect_evidence(
    execution_status: ExecutionStatus,
    side_effects: list[dict[str, Any]],
    *,
    measured: bool,
) -> dict[str, object]:
    if execution_status == "not_invoked":
        return {
            "measurement_status": "measured",
            "count": 0,
            "summary": "The tool runtime invocation boundary was not entered.",
        }
    if measured:
        return {
            "measurement_status": "measured",
            "count": len(side_effects),
            "summary": f"The controlled runtime reported {len(side_effects)} side effect(s).",
        }
    return {
        "measurement_status": "not_measured",
        "count": None,
        "summary": "The runtime did not provide a side-effect measurement.",
    }


def _default_disposition(status: ExecutionStatus) -> ResultDisposition:
    if status == "not_invoked":
        return "not_applicable"
    if status == "executed":
        return "passed_through"
    return "unknown"


def _outcome_kind(
    status: ExecutionStatus,
    disposition: ResultDisposition,
    approval: dict[str, object],
) -> RuntimeOutcomeKind:
    if status == "not_invoked":
        return "pre_execution_deny"
    if status == "failed":
        return "execution_failed"
    if disposition == "modified":
        return "tool_result_modified"
    if disposition == "quarantined":
        return "tool_result_quarantined"
    if status == "executed":
        return "execution_completed"
    if status == "unknown" and approval.get("status") == "allowed":
        return "approval_release"
    raise ValueError("runtime outcome requires an observable outcome kind")


def _outcome_summary(action_name: str, status: ExecutionStatus) -> str:
    labels = {
        "not_invoked": "was not invoked",
        "executed": "completed",
        "failed": "failed",
        "unknown": "has an unknown result",
    }
    return f"Runtime action {action_name} {labels[status]}"


def _lifecycle_summary(state: TraceLifecycleState) -> str:
    labels = {
        "trace_started": "Trace execution started",
        "trace_completed": "Trace execution completed",
        "trace_failed": "Trace execution failed",
        "trace_cancelled": "Trace execution was cancelled",
    }
    return labels[state]


def _optional_string(value: object) -> str | None:
    return str(value) if value not in (None, "") else None
