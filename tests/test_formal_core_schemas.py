from __future__ import annotations

import json
from pathlib import Path

from jsonschema import validate

from agentguard_core.models import AuditEvent, PolicyDecision, ToolCallEvent


ROOT = Path(__file__).resolve().parents[1]


def _load_schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def test_formal_schemas_validate_core_models() -> None:
    tool_call = ToolCallEvent(
        trace_id="trace_schema",
        tool={"name": "read_file", "category": "file", "kind": "file_read", "call_id": "call_schema"},
        arguments={"path": "/docs/public.txt"},
    )
    decision = PolicyDecision(
        decision_id="dec_schema",
        decision="allow",
        risk_score=0,
        severity="low",
        rule_hits=[],
        reason="Allowed.",
        safe_message=None,
        approval=None,
        latency_ms=1,
    )
    audit = AuditEvent(
        audit_id="audit_schema",
        trace_id="trace_schema",
        summary="Agent attempted to call read_file",
        decision="allow",
        risk_score=0,
        severity="low",
        blocked=False,
        reason="Allowed.",
        attack_type="benign",
        is_malicious=False,
        latency_ms=1,
    )

    validate(tool_call.model_dump(mode="json"), _load_schema("tool_call_event.schema.json"))
    validate(decision.model_dump(mode="json"), _load_schema("policy_decision.schema.json"))
    validate(audit.model_dump(mode="json"), _load_schema("audit_event.schema.json"))
    validate(
        {
            "case_id": "BN-SCHEMA",
            "attack_type": "benign",
            "is_malicious": False,
            "runtime_targets": ["langgraph"],
            "input": {"source_type": "user", "source_trust": "trusted", "payload": "Read /docs/public.txt"},
            "target_behavior": {"tool": "read_file", "resource": "/docs/public.txt", "operation": "read"},
            "expected_decision": "allow",
            "success_condition": {"type": "tool_executed", "tool": "read_file", "resource": "/docs/public.txt"},
            "tool_plan": [{"tool": "read_file", "arguments": {"path": "/docs/public.txt"}}],
            "metadata": {},
        },
        _load_schema("attack_case.schema.json"),
    )
