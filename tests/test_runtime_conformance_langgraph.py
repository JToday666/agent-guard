"""RTE-04 Conformance Suite — LangGraph profile (contract 05 §3, 06 §6).

固定决策 → 契约执行：驱动 ``agentguard_langgraph_adapter`` 的
``GuardedToolGateway``（Tier 2：fake guard adapter + in-memory runtime），
逐 CF case 断言 invocation 计数与 runtime_outcome 回执形态。

case ID 与 ``tests/runtime_conformance/contract_cases.json`` 一一对应；
能力矩阵见 ``tests/runtime_conformance/expected_capabilities.json``。
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agentguard_langgraph_adapter.event_models import (
    AuditEvent,
    PolicyDecision,
    ToolCallEvent,
    ToolDescriptor,
)
from agentguard_langgraph_adapter.tool_gateway import GuardedToolGateway

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tests" / "runtime_conformance" / "contract_cases.json"

POLICY_AUDIT_ID = "audit_policy_conformance"


def _case(case_id: str) -> dict[str, Any]:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    for case in registry["cases"]:
        if case["id"] == case_id:
            return case
    raise AssertionError(f"case {case_id} missing from contract_cases.json")


class ConformanceGuardAdapter:
    """固定决策的 fake guard adapter（guard-api-v0.3 模式，回执开启）。"""

    def __init__(
        self,
        decision: str = "allow",
        *,
        approval: dict[str, Any] | None = None,
        approval_resolution: dict[str, Any] | None = None,
        policy_audit_id: str | None = POLICY_AUDIT_ID,
        evaluate_error: Exception | None = None,
        submit_error: str | None = None,
        api_mode: str = "guard-api-v0.3",
    ) -> None:
        self.config = SimpleNamespace(
            core_api_mode=api_mode, defense_enabled=True
        )
        self.decision = decision
        self.approval = approval
        self.approval_resolution = approval_resolution
        self.policy_audit_id = policy_audit_id
        self.evaluate_error = evaluate_error
        self.submit_error = submit_error
        self.submitted: list[Any] = []

    def evaluate_before_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ) -> tuple[ToolCallEvent, PolicyDecision]:
        if self.evaluate_error is not None:
            raise self.evaluate_error
        event = ToolCallEvent(
            trace_id=trace_id,
            tool=ToolDescriptor(
                name=tool_name,
                category="tool",
                kind=tool_name,
                call_id=call_id or "call",
            ),
            arguments=arguments,
        )
        decision = PolicyDecision(
            decision_id="dec_conformance",
            decision=self.decision,  # type: ignore[arg-type]
            risk_score=10,
            severity="low",
            reason="fixed conformance decision",
            approval=self.approval,
            policy_audit_id=self.policy_audit_id,
        )
        return event, decision

    def build_audit_event(
        self, event: ToolCallEvent, decision: PolicyDecision
    ) -> AuditEvent:
        return AuditEvent(
            trace_id=event.trace_id,
            summary="conformance policy audit",
            decision=decision.decision,
            risk_score=decision.risk_score,
            severity=decision.severity,
            blocked=decision.blocked,
            reason=decision.reason,
        )

    def submit_audit_event(self, audit_event: Any) -> dict[str, Any]:
        if self.submit_error is not None:
            return {"ok": False, "error": self.submit_error}
        self.submitted.append(audit_event)
        return {"ok": True, "audit_id": getattr(audit_event, "audit_id", "")}

    def wait_for_approval(self, approval_id: str) -> dict[str, Any]:
        assert self.approval_resolution is not None
        return dict(self.approval_resolution)

    def outcome_receipts(self) -> list[dict[str, Any]]:
        return [
            receipt.model_dump()
            for receipt in self.submitted
            if getattr(receipt, "record_type", None) == "runtime_outcome"
        ]

    def observations(self) -> list[dict[str, Any]]:
        return [
            receipt.model_dump()
            for receipt in self.submitted
            if getattr(receipt, "record_type", None) == "runtime_observation"
        ]


class QuarantineGuardAdapter(ConformanceGuardAdapter):
    """CF-12：带工具结果隔离 gate 的 fake adapter。"""

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
    ) -> tuple[ToolCallEvent, PolicyDecision]:
        event = ToolCallEvent(
            trace_id=trace_id,
            tool=ToolDescriptor(
                name=tool_name,
                category="tool",
                kind=tool_name,
                call_id=call_id or "call",
            ),
            arguments=arguments,
        )
        decision = PolicyDecision(
            decision_id="dec_result_conformance",
            decision="deny",
            risk_score=10,
            severity="low",
            reason="fixed tool result quarantine decision",
            policy_audit_id=self.policy_audit_id,
        )
        return event, decision


class ConformanceRuntime:
    def __init__(self, *, fail_with: str | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail_with = fail_with

    def invoke(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool_name, dict(arguments)))
        if self.fail_with is not None:
            raise RuntimeError(self.fail_with)
        return {"ok": True}


def _gateway(
    guard: ConformanceGuardAdapter, runtime: ConformanceRuntime
) -> GuardedToolGateway:
    return GuardedToolGateway(guard_adapter=guard, tool_runtime=runtime)


def test_cf_01_allow_executes_once_with_terminal_fact() -> None:
    _case("CF-01")
    guard = ConformanceGuardAdapter("allow")
    runtime = ConformanceRuntime()
    gateway = _gateway(guard, runtime)

    result = gateway.invoke_tool(
        tool_name="read_file",
        arguments={"path": "/public/doc-1.txt"},
        security={"user_task": "read public docs"},
        trace_id="trace_cf01",
        call_id="call_cf01",
    )
    assert result.executed is True
    assert result.blocked is False

    # 每个被接受调用恰好一次 invocation + 一份 terminal 回执。
    assert len(runtime.calls) == 1
    receipts = guard.outcome_receipts()
    assert [r["metadata"]["outcome_kind"] for r in receipts] == [
        "execution_completed"
    ]
    execution = receipts[0]["evidence"]["execution"]
    assert execution["status"] == "executed"
    assert execution["error"] is None
    # C2：terminal fact 与 policy 关联齐全。
    assert receipts[0]["links"]["policy_audit_id"] == POLICY_AUDIT_ID
    assert receipts[0]["links"]["action_id"] == "call_cf01"

    # adapter 对每次被接受的调用执行一次（不做客户端重放抑制）；
    # 同事件重放的幂等去重属于 evaluate 层语义，由 CF-10 覆盖。
    second = gateway.invoke_tool(
        tool_name="read_file",
        arguments={"path": "/public/doc-2.txt"},
        security={"user_task": "read public docs"},
        trace_id="trace_cf01_b",
        call_id="call_cf01_b",
    )
    assert second.executed is True
    assert len(runtime.calls) == 2
    assert [
        receipt["links"]["action_id"] for receipt in guard.outcome_receipts()
    ] == ["call_cf01", "call_cf01_b"]


def test_cf_02_deny_not_invoked() -> None:
    _case("CF-02")
    guard = ConformanceGuardAdapter("deny")
    runtime = ConformanceRuntime()
    gateway = _gateway(guard, runtime)

    result = gateway.invoke_tool(
        tool_name="read_file",
        arguments={"path": "/private/token.txt"},
        security={"user_task": "steal token"},
        trace_id="trace_cf02",
        call_id="call_cf02",
    )

    assert result.executed is False
    assert result.blocked is True
    assert runtime.calls == []
    receipts = guard.outcome_receipts()
    assert len(receipts) == 1
    assert receipts[0]["metadata"]["outcome_kind"] == "pre_execution_deny"
    assert receipts[0]["evidence"]["execution"]["status"] == "not_invoked"
    assert receipts[0]["evidence"]["intervention"]["type"] == "policy_deny"


def test_cf_03_ask_human_deny_not_invoked() -> None:
    _case("CF-03")
    guard = ConformanceGuardAdapter(
        "ask",
        approval={"approval_id": "appr_cf03", "required": True},
        approval_resolution={"status": "resolved", "decision": "deny"},
    )
    runtime = ConformanceRuntime()
    gateway = _gateway(guard, runtime)

    result = gateway.invoke_tool(
        tool_name="memory_write",
        arguments={"namespace": "user", "key": "k", "value": "v"},
        security={"user_task": "write memory"},
        trace_id="trace_cf03",
        call_id="call_cf03",
    )

    assert result.executed is False
    assert result.blocked is True
    assert runtime.calls == []
    receipts = guard.outcome_receipts()
    assert len(receipts) == 1
    assert receipts[0]["metadata"]["outcome_kind"] == "pre_execution_deny"
    assert receipts[0]["evidence"]["execution"]["status"] == "not_invoked"
    assert (
        receipts[0]["evidence"]["intervention"]["type"] == "approval_not_obtained"
    )


def test_cf_04_ask_allow_once_releases_and_closes_terminal() -> None:
    _case("CF-04")
    guard = ConformanceGuardAdapter(
        "ask",
        approval={"approval_id": "appr_cf04", "required": True},
        approval_resolution={"status": "resolved", "decision": "allow_once"},
    )
    runtime = ConformanceRuntime()
    gateway = _gateway(guard, runtime)

    result = gateway.invoke_tool(
        tool_name="memory_write",
        arguments={"namespace": "user", "key": "style", "value": "concise"},
        security={"user_task": "remember style"},
        trace_id="trace_cf04",
        call_id="call_cf04",
    )

    assert result.executed is True
    assert len(runtime.calls) == 1
    # 放行证据：LangGraph 以 tool_call_started 观察承载（kind_any 语义）。
    observations = guard.observations()
    assert [o["event_type"] for o in observations] == ["tool_call_started"]
    receipts = guard.outcome_receipts()
    assert [r["metadata"]["outcome_kind"] for r in receipts] == [
        "execution_completed"
    ]
    terminal = receipts[0]
    assert terminal["evidence"]["execution"]["status"] == "executed"
    # terminal 回执经 parent_audit_id 聚合到同一放行链（CF-08 关联）。
    assert terminal["links"]["action_id"] == "call_cf04"
    # 放行观察与策略链同源：started 观察的 parent 即 policy audit。
    assert observations[0]["links"]["parent_audit_id"] == POLICY_AUDIT_ID
    assert terminal["links"]["policy_audit_id"] == POLICY_AUDIT_ID
    assert terminal["evidence"]["approval"]["decision"] == "allow_once"


def test_cf_05_wait_timeout_blocks_and_late_approval_does_not_resurrect() -> None:
    _case("CF-05")
    guard = ConformanceGuardAdapter(
        "ask",
        approval={"approval_id": "appr_cf05", "required": True},
        approval_resolution={"status": "timeout", "decision": "deny"},
    )
    runtime = ConformanceRuntime()
    gateway = _gateway(guard, runtime)

    first = gateway.invoke_tool(
        tool_name="memory_write",
        arguments={"namespace": "user", "key": "a", "value": "1"},
        security={"user_task": "write memory"},
        trace_id="trace_cf05",
        call_id="call_cf05_old",
    )
    assert first.executed is False
    assert first.blocked is True
    assert runtime.calls == []
    receipts_after_timeout = guard.outcome_receipts()
    assert len(receipts_after_timeout) == 1
    assert (
        receipts_after_timeout[0]["evidence"]["execution"]["status"]
        == "not_invoked"
    )
    original_event_id = receipts_after_timeout[0]["links"]["event_id"]

    # 晚到审批放行送达同一 approval/动作：旧 attempt 不得被复活——
    # 原事件不得出现 executed 终态回执；再次提交同一动作属新 attempt
    # （新事件 id），不得复用原事件身份。
    guard.approval_resolution = {"status": "resolved", "decision": "allow_once"}
    second = gateway.invoke_tool(
        tool_name="memory_write",
        arguments={"namespace": "user", "key": "a", "value": "1"},
        security={"user_task": "write memory"},
        trace_id="trace_cf05",
        call_id="call_cf05_old",
    )
    assert second.executed is True
    assert len(runtime.calls) == 1
    receipts = guard.outcome_receipts()
    assert len(receipts) == 2
    # 旧 attempt 的 not_invoked 回执原样保留，无新增终态事实。
    assert receipts[0]["links"]["action_id"] == "call_cf05_old"
    assert receipts[0]["evidence"]["execution"]["status"] == "not_invoked"
    # 复活防护：原事件 id 绝不携带 executed 终态。
    assert not any(
        receipt["links"]["event_id"] == original_event_id
        and receipt["evidence"]["execution"]["status"] == "executed"
        for receipt in receipts
    )
    # 新 attempt 用新事件 id 记录终态。
    assert receipts[1]["metadata"]["outcome_kind"] == "execution_completed"
    assert receipts[1]["links"]["event_id"] != original_event_id


def test_cf_06_evaluate_unavailable_fails_closed_without_policy_receipt() -> None:
    _case("CF-06")
    # Guard API 不可用（evaluate 异常）：受保护动作不得进入 runtime。
    guard = ConformanceGuardAdapter(
        "allow", evaluate_error=RuntimeError("guard api unavailable")
    )
    runtime = ConformanceRuntime()
    gateway = _gateway(guard, runtime)

    with pytest.raises(RuntimeError, match="guard api unavailable"):
        gateway.invoke_tool(
            tool_name="read_file",
            arguments={"path": "/private/token.txt"},
            security={"user_task": "read"},
            trace_id="trace_cf06",
            call_id="call_cf06",
        )
    assert runtime.calls == []

    # 策略审计提交失败（legacy 自提交路径）同样必须 fail-closed，且不产
    # policy-link receipt（基础设施阻断不进 detector 口径，05 §7/§9.6）。
    audit_failing = ConformanceGuardAdapter(
        "deny", submit_error="audit store unavailable", api_mode="legacy"
    )
    audit_runtime = ConformanceRuntime()
    audit_result = _gateway(audit_failing, audit_runtime).invoke_tool(
        tool_name="read_file",
        arguments={"path": "/private/token.txt"},
        security={"user_task": "read"},
        trace_id="trace_cf06_audit",
        call_id="call_cf06_audit",
    )
    assert audit_result.executed is False
    assert audit_result.blocked is True
    # 基础设施阻断的可辨识证据：status=audit_error + block_semantics=
    # audit_failure，且无 policy-link receipt（无 policy fact 不进 detector
    # 口径，05 §7/§9.6）。
    assert audit_result.status == "audit_error"
    assert audit_result.block_semantics == "audit_failure"
    assert audit_result.error is not None
    assert audit_runtime.calls == []
    assert audit_failing.outcome_receipts() == []


def test_cf_07_tool_failure_receipt_and_over_limit_error_passthrough() -> None:
    """CF-07 实测：failed 回执成立；超限 error 原样透传（bounded 缺口）。

    短 error 的 `len <= 2000` 断言是恒真式，不构成 bounded 证据（评审 P1）。
    本用例用超限 error 实测：adapter 将 str(exc) 原样写入回执（evidence 为
    自由 dict，无客户端截断），故 LangGraph 矩阵 CF-07 声明 NOT_SUPPORTED：
    bounded 保证目前仅由 Guard API 侧 ≤2000 校验（422 拒收）承担，
    adapter 端截断为后续硬化项。
    """
    _case("CF-07")
    oversized = "x" * 5000
    guard = ConformanceGuardAdapter("allow")
    runtime = ConformanceRuntime(fail_with=oversized)
    gateway = _gateway(guard, runtime)

    result = gateway.invoke_tool(
        tool_name="fetch_url",
        arguments={"url": "https://docs.example.test"},
        security={"user_task": "fetch docs"},
        trace_id="trace_cf07",
        call_id="call_cf07",
    )

    assert result.status == "error"
    assert len(runtime.calls) == 1
    receipts = guard.outcome_receipts()
    assert [r["metadata"]["outcome_kind"] for r in receipts] == [
        "execution_failed"
    ]
    execution = receipts[0]["evidence"]["execution"]
    assert execution["status"] == "failed"
    assert isinstance(execution["error"], str)
    assert execution["error"]
    # 实测当前行为：超限 error 未被 adapter 截断（缺口记录在矩阵 note）。
    assert len(execution["error"]) == len(oversized)
    assert execution["error"] == oversized


def test_cf_08_policy_and_terminal_receipts_aggregate_to_same_action() -> None:
    _case("CF-08")
    guard = ConformanceGuardAdapter("allow")
    runtime = ConformanceRuntime()
    gateway = _gateway(guard, runtime)

    gateway.invoke_tool(
        tool_name="read_file",
        arguments={"path": "/public/doc.txt"},
        security={"user_task": "read"},
        trace_id="trace_cf08",
        call_id="call_cf08",
    )

    receipts = guard.outcome_receipts()
    assert len(receipts) == 1
    links = receipts[0]["links"]
    # 稳定 action id：policy linkage 与 terminal 回执聚合到同一 action。
    assert links["action_id"] == "call_cf08"
    assert links["policy_audit_id"] == POLICY_AUDIT_ID
    assert links["decision_id"] == "dec_conformance"
    assert receipts[0]["trace_id"] == "trace_cf08"


def test_cf_12_result_quarantine_keeps_executed_with_quarantined_disposition() -> None:
    _case("CF-12")
    guard = QuarantineGuardAdapter("allow")
    runtime = ConformanceRuntime()
    gateway = _gateway(guard, runtime)

    result = gateway.invoke_tool(
        tool_name="fetch_url",
        arguments={"url": "https://poisoned.example.test"},
        security={"user_task": "fetch"},
        trace_id="trace_cf12",
        call_id="call_cf12",
    )

    # 工具真实执行，但结果被隔离，不进入上下文。
    assert len(runtime.calls) == 1
    assert result.status == "quarantined"
    assert result.quarantine_applied is True
    assert result.result is None
    receipts = guard.outcome_receipts()
    assert [r["metadata"]["outcome_kind"] for r in receipts] == [
        "tool_result_quarantined"
    ]
    receipt = receipts[0]
    assert receipt["evidence"]["execution"]["status"] == "executed"
    assert receipt["evidence"]["result"]["disposition"] == "quarantined"
    assert (
        receipt["evidence"]["intervention"]["type"] == "tool_result_quarantine"
    )
