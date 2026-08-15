"""LangGraph adapter runtime receipt bounded error tests (契约 02 §9).

RTE-04 CF-07 硬化：execution.error 必须在 adapter 端截断到 2000 字符
（省略号计入上限），不得依赖 Guard API 侧 422 拒收兜底。
"""

from __future__ import annotations

import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from agentguard_langgraph_adapter.event_models import PolicyDecision  # noqa: E402
from agentguard_langgraph_adapter.runtime_receipts import (  # noqa: E402
    MAX_TERMINAL_ERROR_CHARS,
    bounded_terminal_error,
    build_runtime_outcome,
)


def _event(event_id: str = "evt_bounded") -> dict:
    return {
        "event_id": event_id,
        "trace_id": "trace_bounded",
        "runtime": "langgraph",
        "security_context": {"agent_id": "langgraph"},
    }


def _decision() -> PolicyDecision:
    return PolicyDecision(
        decision_id="dec_bounded",
        decision="allow",
        risk_score=10,
        severity="low",
        reason="bounded error fixture",
        policy_audit_id="audit_policy_bounded",
    )


def test_bounded_terminal_error_keeps_short_and_none_values() -> None:
    assert bounded_terminal_error(None) is None
    assert bounded_terminal_error("short failure") == "short failure"
    exact = "x" * MAX_TERMINAL_ERROR_CHARS
    assert bounded_terminal_error(exact) == exact


def test_bounded_terminal_error_truncates_over_limit_with_counted_ellipsis() -> None:
    oversized = "x" * (MAX_TERMINAL_ERROR_CHARS + 3000)
    bounded = bounded_terminal_error(oversized)
    assert bounded is not None
    assert len(bounded) == MAX_TERMINAL_ERROR_CHARS
    assert bounded.endswith("...")


def test_build_runtime_outcome_bounds_failed_execution_error() -> None:
    receipt = build_runtime_outcome(
        _event(),
        _decision(),
        execution_status="failed",
        error="y" * (MAX_TERMINAL_ERROR_CHARS * 3),
    )
    execution = receipt.model_dump()["evidence"]["execution"]
    assert execution["status"] == "failed"
    assert len(execution["error"]) == MAX_TERMINAL_ERROR_CHARS
    assert execution["error"].endswith("...")


def test_build_runtime_outcome_preserves_none_error_for_executed() -> None:
    receipt = build_runtime_outcome(
        _event(),
        _decision(),
        execution_status="executed",
        error=None,
    )
    execution = receipt.model_dump()["evidence"]["execution"]
    assert execution["error"] is None
