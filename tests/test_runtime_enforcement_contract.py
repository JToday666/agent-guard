"""Runtime Enforcement Contract fixture and conformance tests (PR-RTE-01).

机器化 DoD：Runtime Enforcement Contract 02 §9 的六种 outcome_kind 示例
必须通过当前 JSON Schema（``schemas/runtime_outcome_receipt.schema.json``
与 ``schemas/audit_event.schema.json`` 双校验）以及 pydantic 权威模型
``agentguard_core.decisions.models.RuntimeOutcomeReceipt``。

本文件同时为 PR-RTE-04 Conformance Suite 打底：负例仅断言 validator 已实现
的约束（见 ``RuntimeExecutionEvidence._validate_execution`` 与
``RuntimeOutcomeReceipt._validate_receipt``），未实现的契约约束只以
``DEFERRED`` 注释记录，不写成会红的断言。
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Literal, get_args

import pytest
from jsonschema import validate
from pydantic import ValidationError as PydanticValidationError

from agentguard_core import RuntimeOutcomeReceipt
from agentguard_core.decisions.models import (
    RuntimeExecutionStatus,
    RuntimeOutcomeKind,
    RuntimeResultDisposition,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "runtime_enforcement"

OUTCOME_KINDS: tuple[str, ...] = (
    "pre_execution_deny",
    "approval_release",
    "execution_completed",
    "execution_failed",
    "tool_result_modified",
    "tool_result_quarantined",
)


def _load_schema(name: str) -> dict[str, Any]:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def _load_fixture(outcome_kind: str) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(
        (FIXTURE_DIR / f"{outcome_kind}.json").read_text(encoding="utf-8")
    )
    return payload


# ---------------------------------------------------------------------------
# a. 六个 fixture 双校验：pydantic 权威模型 + 两份 JSON Schema
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("outcome_kind", OUTCOME_KINDS)
def test_runtime_enforcement_fixture_passes_model_and_schema_validation(
    outcome_kind: str,
) -> None:
    payload = _load_fixture(outcome_kind)

    receipt = RuntimeOutcomeReceipt.model_validate(payload)

    # 顶层 20 个 required 字段全部齐全。
    schema = _load_schema("runtime_outcome_receipt.schema.json")
    assert set(schema["required"]) <= set(payload)

    # audit_id 确定性格式与文件内 event_id / outcome_kind 自洽。
    assert payload["audit_id"] == (
        f"audit_outcome_{payload['links']['event_id']}_{outcome_kind}"
    )
    assert payload["metadata"]["outcome_kind"] == outcome_kind
    # completed_at == timestamp，且统一带 +00:00 时区。
    assert receipt.evidence.execution.completed_at == receipt.timestamp
    assert receipt.timestamp.endswith("+00:00")
    # links 三必填齐全。
    assert payload["links"]["event_id"]
    assert payload["links"]["decision_id"]
    assert payload["links"]["policy_audit_id"]
    # latency_ms 必填但只允许 null。
    assert payload["latency_ms"] is None

    dumped = receipt.model_dump(mode="json")
    validate(dumped, schema)
    validate(dumped, _load_schema("audit_event.schema.json"))


@pytest.mark.parametrize("outcome_kind", OUTCOME_KINDS)
def test_runtime_enforcement_fixture_matches_contract_mapping(
    outcome_kind: str,
) -> None:
    """02 §9 契约映射：每个 fixture 的 execution / side_effects / result 取值。"""
    payload = _load_fixture(outcome_kind)
    execution = payload["evidence"]["execution"]
    side_effects = payload["evidence"]["side_effects"]
    result = payload["evidence"]["result"]
    approval = payload["evidence"]["approval"]

    if outcome_kind == "pre_execution_deny":
        assert execution["status"] == "not_invoked"
        assert result["disposition"] == "not_applicable"
        assert side_effects["measurement_status"] == "measured"
        assert side_effects["count"] == 0
        assert execution["tool_result_entered_context"] is False
        assert execution["persisted"] is False
        assert result["sanitized"] is False
    elif outcome_kind == "approval_release":
        assert execution["status"] == "unknown"
        assert result["disposition"] == "unknown"
        assert approval["status"] == "allowed"
        assert approval["decision"] == "allow_once"
        assert approval["approval_id"]
        assert approval["resolved_at"]
    elif outcome_kind == "execution_completed":
        assert execution["status"] == "executed"
        assert execution["error"] is None
        assert result["disposition"] == "unknown"
        assert side_effects["measurement_status"] == "not_measured"
        assert side_effects["count"] is None
    elif outcome_kind == "execution_failed":
        assert execution["status"] == "failed"
        assert isinstance(execution["error"], str) and execution["error"]
        assert len(execution["error"]) <= 2000
        assert result["disposition"] in {"not_applicable", "unknown"}
    elif outcome_kind == "tool_result_modified":
        assert execution["status"] == "executed"
        assert result["disposition"] == "modified"
    elif outcome_kind == "tool_result_quarantined":
        assert execution["status"] == "executed"
        assert result["disposition"] == "quarantined"
        # hook 可证时 tool_result_entered_context=false。
        assert execution["tool_result_entered_context"] is False
    else:  # pragma: no cover - OUTCOME_KINDS 已穷尽
        raise AssertionError(f"unexpected outcome_kind: {outcome_kind}")


# ---------------------------------------------------------------------------
# b. §8.3 负例：仅断言 validator 已实现的约束（深拷贝变异 fixture）
# ---------------------------------------------------------------------------


def _mutate_failed_without_error() -> dict[str, Any]:
    payload = _load_fixture("execution_failed")
    payload["evidence"]["execution"]["error"] = None
    return payload


def _mutate_executed_with_error() -> dict[str, Any]:
    payload = _load_fixture("execution_completed")
    payload["evidence"]["execution"]["error"] = "unexpected error"
    return payload


def _mutate_not_invoked_with_error() -> dict[str, Any]:
    payload = _load_fixture("pre_execution_deny")
    payload["evidence"]["execution"]["error"] = "unexpected error"
    return payload


def _mutate_invoked_after_completed() -> dict[str, Any]:
    payload = _load_fixture("execution_completed")
    payload["evidence"]["execution"]["invoked_at"] = "2026-08-15T08:10:09+00:00"
    return payload


def _mutate_timestamp_mismatch() -> dict[str, Any]:
    payload = _load_fixture("execution_completed")
    payload["timestamp"] = "2026-08-15T08:10:09+00:00"
    return payload


def _mutate_wrong_audit_id() -> dict[str, Any]:
    payload = _load_fixture("execution_completed")
    payload["audit_id"] = "audit_outcome_evt_rte_fixture_003_execution_failed"
    return payload


@pytest.mark.parametrize(
    ("mutate", "constraint"),
    [
        pytest.param(
            _mutate_failed_without_error,
            "failed",
            id="failed-requires-error",
        ),
        pytest.param(
            _mutate_executed_with_error,
            "executed",
            id="executed-forbids-error",
        ),
        pytest.param(
            _mutate_not_invoked_with_error,
            "not_invoked",
            id="not-invoked-forbids-error",
        ),
        pytest.param(
            _mutate_invoked_after_completed,
            "invoked_at",
            id="invoked-at-not-later-than-completed-at",
        ),
        pytest.param(
            _mutate_timestamp_mismatch,
            "completed_at",
            id="completed-at-must-equal-timestamp",
        ),
        pytest.param(
            _mutate_wrong_audit_id,
            "audit_id",
            id="audit-id-deterministic-format",
        ),
    ],
)
def test_runtime_enforcement_model_rejects_section_8_3_violations(
    mutate: Any, constraint: str
) -> None:
    with pytest.raises(PydanticValidationError) as exc_info:
        RuntimeOutcomeReceipt.model_validate(mutate())

    errors = exc_info.value.errors()
    assert any(constraint in error["msg"] for error in errors)


# DEFERRED（契约 02 §8.3/§9 要求但 validator 尚未实现，待 PR-RTE-04
# Conformance Suite 前补齐实现后再升级为断言）：
# - execution_failed 的 disposition 必须为 not_applicable 或 unknown：
#   _validate_receipt 只校验 execution_failed 的 status=failed，不约束
#   disposition。
# - tool_result_quarantined 在 hook 可证时 tool_result_entered_context=false：
#   pydantic 层未强制该取证条件。
# - outcome_kind 与 side_effects / approval 其余映射维度（如
#   pre_execution_deny 的 measured/count=0）：_validate_receipt 未覆盖，
#   目前仅由 JSON Schema 枚举与上方正向映射测试守护。


# ---------------------------------------------------------------------------
# c. 枚举 parity：fixture 集合 == JSON Schema 枚举 == Literal get_args
# ---------------------------------------------------------------------------


def test_outcome_kind_fixture_schema_and_model_enums_are_in_parity() -> None:
    schema = _load_schema("runtime_outcome_receipt.schema.json")
    schema_enum = set(
        schema["properties"]["metadata"]["properties"]["outcome_kind"]["enum"]
    )
    fixture_enum = {
        _load_fixture(kind)["metadata"]["outcome_kind"] for kind in OUTCOME_KINDS
    }

    assert fixture_enum == set(OUTCOME_KINDS)
    assert fixture_enum == schema_enum
    assert schema_enum == set(get_args(RuntimeOutcomeKind))


def test_execution_status_and_disposition_enums_are_in_parity() -> None:
    schema = _load_schema("runtime_outcome_receipt.schema.json")
    execution_enum = set(
        schema["properties"]["evidence"]["properties"]["execution"]["properties"][
            "status"
        ]["enum"]
    )
    disposition_enum = set(
        schema["properties"]["evidence"]["properties"]["result"]["properties"][
            "disposition"
        ]["enum"]
    )
    fixture_statuses = {
        _load_fixture(kind)["evidence"]["execution"]["status"]
        for kind in OUTCOME_KINDS
    }
    fixture_dispositions = {
        _load_fixture(kind)["evidence"]["result"]["disposition"]
        for kind in OUTCOME_KINDS
    }

    # fixture 出现的取值必须是 schema 枚举与模型 Literal 的子集，
    # 且 schema 枚举与模型 Literal 完全一致。
    assert fixture_statuses <= execution_enum == set(get_args(RuntimeExecutionStatus))
    assert fixture_dispositions <= disposition_enum == set(
        get_args(RuntimeResultDisposition)
    )


# ---------------------------------------------------------------------------
# d. GateState 契约常量守护（契约包 02 §3）
# ---------------------------------------------------------------------------

# 契约包 02 §3 GateState 状态机的小写字面量集合；纯契约守护，不 import
# 任何 runtime 实现代码。若契约包后续落地 GateState 实现，应改为与其对齐。
GateState = Literal[
    "evaluating",
    "allowed",
    "approval_pending",
    "approval_released",
    "blocked",
    "timed_out",
    "binding_failed",
]

_GATE_STATES: frozenset[str] = frozenset(get_args(GateState))
_EXECUTION_AUTHORIZED_STATES: frozenset[str] = frozenset(
    {"allowed", "approval_released"}
)


def execution_authorized(state: GateState) -> bool:
    return state in _EXECUTION_AUTHORIZED_STATES


def test_gate_state_contract_constants_are_guarded() -> None:
    assert _GATE_STATES == {
        "evaluating",
        "allowed",
        "approval_pending",
        "approval_released",
        "blocked",
        "timed_out",
        "binding_failed",
    }

    for state in get_args(GateState):
        assert execution_authorized(state) is (
            state in _EXECUTION_AUTHORIZED_STATES
        )

    # execution_authorized 当且仅当 state ∈ {allowed, approval_released}。
    assert {state for state in get_args(GateState) if execution_authorized(state)} == _EXECUTION_AUTHORIZED_STATES


# _validate_receipt 已实现的 outcome_kind 一致性规则（kind -> 必须满足的
# execution.status / result.disposition / approval.status 约束）。
_KIND_RULES: dict[str, dict[str, str]] = {
    "pre_execution_deny": {"status": "not_invoked", "disposition": "not_applicable"},
    "approval_release": {"status": "unknown", "approval_status": "allowed"},
    "execution_completed": {"status": "executed"},
    "execution_failed": {"status": "failed"},
    "tool_result_modified": {"status": "executed", "disposition": "modified"},
    "tool_result_quarantined": {"status": "executed", "disposition": "quarantined"},
}


def test_fixture_variants_rejected_by_every_kind_specific_rule() -> None:
    """正向补充：变异 outcome_kind 与 evidence 组合按已实现规则精确判定。

    覆盖 _validate_receipt 中六条 outcome_kind↔status/disposition/approval
    一致性规则（已实现）：交换 fixture 的 outcome_kind 后，凡是违反目标
    kind 规则的必须拒绝；恰好满足目标 kind 规则的（如 executed 的
    modified/quarantined fixture 换为 execution_completed）允许通过，
    守护 validator 不过度约束。
    """
    for kind in OUTCOME_KINDS:
        base = _load_fixture(kind)
        for foreign_kind in OUTCOME_KINDS:
            if foreign_kind == kind:
                continue
            payload = copy.deepcopy(base)
            payload["metadata"]["outcome_kind"] = foreign_kind
            # audit_id 同步重算，排除确定性格式干扰，只触发一致性规则。
            payload["audit_id"] = (
                f"audit_outcome_{payload['links']['event_id']}_{foreign_kind}"
            )

            rule = _KIND_RULES[foreign_kind]
            violates = (
                payload["evidence"]["execution"]["status"] != rule.get("status")
                or payload["evidence"]["result"]["disposition"]
                != rule.get("disposition", payload["evidence"]["result"]["disposition"])
                or payload["evidence"]["approval"]["status"]
                != rule.get("approval_status", payload["evidence"]["approval"]["status"])
            )
            if violates:
                with pytest.raises(PydanticValidationError):
                    RuntimeOutcomeReceipt.model_validate(payload)
            else:
                RuntimeOutcomeReceipt.model_validate(payload)
