"""V21-05/06/07 Phase 2 集成接线契约测试。

断言接线后不变量：

1. ``TYPED_UPSERT_HANDLERS`` 装配全部 11 容器，顺序严格按 01 §27
   ``SecurityStateDeltaV21`` 字段声明序，handler 与
   ``CONTAINER_OWNERSHIP`` 所有权一致；``apply_typed_updates`` 对
   非空容器确定性应用；
2. ``projector._UNWIRED_TYPED_UPSERT_CONTAINERS`` 清单已移除
   （接线完成，fail-closed 拦截分支退役）；
3. ``handlers.py`` / ``coverage_context.py`` 无 register/unregister
   符号（AST 扫描，禁止运行时注册 API）；
4. 非空 typed upsert delta 正常 apply（容器内容进入 state，CAS /
   版本推进语义不变）；
5. ``execution_leases`` 默认空且 ``SecurityStateDeltaV21`` 无 lease
   写入路径（C5：lease 只存权威 lease store）；
6. ``DOMAIN_COVERAGE_DISPATCH`` 装配六域（task 域不入表），
   ``CoverageContext`` 可用最小字段构造。
"""

from __future__ import annotations

import ast
import inspect

import pytest

from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import (
    OnlineSecurityState,
    SecurityStateDeltaV21,
    apply_delta,
)
from agentguard_core.security_context import coverage_context, handlers
from agentguard_core.security_context import projector as projector_module
from agentguard_core.security_context.coverage_context import (
    DOMAIN_COVERAGE_DISPATCH,
    CoverageContext,
)
from agentguard_core.security_context.handlers import (
    CONTAINER_OWNERSHIP,
    TYPED_UPSERT_HANDLERS,
    apply_typed_updates,
)

from tests.test_v21_security_state_models import (
    make_delta,
    make_grant,
    make_source_fact,
    make_watermarks,
)

#: 01 §27 ``SecurityStateDeltaV21`` 的 11 个 typed upsert 容器字段声明序。
DECLARATION_ORDER = [
    field
    for field in SecurityStateDeltaV21.model_fields
    if field in CONTAINER_OWNERSHIP
]


def empty_state() -> OnlineSecurityState:
    return OnlineSecurityState(watermarks=make_watermarks())


def fixture_plan() -> RequiredCheckPlan:
    return RequiredCheckPlan(
        plan_id="v21-04-plan:fixture",
        impact="high",
        required_domains=["task", "capability"],
        optional_domains=[
            "source",
            "behavior",
            "dataflow",
            "memory",
            "runtime_outcome",
        ],
        required_capabilities=[],
        semantic_resolvable_dimensions=[],
        reason_codes=["v21-04:fixture"],
    )


# ---------------------------------------------------------------------------
# 1. 中央 handler 分发表：11 容器全注册 + 声明序
# ---------------------------------------------------------------------------


def test_typed_upsert_handlers_registers_all_containers_in_order() -> None:
    assert isinstance(TYPED_UPSERT_HANDLERS, tuple)
    containers = [name for name, _ in TYPED_UPSERT_HANDLERS]
    assert len(containers) == 11
    assert len(set(containers)) == 11
    # 顺序严格按 01 §27 SecurityStateDeltaV21 字段声明序。
    assert containers == DECLARATION_ORDER
    # 容器集与所有权表一致（无遗漏无多余）。
    assert set(containers) == set(CONTAINER_OWNERSHIP)
    # 每个 handler 均可调用且为分支私有模块的纯函数。
    for _name, handler in TYPED_UPSERT_HANDLERS:
        assert callable(handler)


def test_handler_ownership_matches_branch_modules() -> None:
    for name, owner in CONTAINER_OWNERSHIP.items():
        handler_fn = dict(TYPED_UPSERT_HANDLERS)[name]
        assert handler_fn.__module__ == (
            f"agentguard_core.security_context.projection.{owner}"
        ), name


def test_apply_typed_updates_applies_non_empty_containers() -> None:
    state = empty_state()
    delta = make_delta().model_copy(
        update={
            "source_upserts": [make_source_fact()],
            "grant_upserts": [make_grant()],
        }
    )
    result = apply_typed_updates(state, delta)
    assert [source.source_id for source in result.source_index] == ["src_1"]
    assert [grant.grant_id for grant in result.active_grants] == ["grant_1"]
    # 纯函数：输入状态不被修改。
    assert state.source_index == []
    assert state.active_grants == []


def test_apply_typed_updates_noop_when_all_containers_empty() -> None:
    state = empty_state()
    delta = make_delta()
    assert apply_typed_updates(state, delta) is state


# ---------------------------------------------------------------------------
# 2. unwired 清单与 fail-closed 拦截分支已退役
# ---------------------------------------------------------------------------


def test_unwired_container_list_is_removed() -> None:
    assert not hasattr(projector_module, "_UNWIRED_TYPED_UPSERT_CONTAINERS")


# ---------------------------------------------------------------------------
# 3. 无 register/unregister 符号（AST 扫描）
# ---------------------------------------------------------------------------


def _module_identifiers(module: object) -> set[str]:
    source = inspect.getsource(module)
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.asname or node.name)
    return names


@pytest.mark.parametrize("module", [handlers, coverage_context])
def test_no_registration_api_symbols(module: object) -> None:
    offenders = {
        name
        for name in _module_identifiers(module)
        if "register" in name.lower()
    }
    assert offenders == set()


# ---------------------------------------------------------------------------
# 4. 非空 typed upsert delta 正常 apply（接线后语义）
# ---------------------------------------------------------------------------


def test_non_empty_typed_upsert_is_applied() -> None:
    state = empty_state()
    delta = make_delta(base_state_version=0).model_copy(
        update={"grant_upserts": [make_grant()]}
    )
    result = apply_delta(state, delta)
    assert result.outcome == "applied"
    assert result.state.state_version == 1
    assert [grant.grant_id for grant in result.state.active_grants] == [
        "grant_1"
    ]
    # CAS / 幂等登记语义不变。
    assert len(result.state.applied_projections) == 1
    # 输入状态不被修改（纯函数）。
    assert state.state_version == 0
    assert state.active_grants == []


# ---------------------------------------------------------------------------
# 5. lease 无 delta 写入路径（C5）
# ---------------------------------------------------------------------------


def test_execution_leases_empty_and_no_delta_write_path() -> None:
    assert empty_state().execution_leases == []
    assert "execution_leases" not in SecurityStateDeltaV21.model_fields
    lease_fields = [
        name for name in SecurityStateDeltaV21.model_fields if "lease" in name
    ]
    assert lease_fields == []


# ---------------------------------------------------------------------------
# 6. coverage 分发表装配六域 + CoverageContext 可构造
# ---------------------------------------------------------------------------


def test_domain_coverage_dispatch_wires_six_domains() -> None:
    assert set(DOMAIN_COVERAGE_DISPATCH) == {
        "source",
        "capability",
        "behavior",
        "dataflow",
        "memory",
        "runtime_outcome",
    }
    # task 域由总分派内既有逻辑处理，不入 dispatch。
    assert "task" not in DOMAIN_COVERAGE_DISPATCH
    for _domain, fn in DOMAIN_COVERAGE_DISPATCH.items():
        assert callable(fn)


def test_coverage_context_constructible_with_minimal_fields() -> None:
    plan = fixture_plan()
    watermarks = make_watermarks()
    context = CoverageContext(plan=plan, watermarks=watermarks)
    assert context.plan is plan
    assert context.watermarks is watermarks
    assert context.gap_context is None
    assert context.gaps == ()
    assert context.eviction_report is None
    assert context.truncated == ()
    assert dict(context.provider_available) == {}
    assert context.authoritative_head_revision is None
