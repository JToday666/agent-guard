"""V21-04 build_required_check_plan 表驱动契约测试（F7）。

覆盖（01 §18：由 ActionIR + PolicySnapshot 确定性映射，不由 LLM 决定）：

- low/moderate/high impact 基线 required/optional 域集合与 reason_codes；
- egress（external_communication / data_egress）与 persistence effects
  的追加规则；
- policy 豁免（not_applicable_actions / capability_not_required_actions /
  requires_task_authority=False）组合；
- plan_id 恒定性（相同输入恒定、输入变化即变化，禁 uuid）；
- runtime_outcome 本期恒为 optional。
"""

from __future__ import annotations

import pytest

from agentguard_core.actions import (
    CANONICALIZATION_VERSION,
    NORMALIZER_VERSION,
    ActionEffect,
    ActionIR,
    CanonicalArguments,
)
from agentguard_core.security_context import (
    COVERAGE_DOMAINS,
    PolicyProfile,
    build_required_check_plan,
)

_ALL_DOMAINS = list(COVERAGE_DOMAINS)


def make_action(
    *, impact: str = "low", action_type: str = "file.read", **effects: bool
) -> ActionIR:
    digest = "sha256:" + "00" * 32
    return ActionIR(
        event_id="event_plan_1",
        action_id="action_plan_1",
        trace_id="trace_plan",
        task_id="task_1",
        task_revision=1,
        scope_digest="hmac-sha256:plan_fixture_scope",
        principal_id="principal_a",
        runtime="openclaw",
        runtime_binding_id="binding_a",
        agent_id="agent_a",
        branch_id=None,
        parent_event_ids=[],
        runtime_sequence=None,
        tool_name=None,
        action_type=action_type,
        effects=ActionEffect(**effects),
        impact=impact,  # pyright: ignore[reportArgumentType]
        resources=[],
        destinations=[],
        data_refs=[],
        canonical_arguments=CanonicalArguments(
            items=[],
            canonicalization_version=CANONICALIZATION_VERSION,
            argument_digest=digest,
        ),
        argument_digest=digest,
        authorization_fingerprint="hmac-sha256:plan_fp",
        audit_fingerprint="hmac-sha256:plan_fp",
        normalizer_version=NORMALIZER_VERSION,
    )


def make_policy(**overrides: object) -> PolicyProfile:
    payload: dict[str, object] = {
        "policy_revision": "rev_1",
        "policy_digest": "sha256:policy_plan_fixture",
    }
    payload.update(overrides)
    return PolicyProfile(**payload)  # pyright: ignore[reportArgumentType]


# ---------------------------------------------------------------------------
# impact 基线（表驱动）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("impact", "expected_required"),
    [
        ("low", {"task", "capability"}),
        ("moderate", {"task", "source", "capability", "dataflow"}),
        (
            "high",
            {"task", "source", "capability", "behavior", "dataflow", "memory"},
        ),
    ],
)
def test_impact_baseline_required_domains(
    impact: str, expected_required: set[str]
) -> None:
    plan = build_required_check_plan(make_action(impact=impact), make_policy())
    assert set(plan.required_domains) == expected_required
    # 未进 required 的域一律进 optional（fail-closed 可见性）。
    assert set(plan.optional_domains) == set(_ALL_DOMAINS) - expected_required
    assert f"v21-04:impact_{impact}" in plan.reason_codes
    assert plan.impact == impact
    # runtime_outcome 本期恒为 optional。
    assert "runtime_outcome" not in plan.required_domains
    assert "runtime_outcome" in plan.optional_domains
    # 域列表按 COVERAGE_DOMAINS 固定序稳定排序。
    assert plan.required_domains == [
        domain for domain in _ALL_DOMAINS if domain in expected_required
    ]
    # 所有 reason_codes 使用 v21-04: 前缀。
    assert all(code.startswith("v21-04:") for code in plan.reason_codes)


def test_impact_shorthand_input_is_supported() -> None:
    plan = build_required_check_plan("low", make_policy())  # pyright: ignore[reportArgumentType]
    assert set(plan.required_domains) == {"task", "capability"}


# ---------------------------------------------------------------------------
# effects 追加规则（egress / persistence）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("effect", ["external_communication", "data_egress"])
def test_egress_effects_add_source_and_dataflow(effect: str) -> None:
    plan = build_required_check_plan(
        make_action(impact="low", **{effect: True}), make_policy()
    )
    assert set(plan.required_domains) == {
        "task",
        "capability",
        "source",
        "dataflow",
    }
    assert (
        "v21-04:effect_external_communication_or_egress" in plan.reason_codes
    )


def test_persistence_effect_adds_memory() -> None:
    plan = build_required_check_plan(
        make_action(impact="low", persistence=True), make_policy()
    )
    assert set(plan.required_domains) == {"task", "capability", "memory"}
    assert "v21-04:effect_persistence" in plan.reason_codes


# ---------------------------------------------------------------------------
# policy 豁免组合
# ---------------------------------------------------------------------------


def test_policy_not_applicable_action_removes_source_dataflow_memory() -> None:
    policy = make_policy(not_applicable_actions=frozenset({"file.read"}))
    plan = build_required_check_plan(make_action(impact="high"), policy)
    assert set(plan.required_domains) == {"task", "capability", "behavior"}
    assert "v21-04:policy_not_applicable_action" in plan.reason_codes


def test_policy_capability_not_required_action() -> None:
    policy = make_policy(capability_not_required_actions=frozenset({"file.read"}))
    plan = build_required_check_plan(make_action(impact="low"), policy)
    assert set(plan.required_domains) == {"task"}
    assert "v21-04:policy_capability_not_required" in plan.reason_codes


def test_task_moves_to_optional_when_policy_waives_task_authority() -> None:
    policy = make_policy(requires_task_authority=False)
    plan = build_required_check_plan(make_action(impact="moderate"), policy)
    assert "task" not in plan.required_domains
    assert "task" in plan.optional_domains
    assert "v21-04:policy_task_not_required" in plan.reason_codes
    # task 非 required → 不产出 task_alignment 语义维度。
    assert plan.semantic_resolvable_dimensions == []

    required_plan = build_required_check_plan(
        make_action(impact="moderate"), make_policy()
    )
    assert required_plan.semantic_resolvable_dimensions == ["task_alignment"]


def test_combined_effects_and_policy_exemption() -> None:
    # high + egress + persistence + policy 豁免 source/dataflow/memory：
    # 豁免在 effects 追加之后生效，最终只保留 task/capability/behavior。
    policy = make_policy(not_applicable_actions=frozenset({"email.send"}))
    plan = build_required_check_plan(
        make_action(
            impact="high",
            action_type="email.send",
            data_egress=True,
            persistence=True,
        ),
        policy,
    )
    assert set(plan.required_domains) == {"task", "capability", "behavior"}
    assert "v21-04:effect_external_communication_or_egress" in plan.reason_codes
    assert "v21-04:effect_persistence" in plan.reason_codes
    assert "v21-04:policy_not_applicable_action" in plan.reason_codes


# ---------------------------------------------------------------------------
# plan_id 确定性（禁 uuid）
# ---------------------------------------------------------------------------


def test_plan_id_is_deterministic_and_input_sensitive() -> None:
    first = build_required_check_plan(make_action(impact="low"), make_policy())
    second = build_required_check_plan(make_action(impact="low"), make_policy())
    assert first.plan_id == second.plan_id
    assert first.plan_id.startswith("v21-04-plan:")

    changed_impact = build_required_check_plan(
        make_action(impact="high"), make_policy()
    )
    assert changed_impact.plan_id != first.plan_id

    changed_policy = build_required_check_plan(
        make_action(impact="low"), make_policy(policy_revision="rev_2")
    )
    assert changed_policy.plan_id != first.plan_id
