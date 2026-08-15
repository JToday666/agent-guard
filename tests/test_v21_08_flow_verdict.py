"""V21-08 T2：FlowVerdict 纯函数生成器契约测试。

口径：

- 02 §6.5：``未发现危险 flow + dataflow=complete`` 才算安全证据；
  ``dataflow=unknown`` 不能解释为安全；
- 10_决策记录 D3：``FlowFact.strength`` 由 producer 给定，投影不重算、
  不推断、不升格；``strength == "possible"`` 在 dataflow 判定中降
  partial（不得作为 safe 证据）；
- flow 数据截断 → 降级（status 不得为 safe）；
- 判定确定性：同输入同输出，无 wall-clock/uuid。
"""

from __future__ import annotations

import pytest

from agentguard_core.actions.models import (
    CANONICALIZATION_VERSION,
    NORMALIZER_VERSION,
    ActionEffect,
    ActionIR,
    CanonicalArguments,
    UrlResource,
)
from agentguard_core.authority.models import EvaluationClock, SecurityStateScope
from agentguard_core.decisions.evidence import CoverageMap, DomainCoverage
from agentguard_core.security_context.facts import (
    FlowFact,
    StateWatermarks,
    StickyTaintSummary,
)
from agentguard_core.security_context.projection.flow_verdict import (
    DANGEROUS_TAINTS,
    compute_flow_verdict,
)
from agentguard_core.security_context.snapshot import SecuritySnapshot
from agentguard_core.signals.models import SequenceRef

PROJECTOR_VERSION = "v21-07.projector.2"


# ---------------------------------------------------------------------------
# 构造辅助
# ---------------------------------------------------------------------------


def _sequence(value: int = 1) -> SequenceRef:
    return SequenceRef(domain="memory", producer_binding_id="binding-1", value=value)


def _coverage(dataflow_status: str = "complete") -> CoverageMap:
    return CoverageMap(
        **{
            domain: DomainCoverage(
                domain=domain,
                status=dataflow_status if domain == "dataflow" else "complete",
                as_of_sequence=None,
                projector_version=PROJECTOR_VERSION,
                reason_codes=[],
            )
            for domain in (
                "task",
                "source",
                "capability",
                "behavior",
                "dataflow",
                "memory",
                "runtime_outcome",
            )
        }
    )


def _snapshot(
    *,
    flows: list[FlowFact] | None = None,
    sticky: list[StickyTaintSummary] | None = None,
    dataflow_status: str = "complete",
    dirty_domains: list[str] | None = None,
) -> SecuritySnapshot:
    return SecuritySnapshot(
        snapshot_id="snap-1",
        state_version=7,
        scope=SecurityStateScope(
            principal_id="principal-1",
            runtime="langgraph",
            runtime_binding_id="binding-1",
            trace_id="trace-1",
            session_id=None,
            scope_digest="sha256:scope",
        ),
        evaluation_clock=EvaluationClock(
            evaluated_at="2026-08-15T00:00:00+00:00",
            clock_version="v1",
        ),
        as_of_sequence=None,
        projector_version=PROJECTOR_VERSION,
        policy_revision="rev-1",
        policy_digest="sha256:policy",
        coverage=_coverage(dataflow_status),
        watermarks=StateWatermarks(
            committed_sequence=None,
            projected_sequence=None,
            runtime_receipt_sequence=None,
            memory_sequence=None,
            gaps=[],
        ),
        task=None,
        sources=[],
        grants=[],
        recent_actions=[],
        flows=flows or [],
        memory_facts=[],
        runtime_outcomes=[],
        behavior_aggregates=[],
        sticky_taint_summaries=sticky or [],
        declassifications=[],
        dirty_domains=dirty_domains or [],
        snapshot_digest="sha256:snapshot",
    )


def _flow_fact(
    flow_id: str,
    *,
    taints: list[str],
    strength: str = "exact",
    relation: str = "sent_to",
    source_ref: str = "action-1",
    target_ref: str = "sink-1",
) -> FlowFact:
    return FlowFact(
        flow_id=flow_id,
        scope_digest="sha256:scope",
        source_ref=source_ref,
        target_ref=target_ref,
        relation=relation,
        taints=taints,
        strength=strength,
        origin="observed",
        sequence=None,
        producer="producer-1",
        evidence_refs=[],
    )


def _sticky(
    summary_id: str = "sticky-1",
    *,
    taints: list[str] | None = None,
    unresolved_flow_refs: list[str] | None = None,
) -> StickyTaintSummary:
    return StickyTaintSummary(
        summary_id=summary_id,
        taints=taints or ["CREDENTIAL"],
        first_seen=_sequence(1),
        last_seen=_sequence(2),
        unresolved_flow_refs=unresolved_flow_refs or [],
        memory_refs=[],
        evidence_refs=[],
    )


def _action_ir(
    *,
    destinations: list | None = None,
    effects: ActionEffect | None = None,
) -> ActionIR:
    return ActionIR(
        event_id="event-1",
        action_id="action-1",
        trace_id="trace-1",
        task_id=None,
        task_revision=None,
        scope_digest="sha256:scope",
        principal_id="principal-1",
        runtime="langgraph",
        runtime_binding_id="binding-1",
        agent_id="agent-1",
        branch_id=None,
        parent_event_ids=[],
        runtime_sequence=None,
        tool_name="http_request",
        action_type="http.send",
        effects=effects or ActionEffect(),
        impact="high",
        resources=[],
        destinations=destinations or [],
        data_refs=[],
        canonical_arguments=CanonicalArguments(
            items=[],
            canonicalization_version=CANONICALIZATION_VERSION,
            argument_digest="sha256:args",
        ),
        argument_digest="sha256:args",
        authorization_fingerprint="sha256:authfp",
        audit_fingerprint="sha256:auditfp",
        normalizer_version=NORMALIZER_VERSION,
    )


def _url_destination() -> UrlResource:
    return UrlResource(
        resource_id="dest-1",
        canonical_id="url:evil.example",
        display_summary="https://evil.example/upload",
        resolution_status="resolved",
        normalizer_version=NORMALIZER_VERSION,
        scheme="https",
        host_ascii="evil.example",
        port=443,
        normalized_path="/upload",
        query_keys=[],
        security_query_arguments=[],
        redirect_policy="forbid",
    )


# ---------------------------------------------------------------------------
# safe 判定双前提（02 §6.5）
# ---------------------------------------------------------------------------


def test_safe_requires_no_dangerous_flow_and_complete_dataflow() -> None:
    snapshot = _snapshot()
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status == "safe"
    assert verdict.strongest_strength is None
    assert verdict.taints == []
    assert verdict.path_refs == []


@pytest.mark.parametrize("dataflow_status", ["unknown", "partial", "stale"])
def test_absence_of_dangerous_flow_is_not_safe_without_complete_dataflow(
    dataflow_status: str,
) -> None:
    snapshot = _snapshot(dataflow_status=dataflow_status)
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status == "uncertain"


def test_dangerous_flow_is_violation_even_with_complete_dataflow() -> None:
    snapshot = _snapshot(
        flows=[_flow_fact("flow-1", taints=["CREDENTIAL"], strength="exact")]
    )
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status == "violation"
    assert verdict.strongest_strength == "exact"
    assert verdict.taints == ["CREDENTIAL"]
    assert verdict.path_refs == ["flow-1"]


def test_non_dangerous_taint_does_not_trigger_violation() -> None:
    assert DANGEROUS_TAINTS == {"CREDENTIAL", "SENSITIVE", "PERSISTENT_UNTRUSTED"}
    snapshot = _snapshot(
        flows=[_flow_fact("flow-benign", taints=["UNTRUSTED"], strength="exact")]
    )
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status == "safe"


# ---------------------------------------------------------------------------
# D3：possible 降 partial，不重算、不推断、不升格
# ---------------------------------------------------------------------------


def test_possible_strength_blocks_safe_even_with_complete_dataflow() -> None:
    snapshot = _snapshot(
        flows=[
            _flow_fact("flow-possible", taints=["UNTRUSTED"], strength="possible")
        ]
    )
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status == "uncertain"
    # strength 透传 producer 值，不升格。
    assert verdict.strongest_strength == "possible"


def test_strength_is_passed_through_never_upgraded() -> None:
    snapshot = _snapshot(
        flows=[
            _flow_fact("flow-a", taints=["SENSITIVE"], strength="possible"),
        ]
    )
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status == "violation"
    assert verdict.strongest_strength == "possible"


def test_strongest_strength_takes_producer_maximum() -> None:
    snapshot = _snapshot(
        flows=[
            _flow_fact("flow-a", taints=["SENSITIVE"], strength="possible"),
            _flow_fact("flow-b", taints=["CREDENTIAL"], strength="exact"),
            _flow_fact("flow-c", taints=["SENSITIVE"], strength="strong"),
        ]
    )
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status == "violation"
    assert verdict.strongest_strength == "exact"
    assert verdict.taints == ["CREDENTIAL", "SENSITIVE"]
    # path_refs 保持 snapshot 内 flow 顺序（确定性）。
    assert verdict.path_refs == ["flow-a", "flow-b", "flow-c"]


# ---------------------------------------------------------------------------
# 截断降级（status 不得为 safe/complete）
# ---------------------------------------------------------------------------


def test_dirty_dataflow_domain_degrades_verdict() -> None:
    snapshot = _snapshot(dirty_domains=["dataflow"])
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status in {"uncertain", "violation"}
    assert verdict.status != "safe"


def test_unresolved_sticky_flow_refs_degrade_verdict() -> None:
    snapshot = _snapshot(
        sticky=[
            _sticky(
                taints=["UNTRUSTED"],
                unresolved_flow_refs=["flow-missing"],
            )
        ]
    )
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status != "safe"
    assert verdict.status in {"uncertain", "violation"}


def test_truncation_does_not_mask_confirmed_violation() -> None:
    snapshot = _snapshot(
        flows=[_flow_fact("flow-1", taints=["CREDENTIAL"], strength="strong")],
        dirty_domains=["dataflow"],
    )
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status == "violation"


# ---------------------------------------------------------------------------
# sticky taint / not_applicable / sink
# ---------------------------------------------------------------------------


def test_dangerous_sticky_taint_blocks_safe() -> None:
    snapshot = _snapshot(sticky=[_sticky(taints=["CREDENTIAL"])])
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status == "uncertain"
    assert verdict.taints == ["CREDENTIAL"]


def test_not_applicable_when_no_flow_requirement() -> None:
    snapshot = _snapshot(dataflow_status="not_applicable")
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status == "not_applicable"
    assert verdict.strongest_strength is None


def test_not_applicable_holds_with_non_dangerous_flows_present() -> None:
    """02 §6.5：dataflow=not_applicable 时未发现危险 flow 即构成安全
    证据，不得要求 complete；非危险 flow 不构成阻碍（危险 flow 已在
    violation 分支先行拦截）。"""
    snapshot = _snapshot(
        dataflow_status="not_applicable",
        flows=[_flow_fact("flow-1", taints=["UNTRUSTED"], strength="strong")],
    )
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.status == "not_applicable"


def test_not_applicable_overrides_bootstrap_unknown_coverage() -> None:
    """Codex review P1-2 回归：bootstrap snapshot 无存储 flow 时把
    dataflow 报为 unknown，但当前动作 plan 派生的 coverage 为
    not_applicable（低影响动作）——flow verdict 必须用后者，否则恒
    uncertain、fusion 永远无法 CLEAR_ALLOW。"""
    snapshot = _snapshot(dataflow_status="unknown")
    verdict = compute_flow_verdict(
        snapshot, _action_ir(), dataflow_status="not_applicable"
    )
    assert verdict.status == "not_applicable"


def test_dangerous_flow_is_violation_even_with_not_applicable_coverage() -> None:
    """not_applicable 不赦免危险 flow：violation 分支先行拦截。"""
    snapshot = _snapshot(
        dataflow_status="unknown",
        flows=[_flow_fact("flow-1", taints=["CREDENTIAL"], strength="exact")],
    )
    verdict = compute_flow_verdict(
        snapshot, _action_ir(), dataflow_status="not_applicable"
    )
    assert verdict.status == "violation"


def test_dangerous_sticky_taint_blocks_not_applicable() -> None:
    snapshot = _snapshot(
        dataflow_status="unknown", sticky=[_sticky(taints=["CREDENTIAL"])]
    )
    verdict = compute_flow_verdict(
        snapshot, _action_ir(), dataflow_status="not_applicable"
    )
    assert verdict.status == "uncertain"
    assert verdict.taints == ["CREDENTIAL"]


def test_current_coverage_unknown_stays_uncertain_fail_closed() -> None:
    """高影响动作：当前 plan 派生的 dataflow 仍为 unknown → 不得
    解释为安全（02 §6.5），fail-closed 保持 uncertain。"""
    snapshot = _snapshot(dataflow_status="unknown")
    verdict = compute_flow_verdict(
        snapshot, _action_ir(), dataflow_status="unknown"
    )
    assert verdict.status == "uncertain"


def test_external_sink_detection() -> None:
    snapshot = _snapshot()

    internal = compute_flow_verdict(snapshot, _action_ir())
    assert internal.external_sink is False

    with_url_destination = compute_flow_verdict(
        snapshot, _action_ir(destinations=[_url_destination()])
    )
    assert with_url_destination.external_sink is True

    with_effect = compute_flow_verdict(
        snapshot,
        _action_ir(effects=ActionEffect(external_communication=True)),
    )
    assert with_effect.external_sink is True

    with_egress = compute_flow_verdict(
        snapshot, _action_ir(effects=ActionEffect(data_egress=True))
    )
    assert with_egress.external_sink is True


def test_evidence_refs_are_never_fabricated() -> None:
    snapshot = _snapshot(
        flows=[_flow_fact("flow-1", taints=["CREDENTIAL"], strength="exact")]
    )
    verdict = compute_flow_verdict(snapshot, _action_ir())
    assert verdict.evidence_refs == []


# ---------------------------------------------------------------------------
# 确定性
# ---------------------------------------------------------------------------


def test_compute_flow_verdict_is_deterministic() -> None:
    snapshot = _snapshot(
        flows=[
            _flow_fact("flow-a", taints=["SENSITIVE"], strength="possible"),
            _flow_fact("flow-b", taints=["CREDENTIAL"], strength="exact"),
        ],
        sticky=[_sticky()],
    )
    action_ir = _action_ir(destinations=[_url_destination()])
    first = compute_flow_verdict(snapshot, action_ir)
    for _ in range(5):
        assert compute_flow_verdict(snapshot, action_ir) == first
    assert first.model_dump() == compute_flow_verdict(snapshot, action_ir).model_dump()


def test_safe_and_not_applicable_outputs_are_stable_models() -> None:
    verdict = compute_flow_verdict(_snapshot(), _action_ir())
    dumped = verdict.model_dump()
    rebuilt = type(verdict).model_validate(dumped)
    assert rebuilt == verdict
