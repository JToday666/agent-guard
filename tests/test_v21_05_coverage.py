"""V21-05 三域 coverage 判定单测（02 §6.2/§6.5/§6.6，Phase 1 纯新增）。

覆盖关键分支：

- 不在 required plan → not_applicable；
- provider 不可用 / 域 dirty → unknown（C3 fail-closed）；
- eviction unprovable → partial；
- dataflow 截断降级（C8，``v21-05:flow_lookup_truncated``）；
- required refs 缺失 → partial / unknown；
- watermark 落后 required window → stale；
- gap localized → partial；
- 证据充分时 complete（不是「有数据就 complete」，而是全维度通过）。

夹具直接构造 OnlineSecurityState / CoverageContext，不依赖接线；
Phase 2 集成后中央 ``DOMAIN_COVERAGE_DISPATCH`` 已一次性装配六域
（末尾断言 V21-05 三域函数入表）。
"""

from __future__ import annotations

from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.security_context import OnlineSecurityState
from agentguard_core.security_context.coverage import (
    GapContext,
    RequiredHistoryWindow,
)
from agentguard_core.security_context.coverage_context import (
    DOMAIN_COVERAGE_DISPATCH,
    CoverageContext,
)
from agentguard_core.security_context.eviction import EvictionReport
from agentguard_core.security_context.facts import (
    GapRange,
    StateWatermarks,
)
from agentguard_core.security_context.projection.provenance_coverage import (
    DATAFLOW_PROVIDER_KEY,
    MEMORY_PROVIDER_KEY,
    SOURCE_PROVIDER_KEY,
    dataflow_coverage,
    memory_coverage,
    source_coverage,
)
from agentguard_core.signals.models import SequenceRef

from tests.test_v21_05_provenance import (
    empty_state,
    make_flow,
    make_memory,
)
from tests.test_v21_security_state_models import make_source_fact

ALL_PROVENANCE_DOMAINS = ["source", "dataflow", "memory"]


# ---------------------------------------------------------------------------
# 夹具构造
# ---------------------------------------------------------------------------


def make_plan(required_domains: list[str]) -> RequiredCheckPlan:
    return RequiredCheckPlan(
        plan_id="v21-05-plan:fixture",
        impact="high",
        required_domains=required_domains,  # type: ignore[list-item]
        optional_domains=[],
        required_capabilities=[],
        semantic_resolvable_dimensions=[],
        reason_codes=["v21-05:fixture"],
    )


def make_watermark(value: int) -> SequenceRef:
    return SequenceRef(
        domain="audit", producer_binding_id="binding_a", value=value
    )


def make_ctx(
    *,
    required: list[str] | None = None,
    stable_refs: tuple[str, ...] = (),
    truncated: tuple[str, ...] = (),
    provider_available: dict[str, bool] | None = None,
    eviction: EvictionReport | None = None,
    gaps: tuple[GapRange, ...] = (),
    windows: tuple[RequiredHistoryWindow, ...] = (),
    watermarks: StateWatermarks | None = None,
) -> CoverageContext:
    return CoverageContext(
        plan=make_plan(required or list(ALL_PROVENANCE_DOMAINS)),
        watermarks=watermarks
        or StateWatermarks(
            committed_sequence=None,
            projected_sequence=make_watermark(10),
            runtime_receipt_sequence=None,
            memory_sequence=None,
            gaps=[],
        ),
        gap_context=GapContext(
            stable_refs=frozenset(stable_refs),
            required_history_windows=windows,
        ),
        gaps=gaps,
        eviction_report=eviction,
        truncated=truncated,  # type: ignore[arg-type]
        provider_available=provider_available or {},
    )


def state_with_sources(*source_ids: str) -> OnlineSecurityState:
    return empty_state().model_copy(
        update={
            "source_index": [
                make_source_fact(source_id=source_id)
                for source_id in source_ids
            ],
            # as_of_sequence 取自 state 水位：与 make_ctx 默认水位对齐
            "watermarks": StateWatermarks(
                committed_sequence=None,
                projected_sequence=make_watermark(10),
                runtime_receipt_sequence=None,
                memory_sequence=None,
                gaps=[],
            ),
        }
    )


# ---------------------------------------------------------------------------
# source 域（02 §6.2）
# ---------------------------------------------------------------------------


def test_source_not_required_is_not_applicable() -> None:
    ctx = make_ctx(required=["dataflow"], stable_refs=("src_1",))
    result = source_coverage(state_with_sources("src_1"), ctx)
    assert result.status == "not_applicable"
    assert result.domain == "source"


def test_source_provider_unavailable_is_unknown() -> None:
    ctx = make_ctx(
        stable_refs=("src_1",),
        provider_available={SOURCE_PROVIDER_KEY: False},
    )
    result = source_coverage(state_with_sources("src_1"), ctx)
    assert result.status == "unknown"
    assert f"v21-05:{SOURCE_PROVIDER_KEY}_unavailable" in result.reason_codes


def test_source_dirty_domain_is_unknown() -> None:
    state = state_with_sources("src_1").model_copy(
        update={"dirty_domains": ["source"]}
    )
    result = source_coverage(state, make_ctx(stable_refs=("src_1",)))
    assert result.status == "unknown"
    assert "v21-05:dirty_projection" in result.reason_codes


def test_source_no_required_refs_is_unknown() -> None:
    # 来源身份无法建立（required 但无 stable refs）
    result = source_coverage(state_with_sources("src_1"), make_ctx())
    assert result.status == "unknown"
    assert "v21-05:source_refs_unresolvable" in result.reason_codes


def test_source_all_refs_unresolved_is_unknown() -> None:
    result = source_coverage(
        empty_state(), make_ctx(stable_refs=("src_missing",))
    )
    assert result.status == "unknown"
    assert "v21-05:source_identity_not_established" in result.reason_codes


def test_source_partial_refs_missing_is_partial() -> None:
    state = state_with_sources("src_1")
    ctx = make_ctx(stable_refs=("src_1", "src_missing"))
    result = source_coverage(state, ctx)
    assert result.status == "partial"
    assert "v21-05:source_refs_missing" in result.reason_codes


def test_source_trust_unknown_is_partial() -> None:
    state = state_with_sources("src_1").model_copy(
        update={
            "source_index": [
                make_source_fact(source_id="src_1", trust="unknown")
            ]
        }
    )
    result = source_coverage(state, make_ctx(stable_refs=("src_1",)))
    assert result.status == "partial"
    assert "v21-05:source_trust_mapping_incomplete" in result.reason_codes


def test_source_eviction_unprovable_is_partial() -> None:
    ctx = make_ctx(
        stable_refs=("src_1",),
        eviction=EvictionReport(unprovable_domains=["source"]),
    )
    result = source_coverage(state_with_sources("src_1"), ctx)
    assert result.status == "partial"
    assert "v21-05:safety_preserving_eviction" in result.reason_codes


def test_source_watermark_behind_window_is_stale() -> None:
    window = RequiredHistoryWindow(
        domain="source",
        start_sequence=1,
        end_sequence=20,
        sequence_domain="audit",
        producer_binding_id="binding_a",
    )
    ctx = make_ctx(stable_refs=("src_1",), windows=(window,))
    # projected watermark=10 < end_sequence=20 → stale
    result = source_coverage(state_with_sources("src_1"), ctx)
    assert result.status == "stale"
    assert "v21-05:source_watermark_behind" in result.reason_codes


def test_source_complete_when_all_refs_have_facts() -> None:
    window = RequiredHistoryWindow(
        domain="source",
        start_sequence=1,
        end_sequence=5,
        sequence_domain="audit",
        producer_binding_id="binding_a",
    )
    ctx = make_ctx(stable_refs=("src_1", "src_2"), windows=(window,))
    state = state_with_sources("src_1", "src_2")
    result = source_coverage(state, ctx)
    assert result.status == "complete"
    assert result.projector_version != ""
    assert result.as_of_sequence is not None


# ---------------------------------------------------------------------------
# dataflow 域（02 §6.5 + C8）
# ---------------------------------------------------------------------------


def test_dataflow_truncated_is_partial_with_frozen_reason() -> None:
    state = empty_state().model_copy(
        update={
            "relevant_flows": [make_flow("f1", "src_1", "sink_1")]
        }
    )
    ctx = make_ctx(
        stable_refs=("src_1", "sink_1"), truncated=("dataflow",)
    )
    result = dataflow_coverage(state, ctx)
    assert result.status == "partial"
    assert "v21-05:flow_lookup_truncated" in result.reason_codes


def test_dataflow_provider_unavailable_is_unknown() -> None:
    ctx = make_ctx(provider_available={DATAFLOW_PROVIDER_KEY: False})
    result = dataflow_coverage(empty_state(), ctx)
    assert result.status == "unknown"


def test_dataflow_no_flows_with_refs_is_partial() -> None:
    ctx = make_ctx(stable_refs=("src_1",))
    result = dataflow_coverage(empty_state(), ctx)
    assert result.status == "partial"
    assert "v21-05:no_relevant_flows" in result.reason_codes


def test_dataflow_no_flows_no_refs_is_unknown() -> None:
    # 未发现危险 flow + dataflow=unknown 不能解释为安全 → fail-closed
    result = dataflow_coverage(empty_state(), make_ctx())
    assert result.status == "unknown"
    assert "v21-05:flow_refs_unresolvable" in result.reason_codes


def test_dataflow_possible_link_is_partial() -> None:
    state = empty_state().model_copy(
        update={
            "relevant_flows": [
                make_flow("f1", "src_1", "sink_1", strength="possible")
            ]
        }
    )
    ctx = make_ctx(stable_refs=("src_1", "sink_1"))
    result = dataflow_coverage(state, ctx)
    assert result.status == "partial"
    assert "v21-05:possible_flow_link" in result.reason_codes


def test_dataflow_unresolved_artifact_ref_is_partial() -> None:
    state = empty_state().model_copy(
        update={
            "relevant_flows": [make_flow("f1", "src_1", "mid_1")]
        }
    )
    ctx = make_ctx(stable_refs=("src_1", "sink_unresolved"))
    result = dataflow_coverage(state, ctx)
    assert result.status == "partial"
    assert "v21-05:unresolved_artifact_ref" in result.reason_codes


def test_dataflow_gap_localized_is_partial() -> None:
    gap = GapRange(
        domain="audit",
        producer_binding_id="binding_a",
        start_sequence=3,
        end_sequence=5,
        reason="missing predecessor",
    )
    window = RequiredHistoryWindow(
        domain="dataflow",
        start_sequence=1,
        end_sequence=8,
        sequence_domain="audit",
        producer_binding_id="binding_a",
    )
    state = empty_state().model_copy(
        update={
            "relevant_flows": [make_flow("f1", "src_1", "sink_1")]
        }
    )
    ctx = make_ctx(
        stable_refs=("src_1", "sink_1"), gaps=(gap,), windows=(window,)
    )
    result = dataflow_coverage(state, ctx)
    assert result.status == "partial"
    assert "v21-05:sequence_gap_localized" in result.reason_codes


def test_dataflow_complete_only_with_full_evidence() -> None:
    state = empty_state().model_copy(
        update={
            "relevant_flows": [
                make_flow("f1", "src_1", "artifact_x", strength="exact"),
                make_flow("f2", "artifact_x", "sink_1", strength="strong"),
            ]
        }
    )
    ctx = make_ctx(stable_refs=("src_1", "sink_1"))
    result = dataflow_coverage(state, ctx)
    assert result.status == "complete"
    assert "v21-05:dataflow_complete" in result.reason_codes


# ---------------------------------------------------------------------------
# memory 域（02 §6.6）
# ---------------------------------------------------------------------------


def test_memory_not_required_is_not_applicable() -> None:
    ctx = make_ctx(required=["source"])
    result = memory_coverage(empty_state(), ctx)
    assert result.status == "not_applicable"


def test_memory_provider_unavailable_is_unknown() -> None:
    ctx = make_ctx(provider_available={MEMORY_PROVIDER_KEY: False})
    result = memory_coverage(empty_state(), ctx)
    assert result.status == "unknown"


def test_memory_empty_index_is_unknown() -> None:
    result = memory_coverage(empty_state(), make_ctx())
    assert result.status == "unknown"
    assert "v21-05:memory_state_unavailable" in result.reason_codes


def test_memory_required_refs_missing_is_partial() -> None:
    state = empty_state().model_copy(
        update={"memory_index": [make_memory("mem_1")]}
    )
    ctx = make_ctx(stable_refs=("mem_missing",))
    result = memory_coverage(state, ctx)
    assert result.status == "partial"
    assert "v21-05:memory_refs_missing" in result.reason_codes


def test_memory_missing_lifecycle_or_source_link_is_partial() -> None:
    state = empty_state().model_copy(
        update={
            "memory_index": [
                make_memory("mem_1", change_status=None),
            ]
        }
    )
    result = memory_coverage(state, make_ctx(stable_refs=("mem_1",)))
    assert result.status == "partial"
    assert (
        "v21-05:memory_lifecycle_or_source_link_missing"
        in result.reason_codes
    )

    state_no_link = empty_state().model_copy(
        update={"memory_index": [make_memory("mem_1", source_refs=[])]}
    )
    result_no_link = memory_coverage(
        state_no_link, make_ctx(stable_refs=("mem_1",))
    )
    assert result_no_link.status == "partial"


def test_memory_trust_unknown_is_partial() -> None:
    state = empty_state().model_copy(
        update={
            "memory_index": [make_memory("mem_1", trust_state="unknown")]
        }
    )
    result = memory_coverage(state, make_ctx(stable_refs=("mem_1",)))
    assert result.status == "partial"
    assert "v21-05:memory_trust_unknown" in result.reason_codes


def test_memory_gap_in_memory_domain_is_partial() -> None:
    gap = GapRange(
        domain="memory",
        producer_binding_id="binding_a",
        start_sequence=1,
        end_sequence=3,
        reason="memory gap",
    )
    state = empty_state().model_copy(
        update={"memory_index": [make_memory("mem_1")]}
    )
    ctx = make_ctx(stable_refs=("mem_1",), gaps=(gap,))
    result = memory_coverage(state, ctx)
    assert result.status == "partial"
    assert "v21-05:sequence_gap_localized" in result.reason_codes


def test_memory_watermark_behind_is_stale() -> None:
    window = RequiredHistoryWindow(
        domain="memory",
        start_sequence=1,
        end_sequence=9,
        sequence_domain="memory",
        producer_binding_id="binding_a",
    )
    watermarks = StateWatermarks(
        committed_sequence=None,
        projected_sequence=make_watermark(10),
        runtime_receipt_sequence=None,
        memory_sequence=SequenceRef(
            domain="memory", producer_binding_id="binding_a", value=4
        ),
        gaps=[],
    )
    state = empty_state().model_copy(
        update={
            "memory_index": [make_memory("mem_1")],
            "watermarks": watermarks,
        }
    )
    ctx = make_ctx(
        stable_refs=("mem_1",), windows=(window,), watermarks=watermarks
    )
    result = memory_coverage(state, ctx)
    assert result.status == "stale"
    assert "v21-05:memory_watermark_behind" in result.reason_codes


def test_memory_complete_with_full_lifecycle() -> None:
    state = empty_state().model_copy(
        update={
            "memory_index": [
                make_memory(
                    "mem_1",
                    change_status="committed",
                    trust_state="tainted",
                    source_refs=["src_1"],
                )
            ]
        }
    )
    result = memory_coverage(state, make_ctx(stable_refs=("mem_1",)))
    assert result.status == "complete"
    assert "v21-05:memory_complete" in result.reason_codes


# ---------------------------------------------------------------------------
# Phase 2 集成：中央分发表一次性装配六域
# ---------------------------------------------------------------------------


def test_central_coverage_dispatch_wired_with_six_domains() -> None:
    assert set(DOMAIN_COVERAGE_DISPATCH) == {
        "source",
        "capability",
        "behavior",
        "dataflow",
        "memory",
        "runtime_outcome",
    }
    # V21-05 三域函数直接入表（同函数对象）。
    assert DOMAIN_COVERAGE_DISPATCH["source"] is source_coverage
    assert DOMAIN_COVERAGE_DISPATCH["dataflow"] is dataflow_coverage
    assert DOMAIN_COVERAGE_DISPATCH["memory"] is memory_coverage
