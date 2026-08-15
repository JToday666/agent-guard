"""CT-PR-03a delta_builder 契约测试（纯函数内核，ct-delta-1，无接线）。

口径依据：

- 01 章 §27 derived projection contract：``task_upsert`` 恒 None、
  同五元组身份 + projector_version 重放恒定；02 章 §4 幂等键五元组；
- 01 章 §29 digest 白名单：排除注册 id 与时间戳，仅随语义白名单
  （scope/source 身份/base/容器内容）变化；
- T-FactReplay：同输入双跑同 ``delta_digest``；模块纪律 AST 断言
  （无 uuid/随机数，纯函数内核）。

夹具复用 ``test_ct_fact_builder`` 的构造工厂（同口径事件/bundle）。
"""

from __future__ import annotations

import ast
from pathlib import Path

from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    SecurityStateDeltaV21,
    WatermarkDelta,
    delta_digest_projection,
    projection_identity_key,
)
from agentguard_core.security_context.facts import DeclassificationFact
from guard_api.security_state import delta_builder
from guard_api.security_state.delta_builder import (
    CT_DELTA_BUILDER_VERSION,
    build_ct_facts_delta,
)
from guard_api.security_state.fact_builder import build_transient_facts
from guard_api.security_state.transient import TransientSecurityFacts

from tests.test_ct_fact_builder import (
    SCOPE,
    _context_source,
    _event,
    _inputs,
    _model_event,
)

MODULE_PATH = Path(delta_builder.__file__)
OTHER_SCOPE = "sha256:" + "f" * 64
BASE = 41


def _record_id(event_id: str = "evt-1") -> str:
    """调用方命名空间化口径：``ct-facts:{event_id}``。"""
    return f"ct-facts:{event_id}"


def _delta(
    *,
    event_id: str = "evt-1",
    scope: str = SCOPE,
    base: int = BASE,
    bundle: TransientSecurityFacts | None = None,
    visible_refs=(),
) -> SecurityStateDeltaV21 | None:
    if bundle is None:
        bundle = build_bundle(event_id=event_id, visible_refs=visible_refs)
    return build_ct_facts_delta(
        scope_digest=scope,
        source_record_id=_record_id(event_id),
        base_state_version=base,
        bundle=bundle,
    )


def build_bundle(
    *, event_id: str = "evt-1", visible_refs=()
) -> TransientSecurityFacts:
    """复用 fact_builder 契约夹具构造非降级 bundle。"""
    event = _event(
        "context_assembled",
        {
            "sources": [
                _context_source(),
                # 第二条带 instruction-like taint → digest 语义区分，
                # 避免两条同口径 web 源被语义去重折叠。
                _context_source(source_id="ctx-2", instruction_like=True),
            ],
            "will_enter_context": True,
            "sanitized": False,
        },
        event_id=event_id,
    )
    return build_transient_facts(
        event=event,
        inputs=_inputs(visible_refs=visible_refs),
    )


def _empty_bundle() -> TransientSecurityFacts:
    """合法但全空的事实 bundle（无降级，scope 对齐）。"""
    return TransientSecurityFacts(event_id="evt-empty", scope_digest=SCOPE)


# ---------------------------------------------------------------------------
# T-FactReplay：确定性重放
# ---------------------------------------------------------------------------


def test_deterministic_replay_same_digest_and_dump() -> None:
    first = _delta()
    second = _delta()
    assert first is not None and second is not None
    assert first.delta_digest == second.delta_digest
    assert first.delta_digest.startswith("sha256:")
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.projection_id == second.projection_id


def test_fact_order_in_bundle_does_not_affect_delta() -> None:
    # 输入事实顺序打乱后，upserts 按 digest 排序 → delta 全等。
    bundle = build_bundle()
    shuffled = bundle.model_copy(
        update={
            "source_facts": tuple(reversed(bundle.source_facts)),
            "flow_facts": tuple(reversed(bundle.flow_facts)),
        }
    )
    assert _delta(bundle=bundle) == _delta(bundle=shuffled)


def test_semantic_duplicates_are_deduped() -> None:
    # 白名单字段全同的事实 digest 相等 → 去重仅保留一条，且与输入
    # 顺序/位置无关（tie-breaker 取全量内容 canonical dump）。
    bundle = build_bundle()
    duplicate = bundle.source_facts[0].model_copy()
    padded = bundle.model_copy(
        update={"source_facts": (duplicate,) + bundle.source_facts}
    )
    assert _delta(bundle=padded) == _delta(bundle=bundle)
    delta = _delta(bundle=padded)
    assert delta is not None
    assert len(delta.source_upserts) == len(bundle.source_facts)


# ---------------------------------------------------------------------------
# 五元组身份（02 §4）与 projection_id 派生
# ---------------------------------------------------------------------------


def test_projection_identity_quintuple() -> None:
    delta = _delta()
    assert delta is not None
    assert delta.source.source_record_type == "runtime_observation"
    assert delta.source.source_record_id == _record_id()
    assert delta.source.source_record_id.startswith("ct-facts:")
    assert delta.source.source_revision == 1
    assert delta.source.source_sequence is None
    assert delta.projector_version == PROJECTOR_VERSION
    assert delta.scope_digest == SCOPE
    expected_key = projection_identity_key(
        SCOPE, "runtime_observation", _record_id(), 1, PROJECTOR_VERSION
    )
    assert delta.projection_id == f"projection:{expected_key}"
    assert delta.base_state_version == BASE
    assert delta.new_state_version == BASE + 1


# ---------------------------------------------------------------------------
# 容器口径：task 恒 None、空 bundle 空容器、declassifications 恒空
# ---------------------------------------------------------------------------


def test_task_upsert_always_none() -> None:
    for delta in (_delta(), _delta(bundle=_empty_bundle())):
        assert delta is not None
        assert delta.task_upsert is None


def test_empty_bundle_produces_empty_containers() -> None:
    delta = _delta(bundle=_empty_bundle())
    assert delta is not None
    assert delta.source_upserts == []
    assert delta.flow_upserts == []
    assert delta.memory_upserts == []
    assert delta.declassification_upserts == []
    assert delta.grant_upserts == []
    assert delta.grant_revocations == []
    assert delta.grant_consumptions == []
    assert delta.action_additions == []
    assert delta.runtime_outcome_upserts == []
    assert delta.behavior_aggregate_upserts == []
    assert delta.sticky_taint_upserts == []
    assert delta.coverage_invalidations == []
    assert delta.dirty_domain_updates == []
    assert delta.watermark_delta == WatermarkDelta()


def test_non_empty_bundle_maps_three_containers_only() -> None:
    delta = _delta()
    assert delta is not None
    assert len(delta.source_upserts) == 2
    assert len(delta.flow_upserts) == 2
    assert delta.memory_upserts == []
    # Non-goal（CT-F0-02）：declassifications 恒不映射。
    assert delta.declassification_upserts == []
    assert delta.action_additions == []


def test_bundle_declassifications_never_mapped() -> None:
    # 即使 bundle 携带 declassifications（本期 fact_builder 恒空，
    # 此处直接构造防御性用例），delta 侧恒空（Non-goal，CT-F0-02）。
    padded = _empty_bundle().model_copy(
        update={
            "declassifications": (
                DeclassificationFact(
                    declass_id="declass:evt-empty:0",
                    input_ref="source:web:evt-empty:0",
                    output_ref="source:web:evt-empty:0:sanitized",
                    removed_taints=["UNTRUSTED"],
                    retained_taints=[],
                    mechanism_id="redactor",
                    mechanism_version="1",
                    policy_revision="policy-rev-1",
                    producer="trusted_declassifier",
                    evidence_refs=[],
                ),
            )
        }
    )
    delta = _delta(bundle=padded)
    assert delta is not None
    assert delta.declassification_upserts == []


# ---------------------------------------------------------------------------
# fail-closed：降级 bundle / scope 不一致 → None
# ---------------------------------------------------------------------------


def test_degraded_bundle_returns_none() -> None:
    degraded = build_transient_facts(
        event=_model_event("input"), inputs=_inputs(visible_refs=None)
    )
    assert degraded.degradations  # 前置：确为降级 bundle
    assert (
        build_ct_facts_delta(
            scope_digest=SCOPE,
            source_record_id=_record_id(),
            base_state_version=BASE,
            bundle=degraded,
        )
        is None
    )


def test_scope_mismatch_returns_none() -> None:
    assert _delta(bundle=_empty_bundle(), scope=OTHER_SCOPE) is None


# ---------------------------------------------------------------------------
# digest 白名单（01 §29）：仅随 scope/source_record_id/base/内容变化
# ---------------------------------------------------------------------------


def test_digest_insensitive_to_timestamp_only() -> None:
    # 同 event_id 不同 timestamp：时间戳不入白名单 → digest 恒定。
    def _bundle_at(timestamp: str) -> TransientSecurityFacts:
        return build_transient_facts(
            event=_event(
                "context_assembled",
                {
                    "sources": [_context_source()],
                    "will_enter_context": True,
                    "sanitized": False,
                },
                event_id="evt-ts",
            ).model_copy(update={"timestamp": timestamp}),
            inputs=_inputs(),
        )

    early = _delta(bundle=_bundle_at("2026-08-15T00:00:00Z"))
    late = _delta(bundle=_bundle_at("2026-08-16T12:34:56Z"))
    assert early is not None and late is not None
    assert early.delta_digest == late.delta_digest
    assert early.model_dump(mode="json") == late.model_dump(mode="json")


def test_digest_changes_with_source_record_id_via_event_id() -> None:
    # event_id 仅经 source_record_id（身份白名单）影响 digest。
    first = _delta(event_id="evt-1")
    second = _delta(event_id="evt-2")
    assert first is not None and second is not None
    assert first.delta_digest != second.delta_digest
    projection = delta_digest_projection(first)
    assert projection["source"]["source_record_id"] == _record_id("evt-1")


def test_digest_changes_with_scope_and_base() -> None:
    base_delta = _delta(bundle=_empty_bundle())
    other_bundle = TransientSecurityFacts(
        event_id="evt-empty", scope_digest=OTHER_SCOPE
    )
    scope_matched = _delta(bundle=other_bundle, scope=OTHER_SCOPE)
    base_shifted = _delta(bundle=_empty_bundle(), base=BASE + 1)
    assert all(
        item is not None for item in (base_delta, scope_matched, base_shifted)
    )
    assert base_delta.delta_digest != scope_matched.delta_digest
    assert base_delta.delta_digest != base_shifted.delta_digest
    # scope 不一致 → fail-closed，不产 delta。
    assert _delta(bundle=_empty_bundle(), scope=OTHER_SCOPE) is None


# ---------------------------------------------------------------------------
# 模块纪律（无接线 / 无随机源）
# ---------------------------------------------------------------------------


def test_module_has_no_uuid_or_random_imports() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            names = {(node.module or "").split(".")[0]}
        else:
            continue
        assert not names & {"uuid", "random", "secrets"}, (
            "delta_builder 必须纯确定性（T-FactReplay），禁止随机源"
        )


def test_module_version_and_dispatch_registry() -> None:
    assert CT_DELTA_BUILDER_VERSION == "ct-delta-1"
    # 分派表当前仅 runtime_observation；CT-PR-05 memory_transition
    # 挂载时本断言须同步更新（扩展点留痕）。
    assert tuple(delta_builder._FACT_DELTA_BUILDERS) == ("runtime_observation",)
