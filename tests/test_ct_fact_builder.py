"""CT-PR-02a fact_builder 契约测试（读路径四事件，ct-fact-1，无接线）。

口径依据：

- 02 章 §8.1-8.4 四事件映射逐字段断言；§11 T-FactReplay 确定性；
  §13 Failure Contract（未知事件/handler 异常 → degradation 不 raise）；
- YAML parity：产物 relation/strength ∈ 冻结 YAML flow_relations /
  flow_strength.order_best_to_worst；LLM 边 == llm_default（possible）；
- no-decision/no-mutation：模块不 import delta/projector/store/engine。
"""

from __future__ import annotations

import ast
import json
import types
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.models import (
    CANONICALIZATION_VERSION,
    NORMALIZER_VERSION,
    ActionEffect,
    ActionIR,
    CanonicalArguments,
)
from agentguard_core.events.contracts import GuardEvent
from guard_api.security_state import fact_builder
from guard_api.security_state.fact_authority import ProducerIdentity
from guard_api.security_state.fact_builder import FactBuildInputs, build_transient_facts
from guard_api.security_state.transient import bundle_digest_projection

ROOT = Path(__file__).resolve().parents[1]
CT_FREEZE_DIR = ROOT / "docs" / "AgentGuard_Context_Isolation_Taint_Tracking_Final_RC"

SCOPE = "sha256:" + "0" * 64
SECRET = "sk-live-abcdefghijklmnop"
SECRET_FP = canonical_sha256(SECRET)


@pytest.fixture(scope="module")
def freeze_yaml() -> dict:
    return json.loads(
        (CT_FREEZE_DIR / "context_taint_contract_freeze.yaml").read_text(
            encoding="utf-8"
        )
    )


# ---------------------------------------------------------------------------
# 构造工厂
# ---------------------------------------------------------------------------


def _inputs(**overrides) -> FactBuildInputs:
    base: dict = {
        "scope_digest": SCOPE,
        "producer_identity": ProducerIdentity(),
    }
    base.update(overrides)
    return FactBuildInputs(**base)


def _context_source(
    source_id: str = "ctx-1",
    source_type: str = "web",
    source_trust: str = "trusted",
    instruction_like: bool = False,
) -> dict:
    return {
        "source_id": source_id,
        "source_type": source_type,
        "source_trust": source_trust,
        "summary": "",
        "contains_instruction_like_text": instruction_like,
        "contains_sensitive_data": False,
    }


def _event(event_type: str, payload: dict, event_id: str = "evt-1") -> GuardEvent:
    return GuardEvent(
        event_id=event_id,
        event_type=event_type,  # type: ignore[arg-type]
        runtime="langgraph",
        trace_id="trace-1",
        timestamp="2026-08-15T00:00:00Z",
        payload=cast(Any, payload),
    )


def _context_event(sources: list[dict], **payload_overrides) -> GuardEvent:
    payload = {"sources": sources, "will_enter_context": True, "sanitized": False}
    payload.update(payload_overrides)
    return _event("context_assembled", payload)


def _model_event(phase: str) -> GuardEvent:
    return _event(
        f"model_{'input_prepared' if phase == 'input' else 'output_produced'}",
        {
            "phase": phase,
            "content_preview": "",
            "contains_instruction_like_text": False,
            "contains_sensitive_data": False,
            "sanitized": False,
        },
    )


def _tool_result_event(**payload_overrides) -> GuardEvent:
    payload: dict = {
        "tool": {"name": "web_search", "call_id": "call-1"},
        "result": {
            "content_preview": "",
            "content_type": "text/plain",
            "size_bytes": 0,
        },
        "will_enter_context": False,
        "will_persist": False,
        "sanitized": False,
        "contains_sensitive_data": False,
        "contains_instruction_like_text": False,
    }
    payload.update(payload_overrides)
    return _event("tool_result_produced", payload)


def _action_ir(action_id: str = "action-1", binding: str = "binding-1") -> ActionIR:
    return ActionIR(
        event_id="evt-1",
        action_id=action_id,
        trace_id="trace-1",
        task_id=None,
        task_revision=None,
        scope_digest=SCOPE,
        principal_id="principal:owner",
        runtime="langgraph",
        runtime_binding_id=binding,
        agent_id="main",
        branch_id=None,
        parent_event_ids=[],
        runtime_sequence=None,
        tool_name="web_search",
        action_type="tool.call",
        effects=ActionEffect(),
        impact="low",
        resources=[],
        destinations=[],
        data_refs=[],
        canonical_arguments=CanonicalArguments(
            items=[],
            canonicalization_version=CANONICALIZATION_VERSION,
            argument_digest=SCOPE,
        ),
        argument_digest=SCOPE,
        authorization_fingerprint="sha256:" + "a" * 64,
        audit_fingerprint="sha256:" + "b" * 64,
        normalizer_version=NORMALIZER_VERSION,
    )


# ---------------------------------------------------------------------------
# 8.1 context_assembled
# ---------------------------------------------------------------------------


def test_context_assembled_web_source_mapping() -> None:
    bundle = build_transient_facts(
        event=_context_event([_context_source()]), inputs=_inputs()
    )
    (source,) = bundle.source_facts
    assert source.source_id == "source:web:evt-1:0"
    assert source.source_type == "web"
    assert source.trust == "untrusted"
    assert source.authority == "untrusted_claim"
    assert source.verification_state == "unverified"
    assert source.origin == "observed"
    assert source.taints == ["UNTRUSTED"]
    assert source.first_sequence is None and source.last_sequence is None
    (flow,) = bundle.flow_facts
    assert flow.source_ref == "source:web:evt-1:0"
    assert flow.target_ref == "context:evt-1"
    assert flow.relation == "assembled_into"
    assert flow.strength == "exact"
    assert flow.origin == "observed"
    assert flow.taints == ["UNTRUSTED"]
    assert bundle.degradations == ()


def test_context_assembled_memory_source_uses_memory_ref() -> None:
    bundle = build_transient_facts(
        event=_context_event([_context_source(source_type="memory")]),
        inputs=_inputs(),
    )
    (source,) = bundle.source_facts
    assert source.source_id == "memory:evt-1:0"
    assert source.trust == "unknown"  # memory_inherit_pending，2b 解析
    (flow,) = bundle.flow_facts
    assert flow.source_ref == "memory:evt-1:0"
    assert flow.relation == "loaded_from_memory"
    assert flow.taints == []


def test_context_assembled_instruction_like_adds_taint() -> None:
    bundle = build_transient_facts(
        event=_context_event([_context_source(instruction_like=True)]),
        inputs=_inputs(),
    )
    assert "EXTERNAL_INSTRUCTION" in bundle.source_facts[0].taints
    assert "EXTERNAL_INSTRUCTION" in bundle.flow_facts[0].taints


@pytest.mark.parametrize("source_trust", ("trusted", "unknown"))
def test_context_assembled_adapter_trust_claim_cannot_upgrade(
    source_trust: str,
) -> None:
    # T-NoClaimUpgrade：web 源 adapter trusted 声明不可洗白。
    bundle = build_transient_facts(
        event=_context_event([_context_source(source_trust=source_trust)]),
        inputs=_inputs(),
    )
    assert bundle.source_facts[0].trust == "untrusted"
    assert bundle.source_facts[0].authority == "untrusted_claim"


def test_context_assembled_sanitized_claim_keeps_taints() -> None:
    # T-NoSanitizeClaim：sanitized=true 只作 transform claim，不清 taint。
    bundle = build_transient_facts(
        event=_context_event([_context_source()], sanitized=True),
        inputs=_inputs(),
    )
    assert bundle.source_facts[0].taints == ["UNTRUSTED"]


def test_context_assembled_without_context_entry_builds_no_flow() -> None:
    bundle = build_transient_facts(
        event=_context_event([_context_source()], will_enter_context=False),
        inputs=_inputs(),
    )
    assert len(bundle.source_facts) == 1
    assert bundle.flow_facts == ()


# ---------------------------------------------------------------------------
# 8.2 model_input_prepared
# ---------------------------------------------------------------------------


def test_model_input_visible_refs_build_assembled_flows() -> None:
    bundle = build_transient_facts(
        event=_model_event("input"),
        inputs=_inputs(visible_refs=("source:web:evt-1:0", "memory:evt-1:0")),
    )
    assert bundle.flow_facts[0].source_ref == "source:web:evt-1:0"
    assert bundle.flow_facts[1].source_ref == "memory:evt-1:0"
    for flow in bundle.flow_facts:
        assert flow.target_ref == "model_input:evt-1"
        assert flow.relation == "assembled_into"
        assert flow.strength == "exact"
        assert flow.origin == "observed"
    assert bundle.degradations == ()


def test_model_input_without_visible_set_degrades() -> None:
    bundle = build_transient_facts(
        event=_model_event("input"), inputs=_inputs(visible_refs=None)
    )
    assert bundle.flow_facts == ()
    (degradation,) = bundle.degradations
    assert degradation.reason_codes == ["ct-fact:visible_set_unavailable"]
    assert degradation.component_id == "ct-fact-builder"
    assert degradation.domain == "dataflow"
    assert degradation.required_for_action is False
    # degradation 确定性 replay：degradation_id 无 uuid，同输入两次
    # 构建 bundle_digest 相等（T-FactReplay）。
    assert degradation.degradation_id == (
        "degradation:evt-1:ct-fact:visible_set_unavailable"
    )
    replay = build_transient_facts(
        event=_model_event("input"), inputs=_inputs(visible_refs=None)
    )
    assert replay.bundle_digest == bundle.bundle_digest
    assert replay.model_dump(mode="json") == bundle.model_dump(mode="json")


# ---------------------------------------------------------------------------
# 8.3 model_output_produced
# ---------------------------------------------------------------------------


def test_model_output_source_is_model_judgment_unknown() -> None:
    bundle = build_transient_facts(
        event=_model_event("output"), inputs=_inputs(visible_refs=())
    )
    (source,) = bundle.source_facts
    assert source.source_id == "source:model:evt-1"
    assert source.source_type == "model"
    assert source.trust == "unknown"
    assert source.authority == "model_judgment"
    assert source.taints == []
    # 空 tuple（非 None）：零 influence 边且无降级。
    assert bundle.flow_facts == ()
    assert bundle.degradations == ()


def test_model_output_without_visible_refs_degrades_symmetrically() -> None:
    # 与 §8.2 口径对称：visible set 缺失 → 零 influence 边 + 降级。
    bundle = build_transient_facts(
        event=_model_event("output"), inputs=_inputs(visible_refs=None)
    )
    (source,) = bundle.source_facts
    assert source.source_id == "source:model:evt-1"
    assert all(flow.relation != "influenced_by" for flow in bundle.flow_facts)
    (degradation,) = bundle.degradations
    assert degradation.reason_codes == ["ct-fact:visible_set_unavailable"]
    assert degradation.degradation_id == (
        "degradation:evt-1:ct-fact:visible_set_unavailable"
    )
    replay = build_transient_facts(
        event=_model_event("output"), inputs=_inputs(visible_refs=None)
    )
    assert replay.bundle_digest == bundle.bundle_digest


def test_model_output_influence_edges_are_always_possible(
    freeze_yaml,
) -> None:
    bundle = build_transient_facts(
        event=_model_event("output"),
        inputs=_inputs(visible_refs=("source:web:evt-1:0", "context:evt-0")),
    )
    llm_default = freeze_yaml["flow_strength"]["llm_default"]
    assert llm_default == "possible"
    for flow in bundle.flow_facts:
        assert flow.relation == "influenced_by"
        assert flow.strength == "possible" == llm_default
        assert flow.origin == "semantic_inferred"
        assert flow.target_ref == "model_output:evt-1"


def test_model_output_exact_credential_fingerprint_hit() -> None:
    bundle = build_transient_facts(
        event=_model_event("output"),
        inputs=_inputs(
            visible_refs=("source:web:evt-1:0",),
            server_credential_evidence=True,
            credential_bearing_text=f"output contains {SECRET}",
            server_credential_fingerprints=frozenset({SECRET_FP}),
        ),
    )
    exact = [flow for flow in bundle.flow_facts if flow.relation == "derived_from"]
    (flow,) = exact
    assert flow.source_ref == f"credential:{SECRET_FP}"
    assert flow.target_ref == "model_output:evt-1"
    assert flow.strength == "exact"
    assert flow.origin == "deterministic"
    assert flow.taints == ["CREDENTIAL", "SENSITIVE"]
    assert set(bundle.source_facts[0].taints) == {"CREDENTIAL", "SENSITIVE"}
    # raw secret 永不进任何 ref/digest。
    rendered = json.dumps(bundle.model_dump(mode="json"))
    assert SECRET not in rendered


def test_model_output_credential_evidence_without_fingerprint_hit_still_taints() -> (
    None
):
    # 02 §6：证据位 True + 指纹库为空（未注册密钥）不得 fail-open：
    # taints 含 CREDENTIAL+SENSITIVE，但不建 derived_from exact 边。
    bundle = build_transient_facts(
        event=_model_event("output"),
        inputs=_inputs(
            visible_refs=("source:web:evt-1:0",),
            server_credential_evidence=True,
            credential_bearing_text=f"output contains {SECRET}",
            server_credential_fingerprints=frozenset(),
        ),
    )
    assert all(flow.relation != "derived_from" for flow in bundle.flow_facts)
    assert all(flow.strength == "possible" for flow in bundle.flow_facts)
    assert bundle.source_facts[0].taints == ["CREDENTIAL", "SENSITIVE"]


def test_model_output_unregistered_key_mismatch_taints_without_exact_edge() -> None:
    # mismatch 盲区：指纹库含其它密钥、文本含未注册密钥，证据位 True →
    # taints 含 CREDENTIAL+SENSITIVE，无 derived_from exact 边。
    other_fingerprint = canonical_sha256("sk-live-other-key-0000000000")
    bundle = build_transient_facts(
        event=_model_event("output"),
        inputs=_inputs(
            visible_refs=("source:web:evt-1:0",),
            server_credential_evidence=True,
            credential_bearing_text=f"output contains {SECRET}",
            server_credential_fingerprints=frozenset({other_fingerprint}),
        ),
    )
    assert bundle.source_facts[0].taints == ["CREDENTIAL", "SENSITIVE"]
    assert all(flow.relation != "derived_from" for flow in bundle.flow_facts)


def test_model_output_sensitive_evidence_adds_sensitive_taint() -> None:
    # server_sensitive_evidence=True → model source 无条件追加 SENSITIVE。
    bundle = build_transient_facts(
        event=_model_event("output"),
        inputs=_inputs(visible_refs=(), server_sensitive_evidence=True),
    )
    assert bundle.source_facts[0].taints == ["SENSITIVE"]
    assert bundle.degradations == ()


def test_model_output_both_evidence_bits_with_fingerprint_hit() -> None:
    # 两证据位同开 + 指纹命中 → taints 与 exact 边并存（保序去重）。
    bundle = build_transient_facts(
        event=_model_event("output"),
        inputs=_inputs(
            visible_refs=("source:web:evt-1:0",),
            server_sensitive_evidence=True,
            server_credential_evidence=True,
            credential_bearing_text=f"output contains {SECRET}",
            server_credential_fingerprints=frozenset({SECRET_FP}),
        ),
    )
    assert bundle.source_facts[0].taints == ["CREDENTIAL", "SENSITIVE"]
    exact = [flow for flow in bundle.flow_facts if flow.relation == "derived_from"]
    (flow,) = exact
    assert flow.source_ref == f"credential:{SECRET_FP}"
    assert flow.strength == "exact"
    assert flow.origin == "deterministic"


# ---------------------------------------------------------------------------
# 8.4 tool_result_produced
# ---------------------------------------------------------------------------


def test_tool_result_with_action_ir_builds_returned_by_flow() -> None:
    bundle = build_transient_facts(
        event=_tool_result_event(),
        inputs=_inputs(action_ir=_action_ir()),
    )
    (source,) = bundle.source_facts
    assert source.source_id == "tool_result:binding-1:action-1"
    assert source.trust == "untrusted"
    assert source.authority == "untrusted_claim"
    assert source.taints == ["UNTRUSTED"]
    (flow,) = bundle.flow_facts
    assert flow.source_ref == "action:action-1"
    assert flow.target_ref == "tool_result:binding-1:action-1"
    assert flow.relation == "returned_by"
    assert flow.strength == "exact"
    assert flow.origin == "deterministic"
    assert bundle.degradations == ()


def test_tool_result_without_action_ir_degrades_ref() -> None:
    bundle = build_transient_facts(
        event=_tool_result_event(), inputs=_inputs(action_ir=None)
    )
    (source,) = bundle.source_facts
    assert source.source_id == "tool_result:evt-1"
    assert bundle.flow_facts == ()
    (degradation,) = bundle.degradations
    assert degradation.reason_codes == ["ct-fact:action_ref_degraded"]
    # degradation 确定性 replay：同输入两次构建 bundle_digest 相等。
    assert degradation.degradation_id == (
        "degradation:evt-1:ct-fact:action_ref_degraded"
    )
    replay = build_transient_facts(
        event=_tool_result_event(), inputs=_inputs(action_ir=None)
    )
    assert replay.bundle_digest == bundle.bundle_digest
    assert replay.model_dump(mode="json") == bundle.model_dump(mode="json")


def test_degradations_excluded_from_bundle_digest_whitelist() -> None:
    # 白名单设计（transient.bundle_digest_projection）：projection 只含
    # fact_builder_version/event_id/scope_digest/source_facts/flow_facts/
    # memory_facts，degradations 与 signals 不在白名单——因此加不加
    # degradation 的 bundle_digest 相同（coverage 缺失不改变事实语义
    # 摘要，属白名单设计使然，非缺陷）。
    projection = bundle_digest_projection(
        build_transient_facts(
            event=_model_event("input"), inputs=_inputs(visible_refs=None)
        )
    )
    assert "degradations" not in projection
    assert "signals" not in projection
    degraded = build_transient_facts(
        event=_model_event("input"), inputs=_inputs(visible_refs=None)
    )
    assert degraded.degradations  # 确实携带降级
    without_degradation = build_transient_facts(
        event=_model_event("input"), inputs=_inputs(visible_refs=())
    )
    assert without_degradation.degradations == ()
    # 两者 source/flow/memory 事实均为空、event_id/scope 相同 →
    # digest 相等，证明 degradation 不进摘要。
    assert degraded.bundle_digest == without_degradation.bundle_digest


def test_tool_result_instruction_like_adds_taint() -> None:
    bundle = build_transient_facts(
        event=_tool_result_event(contains_instruction_like_text=True),
        inputs=_inputs(action_ir=_action_ir()),
    )
    assert "EXTERNAL_INSTRUCTION" in bundle.source_facts[0].taints


# ---------------------------------------------------------------------------
# T-FactReplay 确定性
# ---------------------------------------------------------------------------


def test_fact_replay_same_input_same_digest() -> None:
    # T-FactReplay：同输入两次独立构造 → 同 digest/同序列化；确定性
    # 无随机/时钟源另由 AST 断言（见下方 no-uuid/no-time 用例）静态
    # 证明，不再依赖装饰性 monkeypatch 哨兵。
    event = _context_event([_context_source(), _context_source(source_id="ctx-2")])
    inputs = _inputs(visible_refs=("source:web:evt-1:0",))
    first = build_transient_facts(event=event, inputs=inputs)
    second = build_transient_facts(event=event, inputs=inputs)
    assert first.bundle_digest == second.bundle_digest
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_fact_replay_modules_do_not_import_uuid_or_time() -> None:
    # 静态断言：fact_builder/transient 源码不得 import uuid/time（无
    # 随机/时钟源，id 全部确定性构造，T-FactReplay）。
    for name in ("transient", "fact_builder"):
        path = (
            ROOT / "apps" / "guard-api" / "guard_api" / "security_state" / f"{name}.py"
        )
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in ("uuid", "time"), (name, alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module not in ("uuid", "time"), (name, node.module)


def test_fact_replay_content_perturbation_changes_digest() -> None:
    inputs = _inputs()
    baseline = build_transient_facts(
        event=_context_event([_context_source()]), inputs=inputs
    )
    perturbed = build_transient_facts(
        event=_context_event(
            [_context_source(), _context_source(source_id="ctx-2", source_type="rag")]
        ),
        inputs=inputs,
    )
    assert perturbed.bundle_digest != baseline.bundle_digest


# ---------------------------------------------------------------------------
# Failure Contract（02 §13）
# ---------------------------------------------------------------------------


def test_unknown_event_type_yields_empty_bundle_with_degradation() -> None:
    # 虚构事件类型（写侧三事件已在 Wave 2 注册，不能再用作未知样本）。
    event = _context_event([_context_source()]).model_copy(
        update={"event_type": "nonexistent_event_probe"}
    )
    bundle = build_transient_facts(event=event, inputs=_inputs())
    assert bundle.source_facts == ()
    assert bundle.flow_facts == ()
    (degradation,) = bundle.degradations
    assert degradation.reason_codes == ["ct-fact:unknown_event_type"]


def test_handler_exception_converges_to_degradation(monkeypatch) -> None:
    def _boom(event, inputs):
        raise RuntimeError("injected handler failure")

    monkeypatch.setattr(
        fact_builder,
        "_EVENT_HANDLERS",
        types.MappingProxyType({"context_assembled": _boom}),
    )
    bundle = build_transient_facts(
        event=_context_event([_context_source()]), inputs=_inputs()
    )
    assert bundle.source_facts == () and bundle.flow_facts == ()
    (degradation,) = bundle.degradations
    assert degradation.reason_codes == ["ct-fact:handler_failed"]


# ---------------------------------------------------------------------------
# no-decision / no-mutation 边界
# ---------------------------------------------------------------------------


def test_modules_do_not_import_decision_or_state_paths() -> None:
    forbidden = ("delta", "projector", "store", "engine", "decision")
    for name in ("transient", "fact_builder"):
        path = (
            ROOT / "apps" / "guard-api" / "guard_api" / "security_state" / f"{name}.py"
        )
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        for module in imported:
            parts = module.lower().split(".")
            assert not any(word in parts for word in forbidden), module


def test_inputs_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        FactBuildInputs(scope_digest=SCOPE, producer_identity=ProducerIdentity(), bogus=1)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# YAML parity：relation/strength ∈ 冻结集合
# ---------------------------------------------------------------------------


def test_all_produced_flows_match_frozen_yaml(freeze_yaml) -> None:
    relations = set(freeze_yaml["flow_relations"])
    strengths = set(freeze_yaml["flow_strength"]["order_best_to_worst"])
    bundles = [
        build_transient_facts(
            event=_context_event(
                [_context_source(), _context_source(source_type="memory")]
            ),
            inputs=_inputs(),
        ),
        build_transient_facts(
            event=_model_event("input"),
            inputs=_inputs(visible_refs=("source:web:evt-1:0",)),
        ),
        build_transient_facts(
            event=_model_event("output"),
            inputs=_inputs(
                visible_refs=("source:web:evt-1:0",),
                server_credential_evidence=True,
                credential_bearing_text=f"x {SECRET}",
                server_credential_fingerprints=frozenset({SECRET_FP}),
            ),
        ),
        build_transient_facts(
            event=_tool_result_event(), inputs=_inputs(action_ir=_action_ir())
        ),
    ]
    flows = [flow for bundle in bundles for flow in bundle.flow_facts]
    assert flows
    for flow in flows:
        assert flow.relation in relations
        assert flow.strength in strengths
