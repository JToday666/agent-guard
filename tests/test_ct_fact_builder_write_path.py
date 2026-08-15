"""CT-PR-02b 写侧事件契约测试（ct-fact-1，无接线）。

口径：02 §8.5-8.7/§11/§13、04 §2/§3/§4/§12/§15 与冻结 YAML parity。
"""

from __future__ import annotations

import json
from typing import Literal

import pytest
from agentguard_core.actions.canonical_resources import (
    ResourceNormalizationInput,
    normalize_email_resource,
    normalize_file_resource,
)
from agentguard_core.security_context.facts import MemoryFact, fact_digest_projection
from guard_api.security_state.fact_authority import VerifiedSourceDescriptor
from guard_api.security_state.fact_builder import build_transient_facts

from tests.test_ct_fact_builder import (
    CT_FREEZE_DIR,
    SCOPE,
    ct_action_ir,
    ct_event,
    ct_inputs,
)


@pytest.fixture(scope="module")
def freeze_yaml() -> dict:
    path = CT_FREEZE_DIR / "context_taint_contract_freeze.yaml"
    return json.loads(path.read_text(encoding="utf-8"))


_INBOUND = normalize_file_resource(
    ResourceNormalizationInput(resource_id="", target="/data/report.csv")
)
_OUTBOUND = normalize_email_resource(
    ResourceNormalizationInput(resource_id="", target="sink@example.com")
)
REF = "source:web:evt-0:0"


def _descriptor(
    *, source_id: str = REF, trust: str = "trusted", taints: tuple[str, ...] = ()
) -> VerifiedSourceDescriptor:
    return VerifiedSourceDescriptor(
        source_id=source_id,
        scope_digest=SCOPE,
        source_type="web",
        trust=trust,  # type: ignore[arg-type]
        verification_state="verified",
        fact_authority=("untrusted_claim" if trust == "untrusted" else "trusted_claim"),
        producer="adapter_unattributed",
        initial_taints=tuple(taints),  # type: ignore[arg-type]
    )


def _upstream_memory_fact(
    *, trust_state: str = "clean", taints: tuple[str, ...] = ()
) -> MemoryFact:
    return MemoryFact(
        memory_id="memory://ns/prev",
        change_id=None,
        change_status="committed",
        trust_state=trust_state,  # type: ignore[arg-type]
        taints=list(taints),  # type: ignore[arg-type]
        source_refs=[],
        last_write_sequence=None,
        last_read_sequence=None,
        evidence_refs=[],
    )


def _memory_event(
    *,
    namespace: str = "ns",
    key: str = "note",
    will_persist: bool = True,
    action_id: str | None = None,
):
    payload: dict = {
        "memory": {
            "namespace": namespace,
            "key": key,
            "value_preview": "",
            "source_trust": "trusted",
            "operation": "write",
        },
        "will_persist": will_persist,
        "requires_approval": False,
    }
    if action_id is not None:
        payload["action_id"] = action_id
    return ct_event("memory_write_proposed", payload)


def _send_event(
    *,
    channel: str = "email",
    recipient: str = "User@Example.COM",
    sensitive: bool = False,
):
    payload: dict = {
        "channel": channel,
        "recipient": recipient,
        "content_preview": "",
        "contains_sensitive_data": sensitive,
        "sanitized": False,
        "derived_resources": [],
    }
    return ct_event("message_send_proposed", payload)


def _action_with_data_refs(*refs: str):
    return ct_action_ir().model_copy(update={"data_refs": list(refs)})


def _mem_inputs(**fact_kwargs):
    """单条上游 MemoryFact（memory://ns/prev）的 FactBuildInputs 快捷构造。"""
    return ct_inputs(
        upstream_memory_facts={"memory://ns/prev": _upstream_memory_fact(**fact_kwargs)}
    )


def _desc_inputs(
    *, status: Literal["proposed", "quarantined"] = "proposed", **desc_kwargs
):
    """单条上游 descriptor（REF）的 FactBuildInputs 快捷构造。"""
    return ct_inputs(
        memory_change_status=status,
        upstream_descriptors={REF: _descriptor(**desc_kwargs)},  # type: ignore[arg-type]
    )


# --- 02 §8.5 memory_write_proposed：三态判定 ------------------------------


@pytest.mark.parametrize(
    ("inputs", "state", "taints", "refs", "change_status"),
    [
        pytest.param(
            _desc_inputs(trust="untrusted", taints=("UNTRUSTED",)),
            "tainted",
            ["UNTRUSTED", "PERSISTENT_UNTRUSTED"],
            [REF],
            "proposed",
            id="untrusted-descriptor",
        ),
        pytest.param(ct_inputs(), "unknown", [], [], "proposed", id="empty-upstream"),
        pytest.param(
            _desc_inputs(), "clean", [], [REF], "proposed", id="trusted-clean"
        ),
        pytest.param(
            # 04 §15 ALLOW ≠ TRUST：EXTERNAL_INSTRUCTION 上游不因放行洗白。
            _desc_inputs(taints=("EXTERNAL_INSTRUCTION",)),
            "tainted",
            ["EXTERNAL_INSTRUCTION", "PERSISTENT_UNTRUSTED"],
            [REF],
            "proposed",
            id="allow-does-not-imply-trust",
        ),
        pytest.param(
            # 04 §3 单调传播：上游 MemoryFact tainted 只增不减。
            _mem_inputs(
                trust_state="tainted", taints=("UNTRUSTED", "PERSISTENT_UNTRUSTED")
            ),
            "tainted",
            ["UNTRUSTED", "PERSISTENT_UNTRUSTED"],
            ["memory://ns/prev"],
            "proposed",
            id="upstream-memory-monotonic",
        ),
        pytest.param(
            # Major-1：model/file 源 trust=unknown → 非 clean（04 §12 收紧）。
            _desc_inputs(trust="unknown"),
            "unknown",
            [],
            [REF],
            "proposed",
            id="unknown-trust-descriptor",
        ),
        pytest.param(
            # Major-2（04 §2/§3 对称）：clean MemoryFact 带 UNTRUSTED
            # （无 PERSISTENT_UNTRUSTED）→ tainted + 落 PERSISTENT_UNTRUSTED。
            _mem_inputs(taints=("UNTRUSTED",)),
            "tainted",
            ["UNTRUSTED", "PERSISTENT_UNTRUSTED"],
            ["memory://ns/prev"],
            "proposed",
            id="memory-clean-with-untrusted-taint",
        ),
        pytest.param(
            # 上游 MemoryFact unknown 态 → unknown（非 clean）。
            _mem_inputs(trust_state="unknown"),
            "unknown",
            [],
            ["memory://ns/prev"],
            "proposed",
            id="memory-unknown-state",
        ),
        pytest.param(
            # Minor-5 ③：上游 MemoryFact quarantined 态 → tainted（单调传播）。
            _mem_inputs(trust_state="quarantined"),
            "tainted",
            ["PERSISTENT_UNTRUSTED"],
            ["memory://ns/prev"],
            "proposed",
            id="memory-quarantined-state",
        ),
        pytest.param(
            # Minor-5 ④（04 §12）：clean 要求零 taints，全 trusted 上游仅带
            # SENSITIVE/CREDENTIAL → unknown（Major-1 收紧后）。
            _desc_inputs(taints=("SENSITIVE", "CREDENTIAL")),
            "unknown",
            ["SENSITIVE", "CREDENTIAL"],
            [REF],
            "proposed",
            id="trusted-sensitive-only",
        ),
        pytest.param(
            # 02 §13：visible_refs 声明 ref 查表未命中 → fail-closed tainted。
            ct_inputs(visible_refs=("source:web:evt-0:missing",)),
            "tainted",
            ["PERSISTENT_UNTRUSTED"],
            ["source:web:evt-0:missing"],
            "proposed",
            id="missing-ref-fail-closed",
        ),
        pytest.param(
            # 04 §12：lifecycle quarantine 优先级最高（上游 tainted 不降级它）。
            _desc_inputs(
                status="quarantined", trust="untrusted", taints=("UNTRUSTED",)
            ),
            "quarantined",
            ["UNTRUSTED"],
            [REF],
            "quarantined",
            id="quarantine-precedence",
        ),
    ],
)
def test_memory_write_trust_state_matrix(
    inputs, state, taints, refs, change_status
) -> None:
    bundle = build_transient_facts(event=_memory_event(), inputs=inputs)
    (fact,) = bundle.memory_facts
    assert fact.change_status == change_status
    assert fact.trust_state == state
    assert fact.taints == taints
    assert fact.source_refs == refs
    assert fact.last_write_sequence is None and fact.last_read_sequence is None


# --- 02 §8.5 persisted_to 流与确定性 ---------------------------------------


def test_memory_write_persisted_flow_and_memory_id_deterministic() -> None:
    inputs = ct_inputs(
        upstream_descriptors={REF: _descriptor(taints=("UNTRUSTED",))},
        visible_refs=(REF,),
    )
    bundle = build_transient_facts(
        event=_memory_event(action_id="action-9"), inputs=inputs
    )
    (fact,) = bundle.memory_facts
    # memory_id = V21-02 冻结归一器 canonical_id（CT-PR-05 身份锚点）。
    assert fact.memory_id == "memory://ns/note"
    assert fact.source_refs == [REF, "action:action-9"]
    (flow,) = bundle.flow_facts
    assert flow.source_ref == REF
    assert flow.target_ref == "memory:memory://ns/note"
    assert flow.relation == "persisted_to"
    assert (flow.strength, flow.origin) == ("exact", "observed")
    # Minor-3：边 taints 与 MemoryFact.taints 同口径（04 §4 union + persistent，
    # TAINT_ORDER 保序，tainted 时含 PERSISTENT_UNTRUSTED）。
    assert flow.taints == fact.taints == ["UNTRUSTED", "PERSISTENT_UNTRUSTED"]


def test_memory_write_unordered_inputs_are_deterministic() -> None:
    # 迭代按 key 排序，与 Mapping 插入序无关（T-FactReplay）。
    descriptor_a, descriptor_b = _descriptor(), _descriptor(taints=("SENSITIVE",))
    orderings = [
        {"ref-b": descriptor_b, "ref-a": descriptor_a},
        {"ref-a": descriptor_a, "ref-b": descriptor_b},
    ]
    bundles = [
        build_transient_facts(
            event=_memory_event(), inputs=ct_inputs(upstream_descriptors=table)
        )
        for table in orderings
    ]
    assert bundles[0].bundle_digest == bundles[1].bundle_digest
    assert bundles[0].memory_facts[0].source_refs == ["ref-a", "ref-b"]


# --- 02 §8.6 message_send_proposed：sink 归一化与 sent_to 流 ---------------


@pytest.mark.parametrize(
    ("channel", "recipient", "expected_sink", "sensitive", "taints"),
    [
        ("Email", "User@Example.COM", "mailto:User@example.com", False, []),
        (
            "webhook",
            "https://Hooks.Example.com:443/path?b=2&a=1",
            "https://hooks.example.com/path?a&b",
            False,
            [],
        ),
        ("sms", "+15551234567", "other://+15551234567", False, []),
        ("Email", "User@Example.COM", "mailto:User@example.com", True, ["SENSITIVE"]),
    ],
)
def test_message_send_stable_refs_build_exact_sent_to(
    channel, recipient, expected_sink, sensitive, taints
) -> None:
    # 04 §4 evidence-defined；sink 取 V21-02 canonical_id，前缀随归一器
    # 实际产出（mailto:/http(s)://other://，未自造 network: 前缀）。
    bundle = build_transient_facts(
        event=_send_event(channel=channel, recipient=recipient, sensitive=sensitive),
        inputs=ct_inputs(action_ir=_action_with_data_refs("data:artifact-1")),
    )
    (flow,) = bundle.flow_facts
    assert flow.source_ref == "data:artifact-1"
    assert flow.target_ref == expected_sink
    assert (flow.strength, flow.origin) == ("exact", "deterministic")
    assert flow.taints == taints


@pytest.mark.parametrize(
    ("event", "inputs", "degraded"),
    [
        pytest.param(_send_event(), ct_inputs(), True, id="no-action-ir"),
        pytest.param(
            _send_event(), ct_inputs(action_ir=ct_action_ir()), True, id="empty-data-refs"
        ),
        pytest.param(
            # email 归一失败（无 @）→ unresolved → 不建流。
            _send_event(recipient="not-an-address"),
            ct_inputs(action_ir=_action_with_data_refs("data:artifact-1")),
            True,
            id="unresolvable-sink",
        ),
        pytest.param(
            _memory_event(will_persist=False),
            ct_inputs(),
            False,
            id="memory-no-persist-empty-upstream",
        ),
        pytest.param(
            _memory_event(), ct_inputs(), True, id="memory-empty-upstream-persist"
        ),
    ],
)
def test_write_side_without_stable_flow_builds_no_flow(event, inputs, degraded) -> None:
    # 无稳定流 → 零流；降级口径按 degraded 参数（02 §13）。
    bundle = build_transient_facts(event=event, inputs=inputs)
    assert bundle.flow_facts == ()
    assert bundle.signals == ()
    if degraded:
        assert bundle.degradations[0].reason_codes == ["ct-fact:flow_ref_missing"]
    else:
        assert bundle.degradations == ()
        if event.event_type == "memory_write_proposed":
            assert len(bundle.memory_facts) == 1


def test_message_send_sensitive_preview_signal_without_exact_flow() -> None:
    # 02 §8.6：只有敏感证据 → Signal + 零 exact 流，绝不伪造 provenance。
    bundle = build_transient_facts(event=_send_event(sensitive=True), inputs=ct_inputs())
    assert bundle.flow_facts == ()
    (signal,) = bundle.signals
    assert signal.signal_id == "signal:evt-1:sensitive_send"
    assert signal.detector_id == "ct-fact-builder"
    assert (signal.category, signal.scope) == ("ct-fact:sensitive_outbound", "flow")
    assert (signal.impact, signal.confidence) == ("high", "low")
    assert signal.reason_codes == ["ct-fact:sensitive_outbound_preview"]


def test_message_send_server_sensitive_evidence_signal() -> None:
    # Signal 口径对称：server_sensitive_evidence=True 且无稳定 refs →
    # Signal 存在（与 exact 流 taints 判定同条件位）。
    bundle = build_transient_facts(
        event=_send_event(), inputs=ct_inputs(server_sensitive_evidence=True)
    )
    assert bundle.flow_facts == ()
    (signal,) = bundle.signals
    assert signal.category == "ct-fact:sensitive_outbound"


# --- 02 §8.7 tool_call_proposed：data refs 流 + RecentActionFact 候选 ------


def _tool_call_event():
    payload: dict = {
        "tool": {
            "name": "web_search",
            "category": "tool",
            "kind": "web_search",
            "input_kind": "text",
            "call_id": "call-1",
        },
        "arguments": {},
        "derived_resources": [],
    }
    return ct_event("tool_call_proposed", payload)


def _tool_call_action_ir():
    return ct_action_ir().model_copy(
        update={
            "resources": [_INBOUND],
            "destinations": [_OUTBOUND],
            "data_refs": ["data:artifact-1"],
        }
    )


def test_tool_call_with_action_ir_builds_data_ref_flows_and_candidate() -> None:
    bundle = build_transient_facts(
        event=_tool_call_event(), inputs=ct_inputs(action_ir=_tool_call_action_ir())
    )
    # 方向约定：destinations → written_to；resources → read_from。
    assert [flow.relation for flow in bundle.flow_facts] == ["written_to", "read_from"]
    assert bundle.flow_facts[0].target_ref == _OUTBOUND.canonical_id
    assert bundle.flow_facts[1].target_ref == _INBOUND.canonical_id
    for flow in bundle.flow_facts:
        assert flow.source_ref == "action:action-1"
        assert (flow.strength, flow.origin) == ("exact", "deterministic")
    candidate = bundle.current_action
    assert candidate is not None
    assert (candidate.action_id, candidate.event_id) == ("action-1", "evt-1")
    assert (candidate.authority_status, candidate.final_decision) == ("unknown", None)
    assert candidate.resource_ids == [_INBOUND.canonical_id]
    assert candidate.destination_ids == [_OUTBOUND.canonical_id]
    assert candidate.data_refs == ["data:artifact-1"]
    assert candidate.runtime_sequence is None
    assert bundle.degradations == ()


def test_tool_call_without_action_ir_degrades() -> None:
    bundle = build_transient_facts(event=_tool_call_event(), inputs=ct_inputs())
    assert bundle.flow_facts == ()
    assert bundle.current_action is None
    (degradation,) = bundle.degradations
    assert degradation.reason_codes == ["ct-fact:action_ref_degraded"]


# --- T-FactReplay 与 YAML parity（写侧三事件） ------------------------------


@pytest.mark.parametrize(
    ("case", "event", "inputs"),
    [
        (
            "memory",
            _memory_event(),
            ct_inputs(upstream_descriptors={REF: _descriptor(taints=("UNTRUSTED",))}),
        ),
        ("message", _send_event(sensitive=True), ct_inputs()),
        ("tool_call", _tool_call_event(), ct_inputs(action_ir=_tool_call_action_ir())),
    ],
)
def test_write_side_fact_replay_deterministic(case: str, event, inputs) -> None:
    # 02 §11：写侧三事件同输入两次构建 → digest 与 memory 投影相等。
    first = build_transient_facts(event=event, inputs=inputs)
    second = build_transient_facts(event=event, inputs=inputs)
    assert first.bundle_digest == second.bundle_digest
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    for fact_a, fact_b in zip(first.memory_facts, second.memory_facts):
        assert fact_digest_projection(fact_a) == fact_digest_projection(fact_b)


def test_write_side_flows_match_frozen_yaml(freeze_yaml) -> None:
    relations = set(freeze_yaml["flow_relations"])
    strengths = set(freeze_yaml["flow_strength"]["order_best_to_worst"])
    cases = (
        (_memory_event(), ct_inputs(upstream_descriptors={REF: _descriptor()})),
        (_send_event(), ct_inputs(action_ir=_action_with_data_refs("data:artifact-1"))),
        (_tool_call_event(), ct_inputs(action_ir=_tool_call_action_ir())),
    )
    flows = [
        flow
        for event, inputs in cases
        for flow in build_transient_facts(event=event, inputs=inputs).flow_facts
    ]
    for flow in flows:
        assert flow.relation in relations
        assert flow.strength in strengths
