"""CT-PR-02b 写侧事件契约测试（ct-fact-1，无接线）。

口径依据：02 §8.5-8.7（写侧三事件、§13 failure contract）、04 §12 三态 /
§15 ALLOW ≠ TRUST、§4 sent_to evidence-defined、02 §11 T-FactReplay
与冻结 YAML parity。
"""

from __future__ import annotations

import json

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
    _action_ir,
    _event,
    _inputs,
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
    return _event("memory_write_proposed", payload)


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
    return _event("message_send_proposed", payload)


def _action_with_data_refs(*refs: str):
    return _action_ir().model_copy(update={"data_refs": list(refs)})


# --- 02 §8.5 memory_write_proposed：三态判定 ------------------------------


@pytest.mark.parametrize(
    ("inputs", "state", "taints", "refs", "change_status"),
    [
        pytest.param(
            _inputs(
                upstream_descriptors={
                    REF: _descriptor(trust="untrusted", taints=("UNTRUSTED",))
                }
            ),
            "tainted",
            ["UNTRUSTED", "PERSISTENT_UNTRUSTED"],
            [REF],
            "proposed",
            id="untrusted-descriptor",
        ),
        pytest.param(_inputs(), "unknown", [], [], "proposed", id="empty-upstream"),
        pytest.param(
            _inputs(upstream_descriptors={REF: _descriptor()}),
            "clean",
            [],
            [REF],
            "proposed",
            id="trusted-clean",
        ),
        pytest.param(
            # 04 §15 ALLOW ≠ TRUST：EXTERNAL_INSTRUCTION 上游不因放行洗白。
            _inputs(
                upstream_descriptors={
                    REF: _descriptor(taints=("EXTERNAL_INSTRUCTION",))
                }
            ),
            "tainted",
            ["EXTERNAL_INSTRUCTION", "PERSISTENT_UNTRUSTED"],
            [REF],
            "proposed",
            id="allow-does-not-imply-trust",
        ),
        pytest.param(
            # 04 §3 单调传播：上游 MemoryFact trust/taints 只增不减。
            _inputs(
                upstream_memory_facts={
                    "memory://ns/prev": _upstream_memory_fact(
                        trust_state="tainted",
                        taints=("UNTRUSTED", "PERSISTENT_UNTRUSTED"),
                    )
                }
            ),
            "tainted",
            ["UNTRUSTED", "PERSISTENT_UNTRUSTED"],
            ["memory://ns/prev"],
            "proposed",
            id="upstream-memory-monotonic",
        ),
        pytest.param(
            # 02 §13：visible_refs 声明 ref 查表未命中 → fail-closed tainted。
            _inputs(visible_refs=("source:web:evt-0:missing",)),
            "tainted",
            ["PERSISTENT_UNTRUSTED"],
            ["source:web:evt-0:missing"],
            "proposed",
            id="missing-ref-fail-closed",
        ),
        pytest.param(
            # 04 §12：lifecycle quarantine 优先级最高（上游 tainted 不降级它）。
            _inputs(
                memory_change_status="quarantined",
                upstream_descriptors={
                    REF: _descriptor(trust="untrusted", taints=("UNTRUSTED",))
                },
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
    assert fact.change_id is None
    assert fact.last_write_sequence is None and fact.last_read_sequence is None


# --- 02 §8.5 persisted_to 流与确定性 ---------------------------------------


def test_memory_write_persisted_flow_and_memory_id_deterministic() -> None:
    inputs = _inputs(
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
    assert (flow.relation, flow.strength, flow.origin) == (
        "persisted_to",
        "exact",
        "observed",
    )
    assert flow.taints == ["UNTRUSTED"]
    # T-FactReplay：同输入两次构建逐字段相等（含 memory_id/digest）。
    replay = build_transient_facts(
        event=_memory_event(action_id="action-9"), inputs=inputs
    )
    assert replay.bundle_digest == bundle.bundle_digest
    assert replay.memory_facts == bundle.memory_facts


def test_memory_write_unordered_inputs_are_deterministic() -> None:
    # 迭代按 key 排序，与 Mapping 插入序无关（T-FactReplay）。
    descriptor_a, descriptor_b = _descriptor(), _descriptor(taints=("SENSITIVE",))
    first = build_transient_facts(
        event=_memory_event(),
        inputs=_inputs(
            upstream_descriptors={"ref-b": descriptor_b, "ref-a": descriptor_a}
        ),
    )
    second = build_transient_facts(
        event=_memory_event(),
        inputs=_inputs(
            upstream_descriptors={"ref-a": descriptor_a, "ref-b": descriptor_b}
        ),
    )
    assert first.bundle_digest == second.bundle_digest
    assert first.memory_facts[0].source_refs == second.memory_facts[0].source_refs
    assert first.memory_facts[0].source_refs == ["ref-a", "ref-b"]


# --- 02 §8.6 message_send_proposed：sink 归一化与 sent_to 流 ---------------


@pytest.mark.parametrize(
    ("channel", "recipient", "expected_sink"),
    [
        ("Email", "User@Example.COM", "mailto:User@example.com"),
        (
            "webhook",
            "https://Hooks.Example.com:443/path?b=2&a=1",
            "https://hooks.example.com/path?a&b",
        ),
        ("sms", "+15551234567", "other://+15551234567"),
    ],
)
def test_message_send_stable_refs_build_exact_sent_to(
    channel: str, recipient: str, expected_sink: str
) -> None:
    # 04 §4 sent_to evidence-defined：稳定 ActionIR data_refs →
    # exact/deterministic；sink 取 V21-02 canonical_id。
    bundle = build_transient_facts(
        event=_send_event(channel=channel, recipient=recipient),
        inputs=_inputs(action_ir=_action_with_data_refs("data:artifact-1")),
    )
    (flow,) = bundle.flow_facts
    assert flow.source_ref == "data:artifact-1"
    assert flow.target_ref == expected_sink
    assert (flow.relation, flow.strength, flow.origin) == (
        "sent_to",
        "exact",
        "deterministic",
    )
    assert flow.taints == []
    assert bundle.degradations == ()


def test_message_send_sensitive_evidence_taints_sent_to() -> None:
    bundle = build_transient_facts(
        event=_send_event(sensitive=True),
        inputs=_inputs(action_ir=_action_with_data_refs("data:artifact-1")),
    )
    assert bundle.flow_facts[0].taints == ["SENSITIVE"]


@pytest.mark.parametrize(
    ("event", "inputs"),
    [
        pytest.param(_send_event(), _inputs(), id="no-action-ir"),
        pytest.param(
            _send_event(), _inputs(action_ir=_action_ir()), id="empty-data-refs"
        ),
        pytest.param(
            # email 归一失败（无 @）→ unresolved → 不建流。
            _send_event(recipient="not-an-address"),
            _inputs(action_ir=_action_with_data_refs("data:artifact-1")),
            id="unresolvable-sink",
        ),
        pytest.param(
            # will_persist=False → 不建 persisted_to 流（无降级）。
            _memory_event(will_persist=False),
            _inputs(upstream_descriptors={"source:web:evt-0:0": _descriptor()}),
            id="memory-without-persist",
        ),
    ],
)
def test_write_side_without_stable_flow_builds_no_flow(event, inputs) -> None:
    # 无稳定流 → 零流；仅 message 路径伴随 flow_ref_missing 降级。
    bundle = build_transient_facts(event=event, inputs=inputs)
    assert bundle.flow_facts == ()
    assert bundle.signals == ()
    if event.event_type == "message_send_proposed":
        assert bundle.degradations[0].reason_codes == ["ct-fact:flow_ref_missing"]
    else:
        assert bundle.degradations == ()


def test_message_send_sensitive_preview_signal_without_exact_flow() -> None:
    # 02 §8.6：只有 content preview 可疑 → Signal + uncertain 口径，
    # 绝不伪造 exact provenance。
    bundle = build_transient_facts(event=_send_event(sensitive=True), inputs=_inputs())
    assert bundle.flow_facts == ()
    (signal,) = bundle.signals
    assert signal.signal_id == "signal:evt-1:sensitive_send"
    assert signal.detector_id == "ct-fact-builder"
    assert (signal.category, signal.scope) == ("ct-fact:sensitive_outbound", "flow")
    assert (signal.impact, signal.confidence) == ("high", "low")
    assert signal.reason_codes == ["ct-fact:sensitive_outbound_preview"]
    assert signal.evidence_group == "eg:evt-1:sensitive_send"
    (degradation,) = bundle.degradations
    assert degradation.reason_codes == ["ct-fact:flow_ref_missing"]


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
    return _event("tool_call_proposed", payload)


def _tool_call_action_ir():
    return _action_ir().model_copy(
        update={
            "resources": [_INBOUND],
            "destinations": [_OUTBOUND],
            "data_refs": ["data:artifact-1"],
        }
    )


def test_tool_call_with_action_ir_builds_data_ref_flows_and_candidate() -> None:
    bundle = build_transient_facts(
        event=_tool_call_event(), inputs=_inputs(action_ir=_tool_call_action_ir())
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
    assert candidate.action_id == "action-1"
    assert candidate.event_id == "evt-1"
    assert (candidate.authority_status, candidate.final_decision) == ("unknown", None)
    assert candidate.resource_ids == [_INBOUND.canonical_id]
    assert candidate.destination_ids == [_OUTBOUND.canonical_id]
    assert candidate.data_refs == ["data:artifact-1"]
    # runtime_sequence 登记：裸 int 序号不能构造 SequenceRef，候选取 None。
    assert candidate.runtime_sequence is None
    assert bundle.degradations == ()


def test_tool_call_without_action_ir_degrades() -> None:
    bundle = build_transient_facts(event=_tool_call_event(), inputs=_inputs())
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
            _inputs(upstream_descriptors={REF: _descriptor(taints=("UNTRUSTED",))}),
        ),
        ("message", _send_event(sensitive=True), _inputs()),
        ("tool_call", _tool_call_event(), _inputs(action_ir=_tool_call_action_ir())),
    ],
)
def test_write_side_fact_replay_deterministic(case: str, event, inputs) -> None:
    # 02 §11：写侧三事件同输入两次构建 → 同 bundle_digest；
    # memory_facts 逐条 fact_digest_projection 相等。
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
        (_memory_event(), _inputs(upstream_descriptors={REF: _descriptor()})),
        (_send_event(), _inputs(action_ir=_action_with_data_refs("data:artifact-1"))),
        (_tool_call_event(), _inputs(action_ir=_tool_call_action_ir())),
    )
    flows = [
        flow
        for event, inputs in cases
        for flow in build_transient_facts(event=event, inputs=inputs).flow_facts
    ]
    assert flows
    for flow in flows:
        assert flow.relation in relations
        assert flow.strength in strengths
