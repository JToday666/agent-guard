"""CT-PR-02b 写侧事件契约测试（ct-fact-1，无接线）。

本提交覆盖 02 §8.5 memory_write_proposed：transient MemoryFact +
persisted_to 流；口径依据 04 §12 三态 / §15 ALLOW ≠ TRUST、
02 §11 T-FactReplay（确定性、乱序无关）、§13 fail-closed。
"""

from __future__ import annotations

import pytest
from agentguard_core.security_context.facts import MemoryFact
from guard_api.security_state.fact_authority import VerifiedSourceDescriptor
from guard_api.security_state.fact_builder import build_transient_facts

from tests.test_ct_fact_builder import SCOPE, _event, _inputs

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
