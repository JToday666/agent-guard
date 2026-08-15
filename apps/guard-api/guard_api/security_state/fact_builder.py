"""CT-PR-02a 事件 → transient 事实映射（读路径四事件，ct-fact-1，无接线）。

冻结出处（docs/AgentGuard_Context_Isolation_Taint_Tracking_Final_RC/）：

- 02 章 §8.1-8.4 四事件映射（context_assembled / model_input_prepared
  / model_output_produced / tool_result_produced）；
- 02 章 §9 Pre-decision 分离：只产 ``TransientSecurityFacts``，不改
  OnlineState、不产 final decision；
- 02 章 §11 Determinism Contract（T-FactReplay：id 全部确定性构造，
  禁止 uuid/随机/时钟）；LLM 不透明变换 influence 边恒 ``possible``；
- 02 章 §13 Failure Contract：未知事件/handler 异常收敛为
  ``EvaluationDegradation``，不 raise、不 fail-open；
- 01 章 §29 digest 白名单：bundle digest 由 transient.py 统一计算。

本模块纪律（CT-PR-02a DoD，零接线）：

- 纯函数：无 state mutation、无 I/O、不产 ``GuardDecision``；
- claim 语义全部委托 ``fact_authority.verify_source_claim``
  （CT-F0-07：adapter claim 不可自升 trust/减 taint）；
- exact credential 流只在 server 指纹命中时生成；raw secret 永不进
  任何 ref/digest（仅存 ``credential:<fingerprint>`` 形式）。

reason_code 清单（统一 ``ct-fact:`` 前缀）：
``ct-fact:unknown_event_type`` / ``ct-fact:handler_failed`` /
``ct-fact:visible_set_unavailable`` / ``ct-fact:action_ref_degraded``。
"""

from __future__ import annotations

import types
from collections.abc import Callable, Mapping
from typing import Any, cast

from pydantic import BaseModel, ConfigDict

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.models import ActionIR
from agentguard_core.credentials import (
    CREDENTIAL_ASSIGNMENT_RE,
    PROVIDER_KEY_RE,
)
from agentguard_core.events.contracts import GuardEvent
from agentguard_core.events.payloads import (
    ContextBuildPayload,
    ContextSource,
    ToolResultPayload,
)
from agentguard_core.security_context.facts import FlowFact, MemoryFact, SourceFact
from agentguard_core.signals.models import EvaluationDegradation, SecuritySignal

from .fact_authority import (
    ProducerIdentity,
    SourceClaim,
    VerifiedSourceDescriptor,
    verify_source_claim,
)
from .transient import (
    TransientSecurityFacts,
    compute_bundle_digest,
)

#: 派生事实的统一 producer 标识（02 §10 fact_builder 职责行）。
_FACT_PRODUCER = "ct-fact-builder"


class FactBuildInputs(BaseModel):
    """Fact builder 纯输入（server 侧注入，adapter 不可直接控制）。

    ``server_sensitive_evidence`` / ``server_credential_evidence`` /
    ``server_credential_fingerprints`` 是 server 确定性证据位，不是
    adapter claim（02 §6：确定性 server evidence 压制 claim）。
    ``visible_refs=None`` 表示 Runtime 无法提供 visible set（02 §8.2，
    降级为 degradation，不从 prompt 文本猜 provenance）。
    ``upstream_descriptors`` / ``upstream_memory_facts`` 本 PR 为占位
    输入，由 CT-PR-02b 消费。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope_digest: str
    producer_identity: ProducerIdentity
    server_sensitive_evidence: bool = False
    server_credential_evidence: bool = False
    credential_bearing_text: str | None = None
    server_credential_fingerprints: frozenset[str] = frozenset()
    visible_refs: tuple[str, ...] | None = None
    action_ir: ActionIR | None = None
    upstream_descriptors: Mapping[str, VerifiedSourceDescriptor] = {}
    upstream_memory_facts: Mapping[str, MemoryFact] = {}


class _PartialFacts(BaseModel):
    """handler 内部聚合（frozen；本 PR signals 恒空）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_facts: tuple[SourceFact, ...] = ()
    flow_facts: tuple[FlowFact, ...] = ()
    signals: tuple[SecuritySignal, ...] = ()
    degradations: tuple[EvaluationDegradation, ...] = ()


Handler = Callable[[GuardEvent, FactBuildInputs], _PartialFacts]


def _degradation(
    event: GuardEvent, *, reason_code: str, failure_kind: str
) -> EvaluationDegradation:
    """确定性 degradation（id 含 reason_code，无 uuid；02 §13）。"""
    return EvaluationDegradation(
        degradation_id=f"degradation:{event.event_id}:{reason_code}",
        component_id=_FACT_PRODUCER,
        domain="dataflow",
        required_for_action=False,
        failure_kind=cast(Any, failure_kind),
        reason_codes=[reason_code],
        evidence_refs=[],
    )


def _flow(
    *,
    event: GuardEvent,
    scope_digest: str,
    index: int,
    source_ref: str,
    target_ref: str,
    relation: str,
    strength: str,
    origin: str,
    taints: list[str],
) -> FlowFact:
    """确定性 flow_id：``flow:<event_id>:<idx>``（T-FactReplay）。"""
    return FlowFact(
        flow_id=f"flow:{event.event_id}:{index}",
        scope_digest=scope_digest,
        source_ref=source_ref,
        target_ref=target_ref,
        relation=cast(Any, relation),
        taints=cast(Any, taints),
        strength=cast(Any, strength),
        origin=cast(Any, origin),
        sequence=None,
        producer=_FACT_PRODUCER,
        evidence_refs=[],
    )


def _source_fact_from_descriptor(
    *,
    descriptor: VerifiedSourceDescriptor,
    scope_digest: str,
    source_id: str,
    extra_taints: tuple[str, ...] = (),
) -> SourceFact:
    """descriptor → SourceFact（taints = descriptor ∪ server 确定性追加）。"""
    merged = list(dict.fromkeys((*descriptor.initial_taints, *extra_taints)))
    return SourceFact(
        source_id=source_id,
        scope_digest=scope_digest,
        source_type=cast(Any, descriptor.source_type),
        trust=descriptor.trust,
        verification_state=descriptor.verification_state,
        origin="observed",
        authority=descriptor.fact_authority,
        producer=descriptor.producer,
        taints=cast(Any, merged),
        first_sequence=None,
        last_sequence=None,
        evidence_refs=[],
    )


def _claim_from_context_source(
    source: ContextSource,
    *,
    event: GuardEvent,
    inputs: FactBuildInputs,
    payload: ContextBuildPayload,
    index: int,
) -> SourceClaim:
    """ContextSource → adapter claim 投影（02 §8.1 / 01 §18）。

    ``source_trust`` 仅取冻结三值，表外值 fail-closed 为 ``unknown``；
    ``sanitized`` 取 payload 级 transform claim（只作 claim，不清
    taint——由 fact_authority 保证）；server 证据位来自 inputs。
    """
    return SourceClaim(
        source_id=f"source:{source.source_type}:{event.event_id}:{index}",
        scope_digest=inputs.scope_digest,
        raw_source_type=source.source_type,
        claimed_trust=cast(
            Any,
            (
                source.source_trust
                if source.source_trust in ("trusted", "untrusted", "unknown")
                else "unknown"
            ),
        ),
        sanitized=payload.sanitized,
        instruction_like=source.contains_instruction_like_text,
        server_sensitive_evidence=inputs.server_sensitive_evidence,
        server_credential_evidence=inputs.server_credential_evidence,
        producer="adapter_unattributed",
    )


def _handle_context_assembled(
    event: GuardEvent, inputs: FactBuildInputs
) -> _PartialFacts:
    """02 §8.1：ContextBuildPayload.sources[] → SourceFact + 装配流。"""
    payload = cast(ContextBuildPayload, event.payload)
    source_facts: list[SourceFact] = []
    flow_facts: list[FlowFact] = []
    for index, source in enumerate(payload.sources):
        claim = _claim_from_context_source(
            source, event=event, inputs=inputs, payload=payload, index=index
        )
        descriptor = verify_source_claim(
            claim=claim, producer_identity=inputs.producer_identity
        )
        is_memory = descriptor.source_type == "memory"
        source_id = (
            f"memory:{event.event_id}:{index}"
            if is_memory
            else f"source:{descriptor.source_type}:{event.event_id}:{index}"
        )
        source_facts.append(
            _source_fact_from_descriptor(
                descriptor=descriptor,
                scope_digest=inputs.scope_digest,
                source_id=source_id,
            )
        )
        if payload.will_enter_context:
            flow_facts.append(
                _flow(
                    event=event,
                    scope_digest=inputs.scope_digest,
                    index=index,
                    source_ref=source_id,
                    target_ref=f"context:{event.event_id}",
                    relation=("loaded_from_memory" if is_memory else "assembled_into"),
                    strength="exact",
                    origin="observed",
                    taints=list(descriptor.initial_taints),
                )
            )
    return _PartialFacts(source_facts=tuple(source_facts), flow_facts=tuple(flow_facts))


def _handle_model_input_prepared(
    event: GuardEvent, inputs: FactBuildInputs
) -> _PartialFacts:
    """02 §8.2：visible set → model_input 装配流；缺失则降级。

    Runtime 无法稳定提供 source refs 时不建流、记 degradation；
    不能从整段 prompt 文本猜“完整 provenance”。
    """
    if inputs.visible_refs is None:
        return _PartialFacts(
            degradations=(
                _degradation(
                    event,
                    reason_code="ct-fact:visible_set_unavailable",
                    failure_kind="unavailable",
                ),
            )
        )
    flow_facts = [
        _flow(
            event=event,
            scope_digest=inputs.scope_digest,
            index=index,
            source_ref=ref,
            target_ref=f"model_input:{event.event_id}",
            relation="assembled_into",
            strength="exact",
            origin="observed",
            taints=[],
        )
        for index, ref in enumerate(inputs.visible_refs)
    ]
    return _PartialFacts(flow_facts=tuple(flow_facts))


def _credential_fingerprints(text: str) -> tuple[str, ...]:
    """server 端抽取候选 credential 值并指纹化（保序去重）。

    只产出 ``canonical_sha256(candidate)`` 指纹；raw secret 值不返回、
    不落入任何 fact 字段。
    """
    candidates = list(PROVIDER_KEY_RE.findall(text))
    candidates.extend(
        match.group("value") for match in CREDENTIAL_ASSIGNMENT_RE.finditer(text)
    )
    fingerprints: list[str] = []
    for candidate in candidates:
        fingerprint = canonical_sha256(candidate)
        if fingerprint not in fingerprints:
            fingerprints.append(fingerprint)
    return tuple(fingerprints)


def _handle_model_output_produced(
    event: GuardEvent, inputs: FactBuildInputs
) -> _PartialFacts:
    """02 §8.3：model source + possible influence 边 + exact credential 流。

    LLM 不透明变换：influence 边 strength 恒 ``possible``（02 §8.3 /
    YAML flow_strength.llm_default）。exact 升级仅凭 server 指纹命中：
    ``credential:<fp> → model_output:<event_id>`` derived_from/exact/
    deterministic，且该 model source taints 追加 CREDENTIAL+SENSITIVE；
    adapter claim（trusted/sanitized）不参与任何升级。
    """
    model_source_id = f"source:model:{event.event_id}"
    claim = SourceClaim(
        source_id=model_source_id,
        scope_digest=inputs.scope_digest,
        raw_source_type="model",
        producer="model",
    )
    descriptor = verify_source_claim(
        claim=claim, producer_identity=inputs.producer_identity
    )
    flow_facts: list[FlowFact] = []
    index = 0
    if inputs.visible_refs is not None:
        for ref in inputs.visible_refs:
            flow_facts.append(
                _flow(
                    event=event,
                    scope_digest=inputs.scope_digest,
                    index=index,
                    source_ref=ref,
                    target_ref=f"model_output:{event.event_id}",
                    relation="influenced_by",
                    strength="possible",
                    origin="semantic_inferred",
                    taints=[],
                )
            )
            index += 1
    extra_taints: tuple[str, ...] = ()
    if inputs.server_credential_evidence and inputs.credential_bearing_text:
        matched = [
            fingerprint
            for fingerprint in _credential_fingerprints(inputs.credential_bearing_text)
            if fingerprint in inputs.server_credential_fingerprints
        ]
        if matched:
            extra_taints = ("CREDENTIAL", "SENSITIVE")
            for fingerprint in matched:
                flow_facts.append(
                    _flow(
                        event=event,
                        scope_digest=inputs.scope_digest,
                        index=index,
                        source_ref=f"credential:{fingerprint}",
                        target_ref=f"model_output:{event.event_id}",
                        relation="derived_from",
                        strength="exact",
                        origin="deterministic",
                        taints=["CREDENTIAL", "SENSITIVE"],
                    )
                )
                index += 1
    source_facts = (
        _source_fact_from_descriptor(
            descriptor=descriptor,
            scope_digest=inputs.scope_digest,
            source_id=model_source_id,
            extra_taints=extra_taints,
        ),
    )
    return _PartialFacts(source_facts=source_facts, flow_facts=tuple(flow_facts))


def _claim_from_tool_result(
    event: GuardEvent, *, payload: ToolResultPayload, inputs: FactBuildInputs
) -> SourceClaim:
    """ToolResultPayload → adapter claim 投影（02 §8.4）。"""
    return SourceClaim(
        source_id=f"source:tool_result:{event.event_id}",
        scope_digest=inputs.scope_digest,
        raw_source_type="tool_result",
        sanitized=payload.sanitized,
        instruction_like=payload.contains_instruction_like_text,
        server_sensitive_evidence=inputs.server_sensitive_evidence,
        server_credential_evidence=inputs.server_credential_evidence,
        producer="adapter_unattributed",
    )


def _handle_tool_result_produced(
    event: GuardEvent, inputs: FactBuildInputs
) -> _PartialFacts:
    """02 §8.4：tool_result source + action 归属流（缺失则降级）。

    有 ActionIR：``action:<action_id> → tool_result:<binding>:<action_id>``
    returned_by/exact/deterministic；runtime_binding_id 取 ActionIR
    冻结字段（actions/models.py §9）。无 ActionIR：源 ref 降级为
    ``tool_result:<event_id>``、不建流、记 degradation（02 §13 flow
    ref missing → dataflow partial）。
    """
    payload = cast(ToolResultPayload, event.payload)
    descriptor = verify_source_claim(
        claim=_claim_from_tool_result(event, payload=payload, inputs=inputs),
        producer_identity=inputs.producer_identity,
    )
    action_ir = inputs.action_ir
    degradations: tuple[EvaluationDegradation, ...] = ()
    flow_facts: tuple[FlowFact, ...] = ()
    if action_ir is not None:
        source_id = f"tool_result:{action_ir.runtime_binding_id}:{action_ir.action_id}"
        flow_facts = (
            _flow(
                event=event,
                scope_digest=inputs.scope_digest,
                index=0,
                source_ref=f"action:{action_ir.action_id}",
                target_ref=source_id,
                relation="returned_by",
                strength="exact",
                origin="deterministic",
                taints=[],
            ),
        )
    else:
        source_id = f"tool_result:{event.event_id}"
        degradations = (
            _degradation(
                event,
                reason_code="ct-fact:action_ref_degraded",
                failure_kind="unavailable",
            ),
        )
    source_facts = (
        _source_fact_from_descriptor(
            descriptor=descriptor,
            scope_digest=inputs.scope_digest,
            source_id=source_id,
        ),
    )
    return _PartialFacts(
        source_facts=source_facts,
        flow_facts=flow_facts,
        degradations=degradations,
    )


#: 读路径四事件分派表（02 §8.1-8.4）；memory_write/message_send/
#: tool_call_proposed 属后续 PR（Wave 2），此处视为未知 → fail-closed。
_EVENT_HANDLERS: types.MappingProxyType = types.MappingProxyType(
    {
        "context_assembled": _handle_context_assembled,
        "model_input_prepared": _handle_model_input_prepared,
        "model_output_produced": _handle_model_output_produced,
        "tool_result_produced": _handle_tool_result_produced,
    }
)


def build_transient_facts(
    *, event: GuardEvent, inputs: FactBuildInputs
) -> TransientSecurityFacts:
    """入口：分派 + 装配 + bundle digest（02 §9 Pre-decision）。

    失败契约（02 §13，绝不上抛、不 fail-open）：未知 event_type →
    空 bundle + ``ct-fact:unknown_event_type``；handler 异常 → 空
    bundle + ``ct-fact:handler_failed``。产出的 bundle 仅供后续
    assessment 读取，不写 OnlineState、不产 GuardDecision。
    """
    handler = _EVENT_HANDLERS.get(event.event_type)
    degradations: tuple[EvaluationDegradation, ...] = ()
    if handler is None:
        degradations = (
            _degradation(
                event,
                reason_code="ct-fact:unknown_event_type",
                failure_kind="unsupported",
            ),
        )
        partial = _PartialFacts()
    else:
        try:
            partial = handler(event, inputs)
        except Exception:
            degradations = (
                _degradation(
                    event,
                    reason_code="ct-fact:handler_failed",
                    failure_kind="invalid_output",
                ),
            )
            partial = _PartialFacts()
    bundle = TransientSecurityFacts(
        event_id=event.event_id,
        scope_digest=inputs.scope_digest,
        source_facts=partial.source_facts,
        flow_facts=partial.flow_facts,
        memory_facts=(),
        declassifications=(),
        current_action=None,
        signals=partial.signals,
        degradations=partial.degradations + degradations,
        evidence_refs=(),
    )
    return bundle.model_copy(update={"bundle_digest": compute_bundle_digest(bundle)})
