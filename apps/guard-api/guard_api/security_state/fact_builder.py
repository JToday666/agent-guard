"""GuardEvent → transient 事实映射（ct-fact-2）。

冻结出处（docs/AgentGuard_Context_Isolation_Taint_Tracking_Final_RC/）：

- 02 章 §8.1-8.4 读路径四事件映射（context_assembled /
  model_input_prepared / model_output_produced / tool_result_produced，
  Wave 1 / CT-PR-02a）；
- 02 章 §8.5-8.7 写路径三事件映射（memory_write_proposed /
  message_send_proposed / tool_call_proposed，Wave 2 / CT-PR-02b）；
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
``ct-fact:visible_set_unavailable`` / ``ct-fact:action_ref_degraded`` /
``ct-fact:flow_ref_missing`` / ``ct-fact:sensitive_outbound_preview``。

``ct-fact:flow_ref_missing`` Wave 2 激活：message_send_proposed 无稳定
``data_ref`` 关联时发射（02 §8.6 / §13）；tool_call_proposed 的
ActionIR 缺失仍沿用 ``action_ref_degraded``（§8.4 先例）。
``ct-fact:sensitive_outbound_preview``：敏感 content preview 且无稳定
refs 时的最小 SecuritySignal（02 §8.6，不伪造 exact provenance）。

版本决定（02 §12）：Gate A 将 verified visible refs 接入 model/action
influence 边、传播服务端 taint，并扩展 current action data refs；
这些都改变 fact 语义，因此 bump 为 ``ct-fact-2``。由于
fact→typed delta 容器映射未变，不 bump projector。
"""

from __future__ import annotations

import logging
import types
from collections.abc import Callable, Mapping
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.canonical_resources import (
    ResourceNormalizationInput,
    normalize_api_resource,
    normalize_email_resource,
    normalize_memory_resource,
    normalize_other_resource,
    normalize_url_resource,
)
from agentguard_core.actions.models import ActionIR
from agentguard_core.credentials import (
    CREDENTIAL_ASSIGNMENT_RE,
    PROVIDER_KEY_RE,
)
from agentguard_core.events.contracts import GuardEvent
from agentguard_core.events.payloads import (
    ContextBuildPayload,
    ContextSource,
    MemoryEventPayload,
    MessageSendPayload,
    ToolResultPayload,
)
from agentguard_core.security_context.facts import (
    FlowFact,
    MemoryFact,
    RecentActionFact,
    SourceFact,
)
from agentguard_core.signals.models import EvaluationDegradation, SecuritySignal

from .fact_authority import (
    TAINT_ORDER,
    ProducerIdentity,
    SourceClaim,
    VerifiedSourceDescriptor,
    verify_source_claim,
)
from .transient import (
    TransientSecurityFacts,
    compute_bundle_digest,
    compute_overlay_digest,
)

#: 派生事实的统一 producer 标识（02 §10 fact_builder 职责行）。
_FACT_PRODUCER = "ct-fact-builder"

#: 模块 logger：handler 异常收敛为 degradation 前记录原始异常栈。
logger = logging.getLogger(__name__)


class FactBuildInputs(BaseModel):
    """Fact builder 纯输入（server 侧注入，adapter 不可直接控制）。

    ``server_sensitive_evidence`` / ``server_credential_evidence`` /
    ``server_credential_fingerprints`` 是 server 确定性证据位，不是
    adapter claim（02 §6：确定性 server evidence 压制 claim）。
    ``visible_refs=None`` 表示 Runtime 无法提供 visible set（02 §8.2，
    降级为 degradation，不从 prompt 文本猜 provenance）。
    ``credential_bearing_text`` 信任边界：必须是 **server 侧检测证据
    片段**（如 CredentialExposureDetector 的 hit 片段），不得直接传
    adapter 原始 ``content_preview``/参数原文；CT-PR-03 接线时由服务
    端检测路径提供。
    ``upstream_descriptors`` / ``upstream_memory_facts`` 由 CT-PR-02b
    写侧 handler 消费（上游 source descriptor / 既有 MemoryFact 查表，
    按传入 key 序迭代保证确定性）。
    ``memory_change_status`` 是 MemoryGuard lifecycle 的 change 状态
    投影（04 §12；与 ``MemoryFact.trust_state`` 不混用）：
    ``quarantined`` → trust_state 直接归 quarantined。
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
    memory_change_status: Literal["proposed", "quarantined"] = "proposed"


class _PartialFacts(BaseModel):
    """handler 内部聚合（frozen）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_facts: tuple[SourceFact, ...] = ()
    flow_facts: tuple[FlowFact, ...] = ()
    memory_facts: tuple[MemoryFact, ...] = ()
    current_action: RecentActionFact | None = None
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


def _visible_ref_taints(inputs: FactBuildInputs, ref: str) -> list[str]:
    """Return server-verified upstream taints in the frozen deterministic order."""

    labels: set[str] = set()
    descriptor = inputs.upstream_descriptors.get(ref)
    if descriptor is not None:
        labels.update(descriptor.initial_taints)
    memory_fact = inputs.upstream_memory_facts.get(ref)
    if memory_fact is not None:
        labels.update(memory_fact.taints)
    return [label for label in TAINT_ORDER if label in labels]


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

    注：此处 claim ``source_id`` 仅作 ``verify_source_claim`` 的验证
    入参，不作为注册引用——最终 SourceFact 注册 id 在 handler 内另行
    构造（memory 源用 ``memory:`` 前缀，类型取 descriptor 归一化值）。
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
    """Gate A：verified visible set → current model input assembly edges。

    Runtime 无法稳定提供 source refs 时不建流、记 degradation；
    不能从整段 prompt 文本猜“完整 provenance”。保留冻结的
    ``assembled_into/exact/observed`` 装配语义，但 taint 只从
    服务端已验证的 Snapshot descriptor/memory fact 传播。
    model output 路径继续以 ``influenced_by/possible`` 表达 LLM
    不透明变换。
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
            relation=(
                "loaded_from_memory"
                if ref in inputs.upstream_memory_facts
                else "assembled_into"
            ),
            strength="exact",
            origin="observed",
            taints=_visible_ref_taints(inputs, ref),
        )
        for index, ref in enumerate(inputs.visible_refs)
    ]
    return _PartialFacts(flow_facts=tuple(flow_facts))


def _credential_fingerprints(text: str) -> tuple[str, ...]:
    """server 端抽取候选 credential 值并指纹化（保序去重）。

    只产出 ``canonical_sha256(candidate)`` 指纹；raw secret 值不返回、
    不落入任何 fact 字段。输入 ``text`` 必须是 server 侧检测证据片段
    （见 ``FactBuildInputs.credential_bearing_text`` 信任边界），不得
    是 adapter 原始文本。
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

    server 确定性证据位与指纹命中解耦（02 §6 deterministic server
    evidence dominates claims）：``server_sensitive_evidence=True`` →
    无条件追加 ``SENSITIVE``；``server_credential_evidence=True`` →
    无条件追加 ``CREDENTIAL + SENSITIVE``（保序去重）——指纹命中与否
    仅决定是否额外建 ``credential:<fp>`` exact derived_from 边，证据
    位 True 而指纹库未命中（未注册密钥）不得 fail-open 为无 taint。

    exact credential 路径信任边界重申：``credential_bearing_text`` 必须
    是 server 侧检测证据片段（见 ``FactBuildInputs`` docstring），不得
    直接传 adapter 原始文本。

    无 visible refs（``visible_refs=None``）→ 零 influence 边 +
    ``ct-fact:visible_set_unavailable`` 降级（与 §8.2 口径对称，使
    coverage 缺失可观测）；空 tuple 则零边且无降级。
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
    degradations: tuple[EvaluationDegradation, ...] = ()
    index = 0
    if inputs.visible_refs is None:
        # 与 §8.2 对称：visible set 缺失 → 零 influence 边 + 降级。
        degradations = (
            _degradation(
                event,
                reason_code="ct-fact:visible_set_unavailable",
                failure_kind="unavailable",
            ),
        )
    else:
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
                    taints=_visible_ref_taints(inputs, ref),
                )
            )
            index += 1
    # 02 §6：server 确定性证据位与指纹命中解耦——证据位 True 无条件
    # 追加 taint（未注册密钥/指纹未命中不得 fail-open）；指纹命中仅
    # 决定是否额外建 exact derived_from 边。
    extra: list[str] = []
    if inputs.server_credential_evidence:
        extra.extend(("CREDENTIAL", "SENSITIVE"))
    if inputs.server_sensitive_evidence:
        extra.append("SENSITIVE")
    extra_taints: tuple[str, ...] = tuple(dict.fromkeys(extra))
    if inputs.server_credential_evidence and inputs.credential_bearing_text:
        matched = [
            fingerprint
            for fingerprint in _credential_fingerprints(inputs.credential_bearing_text)
            if fingerprint in inputs.server_credential_fingerprints
        ]
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
    return _PartialFacts(
        source_facts=source_facts,
        flow_facts=tuple(flow_facts),
        degradations=degradations,
    )


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


def _handle_memory_write_proposed(
    event: GuardEvent, inputs: FactBuildInputs
) -> _PartialFacts:
    """02 §8.5 + 04 §12：transient MemoryFact + persisted_to 流。

    ``memory_id`` 取 ``normalize_memory_resource`` canonical_id
    （V21-02 冻结归一器；注册为 CT-PR-05 memory 身份锚点）。

    upstream 判定（按 key 排序迭代两表，T-FactReplay）：descriptor
    taints ∩ {UNTRUSTED, EXTERNAL_INSTRUCTION} 非空或 trust==
    "untrusted"，或上游 MemoryFact trust_state ∈ {tainted,
    quarantined}/含 PERSISTENT_UNTRUSTED/含 UNTRUSTED/
    EXTERNAL_INSTRUCTION（04 §2/§3 对称）/trust_state=="clean" 而
    taints 非空（矛盾态 fail-closed）→ tainted + taints +=
    PERSISTENT_UNTRUSTED（TAINT_ORDER 保序）；visible_refs 未命中 →
    fail-closed tainted（02 §13）；memory_change_status=="quarantined"
    → quarantined（优先级最高）。clean 收紧（04 §12 / CT-F0-05）：
    上游非空 且 descriptor 全 trusted 且零 initial_taints 且上游
    MemoryFact 全 clean 且零 taints；其余（含 unknown trust/带
    SENSITIVE 等）→ unknown，杜绝 model 输出经 memory 读回升级
    trusted。ALLOW ≠ TRUST（04 §15）：tainted 不因放行洗白。

    persisted_to 流（will_persist=True）：每上游 ref →
    ``memory:<canonical_id>``，exact/observed；边 taints 与
    MemoryFact.taints 同口径（并集 + tainted 时 PERSISTENT_UNTRUSTED，
    TAINT_ORDER 保序；04 §4 union + persistent）；will_persist=False →
    不建流。两上游表均空且 will_persist=True →
    ``ct-fact:flow_ref_missing`` 降级（02 §13，与 message 路径同
    口径）；visible_refs 只参与 fail-closed trust 判定。
    """
    payload = cast(MemoryEventPayload, event.payload)
    canonical = normalize_memory_resource(
        ResourceNormalizationInput(
            resource_id="",
            target=payload.memory.key,
            memory_namespace=payload.memory.namespace,
        )
    )
    memory_ref = f"memory:{canonical.canonical_id}"
    upstream_refs: list[str] = []
    tainted_upstream = False
    upstream_taints: list[str] = []
    for key in sorted(inputs.upstream_descriptors):
        descriptor = inputs.upstream_descriptors[key]
        upstream_refs.append(key)
        upstream_taints.extend(descriptor.initial_taints)
        if (
            set(descriptor.initial_taints) & {"UNTRUSTED", "EXTERNAL_INSTRUCTION"}
            or descriptor.trust == "untrusted"
        ):
            tainted_upstream = True
    for key in sorted(inputs.upstream_memory_facts):
        memory_fact = inputs.upstream_memory_facts[key]
        upstream_refs.append(key)
        upstream_taints.extend(memory_fact.taints)
        if memory_fact.trust_state in {"tainted", "quarantined"} or (
            set(memory_fact.taints) & {"UNTRUSTED", "EXTERNAL_INSTRUCTION"}
            or (memory_fact.trust_state == "clean" and memory_fact.taints)
        ):
            tainted_upstream = True
    if inputs.visible_refs is not None:
        # descriptor 查表未命中的上游 ref → fail-closed 按 tainted。
        known = set(inputs.upstream_descriptors) | set(inputs.upstream_memory_facts)
        for ref in inputs.visible_refs:
            if ref not in known:
                upstream_refs.append(ref)
                tainted_upstream = True
    trust_state: str
    if inputs.memory_change_status == "quarantined":
        trust_state = "quarantined"
    elif tainted_upstream:
        trust_state = "tainted"
    elif (
        upstream_refs
        and all(
            descriptor.trust == "trusted" and not descriptor.initial_taints
            for descriptor in inputs.upstream_descriptors.values()
        )
        and all(
            memory_fact.trust_state == "clean" and not memory_fact.taints
            for memory_fact in inputs.upstream_memory_facts.values()
        )
    ):
        # clean 收紧（04 §12）：零 unknown/零 taints，否则 fail-closed unknown。
        trust_state = "clean"
    else:
        trust_state = "unknown"
    union_taints = set(upstream_taints)
    if trust_state == "tainted":
        union_taints.add("PERSISTENT_UNTRUSTED")
    memory_taints = [label for label in TAINT_ORDER if label in union_taints]
    source_refs = list(upstream_refs)
    if payload.action_id is not None:
        source_refs.append(f"action:{payload.action_id}")
    memory_fact = MemoryFact(
        memory_id=canonical.canonical_id,
        change_id=None,
        change_status=inputs.memory_change_status,
        trust_state=cast(Any, trust_state),
        taints=cast(Any, memory_taints),
        source_refs=source_refs,
        last_write_sequence=None,
        last_read_sequence=None,
        evidence_refs=[],
    )
    flow_facts: list[FlowFact] = []
    if payload.will_persist:
        flow_facts = [
            _flow(
                event=event,
                scope_digest=inputs.scope_digest,
                index=index,
                source_ref=ref,
                target_ref=memory_ref,
                relation="persisted_to",
                strength="exact",
                origin="observed",
                taints=list(memory_taints),
            )
            for index, ref in enumerate(upstream_refs)
        ]
    degradations: tuple[EvaluationDegradation, ...] = ()
    if payload.will_persist and not upstream_refs:
        # 两上游表均空且请求持久化 → 无 ref 可建 persisted_to 流（02 §13 同口径）。
        degradations = (
            _degradation(
                event,
                reason_code="ct-fact:flow_ref_missing",
                failure_kind="unavailable",
            ),
        )
    return _PartialFacts(
        memory_facts=(memory_fact,),
        flow_facts=tuple(flow_facts),
        degradations=degradations,
    )


def _canonical_sink_ref(channel: str, recipient: str) -> str | None:
    """message sink → canonical ref（V21-02 冻结归一器）。

    channel strip+lower 分派：email/mail/smtp → email；api/http/
    https/webhook → api；其余 → url，unresolved 退 other。sink_ref
    取 canonical_id（自带 scheme 前缀，与 02 §8.6 分型语义等价）；
    unresolved 返回 None → 不建流（不以不稳定 identity 伪造
    provenance）。
    """
    kind = channel.strip().lower()
    inp = ResourceNormalizationInput(resource_id="", target=recipient)
    if kind in {"email", "mail", "smtp"}:
        resource = normalize_email_resource(inp)
    elif kind in {"api", "http", "https", "webhook"}:
        resource = normalize_api_resource(inp)
    else:
        resource = normalize_url_resource(inp)
        if resource.resolution_status == "unresolved":
            resource = normalize_other_resource(inp)
    if resource.resolution_status == "unresolved":
        return None
    return resource.canonical_id


def _handle_message_send_proposed(
    event: GuardEvent, inputs: FactBuildInputs
) -> _PartialFacts:
    """02 §8.6：sink 归一化 + sent_to 确定性流（evidence-defined）。

    只有稳定 ``data_ref`` 可关联（ActionIR.data_refs 非空）时才生成
    ``<data_ref> → <sink_ref>`` exact/deterministic 流（04 §4：此处
    evidence 即已归一 ActionIR 的稳定 refs）；taints：
    contains_sensitive_data 或 server_sensitive_evidence → [SENSITIVE]。
    channel→canonical 前缀登记：采用 V21-02 归一器实际产出（mailto:/http(s)://other://），未自造 network: 前缀。

    无 ActionIR 或 data_refs 空/sink 不可归一 → 零流 +
    ``ct-fact:flow_ref_missing`` 降级（02 §13）；若另有敏感证据
    （contains_sensitive_data 或 server_sensitive_evidence，与 exact
    流 taints 口径对称）→ 追加最小 SecuritySignal（``ct-fact:sensitive_outbound_preview``，
    impact=high/confidence=low：严重度按“敏感出边界”保守分级，确定
    性交 Fusion；evidence_group 确定性构造）；绝不建 exact sent_to
    伪造 provenance。
    """
    payload = cast(MessageSendPayload, event.payload)
    sink_ref = _canonical_sink_ref(payload.channel, payload.recipient)
    degradations: tuple[EvaluationDegradation, ...] = ()
    flow_facts: tuple[FlowFact, ...] = ()
    signals: tuple[SecuritySignal, ...] = ()
    action_ir = inputs.action_ir
    data_refs = action_ir.data_refs if action_ir is not None else []
    if sink_ref is not None and data_refs:
        sensitive = payload.contains_sensitive_data or inputs.server_sensitive_evidence
        flow_facts = tuple(
            _flow(
                event=event,
                scope_digest=inputs.scope_digest,
                index=index,
                source_ref=ref,
                target_ref=sink_ref,
                relation="sent_to",
                strength="exact",
                origin="deterministic",
                taints=(["SENSITIVE"] if sensitive else []),
            )
            for index, ref in enumerate(data_refs)
        )
    else:
        degradations = (
            _degradation(
                event,
                reason_code="ct-fact:flow_ref_missing",
                failure_kind="unavailable",
            ),
        )
        sensitive = payload.contains_sensitive_data or inputs.server_sensitive_evidence
        if sensitive:
            # 敏感证据且无稳定 refs：最小 Signal，不伪造 exact 流。
            signals = (
                SecuritySignal(
                    signal_id=f"signal:{event.event_id}:sensitive_send",
                    detector_id=_FACT_PRODUCER,
                    category="ct-fact:sensitive_outbound",
                    scope="flow",
                    impact="high",
                    confidence="low",
                    evidence_group=f"eg:{event.event_id}:sensitive_send",
                    reason_codes=["ct-fact:sensitive_outbound_preview"],
                    evidence_refs=[],
                    facts=[],
                    tags=["ct-fact", "outbound"],
                ),
            )
    return _PartialFacts(
        flow_facts=flow_facts,
        signals=signals,
        degradations=degradations,
    )


def _handle_tool_call_proposed(
    event: GuardEvent, inputs: FactBuildInputs
) -> _PartialFacts:
    """Gate A：verified refs → current action influence + action candidate。

    ActionIR 继续由 Core normalizer 拥有；Context Track 将服务端
    验证的 visible refs 以 ``influenced_by/possible/
    semantic_inferred`` 连到 current action，传播 Snapshot fact taint，
    并写入 ``RecentActionFact.data_refs``。

    资源方向约定：CanonicalResource/DerivedResource 无独立方向
    字段，按 ActionIR 字段语义登记——destinations（出站）→
    ``written_to``；resources（入站/读取）→ ``read_from``（04 §4
    两 relation 默认均 exact）。

    无 ActionIR → 零流、无候选、``ct-fact:action_ref_degraded``
    降级（02 §8.4 先例 / §13 flow ref missing）。

    runtime_sequence 登记：ActionIR.runtime_sequence 是裸整数
    序号，而 RecentActionFact 要求 SequenceRef（domain +
    producer_binding_id + value，01 §5 且禁止跨 domain 比较）；
    事实生产者无合法依据构造完整锚点，候选取 None，由持有
    producer 上下文的后续链（CT-PR-04/05 接线）填充。
    """
    action_ir = inputs.action_ir
    if action_ir is None:
        return _PartialFacts(
            degradations=(
                _degradation(
                    event,
                    reason_code="ct-fact:action_ref_degraded",
                    failure_kind="unavailable",
                ),
            )
        )
    flow_facts: list[FlowFact] = []
    index = 0
    degradations: tuple[EvaluationDegradation, ...] = ()
    visible_refs = inputs.visible_refs
    if visible_refs is None:
        # Missing or rejected visible set: do not emit any provenance edge.
        # The action itself remains available to conservative assessment.
        visible_refs = ()
        degradations = (
            _degradation(
                event,
                reason_code="ct-fact:visible_set_unavailable",
                failure_kind="unavailable",
            ),
        )
    for ref in visible_refs:
        flow_facts.append(
            _flow(
                event=event,
                scope_digest=inputs.scope_digest,
                index=index,
                source_ref=ref,
                target_ref=f"action:{action_ir.action_id}",
                relation="influenced_by",
                strength="possible",
                origin="semantic_inferred",
                taints=_visible_ref_taints(inputs, ref),
            )
        )
        index += 1
    for relation, resources in (
        ("written_to", action_ir.destinations),
        ("read_from", action_ir.resources),
    ):
        for resource in resources:
            flow_facts.append(
                _flow(
                    event=event,
                    scope_digest=inputs.scope_digest,
                    index=index,
                    source_ref=f"action:{action_ir.action_id}",
                    target_ref=resource.canonical_id,
                    relation=cast(Any, relation),
                    strength="exact",
                    origin="deterministic",
                    taints=[],
                )
            )
            index += 1
    current_action = RecentActionFact(
        action_id=action_ir.action_id,
        event_id=action_ir.event_id,
        agent_id=action_ir.agent_id,
        branch_id=action_ir.branch_id,
        parent_event_ids=list(action_ir.parent_event_ids),
        # 见 docstring runtime_sequence 登记：裸 int 不能构造 SequenceRef。
        runtime_sequence=None,
        action_type=action_ir.action_type,
        impact=action_ir.impact,
        effects=action_ir.effects,
        resource_ids=[resource.canonical_id for resource in action_ir.resources],
        destination_ids=[resource.canonical_id for resource in action_ir.destinations],
        data_refs=list(dict.fromkeys((*action_ir.data_refs, *visible_refs))),
        # Pre-decision 候选：authority/decision 由 Core 评估链后置填充。
        authority_status="unknown",
        final_decision=None,
        evidence_refs=[],
    )
    return _PartialFacts(
        flow_facts=tuple(flow_facts),
        current_action=current_action,
        degradations=degradations,
    )


#: 事件分派表（02 §8.1-8.7）：Wave 1 读路径四事件 + Wave 2 写侧三
#: 事件；未注册事件类型视为未知 → fail-closed（02 §13）。
_EVENT_HANDLERS: types.MappingProxyType = types.MappingProxyType(
    {
        "context_assembled": _handle_context_assembled,
        "model_input_prepared": _handle_model_input_prepared,
        "model_output_produced": _handle_model_output_produced,
        "tool_result_produced": _handle_tool_result_produced,
        "memory_write_proposed": _handle_memory_write_proposed,
        "message_send_proposed": _handle_message_send_proposed,
        "tool_call_proposed": _handle_tool_call_proposed,
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

    消费方契约：必须以 ``degradations`` 为空作为 bundle 可用的前置
    条件——非空表示 coverage 部分缺失，消费方须显式处理降级场景，
    不得把降级 bundle 当作完整事实图使用。
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
            logger.warning(
                "ct-fact-builder handler failed for event %s; "
                "converging to degradation",
                event.event_id,
                exc_info=True,
            )
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
        memory_facts=partial.memory_facts,
        declassifications=(),
        current_action=partial.current_action,
        signals=partial.signals,
        degradations=partial.degradations + degradations,
        evidence_refs=(),
    )
    stamped = bundle.model_copy(update={"bundle_digest": compute_bundle_digest(bundle)})
    return stamped.model_copy(
        update={"overlay_digest": compute_overlay_digest(stamped)}
    )
