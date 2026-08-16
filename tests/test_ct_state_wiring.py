"""CT-PR-03b DoD e2e：CT 事实投影接线测试（七场景）。

覆盖 CT-PR-03 实施计划步骤 4 DoD 口径：

① flag on + task_ingress → 真实形状 evaluate（tool_result_produced /
   memory_write_proposed）→ state.source_index / relevant_flows /
   memory_index 非空；
② CT flag off → 逐字节不变（响应/键集/零投影）；
③ 重复 evaluate → replayed_noop 五元组短路（不重复投影）；
④ 投影 conflict 注入 → dirty + 告警收敛，响应与审计不受影响；
⑤ dirty → rebuild → 三类事实容器 digest 等价（T-Replay）；
⑥ 无 task 引用 → 跳过留痕不伪造 scope（adapter 入站无 CT 通道）；
⑦ pipeline + CT 双投影共存（前向漂移锁内确定性 rebase 吸收）。

评审补强（CT-PR-03b 三视角评审 S1/S2/S4）：
⑧ 持久信封 round-trip 保真守门（B1 常设守门）；
⑨ backfill 正向重建（删登记 → replay 恢复，容器 digest 等价）；
⑩ backfill 负向分支与前缀 fail-closed 直驱用例。

契约依据：CT-PR-03 实施计划裁决 D1-D6 与 02 §3 commit→project 时序。
"""

from __future__ import annotations

import base64
import copy
import json
import logging
from types import SimpleNamespace

from agentguard_core import AuditEvent, GuardEvent, utc_now_iso
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.authority.models import (
    EvaluationClock,
    SecurityStateScope,
    TaskFact,
)
from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.events.payloads import (
    MemoryEventPayload,
    MemoryRecord,
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
    ToolResult,
    ToolResultPayload,
)
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    OnlineSecurityState,
    projection_identity_key,
)
from agentguard_core.security_context.facts import FlowFact, SourceFact
from guard_api.auth import AuthContext
from guard_api.models import TaskCreateRequest
from guard_api.security_state import SecurityStateService
from guard_api.security_state.transient import (
    LEGACY_FACT_BUILDER_VERSION,
    TransientSecurityFacts,
    compute_bundle_digest,
    compute_overlay_digest,
)
from guard_api.services import (
    ApprovalService,
    AuditService,
    CtProjectionService,
    EvaluationService,
    PolicyService,
    TaskIngressService,
    V21PipelineService,
    V21ShadowService,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import ProjectionIdentityRecord, SecurityStateRecord
from guard_api.storage.memory import MemoryControlPlaneStore

from tests.test_v21_09_pipeline import _normalized_response_dump

_TEST_SECRET = base64.urlsafe_b64encode(
    b"ct-pr-03b-wiring-test-secret-material"
).decode("ascii")
_TRACE_ID = "trace_ct_wiring_1"


def _settings(*, ct_enabled: bool = True) -> GuardApiSettings:
    return GuardApiSettings(
        control_token="control-secret",
        storage_backend="memory",
        v21_shadow_enabled=True,
        v21_shadow_server_secret=_TEST_SECRET,
        ct_fact_projection_enabled=ct_enabled,
        task_scope_active_key_id="ct-test-key-1",
        task_scope_keys=json.dumps(
            {
                "ct-test-key-1": base64.b64encode(
                    b"ct-scope-test-key-material-00001"
                ).decode("ascii")
            }
        ),
    )


def _stack(
    store: MemoryControlPlaneStore, *, settings: GuardApiSettings
) -> tuple[EvaluationService, SecurityStateService, CtProjectionService]:
    state_service = SecurityStateService(store)
    policy_service = PolicyService(store=store)
    pipeline = V21PipelineService(
        settings=settings,
        store=store,
        state_service=state_service,
        policy_service=policy_service,
    )
    shadow = V21ShadowService(
        settings=settings, store=store, state_service=state_service
    )
    ct_service = CtProjectionService(
        settings=settings, store=store, state_service=state_service
    )
    evaluation = EvaluationService(
        policy_service=policy_service,
        audit_service=AuditService(store=store),
        approval_service=ApprovalService(store=store, settings=settings),
        v21_shadow_service=shadow,
        v21_pipeline=pipeline,
        ct_projection_service=ct_service,
    )
    return evaluation, state_service, ct_service


def _ingress_task(
    store: MemoryControlPlaneStore, *, settings: GuardApiSettings
) -> tuple[str, str]:
    """真实 task_ingress 通道建立权威 TaskFact（返回 task_id/scope_digest）。"""

    service = TaskIngressService(store=store, settings=settings)
    auth = AuthContext(
        principal_type="component",
        principal_id="cred_adapter_main",
        role="adapter",
        scopes=["task:write"],
        auth_method="bearer",
        runtime="langgraph",
        agent_id="main",
    )
    request = TaskCreateRequest(
        task_text="CT wiring DoD fixture task",
        runtime="langgraph",
        trace_id=_TRACE_ID,
        action_constraints=[],
        resource_constraints=[],
        destination_constraints=[],
    )
    response = service.create_task(request, auth)
    return response.task_id, response.scope_digest


def _ct_event(
    *,
    event_id: str,
    event_type: str,
    task_id: str | None = None,
    call_id: str | None = None,
) -> GuardEvent:
    metadata: dict[str, object] = {}
    if task_id is not None:
        metadata["task_id"] = task_id
    tool_kwargs: dict[str, object] = {"name": "read_file"}
    if call_id is not None:
        tool_kwargs["call_id"] = call_id
    if event_type == "tool_result_produced":
        payload: object = ToolResultPayload(
            tool=ToolDescriptor(**tool_kwargs),  # type: ignore[arg-type]
            result=ToolResult(content_preview="csv rows", size_bytes=128),
            will_enter_context=True,
        )
    elif event_type == "memory_write_proposed":
        payload = MemoryEventPayload(
            memory=MemoryRecord(
                namespace="notes",
                key="summary",
                operation="write",
                source_trust="trusted",
            ),
            will_persist=True,
            requires_approval=False,
        )
    else:
        payload = ToolCallPayload(tool=ToolDescriptor(**tool_kwargs))  # type: ignore[arg-type]
    return GuardEvent(
        event_id=event_id,
        event_type=event_type,
        runtime="langgraph",
        trace_id=_TRACE_ID,
        timestamp="2026-08-16T00:00:00+00:00",
        security_context=SecurityContext(
            agent_id="main",
            user_task="ct wiring fixture",
            # Existing CT projection fixtures prove an explicitly empty
            # visible set.  Gate A distinguishes this from an omitted set.
            visible_source_refs=(),
        ),
        payload=payload,
        metadata=metadata,
    )


def _online_state(store: MemoryControlPlaneStore, scope_digest: str):
    record = store.get_security_state(scope_digest)
    assert record is not None
    return record, OnlineSecurityState.model_validate(record.canonical_payload)


def test_visible_action_alias_requires_one_returned_by_edge_not_one_target() -> None:
    """Duplicate evidence edges to the same target remain ambiguous."""

    scope_digest = "sha256:" + "9" * 64
    source_ref = "tool_result:binding:test:call_prior"
    source = SourceFact(
        source_id=source_ref,
        scope_digest=scope_digest,
        source_type="tool_result",
        trust="untrusted",
        verification_state="unverified",
        origin="observed",
        authority="untrusted_claim",
        producer="ct-fact-builder",
        taints=["UNTRUSTED"],
        first_sequence=None,
        last_sequence=None,
        evidence_refs=[],
    )

    def returned_by(flow_id: str) -> FlowFact:
        return FlowFact(
            flow_id=flow_id,
            scope_digest=scope_digest,
            source_ref="action:call_prior",
            target_ref=source_ref,
            relation="returned_by",
            taints=[],
            strength="exact",
            origin="deterministic",
            sequence=None,
            producer="ct-fact-builder",
            evidence_refs=[],
        )

    event = _ct_event(
        event_id="evt_visible_alias_ambiguous",
        event_type="tool_call_proposed",
    )
    event = event.model_copy(
        update={
            "security_context": event.security_context.model_copy(
                update={"visible_source_refs": ("action:call_prior",)}
            )
        }
    )
    materials = SimpleNamespace(
        snapshot=SimpleNamespace(
            sources=[source],
            flows=[returned_by("flow:one"), returned_by("flow:two")],
        )
    )
    service = object.__new__(CtProjectionService)
    assert service._resolve_visible_refs(event, materials, scope_digest) is None


def test_visible_refs_reject_mixed_cross_scope_set_without_partial_acceptance() -> None:
    scope_digest = "sha256:" + "8" * 64
    other_scope = "sha256:" + "7" * 64

    def source(source_id: str, scope: str) -> SourceFact:
        return SourceFact(
            source_id=source_id,
            scope_digest=scope,
            source_type="tool_result",
            trust="untrusted",
            verification_state="verified",
            origin="observed",
            authority="authoritative",
            producer="ct-fact-builder",
            taints=["UNTRUSTED"],
            first_sequence=None,
            last_sequence=None,
            evidence_refs=[],
        )

    same_scope_ref = "tool_result:binding:test:call_same_scope"
    cross_scope_ref = "tool_result:binding:test:call_cross_scope"
    event = _ct_event(
        event_id="evt_visible_cross_scope",
        event_type="tool_call_proposed",
    ).model_copy(
        update={
            "security_context": SecurityContext(
                agent_id="main",
                user_task="ct wiring fixture",
                visible_source_refs=(same_scope_ref, cross_scope_ref),
            )
        }
    )
    materials = SimpleNamespace(
        snapshot=SimpleNamespace(
            sources=[
                source(same_scope_ref, scope_digest),
                source(cross_scope_ref, other_scope),
            ],
            flows=[],
        )
    )

    service = object.__new__(CtProjectionService)
    assert service._resolve_visible_refs(event, materials, scope_digest) is None


def test_visible_refs_apply_width_budget_before_deduplication() -> None:
    scope_digest = "sha256:" + "6" * 64
    source_ref = "tool_result:binding:test:call_repeated"
    event = _ct_event(
        event_id="evt_visible_over_width",
        event_type="tool_call_proposed",
    ).model_copy(
        update={
            "security_context": SecurityContext(
                agent_id="main",
                user_task="ct wiring fixture",
                visible_source_refs=tuple(source_ref for _ in range(33)),
            )
        }
    )
    materials = SimpleNamespace(
        snapshot=SimpleNamespace(
            sources=[
                SourceFact(
                    source_id=source_ref,
                    scope_digest=scope_digest,
                    source_type="tool_result",
                    trust="untrusted",
                    verification_state="verified",
                    origin="observed",
                    authority="authoritative",
                    producer="ct-fact-builder",
                    taints=["UNTRUSTED"],
                    first_sequence=None,
                    last_sequence=None,
                    evidence_refs=[],
                )
            ],
            flows=[],
        )
    )

    service = object.__new__(CtProjectionService)
    assert service._resolve_visible_refs(event, materials, scope_digest) is None


def _snapshot_kwargs(scope_digest: str, task_fact: TaskFact) -> dict:
    return {
        "scope": SecurityStateScope(
            principal_id=task_fact.principal_id,
            runtime="langgraph",
            runtime_binding_id=f"binding:{task_fact.principal_id}",
            trace_id=_TRACE_ID,
            session_id=None,
            scope_digest=scope_digest,
        ),
        "task_fact_head": task_fact,
        "evaluation_clock": EvaluationClock(
            evaluated_at="2026-08-16T01:00:00+00:00",
            clock_version="test-clock",
        ),
        "policy_revision": "rev-1",
        "policy_digest": "sha256:policy_fixture",
        "plan": RequiredCheckPlan(
            plan_id="ct-wiring:plan",
            impact="high",
            required_domains=["task", "behavior"],
            optional_domains=[
                "source",
                "capability",
                "dataflow",
                "memory",
                "runtime_outcome",
            ],
            required_capabilities=[],
            semantic_resolvable_dimensions=[],
            reason_codes=["ct-wiring:fixture"],
        ),
    }


def _containers_dump(state: OnlineSecurityState) -> str:
    """三类 CT 事实容器的规范化 digest（T-Replay 等价对照锚点）。"""

    return canonical_sha256(
        {
            "source_index": [
                fact.model_dump(mode="json") for fact in state.source_index
            ],
            "relevant_flows": [
                fact.model_dump(mode="json") for fact in state.relevant_flows
            ],
            "memory_index": [
                fact.model_dump(mode="json") for fact in state.memory_index
            ],
        }
    )


# ---------------------------------------------------------------------------
# ① DoD 主场景：task_ingress + 真实形状 → 三类事实容器非空
# ---------------------------------------------------------------------------


def test_dod_real_shapes_populate_state_indices() -> None:
    store = MemoryControlPlaneStore()
    settings = _settings()
    task_id, scope_digest = _ingress_task(store, settings=settings)
    evaluation, state_service, _ = _stack(store, settings=settings)

    result_event = _ct_event(
        event_id="evt_ct_result_1",
        event_type="tool_result_produced",
        task_id=task_id,
        call_id="call_ct_1",
    )
    response = evaluation.evaluate(
        result_event, requesting_principal_id="cred_adapter_main"
    )
    assert response.decision.decision in ("allow", "ask", "deny")

    memory_event = _ct_event(
        event_id="evt_ct_memory_1",
        event_type="memory_write_proposed",
        task_id=task_id,
    )
    evaluation.evaluate(memory_event, requesting_principal_id="cred_adapter_main")

    # D4 commit 信封：随同一条 policy_evaluation 审计记录落盘；
    # D1 独立投影身份（runtime_observation + ct-facts:{event_id}）。
    for event_id in ("evt_ct_result_1", "evt_ct_memory_1"):
        audit = store.get_policy_evaluation_by_event_id(event_id)
        assert audit is not None
        envelope = audit.evidence["ct_transient_facts"]
        assert envelope["schema_version"] == "1.1"
        payload = envelope["payload"]
        assert payload["fact_builder_version"] == "ct-fact-2"
        assert payload["bundle_digest"].startswith("sha256:")
        assert payload["overlay_digest"].startswith("sha256:")
        assert payload["source_identity"] == {
            "source_record_type": "runtime_observation",
            "source_record_id": f"ct-facts:{event_id}",
            "source_revision": 1,
        }

    # D1 身份登记在册；task_upsert 恒 None 契约（CT delta 不写 task 域）。
    access = state_service.store_access
    for event_id in ("evt_ct_result_1", "evt_ct_memory_1"):
        registration = access.get_projection(
            scope_digest,
            "runtime_observation",
            f"ct-facts:{event_id}",
            1,
            PROJECTOR_VERSION,
        )
        assert registration is not None
        assert registration.delta_payload.get("task_upsert") is None

    # DoD 终态：三类事实容器全部非空且状态干净。
    record, state = _online_state(store, scope_digest)
    assert record.dirty is False
    assert state.source_index, "source_index should be non-empty"
    assert state.relevant_flows, "relevant_flows should be non-empty"
    assert state.memory_index, "memory_index should be non-empty"


# ---------------------------------------------------------------------------
# ② CT flag off：逐字节不变（零信封零投影，响应/键集对照）
# ---------------------------------------------------------------------------


def test_ct_flag_off_byte_identical() -> None:
    dumps: dict[str, dict] = {}
    evidences: dict[str, set[str]] = {}
    for label, ct_enabled in (("on", True), ("off", False)):
        store = MemoryControlPlaneStore()
        settings = _settings(ct_enabled=ct_enabled)
        task_id, scope_digest = _ingress_task(store, settings=settings)
        evaluation, state_service, ct_service = _stack(store, settings=settings)
        assert ct_service.enabled is ct_enabled
        event = _ct_event(
            event_id="evt_ct_off_1",
            event_type="tool_result_produced",
            task_id=task_id,
            call_id="call_off_1",
        )
        response = evaluation.evaluate(
            event, requesting_principal_id="cred_adapter_main"
        )
        dump = _normalized_response_dump(response)
        # latency_ms 是墙钟计时，非语义字段，不参与逐字对照。
        dump.get("decision", {}).pop("latency_ms", None)
        dumps[label] = dump
        audit = store.get_policy_evaluation_by_event_id(event.event_id)
        assert audit is not None
        evidences[label] = set(audit.evidence)
        # flag off：零 CT 投影登记（flag on 侧作对照基线）。
        registration = state_service.store_access.get_projection(
            scope_digest,
            "runtime_observation",
            f"ct-facts:{event.event_id}",
            1,
            PROJECTOR_VERSION,
        )
        if ct_enabled:
            assert registration is not None
        else:
            assert registration is None

    # 官方响应逐字一致；键集只差 ct_transient_facts 一个键。
    assert dumps["on"] == dumps["off"]
    assert "ct_transient_facts" in evidences["on"]
    assert evidences["on"] - {"ct_transient_facts"} == evidences["off"]


# ---------------------------------------------------------------------------
# ③ 重复 evaluate：replayed_noop 五元组短路，不重复投影
# ---------------------------------------------------------------------------


def test_replay_idempotent_short_circuit(monkeypatch, caplog) -> None:
    store = MemoryControlPlaneStore()
    settings = _settings()
    task_id, scope_digest = _ingress_task(store, settings=settings)
    evaluation, state_service, _ = _stack(store, settings=settings)
    event = _ct_event(
        event_id="evt_ct_replay_1",
        event_type="tool_result_produced",
        task_id=task_id,
        call_id="call_replay_1",
    )

    calls = {"count": 0}
    original_project = SecurityStateService.project_committed

    def _counting(self, committed_record, **kwargs):
        calls["count"] += 1
        return original_project(self, committed_record, **kwargs)

    monkeypatch.setattr(SecurityStateService, "project_committed", _counting)

    first = evaluation.evaluate(event, requesting_principal_id="cred_adapter_main")
    count_after_first = calls["count"]
    assert count_after_first >= 1
    version_after_first = store.get_security_state(scope_digest).state_version

    replay = evaluation.evaluate(event, requesting_principal_id="cred_adapter_main")
    # 响应不变（同幂等结果）。
    assert replay.policy_audit_id == first.policy_audit_id
    assert _normalized_response_dump(replay) == _normalized_response_dump(first)
    # 五元组幂等键短路：evaluation 与 CT 补投影均不重复进入 projector。
    assert calls["count"] == count_after_first
    assert store.get_security_state(scope_digest).state_version == version_after_first
    # 评审强化：短路断言必须与「backfill 重建失败」可区分——登记在场
    # （短路前置条件成立），且 replay 全程无任何 backfill 跳过/失败留痕。
    assert (
        state_service.store_access.get_projection(
            scope_digest,
            "runtime_observation",
            f"ct-facts:{event.event_id}",
            1,
            PROJECTOR_VERSION,
        )
        is not None
    )
    assert not any(
        "backfill skipped" in record.message
        or "bundle rebuild failed" in record.message
        or "backfill failed" in record.message
        for record in caplog.records
    )


# ---------------------------------------------------------------------------
# ④ 投影 conflict 注入：dirty + 告警收敛，响应与审计不受影响
# ---------------------------------------------------------------------------


def test_ct_projection_conflict_dirty_response_unaffected(caplog) -> None:
    store = MemoryControlPlaneStore()
    settings = _settings()
    task_id, scope_digest = _ingress_task(store, settings=settings)
    # 预埋异 digest 的同五元组身份登记（确定性 source_record_id 可预推导）。
    state_service = SecurityStateService(store)
    state_service.ensure_ready(scope_digest)
    base = store.get_security_state(scope_digest)
    assert base is not None
    fake_digest = "sha256:" + "00" * 32
    state_service.store_access.record_projection(
        ProjectionIdentityRecord(
            scope_digest=scope_digest,
            source_record_type="runtime_observation",
            source_record_id="ct-facts:evt_ct_conflict_1",
            source_revision=1,
            projector_version=PROJECTOR_VERSION,
            delta_digest=fake_digest,
            delta_payload={},
            applied_state_version=base.state_version,
            created_at=utc_now_iso(),
        )
    )

    evaluation, _, _ = _stack(store, settings=settings)
    event = _ct_event(
        event_id="evt_ct_conflict_1",
        event_type="tool_result_produced",
        task_id=task_id,
        call_id="call_conflict_1",
    )
    with caplog.at_level(logging.WARNING):
        response = evaluation.evaluate(
            event, requesting_principal_id="cred_adapter_main"
        )
    # fail-closed 收敛：响应与审计不受影响。
    assert response.decision.decision in ("allow", "ask", "deny")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    assert "ct_transient_facts" in audit.evidence
    assert "guard_decision" in audit.evidence
    # digest conflict → 置脏；异 digest 登记原样保留（不静默覆盖）。
    record = store.get_security_state(scope_digest)
    assert record is not None
    assert record.dirty is True
    existing = state_service.store_access.get_projection(
        scope_digest,
        "runtime_observation",
        "ct-facts:evt_ct_conflict_1",
        1,
        PROJECTOR_VERSION,
    )
    assert existing is not None
    assert existing.delta_digest == fake_digest
    # 告警收敛留痕（投影失败绝不上抛到响应路径）。
    assert any(
        "ct fact projection failed" in record_log.message
        for record_log in caplog.records
    )


# ---------------------------------------------------------------------------
# ⑤ dirty → rebuild：三类事实容器 digest 等价（T-Replay）
# ---------------------------------------------------------------------------


def test_dirty_rebuild_state_digest_equivalence() -> None:
    store = MemoryControlPlaneStore()
    settings = _settings()
    task_id, scope_digest = _ingress_task(store, settings=settings)
    evaluation, state_service, _ = _stack(store, settings=settings)
    event = _ct_event(
        event_id="evt_ct_rebuild_1",
        event_type="tool_result_produced",
        task_id=task_id,
        call_id="call_rebuild_1",
    )
    evaluation.evaluate(event, requesting_principal_id="cred_adapter_main")

    record, state = _online_state(store, scope_digest)
    assert record.dirty is False
    assert state.source_index
    before = _containers_dump(state)

    # 置脏后 bounded rebuild 必须逐位等价：同投影登记 + 同
    # projector_version → 同事实容器（05 §12 T-Replay）。
    state_service.store_access.mark_security_state_dirty(scope_digest, ["source"])
    task_record = store.get_task_fact(task_id)
    assert task_record is not None
    state_service.read_snapshot_with_revoked(
        scope_digest,
        **_snapshot_kwargs(scope_digest, task_record.task_fact),
    )

    record_after, state_after = _online_state(store, scope_digest)
    # F5：rebuild 成功路径并入既有列级 dirty 域标记（保守留痕），
    # 但重建内容必须逐位等价（T-Replay 核心断言）。
    assert "source" in record_after.dirty_domains
    assert _containers_dump(state_after) == before


# ---------------------------------------------------------------------------
# ⑥ 无 task 引用：跳过留痕不伪造 scope（adapter 入站无 CT 通道）
# ---------------------------------------------------------------------------


def test_no_task_reference_skip_no_fabrication() -> None:
    store = MemoryControlPlaneStore()
    settings = _settings()
    evaluation, _, _ = _stack(store, settings=settings)
    # adapter 入站事件不携带 task claim：CT 无 delta 通道。
    event = _ct_event(
        event_id="evt_ct_notask_1",
        event_type="tool_result_produced",
        call_id="call_notask_1",
    )
    response = evaluation.evaluate(event, requesting_principal_id="cred_adapter_main")
    assert response.decision.decision in ("allow", "ask", "deny")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    # 无信封、权威键完整；且不得为无 task 事件伪造任何 scope 状态。
    assert "ct_transient_facts" not in audit.evidence
    assert "guard_decision" in audit.evidence
    assert store.security_states == {}


# ---------------------------------------------------------------------------
# ⑦ pipeline + CT 双投影共存（前向漂移锁内 rebase 吸收）
# ---------------------------------------------------------------------------


def test_dual_projection_coexistence_forward_drift_rebase() -> None:
    store = MemoryControlPlaneStore()
    settings = _settings()
    task_id, scope_digest = _ingress_task(store, settings=settings)
    evaluation, state_service, _ = _stack(store, settings=settings)
    event = _ct_event(
        event_id="evt_ct_dual_1",
        event_type="tool_result_produced",
        task_id=task_id,
        call_id="call_dual_1",
    )
    response = evaluation.evaluate(event, requesting_principal_id="cred_adapter_main")
    assert response.decision.decision in ("allow", "ask", "deny")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    # 两个信封共存于同一条审计记录。
    assert "state_delta_v21" in audit.evidence
    assert "ct_transient_facts" in audit.evidence

    access = state_service.store_access
    eval_ref = audit.evidence["state_delta_v21"]["payload"]
    eval_registration = access.get_projection(
        scope_digest,
        "policy_evaluation",
        eval_ref["source_record_id"],
        eval_ref["source_revision"],
        PROJECTOR_VERSION,
    )
    assert eval_registration is not None
    ct_registration = access.get_projection(
        scope_digest,
        "runtime_observation",
        f"ct-facts:{event.event_id}",
        1,
        PROJECTOR_VERSION,
    )
    assert ct_registration is not None

    # 双投影都推进了 state version，且状态干净（前向漂移被锁内
    # 确定性 rebase 吸收，不置脏不跳过）。
    record, state = _online_state(store, scope_digest)
    assert record.dirty is False
    assert state.source_index
    assert record.state_version >= eval_registration.applied_state_version


# ---------------------------------------------------------------------------
# ⑧ 评审 S1：持久信封 round-trip 保真守门（B1 常设守门）
# ---------------------------------------------------------------------------


def test_ct_envelope_round_trip_persistence_fidelity() -> None:
    store = MemoryControlPlaneStore()
    settings = _settings()
    task_id, scope_digest = _ingress_task(store, settings=settings)
    evaluation, _, _ = _stack(store, settings=settings)
    event = _ct_event(
        event_id="evt_ct_roundtrip_1",
        event_type="tool_result_produced",
        task_id=task_id,
        call_id="call_roundtrip_1",
    )
    evaluation.evaluate(event, requesting_principal_id="cred_adapter_main")

    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    envelope = audit.evidence["ct_transient_facts"]
    payload = envelope["payload"]
    raw_bundle = payload["bundle"]

    # B1 守门核心：持久 bundle 未被通用 bound 碾平（无 "..." 占位），
    # model_validate 必成功，且保真裁决（S3）下无任何 scrub 改写痕迹。
    serialized = json.dumps(raw_bundle, sort_keys=True)
    assert '"..."' not in serialized
    assert "[redacted]" not in serialized
    rebuilt = TransientSecurityFacts.model_validate(raw_bundle)

    # digest 三角恒等：重建值 == 内嵌字段 == 信封引用。
    assert compute_bundle_digest(rebuilt) == payload["bundle_digest"]
    assert rebuilt.bundle_digest == payload["bundle_digest"]
    assert payload["bundle_digest"].startswith("sha256:")
    assert compute_overlay_digest(rebuilt) == payload["overlay_digest"]
    assert rebuilt.overlay_digest == payload["overlay_digest"]
    assert payload["overlay_digest"].startswith("sha256:")

    # 三类 facts 逐条字段等价：重建 bundle 的事实集与在线状态容器
    # （由同一 bundle 投影，delta_builder 排序去重口径）逐条 digest 相等。
    def _fact_digests(facts) -> set[str]:
        return {canonical_sha256(fact.model_dump(mode="json")) for fact in facts}

    _, state = _online_state(store, scope_digest)
    assert rebuilt.source_facts
    assert rebuilt.flow_facts
    assert _fact_digests(rebuilt.source_facts) == _fact_digests(state.source_index)
    assert _fact_digests(rebuilt.flow_facts) == _fact_digests(state.relevant_flows)
    assert _fact_digests(rebuilt.memory_facts) == _fact_digests(state.memory_index)
    # 身份字段等价。
    assert rebuilt.event_id == event.event_id
    assert rebuilt.scope_digest == scope_digest
    assert all(fact.scope_digest == scope_digest for fact in rebuilt.source_facts)


# ---------------------------------------------------------------------------
# ⑨ 评审 S2：backfill 正向重建（删登记 → replay 恢复，容器 digest 等价）
# ---------------------------------------------------------------------------


def test_backfill_positive_rebuild_restores_registration() -> None:
    store = MemoryControlPlaneStore()
    settings = _settings()
    task_id, scope_digest = _ingress_task(store, settings=settings)
    evaluation, state_service, _ = _stack(store, settings=settings)
    event = _ct_event(
        event_id="evt_ct_backfill_1",
        event_type="tool_result_produced",
        task_id=task_id,
        call_id="call_backfill_1",
    )
    first = evaluation.evaluate(event, requesting_principal_id="cred_adapter_main")
    access = state_service.store_access
    registration = access.get_projection(
        scope_digest,
        "runtime_observation",
        f"ct-facts:{event.event_id}",
        1,
        PROJECTOR_VERSION,
    )
    assert registration is not None
    _, state_before = _online_state(store, scope_digest)
    containers_before = _containers_dump(state_before)
    version_before = store.get_security_state(scope_digest).state_version

    # 模拟该五元组投影整体丢失：删投影登记 + 同步清除状态内
    # applied_projections 对应条目（否则 apply 会命中 in-state 登记的
    # rebase 前 digest → 误判 conflict；两者同删才是「登记丢失 →
    # backfill 正向重建」的良性形态）。
    key = (
        scope_digest,
        "runtime_observation",
        f"ct-facts:{event.event_id}",
        1,
        PROJECTOR_VERSION,
    )
    with store.security_state_lock:
        del store.projection_records[key]
    assert (
        access.get_projection(
            scope_digest,
            "runtime_observation",
            f"ct-facts:{event.event_id}",
            1,
            PROJECTOR_VERSION,
        )
        is None
    )
    incoming_key = projection_identity_key(
        scope_digest,
        "runtime_observation",
        f"ct-facts:{event.event_id}",
        1,
        PROJECTOR_VERSION,
    )
    record_now = store.get_security_state(scope_digest)
    assert record_now is not None
    state_now = OnlineSecurityState.model_validate(record_now.canonical_payload)
    stripped = state_now.model_copy(
        update={
            "applied_projections": [
                applied
                for applied in state_now.applied_projections
                if applied.projection_key != incoming_key
            ]
        }
    )
    assert len(stripped.applied_projections) == len(state_now.applied_projections) - 1
    assert store.cas_security_state(
        scope_digest,
        record_now.state_version,
        SecurityStateRecord(
            scope_digest=scope_digest,
            state_version=record_now.state_version,
            canonical_payload=stripped.model_dump(mode="json"),
            dirty=bool(stripped.dirty_domains),
            dirty_domains=list(stripped.dirty_domains),
            projector_version=PROJECTOR_VERSION,
            updated_at=utc_now_iso(),
        ),
    )

    replay = evaluation.evaluate(event, requesting_principal_id="cred_adapter_main")
    assert replay.policy_audit_id == first.policy_audit_id

    # 登记恢复且容器 digest 与原投影等价；身份派生的 projection_id
    # 恒等（五元组与 base 无关；delta_digest 含 base，rebase 后必然
    # 不同，不作等价断言）；补投影使投影计数 +1（state version 推进
    # 一步）。
    rebuilt_registration = access.get_projection(*key)
    assert rebuilt_registration is not None
    assert rebuilt_registration.delta_payload.get(
        "projection_id"
    ) == registration.delta_payload.get("projection_id")
    record_after, state_after = _online_state(store, scope_digest)
    assert _containers_dump(state_after) == containers_before
    assert record_after.dirty is False
    assert (
        record_after.state_version == version_before + 1
    ), "backfill 补投影应推进一次 state version（投影计数 +1）"


# ---------------------------------------------------------------------------
# ⑩ 评审 S4：backfill 负向分支与前缀 fail-closed 直驱用例
# ---------------------------------------------------------------------------


def _ct_backfill_audit(
    *,
    payload: dict,
    task_id: str | None,
    envelope_schema_version: str = "1.1",
    event_id: str | None = None,
) -> AuditEvent:
    metadata: dict[str, object] = {}
    if task_id is not None:
        metadata["task_id"] = task_id
    return AuditEvent(
        schema_version="0.4",
        record_type="policy_evaluation",
        trace_id="trace_ct_s4",
        event_type="tool_result_produced",
        summary="ct backfill negative fixture",
        decision="allow",
        risk_score=10,
        severity="low",
        blocked=False,
        reason="fixture",
        links=(
            {"event_id": event_id, "decision_id": f"decision:{event_id}"}
            if event_id is not None
            else {}
        ),
        metadata=metadata,
        evidence={
            "ct_transient_facts": {
                "schema_version": envelope_schema_version,
                "payload": payload,
            }
        },
    )


def test_backfill_accepts_legacy_1_0_ct_fact_1_without_overlay_digest() -> None:
    """A pre-Gate audit remains replayable after the fact-builder bump."""

    store = MemoryControlPlaneStore()
    settings = _settings()
    task_id, scope_digest = _ingress_task(store, settings=settings)
    _, state_service, ct_service = _stack(store, settings=settings)

    event_id = "evt_ct_legacy_backfill"
    source_record_id = f"ct-facts:{event_id}"
    source = SourceFact(
        source_id="tool_result:binding:legacy:call-legacy",
        scope_digest=scope_digest,
        source_type="tool_result",
        trust="untrusted",
        verification_state="unverified",
        origin="observed",
        authority="untrusted_claim",
        producer="ct-fact-builder",
        taints=["UNTRUSTED"],
        first_sequence=None,
        last_sequence=None,
        evidence_refs=[],
    )
    bare_bundle = TransientSecurityFacts(
        event_id=event_id,
        scope_digest=scope_digest,
        source_facts=(source,),
    )
    legacy_digest = compute_bundle_digest(
        bare_bundle,
        fact_builder_version=LEGACY_FACT_BUILDER_VERSION,
    )
    legacy_bundle = bare_bundle.model_copy(update={"bundle_digest": legacy_digest})
    raw_bundle = legacy_bundle.model_dump(mode="json")
    raw_bundle.pop("overlay_digest")
    legacy_payload = {
        "ct_delta_builder_version": "ct-delta-1",
        "commit_id": f"ct-commit:{event_id}",
        "bundle_digest": legacy_digest,
        "bundle": raw_bundle,
        "projection_id": "projection:legacy-fixture",
        "base_state_version_at_commit": 0,
        "source_identity": {
            "source_record_type": "runtime_observation",
            "source_record_id": source_record_id,
            "source_revision": 1,
        },
    }
    audit = _ct_backfill_audit(
        payload=legacy_payload,
        task_id=task_id,
        envelope_schema_version="1.0",
        event_id=event_id,
    )
    assert store.add_audit_event(audit) is True
    persisted = store.get_audit_event(audit.audit_id)
    assert persisted is not None

    ct_service.backfill(persisted)

    registration = state_service.store_access.get_projection(
        scope_digest,
        "runtime_observation",
        source_record_id,
        1,
        PROJECTOR_VERSION,
    )
    assert registration is not None
    _, state = _online_state(store, scope_digest)
    assert any(fact.source_id == source.source_id for fact in state.source_index)


def test_backfill_negative_branches_direct_drive(caplog) -> None:
    store = MemoryControlPlaneStore()
    settings = _settings()
    task_id, scope_digest = _ingress_task(store, settings=settings)
    evaluation, state_service, ct_service = _stack(store, settings=settings)
    # 先真实评估一次，取得合法 bundle 材料作为负向用例的改造基底。
    evaluation.evaluate(
        _ct_event(
            event_id="evt_ct_s4_base",
            event_type="tool_result_produced",
            task_id=task_id,
            call_id="call_s4_base",
        ),
        requesting_principal_id="cred_adapter_main",
    )
    base_audit = store.get_policy_evaluation_by_event_id("evt_ct_s4_base")
    assert base_audit is not None
    base_payload = copy.deepcopy(base_audit.evidence["ct_transient_facts"]["payload"])

    def _payload_with_source(source_record_id: str) -> dict:
        payload = copy.deepcopy(base_payload)
        payload["source_identity"]["source_record_id"] = source_record_id
        return payload

    access = state_service.store_access

    def _assert_not_registered(source_record_id: str) -> None:
        assert (
            access.get_projection(
                scope_digest,
                "runtime_observation",
                source_record_id,
                1,
                PROJECTOR_VERSION,
            )
            is None
        )

    def _assert_skip(fragment: str) -> None:
        assert any(
            fragment in record.message for record in caplog.records
        ), f"expected skip log containing {fragment!r}"

    # 用例 1：降级引用（_budget_dropped）跳过（跳过在身份解析前，
    # 断言登记总数不变 + 留痕）。
    caplog.clear()
    registrations_before = len(store.projection_records)
    with caplog.at_level(logging.INFO):
        ct_service.backfill(
            _ct_backfill_audit(
                payload={
                    "_budget_dropped": True,
                    "_envelope_sha256": "sha256:" + "ab" * 32,
                },
                task_id=task_id,
            )
        )
    _assert_skip("budget-degraded to a digest reference")
    assert len(store.projection_records) == registrations_before

    # 用例 2：bundle digest 失真（信封引用 ≠ 重建值）跳过。
    caplog.clear()
    bad_digest_payload = _payload_with_source("ct-facts:evt_ct_s4_digest")
    bad_digest_payload["bundle_digest"] = "sha256:" + "ff" * 32
    with caplog.at_level(logging.INFO):
        ct_service.backfill(
            _ct_backfill_audit(payload=bad_digest_payload, task_id=task_id)
        )
    _assert_skip("rebuilt bundle digest does not match")
    _assert_not_registered("ct-facts:evt_ct_s4_digest")

    # 用例 2b（评审 S6 分支）：内嵌 bundle_digest 与重算值不一致跳过。
    caplog.clear()
    embedded_payload = _payload_with_source("ct-facts:evt_ct_s4_embedded")
    embedded_payload["bundle"]["event_id"] = "evt_ct_s4_tampered"
    with caplog.at_level(logging.INFO):
        ct_service.backfill(
            _ct_backfill_audit(payload=embedded_payload, task_id=task_id)
        )
    _assert_skip("embedded bundle_digest mismatches")
    _assert_not_registered("ct-facts:evt_ct_s4_embedded")

    # 用例 2c：1.1 信封不得宣称旧 fact-builder 版本。
    caplog.clear()
    version_payload = _payload_with_source("ct-facts:evt_ct_s4_version")
    version_payload["fact_builder_version"] = LEGACY_FACT_BUILDER_VERSION
    with caplog.at_level(logging.INFO):
        ct_service.backfill(
            _ct_backfill_audit(payload=version_payload, task_id=task_id)
        )
    _assert_skip("unsupported or mismatched envelope/fact-builder version")
    _assert_not_registered("ct-facts:evt_ct_s4_version")

    # 用例 2d：source_id 不进历史 bundle digest，但进入 Gate A overlay
    # digest；只篡改注册身份也必须在 backfill 时被拒绝。
    caplog.clear()
    overlay_payload = _payload_with_source("ct-facts:evt_ct_s4_overlay")
    overlay_payload["bundle"]["source_facts"][0]["source_id"] += ":tampered"
    tampered_bundle = TransientSecurityFacts.model_validate(overlay_payload["bundle"])
    assert compute_bundle_digest(tampered_bundle) == overlay_payload["bundle_digest"]
    with caplog.at_level(logging.INFO):
        ct_service.backfill(
            _ct_backfill_audit(payload=overlay_payload, task_id=task_id)
        )
    _assert_skip("overlay digest does not match")
    _assert_not_registered("ct-facts:evt_ct_s4_overlay")

    # 用例 3：audit metadata 缺 task_id 跳过。
    caplog.clear()
    with caplog.at_level(logging.INFO):
        ct_service.backfill(
            _ct_backfill_audit(
                payload=_payload_with_source("ct-facts:evt_ct_s4_taskid"),
                task_id=None,
            )
        )
    _assert_skip("no task_id in audit metadata")
    _assert_not_registered("ct-facts:evt_ct_s4_taskid")

    # 用例 4：source_record_id 无 ct-facts: 前缀 → 拒绝不投影。
    caplog.clear()
    with caplog.at_level(logging.INFO):
        ct_service.backfill(
            _ct_backfill_audit(payload=_payload_with_source("evt-x"), task_id=task_id)
        )
    _assert_skip("ct-facts: prefix form check")
    _assert_not_registered("evt-x")
