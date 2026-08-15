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

契约依据：CT-PR-03 实施计划裁决 D1-D6 与 02 §3 commit→project 时序。
"""

from __future__ import annotations

import base64
import json
import logging

from agentguard_core import GuardEvent, utc_now_iso
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
from agentguard_core.security_context import PROJECTOR_VERSION, OnlineSecurityState
from guard_api.auth import AuthContext
from guard_api.models import TaskCreateRequest
from guard_api.security_state import SecurityStateService
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
from guard_api.storage.base import ProjectionIdentityRecord
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
            agent_id="main", user_task="ct wiring fixture"
        ),
        payload=payload,
        metadata=metadata,
    )


def _online_state(
    store: MemoryControlPlaneStore, scope_digest: str
):
    record = store.get_security_state(scope_digest)
    assert record is not None
    return record, OnlineSecurityState.model_validate(record.canonical_payload)


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
    evaluation.evaluate(
        memory_event, requesting_principal_id="cred_adapter_main"
    )

    # D4 commit 信封：随同一条 policy_evaluation 审计记录落盘；
    # D1 独立投影身份（runtime_observation + ct-facts:{event_id}）。
    for event_id in ("evt_ct_result_1", "evt_ct_memory_1"):
        audit = store.get_policy_evaluation_by_event_id(event_id)
        assert audit is not None
        envelope = audit.evidence["ct_transient_facts"]
        assert envelope["schema_version"] == "1.0"
        payload = envelope["payload"]
        assert payload["bundle_digest"].startswith("sha256:")
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
        evaluation, state_service, ct_service = _stack(
            store, settings=settings
        )
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


def test_replay_idempotent_short_circuit(monkeypatch) -> None:
    store = MemoryControlPlaneStore()
    settings = _settings()
    task_id, scope_digest = _ingress_task(store, settings=settings)
    evaluation, _, _ = _stack(store, settings=settings)
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

    monkeypatch.setattr(
        SecurityStateService, "project_committed", _counting
    )

    first = evaluation.evaluate(
        event, requesting_principal_id="cred_adapter_main"
    )
    count_after_first = calls["count"]
    assert count_after_first >= 1
    version_after_first = store.get_security_state(scope_digest).state_version

    replay = evaluation.evaluate(
        event, requesting_principal_id="cred_adapter_main"
    )
    # 响应不变（同幂等结果）。
    assert replay.policy_audit_id == first.policy_audit_id
    assert _normalized_response_dump(replay) == _normalized_response_dump(
        first
    )
    # 五元组幂等键短路：evaluation 与 CT 补投影均不重复进入 projector。
    assert calls["count"] == count_after_first
    assert (
        store.get_security_state(scope_digest).state_version
        == version_after_first
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
    state_service.store_access.mark_security_state_dirty(
        scope_digest, ["source"]
    )
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
    response = evaluation.evaluate(
        event, requesting_principal_id="cred_adapter_main"
    )
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
    response = evaluation.evaluate(
        event, requesting_principal_id="cred_adapter_main"
    )
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
