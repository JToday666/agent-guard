"""V21-09 T2：guard-api revoked_grant_ids 权威注入 + 四段式编排测试。

覆盖 T2 验收口径（memory 后端为主，postgres 后端环境可用则覆盖）：

- D3 revoked 只读入口：与 snapshot 同源同锁读取 online state record；
- flag off：pipeline 返回 None / 编排不触发、既有行为逐字节不变；
- flag on 有 task：Phase A 产出 snapshot V + revoked 真实集注入 assess；
- 事务窗口断言：read_snapshot/ensure_ready 在 evaluation_transaction
  外调用（S8 消除锚点）；
- stale 三类触发（state version 推进 / policy digest 变化 / task digest
  变化）→ degraded_stale_judgment 信封、legacy 响应不变；
- 无 task 引用 → degraded_no_snapshot（V21-08 语义保持）；
- 故障注入（read_snapshot 抛错）→ 降级不上抛。

契约依据：``12_决策记录_V21-09前置.md`` D1/D3/D4/D5/D8。
"""

from __future__ import annotations

import base64
from contextlib import contextmanager

import pytest

from agentguard_core import GuardEngine, GuardEvent, PolicyBundle, utc_now_iso
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.fingerprints import authorization_projection
from agentguard_core.actions.builder import build_action_ir
from agentguard_core.authority.models import (
    EvaluationClock,
    SecurityStateScope,
    TaskFact,
)
from agentguard_core.decisions.evidence import RequiredCheckPlan
from agentguard_core.decisions.evidence_builder import (
    REVALIDATION_COMPONENT_ID,
    build_decision_evidence_v21,
)
from agentguard_core.decisions.finalize import derive_final_decision_id
from agentguard_core.decisions.shadow import shadow_assess_with_coverage
from agentguard_core.events.payloads import (
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
)
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    OnlineSecurityState,
)
from guard_api.security_state import SecurityStateService
from guard_api.services import (
    ApprovalService,
    AuditService,
    EvaluationService,
    PolicyService,
    V21PipelineService,
    V21ShadowService,
)
from guard_api.services.v21_pipeline import PHASE_C_BASE_DRIFT_SKIPS
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import SecurityStateRecord, TaskFactRecord
from guard_api.storage.memory import MemoryControlPlaneStore

#: ≥32 字节的 base64url 测试密钥（形态与 V21-08 shadow 测试同口径）。
_TEST_SECRET = base64.urlsafe_b64encode(
    b"v21-09-pipeline-test-secret-material"
).decode("ascii")

_SCOPE_DIGEST = "hmac-sha256:" + "a9" * 32
_TASK_ID = "task_pipeline_fixture"


def _event(
    *,
    event_id: str = "evt_pipeline_1",
    task_id: str | None = None,
    call_id: str | None = None,
) -> GuardEvent:
    metadata: dict[str, object] = {}
    if task_id is not None:
        metadata["task_id"] = task_id
    tool_kwargs: dict[str, object] = {"name": "read_file"}
    if call_id is not None:
        # 确定性锚点：call_id 缺省工厂是 uuid，同输入同值类测试必须
        # 显式固定（ActionIR 身份并入 assessment 派生输入）。
        tool_kwargs["call_id"] = call_id
    return GuardEvent(
        event_id=event_id,
        event_type="tool_call_proposed",
        runtime="langgraph",
        trace_id="trace_pipeline_1",
        timestamp="2026-08-15T00:00:00+00:00",
        security_context=SecurityContext(agent_id="main", user_task="pipeline fixture"),
        payload=ToolCallPayload(tool=ToolDescriptor(**tool_kwargs)),
        metadata=metadata,
    )


def _task_fact(*, task_digest: str = "sha256:" + "cd" * 32, revision: int = 1) -> TaskFact:
    return TaskFact(
        task_id=_TASK_ID,
        scope_digest=_SCOPE_DIGEST,
        scope_key_id="scope_key_test",
        principal_id="principal_a",
        task_summary="pipeline fixture task",
        task_digest=task_digest,
        revision=revision,
        status="active",
        action_constraints=[],
        resource_constraints=[],
        destination_constraints=[],
        created_sequence=None,
        producer="guard_api_task_ingress",
        authority="authoritative",
        evidence_refs=[],
    )


def _commit_task_fact(
    store: MemoryControlPlaneStore,
    *,
    task_digest: str = "sha256:" + "cd" * 32,
    revision: int = 1,
) -> TaskFact:
    task_fact = _task_fact(task_digest=task_digest, revision=revision)
    store.create_task_fact(
        TaskFactRecord(
            task_fact=task_fact,
            canonical_payload=task_fact.model_dump(mode="json"),
            request_digest="sha256:" + "ef" * 32,
            expected_revision=revision - 1,
            created_at="2026-08-15T00:00:00Z",
        )
    )
    return task_fact


def _scope() -> SecurityStateScope:
    return SecurityStateScope(
        principal_id="principal_a",
        runtime="langgraph",
        runtime_binding_id="binding:principal_a",
        trace_id="trace_pipeline_1",
        session_id=None,
        scope_digest=_SCOPE_DIGEST,
    )


def _clock() -> EvaluationClock:
    return EvaluationClock(
        evaluated_at="2026-08-15T00:00:00+00:00", clock_version="test-clock"
    )


def _plan() -> RequiredCheckPlan:
    return RequiredCheckPlan(
        plan_id="v21-09-pipeline-test:plan",
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
        reason_codes=["v21-09:fixture"],
    )


def _seed_state_with_revoked(
    service: SecurityStateService,
    *,
    revoked_grant_ids: list[str],
    state_version: int = 1,
) -> SecurityStateRecord:
    """先 ensure_ready 初始化空态，再 CAS 推进到携带 revoked 集的版本。"""

    record = service.store_access.get_security_state(_SCOPE_DIGEST)
    if record is None:
        service.ensure_ready(_SCOPE_DIGEST)
        record = service.store_access.get_security_state(_SCOPE_DIGEST)
    assert record is not None
    state = OnlineSecurityState.model_validate(record.canonical_payload)
    updated_state = state.model_copy(
        update={
            "revoked_grant_ids": list(revoked_grant_ids),
            "state_version": state_version,
        }
    )
    updated_record = SecurityStateRecord(
        scope_digest=_SCOPE_DIGEST,
        state_version=state_version,
        canonical_payload=updated_state.model_dump(mode="json"),
        dirty=False,
        dirty_domains=[],
        projector_version=PROJECTOR_VERSION,
        updated_at=utc_now_iso(),
    )
    assert service.store_access.cas_security_state(
        _SCOPE_DIGEST, record.state_version, updated_record
    )
    return updated_record


def _snapshot_kwargs(**overrides):
    kwargs = {
        "scope": _scope(),
        "task_fact_head": _task_fact(),
        "evaluation_clock": _clock(),
        "policy_revision": "rev-1",
        "policy_digest": "sha256:policy_fixture",
        "plan": _plan(),
    }
    kwargs.update(overrides)
    return kwargs


# ---------------------------------------------------------------------------
# D3：revoked_grant_ids 只读入口（同源同锁，不新增存储写面）
# ---------------------------------------------------------------------------


def test_read_revoked_grant_ids_absent_state_returns_empty() -> None:
    service = SecurityStateService(MemoryControlPlaneStore())
    assert service.store_access.read_revoked_grant_ids(_SCOPE_DIGEST) == []


def test_read_revoked_grant_ids_returns_seeded_set() -> None:
    service = SecurityStateService(MemoryControlPlaneStore())
    _seed_state_with_revoked(service, revoked_grant_ids=["grant:1", "grant:2"])
    assert service.store_access.read_revoked_grant_ids(_SCOPE_DIGEST) == [
        "grant:1",
        "grant:2",
    ]


def test_read_snapshot_with_revoked_same_source_same_version() -> None:
    """snapshot 与 revoked 集同源同锁：同版本、同一次读取路径。"""

    service = SecurityStateService(MemoryControlPlaneStore())
    seeded = _seed_state_with_revoked(
        service, revoked_grant_ids=["grant:revoked_a"]
    )

    snapshot, revoked = service.read_snapshot_with_revoked(
        _SCOPE_DIGEST, **_snapshot_kwargs()
    )
    assert revoked == ["grant:revoked_a"]
    # 同源锚点：snapshot 的 state_version 与 revoked 所在记录版本一致。
    assert snapshot.state_version == seeded.state_version
    # 与既有 read_snapshot 行为逐字一致（同一 snapshot 身份）。
    plain = service.read_snapshot(_SCOPE_DIGEST, **_snapshot_kwargs())
    assert plain.snapshot_id == snapshot.snapshot_id
    assert plain.snapshot_digest == snapshot.snapshot_digest


def test_read_snapshot_with_revoked_rebuild_path_stays_same_source() -> None:
    """dirty 态先 bounded rebuild：revoked 仍取自 rebuild 后的同源 state。"""

    service = SecurityStateService(MemoryControlPlaneStore())
    _seed_state_with_revoked(service, revoked_grant_ids=["grant:r1"])
    service.store_access.mark_security_state_dirty(_SCOPE_DIGEST, ["behavior"])

    snapshot, revoked = service.read_snapshot_with_revoked(
        _SCOPE_DIGEST, **_snapshot_kwargs()
    )
    # rebuild 以投影登记为输入；本 fixture 无登记行，重建态为空水位，
    # revoked 集随重建态同源透出（不残留旧版本内容）。
    assert isinstance(revoked, list)
    record = service.store_access.get_security_state(_SCOPE_DIGEST)
    assert record is not None
    assert snapshot.state_version == record.state_version


# ---------------------------------------------------------------------------
# D8：evidence_builder revalidation stale 参数（缺省逐字节回归）
# ---------------------------------------------------------------------------

_STALE_SECRET = b"v21-09-evidence-builder-test-secret-material"


def _degraded_outcome():
    """snapshot 缺态降级路径的 assessment + coverage（纯 core 构件）。"""

    return shadow_assess_with_coverage(
        _event(),
        PolicyBundle(),
        None,
        server_secret=_STALE_SECRET,
    )


def test_evidence_builder_stale_default_byte_identical() -> None:
    """缺省空表参数 → 行为与 V21-08 逐字节一致。"""

    outcome = _degraded_outcome()
    baseline = build_decision_evidence_v21(
        outcome.assessment,
        legacy_decision="allow",
        snapshot_id="v21-08:snapshot_absent",
        state_version=0,
        coverage=outcome.coverage,
    )
    with_default = build_decision_evidence_v21(
        outcome.assessment,
        legacy_decision="allow",
        snapshot_id="v21-08:snapshot_absent",
        state_version=0,
        coverage=outcome.coverage,
        revalidation_stale_reason_codes=(),
    )
    assert with_default == baseline
    assert with_default.model_dump(mode="json") == baseline.model_dump(
        mode="json"
    )


def _present_outcome():
    """snapshot 在场路径的 assessment + coverage（无 shadow 组件降级）。"""

    service = SecurityStateService(MemoryControlPlaneStore())
    _seed_state_with_revoked(service, revoked_grant_ids=[])
    snapshot, _revoked = service.read_snapshot_with_revoked(
        _SCOPE_DIGEST, **_snapshot_kwargs()
    )
    return shadow_assess_with_coverage(
        _event(),
        PolicyBundle(),
        snapshot,
        server_secret=_STALE_SECRET,
    )


def test_evidence_builder_stale_registers_degraded_stale_judgment() -> None:
    """非空 stale codes → D8 受控类目 + failure_kind=stale 降级登记。"""

    outcome = _present_outcome()
    evidence = build_decision_evidence_v21(
        outcome.assessment,
        legacy_decision="allow",
        snapshot_id="v21-04-snapshot:fixture",
        state_version=3,
        coverage=outcome.coverage,
        revalidation_stale_reason_codes=["v21-09:stale_state_version"],
    )
    assert evidence.divergence_category == "degraded_stale_judgment"
    assert (
        f"v21-09-revalidation-stale:{outcome.assessment.event_id}"
        in evidence.degradation_ids
    )
    # shadow 期官方决策者恒 legacy：stale 不改变 final_decision。
    assert evidence.final_decision == "allow"
    assert evidence.legacy_decision == "allow"
    assert evidence.mode == "shadow"


def test_evidence_builder_stale_priority_after_shadow_degradation() -> None:
    """D8 优先序：shadow 组件降级先于 stale（归因更根本）。"""

    outcome = _degraded_outcome()  # snapshot 缺态 → shadow 组件降级在场
    evidence = build_decision_evidence_v21(
        outcome.assessment,
        legacy_decision="deny",
        snapshot_id="v21-08:snapshot_absent",
        state_version=0,
        coverage=outcome.coverage,
        revalidation_stale_reason_codes=["v21-09:stale_task_digest"],
    )
    assert evidence.divergence_category == "degraded_no_snapshot"
    # stale 降级仍如实登记（不静默丢失，D4 同源口径）。
    assert any(
        degradation_id.startswith("v21-09-revalidation-stale:")
        for degradation_id in evidence.degradation_ids
    )
    assert REVALIDATION_COMPONENT_ID != "v21-08-shadow"


# ---------------------------------------------------------------------------
# 四段式 pipeline（D4）：Phase A 事务外 + Phase B 短事务消费 + S8 消除
# ---------------------------------------------------------------------------


def _pipeline_settings(
    *, enabled: bool = True, secret: str | None = _TEST_SECRET
) -> GuardApiSettings:
    return GuardApiSettings(
        control_token="control-secret",
        storage_backend="memory",
        v21_shadow_enabled=enabled,
        v21_shadow_server_secret=secret,
    )


def _pipeline_service(
    store: MemoryControlPlaneStore | None = None,
    *,
    settings: GuardApiSettings | None = None,
) -> tuple[V21PipelineService, MemoryControlPlaneStore]:
    store = store if store is not None else MemoryControlPlaneStore()
    state_service = SecurityStateService(store)
    policy_service = PolicyService(store=store)
    pipeline = V21PipelineService(
        settings=settings or _pipeline_settings(),
        store=store,
        state_service=state_service,
        policy_service=policy_service,
    )
    return pipeline, store


def _evaluation_stack(
    store: MemoryControlPlaneStore, *, settings: GuardApiSettings
) -> tuple[EvaluationService, V21PipelineService]:
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
    evaluation = EvaluationService(
        policy_service=policy_service,
        audit_service=AuditService(store=store),
        approval_service=ApprovalService(store=store, settings=settings),
        v21_shadow_service=shadow,
        v21_pipeline=pipeline,
    )
    return evaluation, pipeline


def _envelope_payload(envelope: dict) -> dict:
    """取 decision_v21 信封 payload（并断言 01 §28 信封形状）。

    兼容两种形态：build 侧完整信封 ``{"decision_v21": {...}}``；
    审计落盘侧外层键由 ``evidence.decision_v21`` 承载，存储值即内层
    ``{"schema_version", "payload"}``。
    """

    if set(envelope) == {"decision_v21"}:
        inner = envelope["decision_v21"]
    else:
        inner = envelope
    assert set(inner) == {"schema_version", "payload"}
    assert inner["schema_version"] == "2.1"
    return inner["payload"]


def _normalized_response_dump(response) -> dict:
    """剔除随机/实例相关 id 后的响应 dump（官方决策字段逐字可比）。"""

    dump = response.model_dump(mode="json")
    dump.pop("policy_audit_id", None)
    # decision_id 含随机分量（同语义不同实例），不参与逐字对照。
    dump.get("decision", {}).pop("decision_id", None)
    if dump.get("approval"):
        dump["approval"].pop("approval_id", None)
    return dump


def test_pipeline_flag_off_returns_none_without_io(monkeypatch) -> None:
    pipeline, store = _pipeline_service(settings=_pipeline_settings(enabled=False))
    assert pipeline.enabled is False

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("flag off must not touch storage or state")

    monkeypatch.setattr(MemoryControlPlaneStore, "get_task_fact", _forbidden)
    monkeypatch.setattr(SecurityStateService, "ensure_ready", _forbidden)
    monkeypatch.setattr(
        SecurityStateService, "read_snapshot_with_revoked", _forbidden
    )
    assert store is not None
    assert pipeline.run_phase_a(_event(task_id=_TASK_ID)) is None


def test_pipeline_flag_on_without_secret_returns_none() -> None:
    pipeline, _ = _pipeline_service(settings=_pipeline_settings(secret=None))
    assert pipeline.enabled is False
    assert pipeline.run_phase_a(_event()) is None


def test_pipeline_phase_a_with_task_snapshot_and_revoked_injection(
    monkeypatch,
) -> None:
    """flag on 有 task：Phase A 产出 snapshot V + revoked 真实集注入 assess。"""

    pipeline, store = _pipeline_service()
    _commit_task_fact(store)
    service = SecurityStateService(store)
    _seed_state_with_revoked(service, revoked_grant_ids=["grant:revoked_a"])

    captured: dict[str, object] = {}
    original = shadow_assess_with_coverage

    def _spy(event, policies, snapshot, **kwargs):
        captured["revoked"] = list(kwargs.get("revoked_grant_ids", ()))
        captured["snapshot"] = snapshot
        return original(event, policies, snapshot, **kwargs)

    monkeypatch.setattr(
        "guard_api.services.v21_pipeline.shadow_assess_with_coverage", _spy
    )
    materials = pipeline.run_phase_a(_event(task_id=_TASK_ID))
    assert materials is not None
    assert materials.degraded_kind is None
    assert materials.snapshot is not None
    assert materials.state_version == materials.snapshot.state_version
    assert materials.revoked_grant_ids == ["grant:revoked_a"]
    # D3 真实注入：assess 收到的 revoked 是同源同锁权威集。
    assert captured["revoked"] == ["grant:revoked_a"]
    assert captured["snapshot"] is materials.snapshot
    # D5 clock 正式化。
    assert materials.clock.clock_version == "v21-09"
    assert materials.clock.evaluated_at == _event().timestamp
    # Phase A 单跑 legacy 决策在材料中（Phase B 不双跑）。
    assert materials.decision.decision in ("allow", "ask", "deny")


def test_pipeline_phase_a_no_task_reference_degraded_no_snapshot() -> None:
    pipeline, store = _pipeline_service()
    materials = pipeline.run_phase_a(_event())
    assert materials is not None
    assert materials.degraded_kind == "snapshot_absent"
    assert materials.snapshot is None
    assert materials.task_id is None
    # V21-08 语义保持：无 task 引用不得创建任何安全状态行。
    assert store.get_security_state(_SCOPE_DIGEST) is None
    outcome = pipeline.build_phase_b(_event(), materials)
    assert outcome is not None
    payload = _envelope_payload(outcome.envelope)
    assert payload["divergence_category"] == "degraded_no_snapshot"
    assert payload["snapshot_id"] == "v21-08:snapshot_absent"
    assert payload["final_decision"] == materials.decision.decision


def test_pipeline_phase_a_task_claim_without_fact_degraded() -> None:
    pipeline, _ = _pipeline_service()
    materials = pipeline.run_phase_a(_event(task_id="task_missing"))
    assert materials is not None
    assert materials.degraded_kind == "snapshot_absent"
    assert materials.task_id == "task_missing"
    outcome = pipeline.build_phase_b(_event(task_id="task_missing"), materials)
    assert outcome is not None
    assert (
        _envelope_payload(outcome.envelope)["divergence_category"]
        == "degraded_no_snapshot"
    )


def test_pipeline_phase_a_snapshot_read_failure_component_failure(
    monkeypatch,
) -> None:
    """故障注入：read_snapshot 抛错 → 降级不上抛（component_failure）。"""

    pipeline, store = _pipeline_service()
    _commit_task_fact(store)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated snapshot read failure")

    monkeypatch.setattr(
        SecurityStateService, "read_snapshot_with_revoked", _boom
    )
    event = _event(task_id=_TASK_ID)
    materials = pipeline.run_phase_a(event)
    assert materials is not None
    assert materials.degraded_kind == "component_failure"
    assert materials.snapshot is None
    outcome = pipeline.build_phase_b(event, materials)
    assert outcome is not None
    assert (
        _envelope_payload(outcome.envelope)["divergence_category"]
        == "degraded_component_failure"
    )


def test_pipeline_phase_b_valid_when_no_drift() -> None:
    pipeline, store = _pipeline_service()
    _commit_task_fact(store)
    event = _event(task_id=_TASK_ID)
    materials = pipeline.run_phase_a(event)
    assert materials is not None and materials.snapshot is not None
    outcome = pipeline.build_phase_b(event, materials)
    assert outcome is not None
    assert outcome.revalidation.status == "valid"
    payload = _envelope_payload(outcome.envelope)
    assert payload["divergence_category"] != "degraded_stale_judgment"
    assert payload["snapshot_id"] == materials.snapshot.snapshot_id
    assert payload["final_decision"] == materials.decision.decision


def test_pipeline_phase_b_stale_state_version() -> None:
    """stale 触发一：Phase A 后 state version 推进。"""

    pipeline, store = _pipeline_service()
    _commit_task_fact(store)
    event = _event(task_id=_TASK_ID)
    materials = pipeline.run_phase_a(event)
    assert materials is not None and materials.scope_digest is not None

    record = store.get_security_state(materials.scope_digest)
    assert record is not None
    state = OnlineSecurityState.model_validate(record.canonical_payload)
    bumped = state.model_copy(
        update={"state_version": record.state_version + 1}
    )
    assert store.cas_security_state(
        materials.scope_digest,
        record.state_version,
        SecurityStateRecord(
            scope_digest=materials.scope_digest,
            state_version=record.state_version + 1,
            canonical_payload=bumped.model_dump(mode="json"),
            dirty=False,
            dirty_domains=[],
            projector_version=PROJECTOR_VERSION,
            updated_at=utc_now_iso(),
        ),
    )

    outcome = pipeline.build_phase_b(event, materials)
    assert outcome is not None
    assert outcome.revalidation.status == "stale"
    assert "v21-09:stale_state_version" in outcome.revalidation.reason_codes
    # 版本漂移必然连带 snapshot digest 漂移（哨兵口径）。
    assert "v21-09:stale_snapshot_digest" in outcome.revalidation.reason_codes
    payload = _envelope_payload(outcome.envelope)
    assert payload["divergence_category"] == "degraded_stale_judgment"
    # legacy 官方决策不受 stale 影响。
    assert payload["final_decision"] == materials.decision.decision
    assert any(
        degradation_id.startswith("v21-09-revalidation-stale:")
        for degradation_id in payload["degradation_ids"]
    )


def test_pipeline_phase_b_stale_policy_digest() -> None:
    """stale 触发二：policy digest 变化（轮换 policy snapshot）。"""

    pipeline, store = _pipeline_service()
    _commit_task_fact(store)
    event = _event(task_id=_TASK_ID)
    materials = pipeline.run_phase_a(event)
    assert materials is not None

    store.save_policy_snapshot(
        PolicyBundle(version="p1-rotated"), expected_revision=0
    )
    outcome = pipeline.build_phase_b(event, materials)
    assert outcome is not None
    assert outcome.revalidation.status == "stale"
    assert "v21-09:stale_policy_digest" in outcome.revalidation.reason_codes
    assert (
        _envelope_payload(outcome.envelope)["divergence_category"]
        == "degraded_stale_judgment"
    )


def test_pipeline_phase_b_stale_task_digest() -> None:
    """stale 触发三：task digest 变化（TaskFact 新 revision 异 digest）。"""

    pipeline, store = _pipeline_service()
    _commit_task_fact(store)
    event = _event(task_id=_TASK_ID)
    materials = pipeline.run_phase_a(event)
    assert materials is not None

    _commit_task_fact(store, task_digest="sha256:" + "aa" * 32, revision=2)
    outcome = pipeline.build_phase_b(event, materials)
    assert outcome is not None
    assert outcome.revalidation.status == "stale"
    assert "v21-09:stale_task_digest" in outcome.revalidation.reason_codes
    assert (
        _envelope_payload(outcome.envelope)["divergence_category"]
        == "degraded_stale_judgment"
    )


# ---------------------------------------------------------------------------
# D11：finalize 确定性引用（valid 分支产出；stale/降级/flag off 不产）
# ---------------------------------------------------------------------------

_FINALIZE_REFERENCE_KEYS = (
    "v21_final_decision_id",
    "v21_final_decision_digest",
)


def _finalize_references(metadata: dict) -> dict:
    return {
        key: value
        for key, value in metadata.items()
        if key in _FINALIZE_REFERENCE_KEYS
    }


def test_pipeline_phase_b_finalize_reference_valid_only() -> None:
    """D11：valid 分支产确定性引用（同输入同值）；降级路径恒 None。"""

    pipeline, store = _pipeline_service()
    _commit_task_fact(store)
    event = _event(task_id=_TASK_ID)
    materials = pipeline.run_phase_a(event)
    assert materials is not None and materials.snapshot is not None

    outcome = pipeline.build_phase_b(event, materials)
    assert outcome is not None and outcome.revalidation.status == "valid"
    # 引用与显式派生口径同源（derive_final_decision_id / 产物 digest）。
    assert outcome.final_decision_id == derive_final_decision_id(
        materials.assessment
    )
    expected_digest = canonical_sha256(
        GuardEngine()
        .finalize(materials.assessment)
        .model_dump(mode="json")
    )
    assert outcome.final_decision_digest == expected_digest
    # 确定性：同输入重复调用同值。
    repeat = pipeline.build_phase_b(event, materials)
    assert repeat is not None
    assert repeat.final_decision_id == outcome.final_decision_id
    assert repeat.final_decision_digest == outcome.final_decision_digest

    # snapshot 缺态降级路径：不产引用。
    degraded = pipeline.run_phase_a(_event(event_id="evt_phase_b_notask"))
    assert degraded is not None and degraded.snapshot is None
    degraded_outcome = pipeline.build_phase_b(
        _event(event_id="evt_phase_b_notask"), degraded
    )
    assert degraded_outcome is not None
    assert degraded_outcome.final_decision_id is None
    assert degraded_outcome.final_decision_digest is None


def test_pipeline_e2e_valid_finalize_reference_deterministic() -> None:
    """D11：flag on valid 路径审计 metadata 含两个确定性键（同输入同值）。"""

    def _run_once() -> dict:
        store = MemoryControlPlaneStore()
        _commit_task_fact(store)
        evaluation_service, _ = _evaluation_stack(
            store, settings=_pipeline_settings()
        )
        event = _event(
            event_id="evt_e2e_finalize",
            task_id=_TASK_ID,
            call_id="call_e2e_finalize",
        )
        evaluation_service.evaluate(
            event, requesting_principal_id="principal_a"
        )
        audit = store.get_policy_evaluation_by_event_id(event.event_id)
        assert audit is not None
        return dict(audit.metadata)

    first = _run_once()
    references = _finalize_references(first)
    assert set(references) == set(_FINALIZE_REFERENCE_KEYS)
    assert references["v21_final_decision_id"].startswith("dec:")
    assert references["v21_final_decision_digest"].startswith("sha256:")
    # 既有同源键不受影响。
    assert "request_digest" in first and "policy_digest" in first
    # 同输入必同值（replay 可复算锚点）。
    assert _finalize_references(_run_once()) == references


def test_pipeline_flag_off_metadata_keyset_byte_identical() -> None:
    """D11：flag off 时审计 metadata 与无 pipeline 注入逐字节一致。"""

    event = _event(
        event_id="evt_finalize_flag_off",
        task_id=_TASK_ID,
        call_id="call_finalize_flag_off",
    )
    settings = _pipeline_settings(enabled=False)

    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, pipeline = _evaluation_stack(store, settings=settings)
    assert pipeline.enabled is False
    evaluation_service.evaluate(event, requesting_principal_id="principal_a")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    assert _finalize_references(audit.metadata) == {}

    # 基线：完全无 pipeline/shadow 注入的同构栈（接线前形态）。
    baseline_store = MemoryControlPlaneStore()
    _commit_task_fact(baseline_store)
    baseline_policy = PolicyService(store=baseline_store)
    baseline_service = EvaluationService(
        policy_service=baseline_policy,
        audit_service=AuditService(store=baseline_store),
        approval_service=ApprovalService(
            store=baseline_store, settings=settings
        ),
    )
    baseline_service.evaluate(event, requesting_principal_id="principal_a")
    baseline_audit = baseline_store.get_policy_evaluation_by_event_id(
        event.event_id
    )
    assert baseline_audit is not None
    # 键集逐字节不变：flag off 不引入任何新 metadata 键。
    assert audit.metadata == baseline_audit.metadata


def test_pipeline_e2e_stale_no_finalize_reference(monkeypatch) -> None:
    """D11：stale 路径不产 finalize 引用（metadata 键集不变）。"""

    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )

    original_read = SecurityStateService.read_snapshot_with_revoked

    def _read_then_rotate(self, scope_digest, **kwargs):
        result = original_read(self, scope_digest, **kwargs)
        # Phase A 读后轮换 policy snapshot → Phase B revalidate stale。
        store.save_policy_snapshot(
            PolicyBundle(version="p1-rotated"), expected_revision=0
        )
        return result

    monkeypatch.setattr(
        SecurityStateService, "read_snapshot_with_revoked", _read_then_rotate
    )
    event = _event(event_id="evt_e2e_finalize_stale", task_id=_TASK_ID)
    evaluation_service.evaluate(event, requesting_principal_id="principal_a")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    payload = _envelope_payload(audit.evidence["decision_v21"])
    assert payload["divergence_category"] == "degraded_stale_judgment"
    # stale 不产 finalize 引用：两键均缺席，既有同源键不受影响。
    assert _finalize_references(audit.metadata) == {}
    assert "request_digest" in audit.metadata
    assert "policy_digest" in audit.metadata


def test_pipeline_policy_revision_frozen_at_phase_a(monkeypatch) -> None:
    """W1：审计 policy_revision 恒等于 Phase A 冻结值（同源同时点）。

    并发策略滚动场景：Phase A 冻结后、事务内落盘前 policy 滚到
    新 revision；审计记录不得出现 "revision N+1 × digest(bundle N)"
    矛盾组合（事务内不再重读 current_snapshot_record，S8 口径）。
    """

    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    seeded = store.save_policy_snapshot(
        PolicyBundle(version="p1-seeded"), expected_revision=0
    )
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )

    original_read = SecurityStateService.read_snapshot_with_revoked

    def _read_then_roll(self, scope_digest, **kwargs):
        result = original_read(self, scope_digest, **kwargs)
        # 模拟并发策略滚动：Phase A 冻结时点后 policy 推进新 revision。
        store.save_policy_snapshot(
            PolicyBundle(version="p1-rolled"), expected_revision=seeded.revision
        )
        return result

    monkeypatch.setattr(
        SecurityStateService, "read_snapshot_with_revoked", _read_then_roll
    )
    event = _event(event_id="evt_e2e_w1", task_id=_TASK_ID)
    evaluation_service.evaluate(event, requesting_principal_id="principal_a")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    # 前置：并发滚动确实发生（当前链头已是新 revision）。
    rolled = store.get_policy_snapshot_record()
    assert rolled is not None and rolled.revision == seeded.revision + 1
    # 同源同时点：revision 与 digest 均取 Phase A 冻结值（bundle N ×
    # revision N），无矛盾组合。
    policy_evidence = audit.evidence["policy"]
    assert policy_evidence["revision"] == seeded.revision
    assert policy_evidence["canonical_digest"] == canonical_sha256(
        PolicyBundle(version="p1-seeded").model_dump(mode="json")
    )


# ---------------------------------------------------------------------------
# Phase C：S1 base 漂移跳过结构化留痕 / S2 缺态哨兵统一为 -1
# ---------------------------------------------------------------------------


def test_pipeline_phase_c_base_drift_skip_structured_trace(caplog) -> None:
    """S1：base 漂移跳过必产结构化留痕（计数器 + 日志键），不置脏、
    不投影、不上抛；D9 补投影不可达，V21-10 对账承接（docstring 口径）。"""

    pipeline, store = _pipeline_service()
    _commit_task_fact(store)
    event = _event(task_id=_TASK_ID)
    materials = pipeline.run_phase_a(event)
    assert materials is not None and materials.scope_digest is not None
    outcome = pipeline.build_phase_b(event, materials)
    assert outcome is not None
    plan = pipeline.prepare_phase_c(outcome)
    assert plan is not None

    # Phase B→C 窗口内并发投影推进 base（其他事件先行落盘）。
    record = store.get_security_state(materials.scope_digest)
    assert record is not None
    state = OnlineSecurityState.model_validate(record.canonical_payload)
    bumped = state.model_copy(
        update={"state_version": record.state_version + 1}
    )
    assert store.cas_security_state(
        materials.scope_digest,
        record.state_version,
        SecurityStateRecord(
            scope_digest=materials.scope_digest,
            state_version=record.state_version + 1,
            canonical_payload=bumped.model_dump(mode="json"),
            dirty=False,
            dirty_domains=[],
            projector_version=PROJECTOR_VERSION,
            updated_at=utc_now_iso(),
        ),
    )

    before = PHASE_C_BASE_DRIFT_SKIPS["count"]
    with caplog.at_level("WARNING", logger="guard_api.services.v21_pipeline"):
        pipeline.run_phase_c(plan)  # 绝不上抛。
    # 结构化留痕：计数器增一 + 日志含结构化键。
    assert PHASE_C_BASE_DRIFT_SKIPS["count"] == before + 1
    messages = "\n".join(caplog.messages)
    assert "v21_phase_c_skip_reason=base_drift" in messages
    assert "v21_phase_c_skip_total=" in messages
    # fail-closed 不置脏、不推进版本（跳过分支不再触碰存储）。
    after = store.get_security_state(materials.scope_digest)
    assert after is not None
    assert after.state_version == record.state_version + 1
    assert after.dirty is False and after.dirty_domains == []


def test_pipeline_phase_c_missing_state_sentinel_minus_one(
    monkeypatch, caplog
) -> None:
    """S2：Phase C 缺态哨兵统一为 -1——不与任何真实 state_version
    （empty_online_state 初始版本 0）碰撞，缺态必然 fail-closed 跳过
    而非误投影。"""

    pipeline, store = _pipeline_service()
    _commit_task_fact(store)
    event = _event(task_id=_TASK_ID)
    materials = pipeline.run_phase_a(event)
    assert materials is not None
    outcome = pipeline.build_phase_b(event, materials)
    assert outcome is not None
    plan = pipeline.prepare_phase_c(outcome)
    assert plan is not None
    assert plan.delta.base_state_version >= 0

    # 模拟 ensure_ready 后仍缺态的极端窗口。
    monkeypatch.setattr(SecurityStateService, "ensure_ready", lambda *_a, **_k: None)
    monkeypatch.setattr(
        MemoryControlPlaneStore, "get_security_state", lambda *_a, **_k: None
    )

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("missing state must fail-closed, never project")

    monkeypatch.setattr(SecurityStateService, "project_committed", _forbidden)

    before = PHASE_C_BASE_DRIFT_SKIPS["count"]
    with caplog.at_level("WARNING", logger="guard_api.services.v21_pipeline"):
        pipeline.run_phase_c(plan)
    assert PHASE_C_BASE_DRIFT_SKIPS["count"] == before + 1
    assert "v21_phase_c_skip_reason=base_drift" in "\n".join(caplog.messages)


# ---------------------------------------------------------------------------
# S5：fingerprint 间接覆盖契约（task_digest 收敛口径，D11 登记）
# ---------------------------------------------------------------------------


def test_fingerprint_indirect_coverage_contract() -> None:
    """S5 契约：authorization_fingerprint 经 task_digest 间接覆盖。

    派生输入白名单 ⊆ {event 身份, scope_digest, task 身份}；task
    身份与 task_digest 同源（snapshot.task），故 task 修订必同时
    改变 task_digest 与 fingerprint——revalidate 只比 task_digest
    即可承接 fingerprint 漂移（revalidation.py 收敛口径锚点）。
    """

    # 锚点一：派生输入白名单钉死，且逐键归入锚定集合（与 shadow
    # assess 同源构造：build_action_ir + 权威 task/scope 注入）。
    probe_ir = build_action_ir(
        _event(task_id=_TASK_ID),
        server_secret=b"v21-09-pipeline-test-secret-material",
        task_id=_TASK_ID,
        task_revision=1,
        scope_digest=_SCOPE_DIGEST,
        principal_id="principal_a",
        runtime_binding_id="binding:principal_a",
    )
    probe_projection = authorization_projection(probe_ir)
    event_identity_keys = {
        "schema_version",
        "action_type",
        "resources",
        "destinations",
        "security_arguments",
        "effects",
        "argument_digest",
    }
    scope_keys = {"principal_id", "runtime_binding_id", "scope_digest"}
    task_identity_keys = {"task_id", "task_revision"}
    assert set(probe_projection) == (
        event_identity_keys | scope_keys | task_identity_keys
    )

    # 锚点二：task 修订（新 revision + 新 task_digest）必同时改变
    # task_digest 与 authorization_fingerprint（event/scope/policy 不变）。
    def _assessment_for(task_digest: str, revision: int):
        pipeline, store = _pipeline_service()
        # 逐 revision 建链：目标 revision 落目标 digest（前置 revision
        # 用异 digest 占位，模拟真实修订历史）。
        for rev in range(1, revision):
            _commit_task_fact(
                store, task_digest="sha256:" + "bb" * 32, revision=rev
            )
        _commit_task_fact(store, task_digest=task_digest, revision=revision)
        event = _event(
            event_id="evt_fingerprint_contract", task_id=_TASK_ID
        )
        materials = pipeline.run_phase_a(event)
        assert materials is not None and materials.snapshot is not None
        return materials.assessment

    assessment_v1 = _assessment_for("sha256:" + "cd" * 32, revision=1)
    assessment_v2 = _assessment_for("sha256:" + "d2" * 32, revision=2)
    assert assessment_v1.task_digest != assessment_v2.task_digest
    assert (
        assessment_v1.authorization_fingerprint
        != assessment_v2.authorization_fingerprint
    )


# ---------------------------------------------------------------------------
# S8 消除锚点：事务窗口内无 snapshot I/O（evaluate 端到端）
# ---------------------------------------------------------------------------


def test_pipeline_transaction_window_excludes_snapshot_io(monkeypatch) -> None:
    """D4/S8：read_snapshot/ensure_ready 在 evaluation_transaction 外，
    revalidate 在事务内（短事务只消费 Phase A 材料）。"""

    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )

    in_tx = {"value": False}
    original_tx = MemoryControlPlaneStore.evaluation_transaction

    @contextmanager
    def _tracking_tx(self, event_id):
        in_tx["value"] = True
        try:
            with original_tx(self, event_id):
                yield
        finally:
            in_tx["value"] = False

    # slots 对象实例属性只读，事务窗口标记需类级 patch。
    monkeypatch.setattr(
        MemoryControlPlaneStore, "evaluation_transaction", _tracking_tx
    )

    calls: dict[str, list[bool]] = {"read": [], "ensure": [], "revalidate": []}
    original_read = SecurityStateService.read_snapshot_with_revoked

    def _read_spy(self, *args, **kwargs):
        calls["read"].append(in_tx["value"])
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(
        SecurityStateService, "read_snapshot_with_revoked", _read_spy
    )
    original_ensure = SecurityStateService.ensure_ready

    def _ensure_spy(self, *args, **kwargs):
        calls["ensure"].append(in_tx["value"])
        return original_ensure(self, *args, **kwargs)

    monkeypatch.setattr(SecurityStateService, "ensure_ready", _ensure_spy)
    import guard_api.services.v21_pipeline as pipeline_mod

    original_revalidate = pipeline_mod.revalidate_assessment

    def _revalidate_spy(*args, **kwargs):
        calls["revalidate"].append(in_tx["value"])
        return original_revalidate(*args, **kwargs)

    monkeypatch.setattr(
        pipeline_mod, "revalidate_assessment", _revalidate_spy
    )

    response = evaluation_service.evaluate(
        _event(task_id=_TASK_ID), requesting_principal_id="principal_a"
    )
    assert response.decision.decision in ("allow", "ask", "deny")
    # S8 锚点：snapshot I/O 全部发生在事务外。read 仅一次（Phase A）；
    # ensure_ready 两次均在事务外（Phase A snapshot 解析 + T3 Phase C
    # 投影前 rebuild 钩子）。
    assert calls["read"] == [False]
    assert calls["ensure"] == [False, False]
    # revalidate 在短事务窗口内执行。
    assert calls["revalidate"] == [True]


# ---------------------------------------------------------------------------
# evaluate 端到端：flag off 逐字节 / flag on 信封 / stale / 降级 / replay
# ---------------------------------------------------------------------------


def test_pipeline_flag_off_response_byte_identical() -> None:
    """flag off：编排不触发，官方响应与无 pipeline 注入逐字节一致。"""

    event = _event(event_id="evt_byte_identical", task_id=_TASK_ID)

    store_off = MemoryControlPlaneStore()
    _commit_task_fact(store_off)
    eval_off, pipeline_off = _evaluation_stack(
        store_off, settings=_pipeline_settings(enabled=False)
    )
    assert pipeline_off.enabled is False
    resp_off = eval_off.evaluate(event, requesting_principal_id="principal_a")

    store_on = MemoryControlPlaneStore()
    _commit_task_fact(store_on)
    eval_on, _ = _evaluation_stack(store_on, settings=_pipeline_settings())
    resp_on = eval_on.evaluate(event, requesting_principal_id="principal_a")

    assert _normalized_response_dump(resp_off) == _normalized_response_dump(
        resp_on
    )


def test_pipeline_e2e_flag_on_valid_envelope() -> None:
    """flag on 有 task：审计 evidence.decision_v21 非降级信封。"""

    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )
    event = _event(event_id="evt_e2e_valid", task_id=_TASK_ID)
    response = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    envelope = audit.evidence.get("decision_v21")
    assert envelope is not None
    payload = _envelope_payload(envelope)
    assert payload["mode"] == "shadow"
    assert payload["snapshot_id"].startswith("v21-04-snapshot:")
    assert payload["divergence_category"] != "degraded_no_snapshot"
    assert payload["divergence_category"] != "degraded_stale_judgment"
    assert payload["final_decision"] == response.decision.decision


def test_pipeline_e2e_stale_between_phase_a_and_phase_b(monkeypatch) -> None:
    """模拟并发 CAS：Phase A 读后 state version 推进 → stale 信封，
    legacy 响应不变，不发生 V21-09 权威提交（shadow 期无写面）。"""

    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )

    original_read = SecurityStateService.read_snapshot_with_revoked

    def _read_then_bump(self, scope_digest, **kwargs):
        result = original_read(self, scope_digest, **kwargs)
        record = store.get_security_state(scope_digest)
        assert record is not None
        state = OnlineSecurityState.model_validate(record.canonical_payload)
        bumped = state.model_copy(
            update={"state_version": record.state_version + 1}
        )
        assert store.cas_security_state(
            scope_digest,
            record.state_version,
            SecurityStateRecord(
                scope_digest=scope_digest,
                state_version=record.state_version + 1,
                canonical_payload=bumped.model_dump(mode="json"),
                dirty=False,
                dirty_domains=[],
                projector_version=PROJECTOR_VERSION,
                updated_at=utc_now_iso(),
            ),
        )
        return result

    monkeypatch.setattr(
        SecurityStateService, "read_snapshot_with_revoked", _read_then_bump
    )

    event = _event(event_id="evt_e2e_stale", task_id=_TASK_ID)
    response = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    # legacy 主链不受 stale 影响。
    assert response.decision.decision in ("allow", "ask", "deny")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    envelope = audit.evidence.get("decision_v21")
    assert envelope is not None
    payload = _envelope_payload(envelope)
    assert payload["divergence_category"] == "degraded_stale_judgment"
    assert payload["final_decision"] == response.decision.decision
    assert any(
        degradation_id.startswith("v21-09-revalidation-stale:")
        for degradation_id in payload["degradation_ids"]
    )


def test_pipeline_e2e_no_task_degraded_no_snapshot_envelope() -> None:
    store = MemoryControlPlaneStore()
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )
    event = _event(event_id="evt_e2e_notask")
    response = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    envelope = audit.evidence.get("decision_v21")
    assert envelope is not None
    payload = _envelope_payload(envelope)
    # V21-08 语义保持。
    assert payload["divergence_category"] == "degraded_no_snapshot"
    assert payload["final_decision"] == response.decision.decision


def test_pipeline_phase_a_failure_falls_back_to_v21_08(monkeypatch) -> None:
    """Phase A 彻底失败 → run_phase_a 返回 None → 回退 V21-08 逐字节路径。"""

    store = MemoryControlPlaneStore()
    evaluation_service, pipeline = _evaluation_stack(
        store, settings=_pipeline_settings()
    )
    assert pipeline.enabled

    def _boom(self, event):
        raise RuntimeError("simulated phase A internal failure")

    monkeypatch.setattr(V21PipelineService, "_run_phase_a", _boom)
    event = _event(event_id="evt_e2e_fallback")
    response = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    # legacy 主链不受影响（官方链照常，旁路收敛为回退）。
    assert response.decision.decision in ("allow", "ask", "deny")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    envelope = audit.evidence.get("decision_v21")
    assert envelope is not None
    # V21-08 回退路径：无 task 引用 → degraded_no_snapshot 语义信封
    # （与 V21-08 逐字节一致，非 pipeline 产物）。
    payload = _envelope_payload(envelope)
    assert payload["divergence_category"] == "degraded_no_snapshot"
    assert payload["final_decision"] == response.decision.decision


def test_pipeline_replay_does_not_rerun_assess(monkeypatch) -> None:
    """D9：同 event_id replay 不重算 assess（Phase A 不跑第二次）。"""

    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )

    calls = {"count": 0}
    original = GuardEngine.evaluate_with_results

    def _counting(self, event, bundle=None):
        calls["count"] += 1
        return original(self, event, bundle)

    monkeypatch.setattr(GuardEngine, "evaluate_with_results", _counting)
    event = _event(event_id="evt_e2e_replay", task_id=_TASK_ID)
    first = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    assert calls["count"] == 1
    replay = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    assert calls["count"] == 1
    assert replay.policy_audit_id == first.policy_audit_id


# ---------------------------------------------------------------------------
# postgres 后端（环境可用则覆盖，不可用自动跳过）
# ---------------------------------------------------------------------------


def _postgres_store():
    from guard_api.storage.postgres import PostgresControlPlaneStore
    from tests.support.postgres import (
        get_test_database_url,
        reset_control_plane_schema,
    )

    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    store = PostgresControlPlaneStore(database_url)
    store.initialize()
    return store


def test_pipeline_postgres_backend() -> None:
    try:
        store = _postgres_store()
    except Exception as exc:  # noqa: BLE001 - 环境不可用自动跳过。
        pytest.skip(f"postgres test environment unavailable: {exc}")

    settings = _pipeline_settings()
    evaluation_service, pipeline = _evaluation_stack(store, settings=settings)
    assert pipeline.enabled

    # 无 task 引用 → degraded_no_snapshot。
    absent_event = _event(event_id="evt_pipeline_pg_1")
    evaluation_service.evaluate(
        absent_event, requesting_principal_id="principal_a"
    )
    audit = store.get_policy_evaluation_by_event_id(absent_event.event_id)
    assert audit is not None
    payload = _envelope_payload(audit.evidence["decision_v21"])
    assert payload["divergence_category"] == "degraded_no_snapshot"

    # 有权威 TaskFact → snapshot 信封（非降级类目）。
    _commit_task_fact(store)
    present_event = _event(event_id="evt_pipeline_pg_2", task_id=_TASK_ID)
    evaluation_service.evaluate(
        present_event, requesting_principal_id="principal_a"
    )
    audit = store.get_policy_evaluation_by_event_id(present_event.event_id)
    assert audit is not None
    payload = _envelope_payload(audit.evidence["decision_v21"])
    assert payload["snapshot_id"].startswith("v21-04-snapshot:")
    assert payload["divergence_category"] != "degraded_no_snapshot"
    assert payload["divergence_category"] != "degraded_stale_judgment"
