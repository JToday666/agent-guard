"""V21-09 T3：commit→project 投影接线 + state_delta_v21 信封测试。

覆盖 T3 验收口径（memory 后端为主，postgres 后端环境可用则覆盖）：

- commit→project 顺序：audit 落盘（事务内）先于投影（事务退出后）；
- 同 event 重放：五元组幂等键短路 replayed_noop，不重复投影、响应不变；
- digest conflict → dirty + fail-closed（响应与审计不受影响）；
- 投影失败注入 → 告警收敛，响应与审计完整；
- stale Phase B → 无 Phase C、无 state_delta_v21 信封；
- flag off → 零投影零信封（evidence 恰 8 键，None 参数逐字节不变）；
- state_delta_v21 引用形状（只含投影身份，D2）+ 预算 dropped-reference；
- D9 replay 补投影幂等（不重算、缺材料静默跳过留痕）。

契约依据：``12_决策记录_V21-09前置.md`` D2/D4/D6/D9。
"""

from __future__ import annotations

import threading
from contextlib import contextmanager

import pytest

from agentguard_core import GuardEngine, PolicyBundle, utc_now_iso
from agentguard_core.decisions.evidence import state_delta_v21_envelope
from agentguard_core.decisions.finalize import derive_final_audit_id
from agentguard_core.security_context import PROJECTOR_VERSION, CommittedRecord
from guard_api.security_state import SecurityStateService
from guard_api.security_state.store import SecurityStateStoreAccess
from guard_api.storage.base import ProjectionIdentityRecord
from guard_api.storage.memory import MemoryControlPlaneStore

import guard_api.services.evidence as evidence_mod
from guard_api.services.v21_pipeline import build_evaluation_delta

from tests.test_v21_09_pipeline import (
    _SCOPE_DIGEST,
    _TASK_ID,
    _commit_task_fact,
    _envelope_payload,
    _evaluation_stack,
    _event,
    _normalized_response_dump,
    _pipeline_service,
    _pipeline_settings,
)

_EVIDENCE_LEGACY_KEYS = {
    "guard_event",
    "guard_decision",
    "policy",
    "intervention",
    "execution",
    "side_effects",
    "result",
    "approval",
}

_REFERENCE_KEYS = {
    "projection_id",
    "delta_digest",
    "source_record_type",
    "source_record_id",
    "source_revision",
}


def _projection_registration(store, ref: dict):
    return SecurityStateService(store).store_access.get_projection(
        _SCOPE_DIGEST,
        "policy_evaluation",
        ref["source_record_id"],
        ref["source_revision"],
        PROJECTOR_VERSION,
    )


def _tx_tracker(monkeypatch) -> dict[str, bool]:
    """evaluation_transaction 窗口标记（事务内外断言基建）。"""

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
    return in_tx


# ---------------------------------------------------------------------------
# commit→project 顺序（D4 / 02 §3：audit 落盘先于投影，投影在事务外）
# ---------------------------------------------------------------------------


def test_projection_commit_before_project_outside_tx(monkeypatch) -> None:
    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )
    in_tx = _tx_tracker(monkeypatch)

    order: list[tuple[str, bool]] = []
    original_add = MemoryControlPlaneStore.add_audit_event

    def _add_spy(self, event):
        order.append(("audit_commit", in_tx["value"]))
        return original_add(self, event)

    monkeypatch.setattr(MemoryControlPlaneStore, "add_audit_event", _add_spy)

    original_project = SecurityStateService.project_committed

    def _project_spy(self, committed_record, **kwargs):
        order.append(("project", in_tx["value"]))
        return original_project(self, committed_record, **kwargs)

    monkeypatch.setattr(
        SecurityStateService, "project_committed", _project_spy
    )

    event = _event(event_id="evt_order", task_id=_TASK_ID)
    response = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    assert response.decision.decision in ("allow", "ask", "deny")

    kinds = [kind for kind, _ in order]
    assert "audit_commit" in kinds and "project" in kinds
    # audit 落盘先于投影（commit→project 时序）。
    assert kinds.index("audit_commit") < kinds.index("project")
    # audit 在事务内落盘；投影在事务退出后执行。
    assert [flag for kind, flag in order if kind == "audit_commit"] == [True]
    assert [flag for kind, flag in order if kind == "project"] == [False]

    # 投影真实落地：登记在册且 digest 与审计信封引用一致。
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    ref = audit.evidence["state_delta_v21"]["payload"]
    registration = _projection_registration(store, ref)
    assert registration is not None
    assert registration.delta_digest == ref["delta_digest"]


# ---------------------------------------------------------------------------
# 同 event 重放：五元组幂等键短路（replayed_noop，不重复投影）
# ---------------------------------------------------------------------------


def test_replay_no_duplicate_projection_response_unchanged(monkeypatch) -> None:
    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )
    event = _event(event_id="evt_replay", task_id=_TASK_ID)
    first = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    record = store.get_security_state(_SCOPE_DIGEST)
    assert record is not None
    version_after_first = record.state_version

    calls = {"count": 0}
    original_project = SecurityStateService.project_committed

    def _counting(self, committed_record, **kwargs):
        calls["count"] += 1
        return original_project(self, committed_record, **kwargs)

    monkeypatch.setattr(
        SecurityStateService, "project_committed", _counting
    )

    replay = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    # 响应不变（同幂等结果）。
    assert replay.policy_audit_id == first.policy_audit_id
    assert _normalized_response_dump(replay) == _normalized_response_dump(
        first
    )
    # 幂等登记已在场 → 补投影短路，不重复进入 projector。
    assert calls["count"] == 0
    assert (
        store.get_security_state(_SCOPE_DIGEST).state_version
        == version_after_first
    )


def test_projector_replayed_noop_for_same_committed_record() -> None:
    """同身份同 digest 的 CommittedRecord 二次投影 → replayed_noop。"""

    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )
    event = _event(event_id="evt_noop", task_id=_TASK_ID)
    evaluation_service.evaluate(event, requesting_principal_id="principal_a")

    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    ref = audit.evidence["state_delta_v21"]["payload"]
    registration = _projection_registration(store, ref)
    assert registration is not None
    version_after = store.get_security_state(_SCOPE_DIGEST).state_version

    # 以 backfill 同源口径重建同身份同 digest 的 delta 再投影。
    decision_payload = _envelope_payload(audit.evidence["decision_v21"])
    delta = build_evaluation_delta(
        scope_digest=_SCOPE_DIGEST,
        audit_id=ref["source_record_id"],
        base_state_version=decision_payload["state_version"],
    )
    assert delta.delta_digest == ref["delta_digest"]
    committed = CommittedRecord(
        record_id=f"policy-evaluation:{ref['source_record_id']}",
        committed=True,
        source_record_type="policy_evaluation",
        source_record_id=ref["source_record_id"],
        source_revision=ref["source_revision"],
        scope_digest=_SCOPE_DIGEST,
        projector_version=PROJECTOR_VERSION,
        delta=delta,
    )
    result = SecurityStateService(store).project_committed(
        committed, scope_digest=_SCOPE_DIGEST
    )
    assert result.outcome == "replayed_noop"
    assert (
        store.get_security_state(_SCOPE_DIGEST).state_version
        == version_after
    )


# ---------------------------------------------------------------------------
# digest conflict → dirty + fail-closed（响应与审计不受影响）
# ---------------------------------------------------------------------------


def test_digest_conflict_dirty_fail_closed() -> None:
    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    # 先经 pipeline Phase A 确定性派生本次评估的 audit_id（assessment
    # 身份含 event_id，重跑恒定），预埋异 digest 的同身份登记。
    pipeline, _ = _pipeline_service(store)
    event = _event(event_id="evt_conflict", task_id=_TASK_ID)
    materials = pipeline.run_phase_a(event)
    assert materials is not None and materials.snapshot is not None
    audit_id = derive_final_audit_id(materials.assessment)

    access = SecurityStateService(store).store_access
    record = store.get_security_state(_SCOPE_DIGEST)
    assert record is not None
    fake_digest = "sha256:" + "00" * 32
    access.record_projection(
        ProjectionIdentityRecord(
            scope_digest=_SCOPE_DIGEST,
            source_record_type="policy_evaluation",
            source_record_id=audit_id,
            source_revision=1,
            projector_version=PROJECTOR_VERSION,
            delta_digest=fake_digest,
            delta_payload={},
            applied_state_version=record.state_version,
            created_at=utc_now_iso(),
        )
    )

    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )
    response = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    # fail-closed 收敛：响应与审计不受影响。
    assert response.decision.decision in ("allow", "ask", "deny")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    assert audit.audit_id == audit_id
    assert "state_delta_v21" in audit.evidence
    assert "guard_decision" in audit.evidence
    # digest conflict → 置脏；不得静默覆盖（异 digest 登记原样保留）。
    state_record = store.get_security_state(_SCOPE_DIGEST)
    assert state_record is not None
    assert state_record.dirty is True
    existing = access.get_projection(
        _SCOPE_DIGEST, "policy_evaluation", audit_id, 1, PROJECTOR_VERSION
    )
    assert existing is not None
    assert existing.delta_digest == fake_digest


# ---------------------------------------------------------------------------
# 投影失败注入 → 告警收敛、响应与审计完整
# ---------------------------------------------------------------------------


def test_projection_failure_converges(monkeypatch, caplog) -> None:
    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )

    def _boom(self, committed_record, **kwargs):
        raise RuntimeError("simulated projection failure")

    monkeypatch.setattr(SecurityStateService, "project_committed", _boom)

    event = _event(event_id="evt_fail", task_id=_TASK_ID)
    response = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    assert response.decision.decision in ("allow", "ask", "deny")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    # 审计完整：信封已随 audit commit 落盘，权威键不受投影失败影响。
    assert "state_delta_v21" in audit.evidence
    assert "guard_decision" in audit.evidence
    # 告警收敛留痕。
    assert any(
        "evaluation projection failed" in record.message
        for record in caplog.records
    )
    # 无投影登记（fail-closed：不投影不伪造）。
    ref = audit.evidence["state_delta_v21"]["payload"]
    assert _projection_registration(store, ref) is None


# ---------------------------------------------------------------------------
# stale Phase B → 无 Phase C、无 state_delta_v21 信封
# ---------------------------------------------------------------------------


def test_stale_phase_b_no_phase_c(monkeypatch) -> None:
    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )

    # Phase A snapshot 读取后即刻推进 state version → Phase B stale。
    original_read = SecurityStateService.read_snapshot_with_revoked

    def _read_then_bump(self, scope_digest, **kwargs):
        result = original_read(self, scope_digest, **kwargs)
        record = store.get_security_state(scope_digest)
        assert record is not None
        from agentguard_core.security_context import OnlineSecurityState
        from guard_api.storage.base import SecurityStateRecord

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

    calls = {"count": 0}
    original_project = SecurityStateService.project_committed

    def _counting(self, committed_record, **kwargs):
        calls["count"] += 1
        return original_project(self, committed_record, **kwargs)

    monkeypatch.setattr(
        SecurityStateService, "project_committed", _counting
    )

    event = _event(event_id="evt_stale_c", task_id=_TASK_ID)
    response = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    assert response.decision.decision in ("allow", "ask", "deny")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    payload = _envelope_payload(audit.evidence["decision_v21"])
    assert payload["divergence_category"] == "degraded_stale_judgment"
    # stale → 不进入 Phase C、不产 state_delta_v21 信封。
    assert "state_delta_v21" not in audit.evidence
    assert calls["count"] == 0


# ---------------------------------------------------------------------------
# flag off：零投影零信封（evidence 恰 8 键，None 参数逐字节不变）
# ---------------------------------------------------------------------------


def test_flag_off_zero_projection_zero_envelope() -> None:
    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, pipeline = _evaluation_stack(
        store, settings=_pipeline_settings(enabled=False)
    )
    assert pipeline.enabled is False

    event = _event(event_id="evt_flagoff", task_id=_TASK_ID)
    response = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    assert response.decision.decision in ("allow", "ask", "deny")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    # evidence 键集恰 8 键：零 v21 信封。
    assert set(audit.evidence) == _EVIDENCE_LEGACY_KEYS
    # 零投影：无安全状态行、无投影登记写面。
    assert store.get_security_state(_SCOPE_DIGEST) is None


def test_state_delta_evidence_none_byte_identical() -> None:
    """None 透传参数逐字节不变（仿 v21_evidence 参数纪律）。"""

    event = _event(event_id="evt_byte_delta")
    bundle = PolicyBundle()
    decision, _ = GuardEngine().evaluate_with_results(event, bundle)
    baseline = evidence_mod.build_audit_event(
        event, decision, policy_bundle=bundle, policy_revision=None
    )
    with_params = evidence_mod.build_audit_event(
        event,
        decision,
        policy_bundle=bundle,
        policy_revision=None,
        state_delta_evidence=None,
        audit_id=None,
    )
    baseline_dump = baseline.model_dump(mode="json")
    with_dump = with_params.model_dump(mode="json")
    # audit_id / timestamp 默认工厂含随机/瞬时分量，不参与逐字对照；
    # 其余全字段一致（evidence 键集与内容逐字节不变）。
    for dump in (baseline_dump, with_dump):
        dump.pop("audit_id")
        dump.pop("timestamp")
    assert with_dump == baseline_dump


# ---------------------------------------------------------------------------
# state_delta_v21 引用形状（D2）+ 预算 dropped-reference 留痕
# ---------------------------------------------------------------------------


def test_state_delta_reference_shape() -> None:
    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )
    event = _event(event_id="evt_shape", task_id=_TASK_ID)
    evaluation_service.evaluate(event, requesting_principal_id="principal_a")

    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    envelope = audit.evidence.get("state_delta_v21")
    assert isinstance(envelope, dict)
    # 07 §10 版本信封形状（与 decision_v21 同构）。
    assert set(envelope) == {"schema_version", "payload"}
    assert envelope["schema_version"] == "2.1"
    ref = envelope["payload"]
    # D2：只存投影身份引用（恰三组：projection_id / delta_digest /
    # source identity），不内嵌 delta 本体。
    assert set(ref) == _REFERENCE_KEYS
    assert ref["source_record_type"] == "policy_evaluation"
    assert ref["source_record_id"] == audit.audit_id
    assert ref["source_revision"] == 1
    assert ref["projection_id"].startswith("projection:")
    assert "watermark_delta" not in ref
    assert "grant_upserts" not in ref
    # 引用 digest 与投影登记一致（全量 delta 本体随 projection_records）。
    registration = _projection_registration(store, ref)
    assert registration is not None
    assert registration.delta_digest == ref["delta_digest"]


def test_state_delta_budget_dropped_reference(monkeypatch) -> None:
    """预算吃紧 → state_delta_v21 降级为 dropped-reference（禁静默丢失）。"""

    event = _event(event_id="evt_budget")
    bundle = PolicyBundle()
    decision, _ = GuardEngine().evaluate_with_results(event, bundle)
    baseline = evidence_mod.build_audit_event(
        event, decision, policy_bundle=bundle, policy_revision=None
    )
    baseline_size = evidence_mod.evidence_serialized_size(baseline.evidence)

    envelope = state_delta_v21_envelope(
        {
            "projection_id": "projection:fixture",
            "delta_digest": "sha256:" + "ab" * 32,
            "source_record_type": "policy_evaluation",
            "source_record_id": "audit:fixture",
            "source_revision": 1,
        }
    )
    # 预算收紧到「基线达标、合并信封后超限」的临界值。
    monkeypatch.setattr(evidence_mod, "MAX_EVIDENCE_BYTES", baseline_size + 8)
    audit_event = evidence_mod.build_audit_event(
        event,
        decision,
        policy_bundle=bundle,
        policy_revision=None,
        state_delta_evidence=envelope,
    )
    dropped = audit_event.evidence["state_delta_v21"]
    assert dropped["_budget_dropped"] is True
    assert dropped["_envelope_sha256"].startswith("sha256:")
    # replay 权威键 guard_decision 绝不触碰。
    assert "guard_decision" in audit_event.evidence
    assert audit_event.evidence["guard_decision"] == baseline.evidence[
        "guard_decision"
    ]


# ---------------------------------------------------------------------------
# D9：replay 幂等补投影（不重算；缺材料静默跳过留痕）
# ---------------------------------------------------------------------------


def test_d9_replay_backfill_projection_idempotent(monkeypatch) -> None:
    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )

    # 首次投影失败（模拟 crash 窗口：audit 已落盘、投影未登记）。
    state = {"fail": True}
    original_project = SecurityStateService.project_committed

    def _flaky(self, committed_record, **kwargs):
        if state["fail"]:
            state["fail"] = False
            raise RuntimeError("simulated crash before projection")
        return original_project(self, committed_record, **kwargs)

    monkeypatch.setattr(SecurityStateService, "project_committed", _flaky)

    event = _event(event_id="evt_backfill", task_id=_TASK_ID)
    first = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    ref = audit.evidence["state_delta_v21"]["payload"]
    assert _projection_registration(store, ref) is None
    record = store.get_security_state(_SCOPE_DIGEST)
    assert record is not None
    version_before = record.state_version

    # 同 event 重放：不重算 assess，仅幂等补投影。
    replay = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    assert replay.policy_audit_id == first.policy_audit_id
    registration = _projection_registration(store, ref)
    assert registration is not None
    assert registration.delta_digest == ref["delta_digest"]
    assert (
        store.get_security_state(_SCOPE_DIGEST).state_version
        == version_before + 1
    )

    # 再次重放：幂等登记已在场 → 短路，版本不再推进。
    third = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    assert third.policy_audit_id == first.policy_audit_id
    assert (
        store.get_security_state(_SCOPE_DIGEST).state_version
        == version_before + 1
    )


def test_concurrent_replay_backfill_idempotent(monkeypatch) -> None:
    """S4：flag on replay 跳过 evaluation_transaction，D9 补投影在
    事件级锁外——并发双 replay 同 event 必须幂等：投影登记恰一次、
    state version 恰推进一次、响应完全一致（scope_lock + 五元组
    幂等键承接锁外时序，该时序变化为 D4/D9 有意设计）。"""

    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store, settings=_pipeline_settings()
    )

    # 首次投影失败（crash 窗口：audit 已落盘、投影未登记）。
    state = {"fail": True}
    original_project = SecurityStateService.project_committed

    def _flaky(self, committed_record, **kwargs):
        if state["fail"]:
            state["fail"] = False
            raise RuntimeError("simulated crash before projection")
        return original_project(self, committed_record, **kwargs)

    monkeypatch.setattr(SecurityStateService, "project_committed", _flaky)

    event = _event(event_id="evt_concurrent_replay", task_id=_TASK_ID)
    first = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    ref = audit.evidence["state_delta_v21"]["payload"]
    assert _projection_registration(store, ref) is None
    record = store.get_security_state(_SCOPE_DIGEST)
    assert record is not None
    version_before = record.state_version

    # 登记写面计数：幂等时投影登记必须恰一次。
    registrations = {"count": 0}
    original_record = SecurityStateStoreAccess.record_projection

    def _counting_record(self, projection_record):
        registrations["count"] += 1
        return original_record(self, projection_record)

    monkeypatch.setattr(
        SecurityStateStoreAccess, "record_projection", _counting_record
    )

    # 并发双 replay（补投影在事件级锁外，barrier 同步起跑）。
    responses: list = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(2)

    def _replay() -> None:
        try:
            barrier.wait(timeout=10)
            responses.append(
                evaluation_service.evaluate(
                    event, requesting_principal_id="principal_a"
                )
            )
        except BaseException as exc:  # noqa: BLE001 - 收集线程异常。
            errors.append(exc)

    threads = [threading.Thread(target=_replay) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert errors == []
    assert len(responses) == 2
    for replay in responses:
        assert replay.policy_audit_id == first.policy_audit_id
        assert _normalized_response_dump(replay) == _normalized_response_dump(
            first
        )
    # 幂等收敛：登记恰一次、版本恰推进一次、digest 与信封引用一致。
    assert registrations["count"] == 1
    registration = _projection_registration(store, ref)
    assert registration is not None
    assert registration.delta_digest == ref["delta_digest"]
    assert (
        store.get_security_state(_SCOPE_DIGEST).state_version
        == version_before + 1
    )


def test_d9_backfill_skips_records_without_envelope(monkeypatch) -> None:
    """无信封记录（flag off 存量 / 降级）→ 静默跳过，绝不外抛。"""

    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    pipeline, _ = _pipeline_service(store)

    calls = {"count": 0}
    original_project = SecurityStateService.project_committed

    def _counting(self, committed_record, **kwargs):
        calls["count"] += 1
        return original_project(self, committed_record, **kwargs)

    monkeypatch.setattr(SecurityStateService, "project_committed", _counting)

    event = _event(event_id="evt_no_envelope")
    bundle = PolicyBundle()
    decision, _ = GuardEngine().evaluate_with_results(event, bundle)
    audit = evidence_mod.build_audit_event(
        event, decision, policy_bundle=bundle, policy_revision=None
    )
    assert "state_delta_v21" not in audit.evidence
    pipeline.backfill_projection(audit)  # 不外抛。
    assert calls["count"] == 0


# ---------------------------------------------------------------------------
# postgres 后端（环境可用则覆盖，不可用自动跳过）
# ---------------------------------------------------------------------------


@pytest.mark.postgres
def test_projection_postgres_backend() -> None:
    from tests.test_v21_09_pipeline import _postgres_store

    try:
        store = _postgres_store()
    except Exception as exc:  # noqa: BLE001 - 环境不可用自动跳过。
        pytest.skip(f"postgres test environment unavailable: {exc}")

    settings = _pipeline_settings()
    evaluation_service, _ = _evaluation_stack(store, settings=settings)
    _commit_task_fact(store)
    event = _event(event_id="evt_projection_pg", task_id=_TASK_ID)
    response = evaluation_service.evaluate(
        event, requesting_principal_id="principal_a"
    )
    assert response.decision.decision in ("allow", "ask", "deny")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    ref = audit.evidence["state_delta_v21"]["payload"]
    assert set(ref) == _REFERENCE_KEYS
    registration = _projection_registration(store, ref)
    assert registration is not None
    assert registration.delta_digest == ref["delta_digest"]
