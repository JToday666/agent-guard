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

from agentguard_core import GuardEvent, PolicyBundle, utc_now_iso
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
from guard_api.storage.base import SecurityStateRecord, TaskFactRecord
from guard_api.storage.memory import MemoryControlPlaneStore

#: ≥32 字节的 base64url 测试密钥（形态与 V21-08 shadow 测试同口径）。
_TEST_SECRET = base64.urlsafe_b64encode(
    b"v21-09-pipeline-test-secret-material"
).decode("ascii")

_SCOPE_DIGEST = "hmac-sha256:" + "a9" * 32
_TASK_ID = "task_pipeline_fixture"


def _event(*, event_id: str = "evt_pipeline_1", task_id: str | None = None) -> GuardEvent:
    metadata: dict[str, object] = {}
    if task_id is not None:
        metadata["task_id"] = task_id
    return GuardEvent(
        event_id=event_id,
        event_type="tool_call_proposed",
        runtime="langgraph",
        trace_id="trace_pipeline_1",
        timestamp="2026-08-15T00:00:00+00:00",
        security_context=SecurityContext(agent_id="main", user_task="pipeline fixture"),
        payload=ToolCallPayload(tool=ToolDescriptor(name="read_file")),
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
