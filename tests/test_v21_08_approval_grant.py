"""V21-08 T6：Approval 服务接线测试（D4 承接 + human allow_once → grant 投影）。

覆盖 T6 验收口径（memory 后端为主，postgres 后端环境可用则覆盖）：

- flag on：human ``allow_once`` → grant 投影成功且确定性（同输入同
  digest，禁 uuid 入摘要）；投影后 snapshot capability 域可读到该
  grant（经存储投影登记 + 安全状态 active_grants 断言）；
- flag on：LLM resolution_source 的 ``allow_once`` 不产生可消费 grant；
  ``_llm_can_allow_once`` 恒 False，auto_review 只能 deny/kept_pending；
- flag off 双模式：LLM low/medium ``allow_once`` 行为与现状一致
  （审批面不回归），且不触发任何投影；
- expired / deny（revoked 终态）/ fingerprint 缺失（secret 未配置）
  → fail-closed 不投影，且审批决议正常返回；
- 投影重放 no-op（同 approval 二次触发不重复投影）；
- 投影失败（compile 故障注入）不影响 resolve_approval 返回与
  provenance 写入。
"""

from __future__ import annotations

import base64
import threading

import pytest

from agentguard_core import GuardDecision, GuardEvent, PolicyBundle
from agentguard_core.authority.models import TaskFact
from agentguard_core.decisions.models import ApprovalIntent
from agentguard_core.events.payloads import (
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
)
from agentguard_core.security_context import PROJECTOR_VERSION, OnlineSecurityState
from guard_api.models import ApprovalRequest
from guard_api.security_state import SecurityStateService
from guard_api.services import AuditService, ProvenanceWriter
from guard_api.services import approval as approval_module
from guard_api.services.approval import (
    ApprovalService,
    _llm_can_allow_once,
    derive_approval_grant_fingerprint,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import (
    ApprovalStateConflictError,
    SecurityStateRecord,
    TaskFactRecord,
)
from guard_api.storage.memory import MemoryControlPlaneStore

#: ≥32 字节的 base64url 测试密钥（与 T4 shadow 测试同口径）。
_TEST_SECRET = base64.urlsafe_b64encode(
    b"v21-08-approval-grant-test-secret-material"
).decode("ascii")

_SCOPE_DIGEST = "hmac-sha256:" + "ab" * 32
_TASK_ID = "task_approval_grant_fixture"
_PRINCIPAL_ID = "principal_a"


def _settings(
    *,
    shadow_enabled: bool = True,
    secret: str | None = _TEST_SECRET,
    llm_approval_enabled: bool = False,
) -> GuardApiSettings:
    return GuardApiSettings(
        control_token="control-secret",
        storage_backend="memory",
        v21_shadow_enabled=shadow_enabled,
        v21_shadow_server_secret=secret,
        llm_approval_enabled=llm_approval_enabled,
    )


class _FakeLlmReviewer:
    """可编程的 LLM Reviewer 桩（Protocol 兼容，返回 dict）。"""

    def __init__(self, decision: str, *, reason: str = "fixture review") -> None:
        self._decision = decision
        self._reason = reason

    def review(self, request):
        del request
        return {
            "decision": self._decision,
            "reason": self._reason,
            "status": "reviewed",
        }


class _Rig:
    """服务装配夹具：装配顺序与 main.py 一致（复用同一 state_service）。"""

    def __init__(
        self,
        *,
        settings: GuardApiSettings | None = None,
        llm_reviewer=None,
        store=None,
    ) -> None:
        self.store = store if store is not None else MemoryControlPlaneStore()
        self.settings = settings or _settings()
        self.state_service = SecurityStateService(self.store)
        provenance_writer = ProvenanceWriter(store=self.store)
        self.audit_service = AuditService(
            store=self.store, provenance_writer=provenance_writer
        )
        self.approval_service = ApprovalService(
            store=self.store,
            settings=self.settings,
            llm_reviewer=llm_reviewer,
            provenance_writer=provenance_writer,
            state_service=self.state_service,
        )
        self._task_committed = False

    def commit_task_fact(self) -> TaskFact:
        if not self._task_committed:
            _commit_task_fact(self.store)
            self._task_committed = True
        return _task_fact()

    def open_pending_approval(
        self,
        *,
        event_id: str = "evt_approval_1",
        task_id: str | None = _TASK_ID,
        severity: str = "medium",
        record_audit: bool = True,
    ) -> ApprovalRequest:
        """复刻生产时序：create_for_decision → record_evaluation。"""

        event = _event(event_id=event_id, task_id=task_id)
        decision = _decision(severity=severity)
        approval = self.approval_service.create_for_decision(
            event, decision, requesting_principal_id=_PRINCIPAL_ID
        )
        assert approval is not None
        if record_audit:
            self.audit_service.record_evaluation(
                event,
                decision,
                policy_bundle=PolicyBundle(),
                policy_revision=None,
                approval_id=approval.approval_id,
            )
        return approval

    def active_grants(self) -> list:
        record = self.store.get_security_state(_SCOPE_DIGEST)
        if record is None:
            return []
        state = OnlineSecurityState.model_validate(record.canonical_payload)
        return list(state.active_grants)


def _event(*, event_id: str = "evt_approval_1", task_id: str | None = _TASK_ID):
    metadata: dict[str, object] = {}
    if task_id is not None:
        metadata["task_id"] = task_id
    return GuardEvent(
        event_id=event_id,
        event_type="tool_call_proposed",
        runtime="langgraph",
        trace_id="trace_approval_1",
        timestamp="2026-08-15T00:00:00+00:00",
        security_context=SecurityContext(agent_id="main", user_task="fixture"),
        payload=ToolCallPayload(tool=ToolDescriptor(name="read_file")),
        metadata=metadata,
    )


def _decision(*, severity: str = "medium") -> GuardDecision:
    return GuardDecision(
        decision="ask",
        risk_score=60,
        severity=severity,
        reason="fixture requires human approval",
        approval_intent=ApprovalIntent(resource="file://fixture/secret.txt"),
    )


def _task_fact() -> TaskFact:
    return TaskFact(
        task_id=_TASK_ID,
        scope_digest=_SCOPE_DIGEST,
        scope_key_id="scope_key_test",
        principal_id=_PRINCIPAL_ID,
        task_summary="approval grant fixture task",
        task_digest="sha256:" + "cd" * 32,
        revision=1,
        status="active",
        action_constraints=[],
        resource_constraints=[],
        destination_constraints=[],
        created_sequence=None,
        producer="guard_api_task_ingress",
        authority="authoritative",
        evidence_refs=[],
    )


def _commit_task_fact(store) -> TaskFact:
    task_fact = _task_fact()
    store.create_task_fact(
        TaskFactRecord(
            task_fact=task_fact,
            canonical_payload=task_fact.model_dump(mode="json"),
            request_digest="sha256:" + "ef" * 32,
            expected_revision=0,
            created_at="2026-08-15T00:00:00Z",
        )
    )
    return task_fact


def _bare_approval(
    *,
    severity: str = "medium",
    options: tuple[str, ...] = ("allow_once", "deny"),
) -> ApprovalRequest:
    return ApprovalRequest(
        trace_id="trace_bare",
        subject_id="subject_bare",
        subject_type="agent",
        action_id="action_bare",
        action_name="read_file",
        requesting_principal_id=_PRINCIPAL_ID,
        resource="file://fixture/secret.txt",
        reason="fixture",
        risk_score=50,
        severity=severity,
        decision_options=list(options),
        created_at="2026-08-15T00:00:00+00:00",
        expires_at="2026-08-15T01:00:00+00:00",
    )


# ---------------------------------------------------------------------------
# D4 承接：_llm_can_allow_once 的 flag 语义
# ---------------------------------------------------------------------------


def test_llm_can_allow_once_flag_on_always_false() -> None:
    for severity in ("low", "medium", "high", "critical"):
        assert (
            _llm_can_allow_once(_bare_approval(severity=severity), v2_enabled=True)
            is False
        )


def test_llm_can_allow_once_flag_off_legacy_semantics() -> None:
    assert _llm_can_allow_once(_bare_approval(severity="low")) is True
    assert _llm_can_allow_once(_bare_approval(severity="medium")) is True
    assert _llm_can_allow_once(_bare_approval(severity="high")) is False
    assert (
        _llm_can_allow_once(_bare_approval(severity="low", options=("deny",)))
        is False
    )


# ---------------------------------------------------------------------------
# flag on：human allow_once → grant 投影成功且确定性
# ---------------------------------------------------------------------------


def test_flag_on_human_allow_once_projects_grant() -> None:
    rig = _Rig()
    rig.commit_task_fact()
    approval = rig.open_pending_approval()

    resolved = rig.approval_service.resolve_approval(
        approval.approval_id, "allow_once", resolution_source="human"
    )
    # 审批决议本身正常返回（既有契约不变）。
    assert resolved.status == "resolved"
    assert resolved.decision == "allow_once"
    assert resolved.resolution_source == "human"

    grants = rig.active_grants()
    assert len(grants) == 1
    grant = grants[0]
    # V21-06 冻结约束：单次、不可委托、精确 fingerprint 绑定。
    assert grant.source_type == "human_approval"
    assert grant.usage_limit == 1
    assert grant.remaining_uses == 1
    assert grant.delegable is False
    assert grant.revoked is False
    assert grant.exact_authorization_fingerprint is not None
    assert grant.exact_authorization_fingerprint.startswith("hmac-sha256:")
    assert grant.action_types == ["tool_call"]
    assert grant.scope_digest == _SCOPE_DIGEST
    assert grant.subject_principal_id == _PRINCIPAL_ID
    assert grant.task_id == _TASK_ID
    assert grant.source_ref == f"approval:{approval.approval_id}"

    # fingerprint 确定性：同 secret 同审批身份恒同输出（禁 uuid）。
    secret = rig.settings.v21_shadow_server_secret_bytes()
    assert secret is not None
    expected_fingerprint = derive_approval_grant_fingerprint(secret, approval)
    assert grant.exact_authorization_fingerprint == expected_fingerprint

    # 状态推进 + 投影登记（snapshot capability 域可重建出该 grant）。
    state_record = rig.store.get_security_state(_SCOPE_DIGEST)
    assert state_record is not None
    assert state_record.state_version == 1
    envelope = rig.state_service.store_access.get_projection(
        _SCOPE_DIGEST,
        "approval",
        approval.approval_id,
        1,
        PROJECTOR_VERSION,
    )
    assert envelope is not None
    assert envelope.applied_state_version == 1
    assert envelope.delta_digest.startswith("sha256:")


def test_projection_replay_is_noop_without_duplicate_grant() -> None:
    rig = _Rig()
    rig.commit_task_fact()
    approval = rig.open_pending_approval()
    resolved = rig.approval_service.resolve_approval(
        approval.approval_id, "allow_once", resolution_source="human"
    )
    assert len(rig.active_grants()) == 1
    version_after_first = rig.store.get_security_state(_SCOPE_DIGEST).state_version

    # 同 approval 二次触发：幂等重放短路，版本与 grant 数均不变。
    rig.approval_service._maybe_project_allow_once_grant(resolved)
    rig.approval_service._maybe_project_allow_once_grant(resolved)
    assert len(rig.active_grants()) == 1
    assert (
        rig.store.get_security_state(_SCOPE_DIGEST).state_version
        == version_after_first
    )


def test_grant_projection_survives_version_advanced_by_other_producer() -> None:
    """Major 2：版本已被其他投影推进后，新 grant 投影持锁重读最新 base。"""
    rig = _Rig()
    rig.commit_task_fact()
    first = rig.open_pending_approval(event_id="evt_concurrent_a")
    rig.approval_service.resolve_approval(
        first.approval_id, "allow_once", resolution_source="human"
    )
    assert len(rig.active_grants()) == 1

    # 并发推进者：另一 approval 的投影把同 scope 版本 1→2。
    second = rig.open_pending_approval(event_id="evt_concurrent_b")
    rig.approval_service.resolve_approval(
        second.approval_id, "allow_once", resolution_source="human"
    )
    assert rig.store.get_security_state(_SCOPE_DIGEST).state_version == 2

    # 新 grant 投影仍须成功：版本推进、grant 在场、不留全域 dirty。
    third = rig.open_pending_approval(event_id="evt_concurrent_c")
    rig.approval_service.resolve_approval(
        third.approval_id, "allow_once", resolution_source="human"
    )
    assert len(rig.active_grants()) == 3
    record = rig.store.get_security_state(_SCOPE_DIGEST)
    assert record.state_version == 3
    assert record.dirty is False
    assert record.dirty_domains == []


def test_grant_projection_base_read_and_apply_are_atomic_under_scope_lock(
    monkeypatch,
) -> None:
    """Major 2：base 读取 → delta 构造 → project_committed 整段持锁原子。

    在 delta 构造点注入一个同样竞争 scope_lock 的并发推进者：
    修复后 base 读取已持锁，并发者阻塞至本投影完成（base 新鲜，
    投影成功）；旧实现锁外读取会让并发者抢先推进 → CAS 版本冲突
    （base_state_version 已陈旧）→ fail-closed，grant 永久不投影。
    """
    rig = _Rig()
    rig.commit_task_fact()
    seed = rig.open_pending_approval(event_id="evt_lock_seed")
    rig.approval_service.resolve_approval(
        seed.approval_id, "allow_once", resolution_source="human"
    )
    assert rig.store.get_security_state(_SCOPE_DIGEST).state_version == 1

    target = rig.open_pending_approval(event_id="evt_lock_target")
    access = rig.state_service.store_access
    racing = threading.Event()

    def _racing_advance() -> None:
        # 并发推进者：竞争同一 scope_lock 后做 CAS 版本 bump（payload 不变）。
        with access.scope_lock(_SCOPE_DIGEST):
            latest = access.get_security_state(_SCOPE_DIGEST)
            assert latest is not None
            bumped = SecurityStateRecord(
                scope_digest=_SCOPE_DIGEST,
                state_version=latest.state_version + 1,
                canonical_payload=latest.canonical_payload,
                dirty=latest.dirty,
                dirty_domains=list(latest.dirty_domains),
                projector_version=latest.projector_version,
                updated_at=latest.updated_at,
            )
            access.cas_security_state(
                _SCOPE_DIGEST, latest.state_version, bumped
            )
        racing.set()

    original_build = approval_module._build_approval_grant_delta

    def _build_with_racing_advance(*args, **kwargs):
        delta = original_build(*args, **kwargs)
        thread = threading.Thread(target=_racing_advance)
        thread.start()
        # 修复后并发者被锁阻塞至本投影完成 → 等待超时；旧实现锁外
        # 构造时并发者会立即完成推进。两种情形下均继续返回旧 base
        # 构造的 delta，由后续断言判定成败。
        thread.join(timeout=2.0)
        return delta

    monkeypatch.setattr(
        approval_module, "_build_approval_grant_delta", _build_with_racing_advance
    )

    resolved = rig.approval_service.resolve_approval(
        target.approval_id, "allow_once", resolution_source="human"
    )
    assert resolved.status == "resolved"

    # 投影成功：target grant 在场且不留 dirty（旧实现此处 fail-closed）。
    grants = rig.active_grants()
    assert len(grants) == 2
    assert any(
        grant.source_ref == f"approval:{target.approval_id}" for grant in grants
    )
    record = rig.store.get_security_state(_SCOPE_DIGEST)
    assert record.dirty is False
    assert record.dirty_domains == []

    # 并发推进者在锁释放后完成 bump（1→2 投影 + 2→3 bump）。
    racing.wait(timeout=5.0)
    assert racing.is_set()
    assert rig.store.get_security_state(_SCOPE_DIGEST).state_version == 3


# ---------------------------------------------------------------------------
# flag on：LLM 路径收紧（D4）——只能 deny 或保持 pending
# ---------------------------------------------------------------------------


def test_flag_on_llm_allow_once_kept_pending_and_no_grant() -> None:
    rig = _Rig(
        settings=_settings(llm_approval_enabled=True),
        llm_reviewer=_FakeLlmReviewer("allow_once"),
    )
    rig.commit_task_fact()
    approval = rig.open_pending_approval(severity="low")

    reviewed = rig.approval_service.auto_review_with_llm(approval)
    assert reviewed is not None
    # LLM allow_once 被收紧为保持 pending（不得自动批准）。
    assert reviewed.status == "pending"
    assert reviewed.decision is None
    assert reviewed.llm_review is not None
    assert reviewed.llm_review.status == "kept_pending"
    assert rig.store.get_security_state(_SCOPE_DIGEST) is None

    # 即便以 llm 来源强行决议 allow_once，投影层双保险拒绝投影。
    resolved = rig.approval_service.resolve_approval(
        approval.approval_id, "allow_once", resolution_source="llm"
    )
    assert resolved.status == "resolved"
    assert rig.active_grants() == []
    assert rig.store.get_security_state(_SCOPE_DIGEST) is None


def test_flag_on_llm_deny_still_resolves() -> None:
    rig = _Rig(
        settings=_settings(llm_approval_enabled=True),
        llm_reviewer=_FakeLlmReviewer("deny", reason="fixture deny"),
    )
    rig.commit_task_fact()
    approval = rig.open_pending_approval(severity="high")

    resolved = rig.approval_service.auto_review_with_llm(approval)
    assert resolved is not None
    assert resolved.status == "resolved"
    assert resolved.decision == "deny"
    assert resolved.resolution_source == "llm"
    assert rig.store.get_security_state(_SCOPE_DIGEST) is None


# ---------------------------------------------------------------------------
# flag off：双模式不回归（LLM 自动批准保持现状，且不触发投影）
# ---------------------------------------------------------------------------


def test_flag_off_llm_allow_once_legacy_behavior_and_no_projection() -> None:
    rig = _Rig(
        settings=_settings(shadow_enabled=False, llm_approval_enabled=True),
        llm_reviewer=_FakeLlmReviewer("allow_once"),
    )
    rig.commit_task_fact()
    approval = rig.open_pending_approval(severity="low")

    resolved = rig.approval_service.auto_review_with_llm(approval)
    assert resolved is not None
    # legacy official：low/medium LLM 可自动 allow_once。
    assert resolved.status == "resolved"
    assert resolved.decision == "allow_once"
    assert resolved.resolution_source == "llm"
    # flag off：投影接线完全不触发（零状态行）。
    assert rig.store.get_security_state(_SCOPE_DIGEST) is None


def test_flag_off_human_allow_once_matches_legacy_and_projects_nothing() -> None:
    rig = _Rig(settings=_settings(shadow_enabled=False))
    rig.commit_task_fact()
    approval = rig.open_pending_approval()

    resolved = rig.approval_service.resolve_approval(
        approval.approval_id, "allow_once", resolution_source="human"
    )
    assert resolved.status == "resolved"
    assert resolved.decision == "allow_once"
    assert rig.store.get_security_state(_SCOPE_DIGEST) is None


# ---------------------------------------------------------------------------
# fail-closed：expired / deny / fingerprint 缺失 / scope 不可解析
# ---------------------------------------------------------------------------


def test_expired_approval_rejected_and_not_projected() -> None:
    rig = _Rig()
    rig.commit_task_fact()
    expired = ApprovalRequest(
        trace_id="trace_expired",
        subject_id="subject_expired",
        subject_type="agent",
        action_id="action_expired",
        action_name="read_file",
        requesting_principal_id=_PRINCIPAL_ID,
        resource="file://fixture/secret.txt",
        reason="fixture",
        risk_score=50,
        severity="medium",
        created_at="2020-01-01T00:00:00+00:00",
        expires_at="2020-01-01T00:15:00+00:00",
        evidence={"event": {"event_id": "evt_expired"}},
    )
    rig.store.create_approval(expired)

    # 存储层状态机：过期审批不得 resolve 为 allow_once。
    with pytest.raises(ApprovalStateConflictError):
        rig.approval_service.resolve_approval(
            expired.approval_id, "allow_once", resolution_source="human"
        )
    assert rig.store.get_security_state(_SCOPE_DIGEST) is None

    # 投影侧纵深防御：resolved_at 晚于 expires_at 的决议对象不投影。
    expired_resolved = expired.model_copy(
        update={
            "status": "resolved",
            "decision": "allow_once",
            "resolution_source": "human",
            "resolved_at": "2020-01-01T00:20:00+00:00",
        }
    )
    rig.approval_service._maybe_project_allow_once_grant(expired_resolved)
    assert rig.store.get_security_state(_SCOPE_DIGEST) is None


def test_human_deny_not_projected() -> None:
    rig = _Rig()
    rig.commit_task_fact()
    approval = rig.open_pending_approval()

    resolved = rig.approval_service.resolve_approval(
        approval.approval_id, "deny", resolution_source="human"
    )
    assert resolved.status == "resolved"
    assert resolved.decision == "deny"
    assert rig.store.get_security_state(_SCOPE_DIGEST) is None


def test_missing_server_secret_fail_closed_but_resolution_ok() -> None:
    rig = _Rig(settings=_settings(secret=None))
    rig.commit_task_fact()
    approval = rig.open_pending_approval()

    resolved = rig.approval_service.resolve_approval(
        approval.approval_id, "allow_once", resolution_source="human"
    )
    # 审批决议正常返回；fingerprint 无法派生 → fail-closed 不投影。
    assert resolved.status == "resolved"
    assert resolved.decision == "allow_once"
    assert rig.store.get_security_state(_SCOPE_DIGEST) is None


def test_scope_unresolvable_fail_closed_but_resolution_ok() -> None:
    # 无权威 TaskFact：claim 链断裂 → fail-closed 不投影。
    rig = _Rig()
    approval = rig.open_pending_approval(event_id="evt_no_fact")
    resolved = rig.approval_service.resolve_approval(
        approval.approval_id, "allow_once", resolution_source="human"
    )
    assert resolved.status == "resolved"
    assert rig.store.get_security_state(_SCOPE_DIGEST) is None

    # 事件无 task_id claim：审计记录缺 task_id → fail-closed 不投影。
    rig2 = _Rig()
    rig2.commit_task_fact()
    approval2 = rig2.open_pending_approval(event_id="evt_no_claim", task_id=None)
    resolved2 = rig2.approval_service.resolve_approval(
        approval2.approval_id, "allow_once", resolution_source="human"
    )
    assert resolved2.status == "resolved"
    assert rig2.store.get_security_state(_SCOPE_DIGEST) is None

    # 无审计记录：evidence event_id 查不到 policy_evaluation → 不投影。
    rig3 = _Rig()
    rig3.commit_task_fact()
    approval3 = rig3.open_pending_approval(
        event_id="evt_no_audit", record_audit=False
    )
    resolved3 = rig3.approval_service.resolve_approval(
        approval3.approval_id, "allow_once", resolution_source="human"
    )
    assert resolved3.status == "resolved"
    assert rig3.store.get_security_state(_SCOPE_DIGEST) is None


# ---------------------------------------------------------------------------
# 投影失败收敛：不影响 resolve_approval 返回与 provenance 写入
# ---------------------------------------------------------------------------


def test_projection_failure_does_not_affect_resolution_or_provenance(
    monkeypatch,
) -> None:
    rig = _Rig()
    rig.commit_task_fact()
    approval = rig.open_pending_approval()

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated compile failure")

    monkeypatch.setattr(approval_module, "compile_approval_to_grant", _boom)

    resolved = rig.approval_service.resolve_approval(
        approval.approval_id, "allow_once", resolution_source="human"
    )
    # 决议正常返回；无 grant、无状态行（fail-closed）。
    assert resolved.status == "resolved"
    assert resolved.decision == "allow_once"
    assert rig.store.get_security_state(_SCOPE_DIGEST) is None

    # provenance 写入不受投影失败影响：审批节点已更新为终态。
    node = rig.store.get_provenance_node(f"approval:{approval.approval_id}")
    assert node is not None
    assert node.metadata["status"] == "resolved"
    assert node.metadata["decision"] == "allow_once"


def test_state_service_not_wired_fail_closed_but_resolution_ok() -> None:
    rig = _Rig()
    rig.approval_service.state_service = None
    rig.commit_task_fact()
    approval = rig.open_pending_approval()

    resolved = rig.approval_service.resolve_approval(
        approval.approval_id, "allow_once", resolution_source="human"
    )
    assert resolved.status == "resolved"
    assert rig.store.get_security_state(_SCOPE_DIGEST) is None


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


def test_approval_grant_projection_postgres_backend() -> None:
    rig = _Rig(store=_postgres_store())
    rig.commit_task_fact()
    approval = rig.open_pending_approval(event_id="evt_approval_pg_1")

    resolved = rig.approval_service.resolve_approval(
        approval.approval_id, "allow_once", resolution_source="human"
    )
    assert resolved.status == "resolved"

    grants = rig.active_grants()
    assert len(grants) == 1
    assert grants[0].usage_limit == 1
    assert grants[0].remaining_uses == 1
    assert grants[0].delegable is False
    assert grants[0].exact_authorization_fingerprint is not None

    # 重放 no-op。
    rig.approval_service._maybe_project_allow_once_grant(resolved)
    assert len(rig.active_grants()) == 1
