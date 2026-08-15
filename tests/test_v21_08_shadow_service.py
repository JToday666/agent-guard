"""V21-08 T4：guard-api shadow 编排与 SecurityStateService 注册测试。

覆盖 T4 验收口径（memory 后端为主，postgres 后端环境可用则覆盖）：

- flag off：编排器返回 None 且零 I/O、ApiContext 组装正常、既有
  evaluate 行为零变化；
- flag on 无 task 引用 → ``degraded_no_snapshot`` 信封且形状符合
  decision_v21 版本信封（01 §28）；
- flag on 有 task（TaskFact fixture，手法参照 test_v21_state_service）
  → 正常 snapshot 信封 + 确定性（同输入同输出）；
- 故障注入：read_snapshot/ensure_ready/旁路评估抛异常 → 降级信封
  不上抛（D2 ``degraded_component_failure``）；
- envelope 不进入 GuardEvaluationResponse 任何字段。
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from agentguard_core import GuardEvent, PolicyBundle, utc_now_iso
from agentguard_core.authority.models import TaskFact
from agentguard_core.decisions.divergence import DIVERGENCE_VOCABULARY
from agentguard_core.decisions.models import RuleHit
from agentguard_core.decisions.results import DetectionResult
from agentguard_core.decisions.shadow import (
    ABSENT_SNAPSHOT_ID,
    shadow_assess_with_coverage,
)
from agentguard_core.engine import GuardEngine
from agentguard_core.events.payloads import (
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
)
from agentguard_core.security_context import PROJECTOR_VERSION, OnlineSecurityState
from guard_api.main import create_app
from guard_api.security_state import SecurityStateService
from guard_api.services import V21ShadowService
from guard_api.settings import GuardApiConfigurationError, GuardApiSettings
from guard_api.storage.base import SecurityStateRecord, TaskFactRecord
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.auth import memory_store_with_adapter

#: ≥32 字节的 base64url 测试密钥（形态与 checkpoint key 校验同口径）。
_TEST_SECRET = base64.urlsafe_b64encode(
    b"v21-08-shadow-test-secret-material"
).decode("ascii")

_SCOPE_DIGEST = "hmac-sha256:" + "ab" * 32
_TASK_ID = "task_shadow_fixture"


def _settings(
    *,
    shadow_enabled: bool = True,
    secret: str | None = _TEST_SECRET,
) -> GuardApiSettings:
    return GuardApiSettings(
        control_token="control-secret",
        storage_backend="memory",
        v21_shadow_enabled=shadow_enabled,
        v21_shadow_server_secret=secret,
    )


def _service(
    store: MemoryControlPlaneStore | None = None,
    *,
    settings: GuardApiSettings | None = None,
) -> tuple[V21ShadowService, MemoryControlPlaneStore]:
    store = store if store is not None else MemoryControlPlaneStore()
    state_service = SecurityStateService(store)
    service = V21ShadowService(
        settings=settings or _settings(),
        store=store,
        state_service=state_service,
    )
    return service, store


def _event(*, event_id: str = "evt_shadow_1", task_id: str | None = None) -> GuardEvent:
    metadata: dict[str, object] = {}
    if task_id is not None:
        metadata["task_id"] = task_id
    return GuardEvent(
        event_id=event_id,
        event_type="tool_call_proposed",
        runtime="langgraph",
        trace_id="trace_shadow_1",
        timestamp="2026-08-15T00:00:00+00:00",
        security_context=SecurityContext(agent_id="main", user_task="shadow fixture"),
        payload=ToolCallPayload(tool=ToolDescriptor(name="read_file")),
        metadata=metadata,
    )


def _task_fact() -> TaskFact:
    return TaskFact(
        task_id=_TASK_ID,
        scope_digest=_SCOPE_DIGEST,
        scope_key_id="scope_key_test",
        principal_id="principal_a",
        task_summary="shadow fixture task",
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


def _payload(envelope: dict) -> dict:
    """取 decision_v21 信封 payload（并断言信封形状符合 01 §28）。"""

    assert set(envelope) == {"decision_v21"}
    inner = envelope["decision_v21"]
    assert inner["schema_version"] == "2.1"
    assert isinstance(inner["payload"], dict)
    return inner["payload"]


# ---------------------------------------------------------------------------
# settings：flag 默认值与 secret 形态
# ---------------------------------------------------------------------------


def test_settings_flag_defaults_off(monkeypatch) -> None:
    monkeypatch.delenv("AGENTGUARD_V21_SHADOW_ENABLED", raising=False)
    assert GuardApiSettings().v21_shadow_enabled is False

    monkeypatch.setenv("AGENTGUARD_V21_SHADOW_ENABLED", "true")
    assert GuardApiSettings().v21_shadow_enabled is True
    monkeypatch.setenv("AGENTGUARD_V21_SHADOW_ENABLED", "not-a-bool")
    with pytest.raises(GuardApiConfigurationError):
        GuardApiSettings()


def test_settings_shadow_secret_validation() -> None:
    assert _settings().v21_shadow_server_secret_bytes() is not None
    assert (
        _settings(secret=None).v21_shadow_server_secret_bytes() is None
    )
    with pytest.raises(GuardApiConfigurationError):
        _settings(secret="!!!not-base64!!!").v21_shadow_server_secret_bytes()


# ---------------------------------------------------------------------------
# flag off：零行为变化（仅一次布尔判断，零 I/O）
# ---------------------------------------------------------------------------


def test_flag_off_returns_none_without_any_store_or_state_access(
    monkeypatch,
) -> None:
    service, store = _service(settings=_settings(shadow_enabled=False))
    assert service.enabled is False

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("flag off must not touch storage or state")

    monkeypatch.setattr(MemoryControlPlaneStore, "get_task_fact", _forbidden)
    monkeypatch.setattr(SecurityStateService, "ensure_ready", _forbidden)
    monkeypatch.setattr(SecurityStateService, "read_snapshot", _forbidden)
    assert store is not None  # 保留引用以明确作用域

    assert (
        service.build_shadow_evidence(
            _event(task_id=_TASK_ID),
            PolicyBundle(),
            legacy_decision="allow",
        )
        is None
    )


def test_flag_on_without_secret_returns_none() -> None:
    service, _ = _service(settings=_settings(secret=None))
    assert service.enabled is False
    assert (
        service.build_shadow_evidence(
            _event(), PolicyBundle(), legacy_decision="deny"
        )
        is None
    )


def test_flag_on_with_malformed_secret_disables_shadow() -> None:
    service, _ = _service(settings=_settings(secret="!!!bad!!!"))
    assert service.enabled is False
    assert (
        service.build_shadow_evidence(
            _event(), PolicyBundle(), legacy_decision="deny"
        )
        is None
    )


# ---------------------------------------------------------------------------
# flag on 无 task 引用 → degraded_no_snapshot 信封（01 §25 禁伪造 Snapshot）
# ---------------------------------------------------------------------------


def test_flag_on_no_task_reference_degraded_no_snapshot_envelope() -> None:
    service, store = _service()
    envelope = service.build_shadow_evidence(
        _event(), PolicyBundle(), legacy_decision="allow"
    )
    assert envelope is not None
    payload = _payload(envelope)

    assert payload["mode"] == "shadow"
    assert payload["legacy_decision"] == "allow"
    assert payload["final_decision"] == "allow"  # shadow 期官方决策者是 legacy
    assert payload["v21_fast_disposition"] == "DEFER"
    assert payload["divergence_category"] == "degraded_no_snapshot"
    assert payload["snapshot_id"] == ABSENT_SNAPSHOT_ID
    assert payload["state_version"] == 0
    assert payload["assessment_digest"].startswith("sha256:")
    assert payload["semantic_judgment_id"] is None  # V21-13 预留
    assert payload["semantic_digest"] is None
    # 七域 coverage 全域 unknown（缺态降级，fail-closed）。
    coverage = payload["coverage"]
    assert len(coverage) == 7
    assert all(domain["status"] == "unknown" for domain in coverage.values())
    # shadow 组件降级登记在案（divergence 降级优先的输入）。
    assert any(
        degradation_id.startswith("v21-08-shadow-degrade:")
        for degradation_id in payload["degradation_ids"]
    )
    # 无 task 引用不得创建任何安全状态行。
    assert store.get_security_state(_SCOPE_DIGEST) is None


def test_flag_on_task_claim_without_authoritative_fact_degrades() -> None:
    service, _ = _service()
    envelope = service.build_shadow_evidence(
        _event(task_id="task_missing"), PolicyBundle(), legacy_decision="deny"
    )
    assert envelope is not None
    payload = _payload(envelope)
    assert payload["divergence_category"] == "degraded_no_snapshot"
    assert payload["snapshot_id"] == ABSENT_SNAPSHOT_ID


# ---------------------------------------------------------------------------
# flag on 有 task → snapshot 信封 + 确定性
# ---------------------------------------------------------------------------


def test_flag_on_with_task_fact_produces_snapshot_envelope() -> None:
    service, store = _service()
    _commit_task_fact(store)

    event = _event(task_id=_TASK_ID)
    bundle = PolicyBundle()
    envelope = service.build_shadow_evidence(
        event, bundle, legacy_decision="deny", policy_revision="rev-1"
    )
    assert envelope is not None
    payload = _payload(envelope)

    assert payload["mode"] == "shadow"
    assert payload["legacy_decision"] == "deny"
    assert payload["final_decision"] == "deny"
    assert payload["snapshot_id"].startswith("v21-04-snapshot:")
    assert payload["snapshot_digest"].startswith("sha256:")
    assert payload["assessment_digest"].startswith("sha256:")
    assert payload["state_version"] >= 0
    # snapshot 存在时不得归入 snapshot 缺态降级类目；九宫格词表内（含 parity None）。
    assert payload["divergence_category"] != "degraded_no_snapshot"
    assert (
        payload["divergence_category"] is None
        or payload["divergence_category"] in DIVERGENCE_VOCABULARY
    )
    # ensure_ready 初始化了该 scope 的安全状态行（既有入口语义）。
    assert store.get_security_state(_SCOPE_DIGEST) is not None

    # 确定性：同输入必同输出（T-Replay 锚点语义）。
    replay = service.build_shadow_evidence(
        event, bundle, legacy_decision="deny", policy_revision="rev-1"
    )
    assert replay == envelope


def _seed_revoked_state(
    store: MemoryControlPlaneStore, revoked_grant_ids: list[str]
) -> None:
    """向 online state record 写入权威 revoked 集（CAS 推进一版）。"""

    state_service = SecurityStateService(store)
    if store.get_security_state(_SCOPE_DIGEST) is None:
        state_service.ensure_ready(_SCOPE_DIGEST)
    record = store.get_security_state(_SCOPE_DIGEST)
    assert record is not None
    state = OnlineSecurityState.model_validate(record.canonical_payload)
    next_version = record.state_version + 1
    updated = state.model_copy(
        update={
            "revoked_grant_ids": list(revoked_grant_ids),
            "state_version": next_version,
        }
    )
    assert store.cas_security_state(
        _SCOPE_DIGEST,
        record.state_version,
        SecurityStateRecord(
            scope_digest=_SCOPE_DIGEST,
            state_version=next_version,
            canonical_payload=updated.model_dump(mode="json"),
            dirty=False,
            dirty_domains=[],
            projector_version=PROJECTOR_VERSION,
            updated_at=utc_now_iso(),
        ),
    )


def test_flag_on_with_task_fact_injects_authoritative_revoked(monkeypatch) -> None:
    """V21-09 真实注入：有 snapshot 路径 revoked 恒取同源同锁权威值（D3）。

    入参桩值（即使非空）必须被存储层权威读取值覆盖，杜绝双源不一致。
    """
    service, store = _service()
    _commit_task_fact(store)
    _seed_revoked_state(store, ["grant:revoked_a"])

    captured: list[list[str]] = []
    original = shadow_assess_with_coverage

    def _spy(event, policies, snapshot, **kwargs):
        captured.append(list(kwargs.get("revoked_grant_ids", ())))
        return original(event, policies, snapshot, **kwargs)

    monkeypatch.setattr(
        "guard_api.services.v21_shadow.shadow_assess_with_coverage", _spy
    )
    envelope = service.build_shadow_evidence(
        _event(task_id=_TASK_ID),
        PolicyBundle(),
        legacy_decision="allow",
        revoked_grant_ids=["grant:stub_should_be_overridden"],
    )
    assert envelope is not None
    assert captured == [["grant:revoked_a"]]
    assert _payload(envelope)["divergence_category"] != "degraded_no_snapshot"


# ---------------------------------------------------------------------------
# 故障注入：snapshot 读取 / 旁路评估异常一律收敛为降级信封，不上抛
# ---------------------------------------------------------------------------


def test_snapshot_read_failure_converges_to_component_failure(
    monkeypatch,
) -> None:
    service, store = _service()
    _commit_task_fact(store)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated snapshot read failure")

    # V21-09 起 shadow 编排改经 read_snapshot_with_revoked（D3 同源同锁）。
    monkeypatch.setattr(SecurityStateService, "read_snapshot_with_revoked", _boom)
    envelope = service.build_shadow_evidence(
        _event(task_id=_TASK_ID), PolicyBundle(), legacy_decision="allow"
    )
    assert envelope is not None
    payload = _payload(envelope)
    assert payload["divergence_category"] == "degraded_component_failure"
    assert payload["snapshot_id"] == ABSENT_SNAPSHOT_ID
    assert payload["final_decision"] == "allow"


def test_ensure_ready_failure_converges_to_component_failure(
    monkeypatch,
) -> None:
    service, store = _service()
    _commit_task_fact(store)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated projector unavailability")

    monkeypatch.setattr(SecurityStateService, "ensure_ready", _boom)
    envelope = service.build_shadow_evidence(
        _event(task_id=_TASK_ID), PolicyBundle(), legacy_decision="ask"
    )
    assert envelope is not None
    assert (
        _payload(envelope)["divergence_category"]
        == "degraded_component_failure"
    )


def _detection_result(index: int) -> DetectionResult:
    return DetectionResult(
        decision="ask",
        risk_score=55,
        category="command_risk",
        rule_hit=RuleHit(
            rule_id=f"rule_{index:03d}",
            rule_name=f"rule {index}",
            severity="medium",
            evidence=[f"evidence-{index}"],
        ),
        reason="test fixture detection",
    )


def test_component_failure_envelope_preserves_injected_detection_results(
    monkeypatch,
) -> None:
    """S5：兜底降级信封必须透传调用方注入的 detection_results。

    snapshot 读取故障 → 兜底信封；注入的检测结果派生的 legacy
    signals 不得被静默丢弃（兜底路径与正常路径同源输入）。
    """
    service, store = _service()
    _commit_task_fact(store)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated snapshot read failure")

    # V21-09 起 shadow 编排改经 read_snapshot_with_revoked（D3 同源同锁）。
    monkeypatch.setattr(SecurityStateService, "read_snapshot_with_revoked", _boom)
    envelope = service.build_shadow_evidence(
        _event(task_id=_TASK_ID),
        PolicyBundle(),
        legacy_decision="allow",
        detection_results=[_detection_result(0), _detection_result(1)],
    )
    assert envelope is not None
    payload = _payload(envelope)
    assert payload["divergence_category"] == "degraded_component_failure"
    assert payload["snapshot_id"] == ABSENT_SNAPSHOT_ID
    # 注入检测结果派生的 legacy signals 在兜底信封中存活。
    assert len(payload["signal_ids"]) == 2
    # 组件故障降级登记在案（divergence 降级优先的输入）。
    assert payload["degradation_ids"]
    assert any(
        degradation_id.startswith("v21-08-shadow-degrade:")
        for degradation_id in payload["degradation_ids"]
    )


def test_bypass_evaluation_failure_converges_to_component_failure(
    monkeypatch,
) -> None:
    service, _ = _service()

    def _boom(self, event, policies=None):
        raise RuntimeError("simulated engine bypass failure")

    monkeypatch.setattr(GuardEngine, "evaluate_with_results", _boom)
    envelope = service.build_shadow_evidence(
        _event(), PolicyBundle(), legacy_decision="deny"
    )
    assert envelope is not None
    assert (
        _payload(envelope)["divergence_category"]
        == "degraded_component_failure"
    )


def test_unrecoverable_failure_returns_none_without_raising(monkeypatch) -> None:
    service, _ = _service()

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated total failure")

    monkeypatch.setattr(GuardEngine, "evaluate_with_results", _boom)
    monkeypatch.setattr(
        V21ShadowService, "_component_failure_envelope", _boom
    )
    assert (
        service.build_shadow_evidence(
            _event(), PolicyBundle(), legacy_decision="allow"
        )
        is None
    )


# ---------------------------------------------------------------------------
# create_app 注册与 evaluate 响应隔离（envelope 不进入响应任何字段）
# ---------------------------------------------------------------------------


def _evaluate_once_via_api(settings: GuardApiSettings) -> dict:
    app = create_app(store=memory_store_with_adapter(), settings=settings)
    client = TestClient(app)
    payload = {
        "schema_version": "0.3",
        "event_id": "evt_shadow_api_1",
        "event_type": "tool_call_proposed",
        "runtime": "langgraph",
        "trace_id": "trace_shadow_api",
        "timestamp": "2026-08-15T00:00:00+00:00",
        "security_context": {"agent_id": "main", "user_task": "fixture"},
        "payload": {
            "tool": {"name": "read_file"},
            "arguments": {},
            "derived_resources": [],
        },
        "metadata": {},
    }
    response = client.post(
        "/v1/guard/evaluate",
        headers={"Authorization": "Bearer adapter-secret"},
        json=payload,
    )
    assert response.status_code == 200
    return response.json()


def test_create_app_registers_services_and_response_excludes_envelope() -> None:
    flag_off = _evaluate_once_via_api(_settings(shadow_enabled=False))
    flag_on = _evaluate_once_via_api(_settings(shadow_enabled=True))

    # decision_v21 envelope 不进入 GuardEvaluationResponse 任何字段
    # （T4 不接线审计落盘；T5 也只写审计 evidence，不改响应）。
    assert "decision_v21" not in json.dumps(flag_off)
    assert "decision_v21" not in json.dumps(flag_on)
    # 响应顶层形状一致；官方决策不因 flag 改变。
    assert set(flag_off) == set(flag_on) == {
        "decision",
        "approval",
        "policy_audit_id",
    }
    assert flag_off["decision"]["decision"] == flag_on["decision"]["decision"]


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


def test_shadow_service_postgres_backend() -> None:
    store = _postgres_store()
    state_service = SecurityStateService(store)
    service = V21ShadowService(
        settings=_settings(), store=store, state_service=state_service
    )

    # 无 task 引用 → degraded_no_snapshot。
    absent = service.build_shadow_evidence(
        _event(event_id="evt_shadow_pg_1"),
        PolicyBundle(),
        legacy_decision="allow",
    )
    assert absent is not None
    assert _payload(absent)["divergence_category"] == "degraded_no_snapshot"

    # 有权威 TaskFact → snapshot 信封。
    _commit_task_fact(store)
    envelope = service.build_shadow_evidence(
        _event(event_id="evt_shadow_pg_2", task_id=_TASK_ID),
        PolicyBundle(),
        legacy_decision="deny",
    )
    assert envelope is not None
    payload = _payload(envelope)
    assert payload["snapshot_id"].startswith("v21-04-snapshot:")
    assert payload["divergence_category"] != "degraded_no_snapshot"
