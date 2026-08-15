"""V21-08 T5：guard-api 审计证据保存接线（shadow-only）测试。

覆盖 T5 验收口径（memory 后端为主，postgres 环境可用则覆盖）：

- flag off：evidence 形状与现状完全一致（8 键）、evaluate 响应不变；
- flag on（``AGENTGUARD_V21_SHADOW_ENABLED`` +
  ``AGENTGUARD_V21_SHADOW_SERVER_SECRET`` 已配置）：同一条
  policy_evaluation 审计记录内嵌 ``decision_v21`` 信封（01 §28 形状），
  不新增第二条审计记录；
- replay 幂等：同 event_id 重放返回原决策且 request_digest 不变
  （decision_v21 不进入 request digest 输入）；异内容仍 409；
- 历史无 decision_v21 记录在 flag on 下 replay 正常；
- 大 payload 下 evidence ≤64 KiB（enforce_evidence_budget 兜底）；
- 审计完整性链不回退（test_audit_integrity.py 最小口径）；
- 无 task 引用事件 → degraded_no_snapshot 信封落盘（01 §25 禁伪造
  Snapshot）。
"""

from __future__ import annotations

import base64
from typing import Any

from fastapi.testclient import TestClient

from agentguard_core import GuardEvent
from agentguard_core.authority.models import TaskFact
from agentguard_core.decisions.divergence import DIVERGENCE_VOCABULARY
from agentguard_core.decisions.shadow import ABSENT_SNAPSHOT_ID
from guard_api.main import create_app
from guard_api.services.evaluation import canonical_request_dump
from guard_api.services.redaction import (
    MAX_EVIDENCE_BYTES,
    evidence_serialized_size,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import AuditEventFilters, TaskFactRecord
from guard_api.storage.integrity import canonical_sha256
from tests.support.auth import add_adapter_credential, memory_store_with_adapter

#: ≥32 字节 base64url 测试密钥（形态与 checkpoint key 校验同口径）。
_TEST_SECRET = base64.urlsafe_b64encode(
    b"v21-08-audit-evidence-test-secret-material"
).decode("ascii")

_ADAPTER_HEADERS = {"Authorization": "Bearer adapter-secret"}

_SCOPE_DIGEST = "hmac-sha256:" + "12" * 32
_TASK_ID = "task_v21_08_audit_fixture"

_LEGACY_EVIDENCE_KEYS = {
    "guard_event",
    "guard_decision",
    "policy",
    "intervention",
    "execution",
    "side_effects",
    "result",
    "approval",
}


def _settings(
    *,
    shadow_enabled: bool,
    secret: str | None = _TEST_SECRET,
    max_request_body_bytes: int = 1_048_576,
) -> GuardApiSettings:
    return GuardApiSettings(
        control_token="control-secret",
        storage_backend="memory",
        v21_shadow_enabled=shadow_enabled,
        v21_shadow_server_secret=secret,
        max_request_body_bytes=max_request_body_bytes,
    )


def _client(store, *, shadow_enabled: bool) -> TestClient:
    return TestClient(
        create_app(store=store, settings=_settings(shadow_enabled=shadow_enabled))
    )


def _event_payload(
    *,
    event_id: str,
    trace_id: str,
    arguments: dict[str, Any] | None = None,
    task_id: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if task_id is not None:
        metadata["task_id"] = task_id
    return {
        "schema_version": "0.3",
        "event_id": event_id,
        "event_type": "tool_call_proposed",
        "runtime": "langgraph",
        "trace_id": trace_id,
        "timestamp": "2026-08-15T00:00:00+00:00",
        "security_context": {
            "user_task": "complete the visible task only",
            "source_type": "webpage",
            "source_trust": "untrusted",
            "agent_id": "main",
        },
        "payload": {
            "tool": {
                "name": "read_file",
                "category": "filesystem",
                "kind": "file_read",
                "call_id": f"call_{event_id}",
            },
            "arguments": arguments or {"path": "notes/meeting-summary.txt"},
            "derived_resources": [],
        },
        "metadata": metadata,
    }


def _post_evaluate(client: TestClient, payload: dict[str, Any]):
    return client.post("/v1/guard/evaluate", headers=_ADAPTER_HEADERS, json=payload)


def _policy_audits(store, trace_id: str):
    return store.list_audit_events(AuditEventFilters(trace_id=trace_id))


def _commit_task_fact(store) -> None:
    task_fact = TaskFact(
        task_id=_TASK_ID,
        scope_digest=_SCOPE_DIGEST,
        scope_key_id="scope_key_test",
        principal_id="principal_a",
        task_summary="v21-08 audit evidence fixture task",
        task_digest="sha256:" + "34" * 32,
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
    store.create_task_fact(
        TaskFactRecord(
            task_fact=task_fact,
            canonical_payload=task_fact.model_dump(mode="json"),
            request_digest="sha256:" + "56" * 32,
            expected_revision=0,
            created_at="2026-08-15T00:00:00Z",
        )
    )


def _envelope_payload(evidence: dict[str, Any]) -> dict[str, Any]:
    """取落盘 evidence 内嵌 decision_v21 信封的 payload（01 §28 形状）。"""

    assert "decision_v21" in evidence
    inner = evidence["decision_v21"]
    assert inner["schema_version"] == "2.1"
    payload = inner["payload"]
    assert isinstance(payload, dict)
    return payload


# ---------------------------------------------------------------------------
# flag off：evidence 形状与响应零变化
# ---------------------------------------------------------------------------


def test_flag_off_evidence_shape_and_response_unchanged() -> None:
    store_off = memory_store_with_adapter()
    store_on = memory_store_with_adapter()
    payload = _event_payload(
        event_id="evt_v21_08_flag_compare", trace_id="trace_v21_08_flag_compare"
    )

    flag_off = _post_evaluate(_client(store_off, shadow_enabled=False), payload).json()
    flag_on = _post_evaluate(_client(store_on, shadow_enabled=True), payload).json()

    # flag off：evidence 键集与现状完全一致（不插入任何键）。
    evidence_off = _policy_audits(store_off, "trace_v21_08_flag_compare")[0].evidence
    assert set(evidence_off) == _LEGACY_EVIDENCE_KEYS

    # 响应形状不因 flag 改变；官方决策恒为 legacy。
    assert (
        set(flag_off)
        == set(flag_on)
        == {
            "decision",
            "approval",
            "policy_audit_id",
        }
    )
    assert flag_off["decision"]["decision"] == flag_on["decision"]["decision"]
    assert flag_off["decision"]["risk_score"] == flag_on["decision"]["risk_score"]
    assert flag_off["decision"]["severity"] == flag_on["decision"]["severity"]


# ---------------------------------------------------------------------------
# flag on：同一条审计记录内嵌 decision_v21 信封，不新增第二条记录
# ---------------------------------------------------------------------------


def test_flag_on_embeds_envelope_in_single_audit_record() -> None:
    store = memory_store_with_adapter()
    payload = _event_payload(event_id="evt_v21_08_embed", trace_id="trace_v21_08_embed")

    response = _post_evaluate(_client(store, shadow_enabled=True), payload)
    assert response.status_code == 200

    audits = _policy_audits(store, "trace_v21_08_embed")
    # 不新增第二条审计记录（审计全局 advisory lock 写放大防护，D4）。
    assert len(audits) == 1
    evidence = audits[0].evidence
    assert set(evidence) == _LEGACY_EVIDENCE_KEYS | {"decision_v21"}

    decision_v21 = _envelope_payload(evidence)
    # shadow 期官方决策者恒为 legacy（04 §1-§2）。
    assert decision_v21["legacy_decision"] == response.json()["decision"]["decision"]
    assert decision_v21["final_decision"] == response.json()["decision"]["decision"]
    assert decision_v21["mode"] == "shadow"


def test_flag_on_no_task_reference_persists_degraded_no_snapshot() -> None:
    store = memory_store_with_adapter()
    payload = _event_payload(
        event_id="evt_v21_08_degraded", trace_id="trace_v21_08_degraded"
    )
    assert (
        _post_evaluate(_client(store, shadow_enabled=True), payload).status_code == 200
    )

    evidence = _policy_audits(store, "trace_v21_08_degraded")[0].evidence
    payload_v21 = _envelope_payload(evidence)
    # 无 task 引用 → 禁伪造 Snapshot（01 §25），落 degraded_no_snapshot。
    assert payload_v21["divergence_category"] == "degraded_no_snapshot"
    assert payload_v21["snapshot_id"] == ABSENT_SNAPSHOT_ID
    assert payload_v21["state_version"] == 0
    assert payload_v21["assessment_digest"].startswith("sha256:")
    # 无 task 引用不得创建任何安全状态行。
    assert store.get_security_state(_SCOPE_DIGEST) is None


def test_flag_on_with_task_fact_persists_snapshot_envelope() -> None:
    store = memory_store_with_adapter()
    _commit_task_fact(store)
    payload = _event_payload(
        event_id="evt_v21_08_snapshot",
        trace_id="trace_v21_08_snapshot",
        task_id=_TASK_ID,
    )
    assert (
        _post_evaluate(_client(store, shadow_enabled=True), payload).status_code == 200
    )

    evidence = _policy_audits(store, "trace_v21_08_snapshot")[0].evidence
    payload_v21 = _envelope_payload(evidence)
    # snapshot 可读时不得归入 snapshot 缺态降级类目；九宫格词表内（含 parity None）。
    assert payload_v21["divergence_category"] != "degraded_no_snapshot"
    assert (
        payload_v21["divergence_category"] is None
        or payload_v21["divergence_category"] in DIVERGENCE_VOCABULARY
    )
    assert payload_v21["snapshot_id"].startswith("v21-04-snapshot:")


# ---------------------------------------------------------------------------
# replay 幂等：decision_v21 不进入 request digest 输入
# ---------------------------------------------------------------------------


def test_flag_on_replay_idempotent_and_digest_invariant() -> None:
    store = memory_store_with_adapter()
    payload = _event_payload(
        event_id="evt_v21_08_replay", trace_id="trace_v21_08_replay"
    )
    client = _client(store, shadow_enabled=True)

    first = _post_evaluate(client, payload)
    second = _post_evaluate(client, payload)
    assert first.status_code == 200
    assert second.status_code == 200
    assert (
        second.json()["decision"]["decision_id"]
        == first.json()["decision"]["decision_id"]
    )

    audits = _policy_audits(store, "trace_v21_08_replay")
    assert len(audits) == 1
    # request_digest 与 canonical_request_dump 口径一致且不受 decision_v21 影响。
    expected_digest = canonical_sha256(
        canonical_request_dump(GuardEvent.model_validate(payload))
    )
    assert audits[0].metadata["request_digest"] == expected_digest
    assert "decision_v21" in audits[0].evidence

    # 异内容同 event_id 仍 409。
    conflict = _post_evaluate(
        client,
        _event_payload(
            event_id="evt_v21_08_replay",
            trace_id="trace_v21_08_replay",
            arguments={"path": "other/file.txt"},
        ),
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "EVALUATION_CONFLICT"
    assert len(_policy_audits(store, "trace_v21_08_replay")) == 1


def test_legacy_record_without_envelope_replays_under_flag_on() -> None:
    store = memory_store_with_adapter()
    payload = _event_payload(
        event_id="evt_v21_08_legacy_replay", trace_id="trace_v21_08_legacy_replay"
    )

    # 历史路径：flag off 写入的记录不携带 decision_v21。
    first = _post_evaluate(_client(store, shadow_enabled=False), payload)
    assert first.status_code == 200
    audits = _policy_audits(store, "trace_v21_08_legacy_replay")
    assert "decision_v21" not in audits[0].evidence

    # flag on 实例重放历史记录：照常返回原决策，不改写历史记录。
    replay = _post_evaluate(_client(store, shadow_enabled=True), payload)
    assert replay.status_code == 200
    assert (
        replay.json()["decision"]["decision_id"]
        == first.json()["decision"]["decision_id"]
    )
    audits = _policy_audits(store, "trace_v21_08_legacy_replay")
    assert len(audits) == 1
    assert "decision_v21" not in audits[0].evidence


# ---------------------------------------------------------------------------
# evidence 预算（64 KiB）与审计完整性链
# ---------------------------------------------------------------------------


def test_flag_on_large_payload_evidence_within_budget() -> None:
    store = memory_store_with_adapter()
    payload = _event_payload(
        event_id="evt_v21_08_budget",
        trace_id="trace_v21_08_budget",
        arguments={"content": "agentguard-budget-probe-" * 6000},  # ≈147 KiB
    )
    response = _post_evaluate(_client(store, shadow_enabled=True), payload)
    assert response.status_code == 200

    evidence = _policy_audits(store, "trace_v21_08_budget")[0].evidence
    assert evidence_serialized_size(evidence) <= MAX_EVIDENCE_BYTES
    # 截断投影不丢 replay 权威快照；信封随预算兼容后仍在（或整体兜底）。
    assert evidence.get("guard_decision") is not None or evidence.get("_truncated")
    if "decision_v21" in evidence:
        assert evidence["decision_v21"]["schema_version"] == "2.1"


def test_flag_on_audit_integrity_chain_not_regressed() -> None:
    store = memory_store_with_adapter()
    for index in range(3):
        payload = _event_payload(
            event_id=f"evt_v21_08_integrity_{index}",
            trace_id=f"trace_v21_08_integrity_{index}",
        )
        assert (
            _post_evaluate(_client(store, shadow_enabled=True), payload).status_code
            == 200
        )

    # test_audit_integrity.py 最小口径：完整性链全绿。
    status = store.verify_audit_integrity()
    assert status.valid is True
    assert status.event_count >= 3
    assert status.first_broken_audit_id is None


# ---------------------------------------------------------------------------
# postgres 后端（环境可用则覆盖，不可用自动跳过）
# ---------------------------------------------------------------------------


def test_v21_08_audit_evidence_postgres_backend() -> None:
    from guard_api.storage.postgres import PostgresControlPlaneStore
    from tests.support.postgres import (
        get_test_database_url,
        reset_control_plane_schema,
    )

    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    store = PostgresControlPlaneStore(database_url)
    store.initialize()
    add_adapter_credential(store)

    payload = _event_payload(event_id="evt_v21_08_pg", trace_id="trace_v21_08_pg")
    client = _client(store, shadow_enabled=True)
    first = _post_evaluate(client, payload)
    replay = _post_evaluate(client, payload)
    assert first.status_code == 200
    assert replay.status_code == 200
    assert (
        replay.json()["decision"]["decision_id"]
        == first.json()["decision"]["decision_id"]
    )

    audits = _policy_audits(store, "trace_v21_08_pg")
    assert len(audits) == 1
    assert "decision_v21" in audits[0].evidence
    assert _envelope_payload(audits[0].evidence)["mode"] == "shadow"
    assert evidence_serialized_size(audits[0].evidence) <= MAX_EVIDENCE_BYTES
    status = store.verify_audit_integrity()
    assert status.valid is True
