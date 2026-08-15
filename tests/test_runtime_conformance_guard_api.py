"""RTE-04 Conformance Suite — Guard API 幂等/冲突语义（CF-10/CF-11）。

契约 05 §3 CF-10/CF-11 与 02 §12.3：
- same event_id + same digest → idempotent replay；different content → conflict；
- same audit_id + same content → idempotent；different content → 409。

两个 runtime（LangGraph/OpenClaw）共享同一 Guard API 后端，故矩阵中各自
CF-10/11 条目均以本文件为 evidence。复用 ``tests/test_guard_api.py`` 的
payload/store harness，保持与既有端点测试同一口径。
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from guard_api.main import create_app
from guard_api.settings import GuardApiSettings
from tests.support.auth import memory_store_with_adapter
from tests.test_guard_api import (
    _audit_event_payload,
    _evaluate_client_and_store,
    _guard_event_payload,
    _post_evaluate,
    _runtime_outcome_payload,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tests" / "runtime_conformance" / "contract_cases.json"

ADAPTER_HEADERS = {"Authorization": "Bearer adapter-secret"}


def _case(case_id: str) -> dict:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    for case in registry["cases"]:
        if case["id"] == case_id:
            return case
    raise AssertionError(f"case {case_id} missing from contract_cases.json")


def test_cf_10_same_event_same_content_is_idempotent_replay() -> None:
    case = _case("CF-10")
    assert case["expect"]["same_content"] == "idempotent_replay"
    client, store = _evaluate_client_and_store()
    payload = _guard_event_payload(event_id="evt_cf10_replay")

    first = _post_evaluate(client, payload)
    second = _post_evaluate(client, payload)

    assert first.status_code == 200
    assert second.status_code == 200
    # 幂等重放必须返回同一决策与审批，且不产生重复策略审计。
    assert (
        second.json()["decision"]["decision_id"]
        == first.json()["decision"]["decision_id"]
    )
    assert second.json()["approval"] == first.json()["approval"]
    assert len(store.audit_events) == 1


def test_cf_10_same_event_different_content_is_conflict() -> None:
    case = _case("CF-10")
    assert case["expect"]["different_content"] == "conflict"
    client, store = _evaluate_client_and_store()

    first = _post_evaluate(client, _guard_event_payload(event_id="evt_cf10_conflict"))
    second = _post_evaluate(
        client,
        _guard_event_payload(
            event_id="evt_cf10_conflict",
            arguments={"to": "different-recipient@red-team.agentguard.local"},
        ),
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "EVALUATION_CONFLICT"
    # 冲突不得覆盖或新增权威记录。
    assert len(store.audit_events) == 1
    assert store.audit_events[0].links["event_id"] == "evt_cf10_conflict"


def _runtime_outcome_client_and_receipt() -> tuple[TestClient, dict]:
    settings = GuardApiSettings(control_token="control-secret")
    store = memory_store_with_adapter()
    client = TestClient(create_app(store=store, settings=settings))
    evaluation = client.post(
        "/v1/guard/evaluate",
        headers=ADAPTER_HEADERS,
        json=_guard_event_payload(event_id="evt_cf11_parent"),
    )
    assert evaluation.status_code == 200
    parent = store.get_audit_event(evaluation.json()["policy_audit_id"])
    assert parent is not None
    return client, _runtime_outcome_payload(parent)


def test_cf_11_same_receipt_same_content_is_idempotent() -> None:
    case = _case("CF-11")
    assert case["expect"]["same_content"] == "idempotent_replay"
    client, receipt = _runtime_outcome_client_and_receipt()

    first = client.post("/v1/audit/events", headers=ADAPTER_HEADERS, json=receipt)
    replay = client.post("/v1/audit/events", headers=ADAPTER_HEADERS, json=receipt)

    assert first.status_code == 200
    assert first.json()["created"] is True
    assert replay.status_code == 200
    assert replay.json()["idempotent_replay"] is True
    assert replay.json()["audit_id"] == receipt["audit_id"]


def test_cf_11_same_receipt_different_content_is_conflict() -> None:
    case = _case("CF-11")
    assert case["expect"]["different_content"] == "conflict"
    client, receipt = _runtime_outcome_client_and_receipt()

    first = client.post("/v1/audit/events", headers=ADAPTER_HEADERS, json=receipt)
    assert first.status_code == 200

    # 同 audit_id 不同内容：runtime_outcome 以父绑定一致性冲突拒收。
    mismatch = client.post(
        "/v1/audit/events",
        headers=ADAPTER_HEADERS,
        json={**receipt, "risk_score": int(receipt["risk_score"]) - 1},
    )
    assert mismatch.status_code == 409
    assert mismatch.json()["error"]["code"] == "RUNTIME_OUTCOME_PARENT_MISMATCH"

    # 通用审计事件同 audit_id 不同内容走 AUDIT_ID_CONFLICT 口径。
    generic = _audit_event_payload(
        audit_id="audit_cf11_generic",
        trace_id="trace_cf11_generic",
        decision="allow",
        runtime="langgraph",
        blocked=False,
    )
    assert (
        client.post(
            "/v1/audit/events", headers=ADAPTER_HEADERS, json=generic
        ).status_code
        == 200
    )
    conflict = client.post(
        "/v1/audit/events",
        headers=ADAPTER_HEADERS,
        json={**generic, "decision": "deny", "blocked": True, "risk_score": 90},
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "AUDIT_ID_CONFLICT"
