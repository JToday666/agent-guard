from __future__ import annotations

# Dashboard-facing Guard API capability regressions.

import hashlib

from fastapi.testclient import TestClient

from agentguard_core import AuditEvent
from guard_api.main import create_app
from guard_api.models import CredentialRecord
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore


def test_evaluation_run_import_and_latest_requires_control_write_and_browser_or_control_read() -> None:
    app = create_app(
        store=MemoryControlPlaneStore(),
        settings=GuardApiSettings(adapter_token="adapter-secret", control_token="control-secret"),
    )
    client = TestClient(app)

    _login_dashboard(client)
    missing_response = client.get("/v1/evaluations/latest")
    assert missing_response.status_code == 404
    assert missing_response.json()["error"]["code"] == "EVALUATION_NOT_FOUND"

    payload = _evaluation_run_payload(run_id="eval_older", run_at="2026-06-20T00:00:00+00:00")
    adapter_response = client.post(
        "/v1/evaluations",
        headers={"Authorization": "Bearer adapter-secret"},
        json=payload,
    )
    assert adapter_response.status_code == 403
    assert adapter_response.json()["error"]["code"] == "SCOPE_DENIED"

    control_response = client.post(
        "/v1/evaluations",
        headers={"Authorization": "Bearer control-secret"},
        json=payload,
    )
    assert control_response.status_code == 200
    assert control_response.json()["run_id"] == "eval_older"

    newer_payload = _evaluation_run_payload(run_id="eval_newer", run_at="2026-06-21T00:00:00+00:00")
    assert client.post(
        "/v1/evaluations",
        headers={"Authorization": "Bearer control-secret"},
        json=newer_payload,
    ).status_code == 200

    browser_latest = client.get("/v1/evaluations/latest")
    control_latest = client.get(
        "/v1/evaluations/latest",
        headers={"Authorization": "Bearer control-secret"},
    )

    assert browser_latest.status_code == 200
    assert browser_latest.json()["run_id"] == "eval_newer"
    assert browser_latest.json()["asr_before"] == 0.72
    assert browser_latest.json()["asr_after"] == 0.08
    assert browser_latest.json()["cases"][0]["blocked"] is True
    assert control_latest.status_code == 200
    assert control_latest.json()["run_id"] == "eval_newer"


def test_evaluation_run_rejects_invalid_asr_range() -> None:
    app = create_app(
        store=MemoryControlPlaneStore(),
        settings=GuardApiSettings(control_token="control-secret"),
    )
    client = TestClient(app)

    response = client.post(
        "/v1/evaluations",
        headers={"Authorization": "Bearer control-secret"},
        json={
            **_evaluation_run_payload(),
            "asr_before": 1.2,
        },
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_config_audit_findings_can_be_read_with_filters() -> None:
    app = create_app(
        store=MemoryControlPlaneStore(),
        settings=GuardApiSettings(adapter_token="adapter-secret", control_token="control-secret"),
    )
    client = TestClient(app)
    response = client.post(
        "/v1/config-audit/evaluate",
        headers={"Authorization": "Bearer adapter-secret"},
        json={
            "event_id": "cfg_findings",
            "runtime": "openclaw",
            "target_type": "plugin_config",
            "target_id": "agentguard-security",
            "action": "before_install",
            "timestamp": "2026-06-28T00:00:00+00:00",
            "metadata": {"trace_id": "trace_cfg_findings"},
            "findings": [
                {
                    "finding_id": "finding_cfg_high",
                    "severity": "high",
                    "category": "openclaw.plugin",
                    "title": "Raw conversation access enabled",
                    "subject": "hooks.allowConversationAccess",
                    "description": "Plugin can read raw conversation content.",
                    "evidence": ["allowConversationAccess=true"],
                    "recommendation": "Disable raw conversation access unless required.",
                }
            ],
        },
    )
    assert response.status_code == 200
    _login_dashboard(client)

    findings_response = client.get(
        "/v1/config-audit/findings"
        "?trace_id=trace_cfg_findings&target_id=agentguard-security&severity=high"
    )
    adapter_read = client.get(
        "/v1/config-audit/findings",
        headers={"Authorization": "Bearer adapter-secret"},
    )

    assert findings_response.status_code == 200
    rows = findings_response.json()
    assert len(rows) == 1
    assert rows[0]["runtime"] == "openclaw"
    assert rows[0]["target_type"] == "plugin_config"
    assert rows[0]["target_id"] == "agentguard-security"
    assert rows[0]["trace_id"] == "trace_cfg_findings"
    assert rows[0]["event_id"] == "cfg_findings"
    assert rows[0]["timestamp"] == "2026-06-28T00:00:00+00:00"
    assert rows[0]["finding"]["title"] == "Raw conversation access enabled"
    assert adapter_read.status_code == 403
    assert adapter_read.json()["error"]["code"] == "SCOPE_DENIED"


def test_openclaw_adapter_status_can_be_recorded_and_read() -> None:
    app = create_app(
        store=MemoryControlPlaneStore(),
        settings=GuardApiSettings(adapter_token="adapter-secret", control_token="control-secret"),
    )
    client = TestClient(app)
    _login_dashboard(client)

    unknown_response = client.get("/v1/adapters/openclaw/status")
    assert unknown_response.status_code == 200
    assert unknown_response.json() == {
        "status": "unknown",
        "loaded": False,
        "hook_count": None,
        "expected_hook_count": 22,
        "last_verified_at": None,
        "error": None,
        "source": None,
    }

    adapter_write = client.put(
        "/v1/adapters/openclaw/status",
        headers={"Authorization": "Bearer adapter-secret"},
        json=_openclaw_status_payload(),
    )
    assert adapter_write.status_code == 403
    assert adapter_write.json()["error"]["code"] == "SCOPE_DENIED"

    write_response = client.put(
        "/v1/adapters/openclaw/status",
        headers={"Authorization": "Bearer control-secret"},
        json=_openclaw_status_payload(),
    )
    read_response = client.get("/v1/adapters/openclaw/status")

    assert write_response.status_code == 200
    assert write_response.json()["status"] == "loaded"
    assert write_response.json()["hook_count"] == 22
    assert read_response.status_code == 200
    assert read_response.json() == write_response.json()


def _login_dashboard(client: TestClient) -> None:
    launch_response = client.post(
        "/v1/auth/browser/launch",
        headers={"Authorization": "Bearer control-secret"},
    )
    assert launch_response.status_code == 200
    exchange_response = client.post(
        "/v1/auth/browser/exchange",
        json={"launch_code": launch_response.json()["launch_code"]},
    )
    assert exchange_response.status_code == 200


def _evaluation_run_payload(
    *,
    run_id: str = "eval_test",
    run_at: str = "2026-06-20T00:00:00+00:00",
) -> dict:
    return {
        "run_id": run_id,
        "run_at": run_at,
        "asr_before": 0.72,
        "asr_after": 0.08,
        "per_attack": {
            "prompt_injection": {"asr_before": 0.8, "asr_after": 0.1},
        },
        "cases": [
            {
                "case_id": "PI-001",
                "attack_type": "prompt_injection",
                "runtime": "openclaw",
                "expected_decision": "deny",
                "actual_decision": "ask",
                "blocked": True,
                "attack_success": False,
                "trace_id": "trace_eval_001",
            }
        ],
    }


def _openclaw_status_payload() -> dict:
    return {
        "status": "loaded",
        "loaded": True,
        "hook_count": 22,
        "expected_hook_count": 22,
        "last_verified_at": "2026-06-28T00:00:00+00:00",
        "error": None,
        "source": "agentguardctl",
    }


# 契约 §5/§6/§14：原子审计窗口与 policy_evaluation cohort HTTP 层回归。


def _window_app() -> tuple[MemoryControlPlaneStore, TestClient]:
    store = MemoryControlPlaneStore()
    app = create_app(
        store=store,
        settings=GuardApiSettings(
            adapter_token="adapter-secret", control_token="control-secret"
        ),
    )
    return store, TestClient(app)


def _window_policy_audit(
    *, index: int, decision: str = "allow", trace_id: str = "trace_http_window"
) -> AuditEvent:
    return AuditEvent(
        audit_id=f"audit_http_window_{index}",
        schema_version="0.4",
        record_type="policy_evaluation",
        trace_id=trace_id,
        timestamp=f"2026-08-01T00:0{index}:00+00:00",
        summary=f"HTTP window record {index}",
        decision=decision,
        risk_score=5,
        severity="low",
        blocked=decision in {"ask", "deny"},
        reason="HTTP window fixture.",
        links={"event_id": f"evt_http_window_{index}", "decision_id": f"dec_http_window_{index}"},
    )


def test_audit_window_requires_dual_scopes_for_bearer() -> None:
    store, client = _window_app()
    for index in range(2):
        store.add_audit_event(_window_policy_audit(index=index))

    # control 同时具备 audit:read 与 metrics:read。
    control_response = client.get(
        "/v1/audit/window",
        headers={"Authorization": "Bearer control-secret"},
    )
    assert control_response.status_code == 200
    body = control_response.json()
    assert body["scope"]["kind"] == "audit_window"
    assert body["scope"]["order"] == "audit_sequence"
    assert body["scope"]["returned_record_count"] == 2
    assert body["policy_metrics"]["metric_version"] == "policy_evaluation.v2"

    # adapter 两个 scope 都缺失。
    adapter_response = client.get(
        "/v1/audit/window", headers={"Authorization": "Bearer adapter-secret"}
    )
    assert adapter_response.status_code == 403
    assert adapter_response.json()["error"]["code"] == "SCOPE_DENIED"

    # 只持单一 scope 的凭证同样被拒（契约 §5.1）。
    for scopes in (("audit:read",), ("metrics:read",)):
        token = f"single-scope-{scopes[0]}"
        store.create_credential(
            CredentialRecord(
                credential_id=f"cred_window_{scopes[0].replace(':', '_')}",
                token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
                principal_type="cli",
                principal_id=f"principal_{scopes[0]}",
                role="viewer",
                scopes=list(scopes),
            )
        )
        single_response = client.get(
            "/v1/audit/window", headers={"Authorization": f"Bearer {token}"}
        )
        assert single_response.status_code == 403
        assert single_response.json()["error"]["code"] == "SCOPE_DENIED"

    # browser session 允许读取。
    _login_dashboard(client)
    browser_response = client.get("/v1/audit/window")
    assert browser_response.status_code == 200
    assert browser_response.json()["scope"]["returned_record_count"] == 2


def test_audit_window_cursor_scope_mismatch_and_expired() -> None:
    store, client = _window_app()
    for index in range(4):
        store.add_audit_event(_window_policy_audit(index=index))
    headers = {"Authorization": "Bearer control-secret"}

    first = client.get("/v1/audit/window?limit=2", headers=headers)
    assert first.status_code == 200
    cursor = first.json()["scope"]["next_cursor"]
    assert cursor

    # filters 与 cursor 作用域不一致 → 400 CURSOR_SCOPE_MISMATCH。
    mismatch_filters = client.get(
        f"/v1/audit/window?limit=2&cursor={cursor}&trace_id=other", headers=headers
    )
    assert mismatch_filters.status_code == 400
    assert mismatch_filters.json()["error"]["code"] == "CURSOR_SCOPE_MISMATCH"

    # limit 与 cursor 绑定值不一致同样视为作用域不一致。
    mismatch_limit = client.get(
        f"/v1/audit/window?limit=3&cursor={cursor}", headers=headers
    )
    assert mismatch_limit.status_code == 400
    assert mismatch_limit.json()["error"]["code"] == "CURSOR_SCOPE_MISMATCH"

    # 无法解码的 cursor → 410 CURSOR_EXPIRED。
    expired = client.get("/v1/audit/window?cursor=not-a-cursor", headers=headers)
    assert expired.status_code == 410
    assert expired.json()["error"]["code"] == "CURSOR_EXPIRED"

    # 同作用域续页成功且快照不变。
    second = client.get(f"/v1/audit/window?limit=2&cursor={cursor}", headers=headers)
    assert second.status_code == 200
    assert second.json()["scope"]["snapshot_id"] == first.json()["scope"]["snapshot_id"]
    assert second.json()["scope"]["has_more"] is False


def test_policy_evaluation_cohort_range_required_and_utc_normalized() -> None:
    store, client = _window_app()
    for index in range(5):
        store.add_audit_event(_window_policy_audit(index=index))
    headers = {"Authorization": "Bearer control-secret"}

    missing = client.get("/v1/metrics/policy-evaluations", headers=headers)
    assert missing.status_code == 400
    assert missing.json()["error"]["code"] == "COHORT_RANGE_MISSING"

    # +08:00 偏移规范化为 UTC；outcomes_as_of 缺省回显请求快照时刻。
    response = client.get(
        "/v1/metrics/policy-evaluations"
        "?evaluated_from=2026-08-01T08:00:00%2B08:00"
        "&evaluated_to=2026-08-01T08:06:00%2B08:00",
        headers=headers,
    )
    assert response.status_code == 200
    scope = response.json()["scope"]
    assert scope["kind"] == "aggregate_history"
    assert scope["evaluated_from"] == "2026-08-01T00:00:00Z"
    assert scope["evaluated_to"] == "2026-08-01T00:06:00Z"
    assert scope["outcomes_as_of"].endswith("Z")
    assert scope["deduplication"] == "logical_policy_evaluation"
    assert scope["snapshot_id"]
    assert response.json()["policy_metrics"]["evaluation_count"] == 5

    echo = client.get(
        "/v1/metrics/policy-evaluations"
        "?evaluated_from=2026-08-01T00:00:00Z"
        "&evaluated_to=2026-08-01T00:06:00Z"
        "&outcomes_as_of=2026-08-02T00:00:00%2B00:00",
        headers=headers,
    )
    assert echo.status_code == 200
    assert echo.json()["scope"]["outcomes_as_of"] == "2026-08-02T00:00:00Z"

    # cohort 端点只需 metrics:read；缺 scope 的 bearer 被拒。
    adapter_response = client.get(
        "/v1/metrics/policy-evaluations"
        "?evaluated_from=2026-08-01T00:00:00Z&evaluated_to=2026-08-02T00:00:00Z",
        headers={"Authorization": "Bearer adapter-secret"},
    )
    assert adapter_response.status_code == 403
    assert adapter_response.json()["error"]["code"] == "SCOPE_DENIED"


def test_audit_window_flag_disabled_returns_404(monkeypatch) -> None:
    monkeypatch.delenv("AGENTGUARD_AUDIT_WINDOW_ENABLED", raising=False)
    settings = GuardApiSettings(
        adapter_token="adapter-secret",
        control_token="control-secret",
        audit_window_enabled=False,
    )
    client = TestClient(create_app(store=MemoryControlPlaneStore(), settings=settings))
    headers = {"Authorization": "Bearer control-secret"}

    window_response = client.get("/v1/audit/window", headers=headers)
    assert window_response.status_code == 404
    assert window_response.json()["error"]["code"] == "NOT_FOUND"

    cohort_response = client.get(
        "/v1/metrics/policy-evaluations"
        "?evaluated_from=2026-08-01T00:00:00Z&evaluated_to=2026-08-02T00:00:00Z",
        headers=headers,
    )
    assert cohort_response.status_code == 404
    assert cohort_response.json()["error"]["code"] == "NOT_FOUND"


def test_audit_window_flag_defaults_follow_environment(monkeypatch) -> None:
    monkeypatch.delenv("AGENTGUARD_AUDIT_WINDOW_ENABLED", raising=False)
    monkeypatch.setenv("AGENTGUARD_ENV", "development")
    assert GuardApiSettings().audit_window_enabled is True
    monkeypatch.setenv("AGENTGUARD_ENV", "production")
    assert GuardApiSettings().audit_window_enabled is False
    monkeypatch.setenv("AGENTGUARD_AUDIT_WINDOW_ENABLED", "true")
    assert GuardApiSettings().audit_window_enabled is True
    monkeypatch.setenv("AGENTGUARD_AUDIT_WINDOW_ENABLED", "0")
    assert GuardApiSettings().audit_window_enabled is False
