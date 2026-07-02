from __future__ import annotations

from fastapi.testclient import TestClient

from guard_api.main import create_app
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
        "expected_hook_count": 19,
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
    assert write_response.json()["hook_count"] == 19
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
        "hook_count": 19,
        "expected_hook_count": 19,
        "last_verified_at": "2026-06-28T00:00:00+00:00",
        "error": None,
        "source": "agentguardctl",
    }
