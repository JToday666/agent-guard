from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import httpx
import pytest

from agentguard_cli import cli

def _run_cli(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    transport: httpx.MockTransport | None = None,
    run_command=None,
):
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = cli.run(
        argv,
        env=env or {},
        stdout=stdout,
        stderr=stderr,
        transport=transport,
        run_command=run_command,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue()


def test_health_uses_host_and_port_default_api_url() -> None:
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(200, json={"status": "ok"})

    exit_code, output, error = _run_cli(
        ["health", "--json"],
        env={"AGENTGUARD_HOST": "127.0.0.5", "AGENTGUARD_PORT": "9090"},
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 0
    assert json.loads(output) == {"status": "ok"}
    assert error == ""
    assert seen_urls == ["http://127.0.0.5:9090/health"]


def test_health_check_db_requests_database_health() -> None:
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(200, json={"status": "ok", "database": "ok"})

    exit_code, output, error = _run_cli(
        ["health", "--check-db"],
        env={"AGENTGUARD_API_URL": "https://guard.local"},
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 0
    assert output == "Guard API: ok, database: ok\n"
    assert error == ""
    assert seen_urls == ["https://guard.local/health?check_db=true"]


def test_launch_requires_control_token_and_prints_dashboard_url() -> None:
    missing_code, missing_output, missing_error = _run_cli(
        ["launch"],
        env={"AGENTGUARD_API_URL": "https://guard.local"},
        transport=httpx.MockTransport(lambda _: httpx.Response(500)),
    )

    seen_auth: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append(request.headers.get("authorization"))
        return httpx.Response(200, json={"launch_code": "lc_test"})

    exit_code, output, error = _run_cli(
        ["launch", "--dashboard-url", "http://dashboard.local/app"],
        env={
            "AGENTGUARD_API_URL": "https://guard.local",
            "AGENTGUARD_CONTROL_TOKEN": "control-secret",
        },
        transport=httpx.MockTransport(handler),
    )

    assert missing_code == 2
    assert missing_output == ""
    assert "AGENTGUARD_CONTROL_TOKEN" in missing_error
    assert exit_code == 0
    assert output == "http://dashboard.local/app?launch_code=lc_test\n"
    assert error == ""
    assert seen_auth == ["Bearer control-secret"]


def test_audit_export_writes_jsonl_to_stdout_and_file(tmp_path: Path) -> None:
    events = [
        {"audit_id": "audit_1", "trace_id": "trace_1"},
        {"audit_id": "audit_2", "trace_id": "trace_1"},
    ]
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        assert request.headers["authorization"] == "Bearer control-secret"
        return httpx.Response(
            200,
            json={
                "scope": {"has_more": False, "next_cursor": None},
                "events": events,
                "policy_metrics": {},
            },
        )

    stdout_code, stdout_output, stdout_error = _run_cli(
        ["audit", "export", "--trace-id", "trace_1", "--limit", "2"],
        env={
            "AGENTGUARD_API_URL": "https://guard.local",
            "AGENTGUARD_CONTROL_TOKEN": "control-secret",
        },
        transport=httpx.MockTransport(handler),
    )
    output_path = tmp_path / "audit.jsonl"
    file_code, file_output, file_error = _run_cli(
        [
            "audit",
            "export",
            "--trace-id",
            "trace_1",
            "--limit",
            "2",
            "--output",
            str(output_path),
        ],
        env={
            "AGENTGUARD_API_URL": "https://guard.local",
            "AGENTGUARD_CONTROL_TOKEN": "control-secret",
        },
        transport=httpx.MockTransport(handler),
    )

    assert stdout_code == 0
    assert [json.loads(line) for line in stdout_output.splitlines()] == events
    assert stdout_error == ""
    assert file_code == 0
    assert file_output == f"Wrote 2 audit events to {output_path}\n"
    assert file_error == ""
    assert [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ] == events
    assert seen_urls == [
        "https://guard.local/v1/audit/window?trace_id=trace_1&limit=2",
        "https://guard.local/v1/audit/window?trace_id=trace_1&limit=2",
    ]


def test_audit_export_follows_one_snapshot_cursor() -> None:
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        cursor = request.url.params.get("cursor")
        if cursor is None:
            return httpx.Response(
                200,
                json={
                    "scope": {"has_more": True, "next_cursor": "cursor-1"},
                    "events": [{"audit_id": "audit_3"}, {"audit_id": "audit_2"}],
                    "policy_metrics": {},
                },
            )
        assert cursor == "cursor-1"
        return httpx.Response(
            200,
            json={
                "scope": {"has_more": False, "next_cursor": None},
                "events": [{"audit_id": "audit_1"}],
                "policy_metrics": {},
            },
        )

    exit_code, output, error = _run_cli(
        ["audit", "export", "--runtime", "openclaw", "--limit", "3"],
        env={
            "AGENTGUARD_API_URL": "https://guard.local",
            "AGENTGUARD_CONTROL_TOKEN": "control-secret",
        },
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 0
    assert error == ""
    assert [json.loads(line)["audit_id"] for line in output.splitlines()] == [
        "audit_3",
        "audit_2",
        "audit_1",
    ]
    assert seen_urls == [
        "https://guard.local/v1/audit/window?runtime=openclaw&limit=3",
        "https://guard.local/v1/audit/window?cursor=cursor-1",
    ]


def test_metrics_outputs_stable_json() -> None:
    payload = {
        "scope": {
            "kind": "aggregate_history",
            "evaluated_from": "2026-08-01T00:00:00Z",
            "evaluated_to": "2026-08-02T00:00:00Z",
        },
        "policy_metrics": {"evaluation_count": 1, "deny_count": 1},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == (
            "https://guard.local/v1/metrics/policy-evaluations"
            "?evaluated_from=2026-08-01T00%3A00%3A00Z"
            "&evaluated_to=2026-08-02T00%3A00%3A00Z&runtime=openclaw"
        )
        return httpx.Response(200, json=payload)

    exit_code, output, error = _run_cli(
        [
            "metrics",
            "--evaluated-from",
            "2026-08-01T00:00:00Z",
            "--evaluated-to",
            "2026-08-02T00:00:00Z",
            "--runtime",
            "openclaw",
            "--json",
        ],
        env={
            "AGENTGUARD_API_URL": "https://guard.local",
            "AGENTGUARD_CONTROL_TOKEN": "control-secret",
        },
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 0
    assert json.loads(output) == payload
    assert error == ""


def test_trace_get_writes_provenance_json(tmp_path: Path) -> None:
    output_path = tmp_path / "trace.json"

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://guard.local/v1/traces/trace_1/provenance"
        return httpx.Response(200, json={"trace_id": "trace_1", "graph": {"nodes": []}})

    exit_code, output, error = _run_cli(
        ["trace", "get", "trace_1", "--provenance", "--output", str(output_path)],
        env={
            "AGENTGUARD_API_URL": "https://guard.local",
            "AGENTGUARD_CONTROL_TOKEN": "control-secret",
        },
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 0
    assert output == f"Wrote trace trace_1 to {output_path}\n"
    assert error == ""
    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "graph": {"nodes": []},
        "trace_id": "trace_1",
    }


def test_credential_issue_posts_runtime_binding_and_shows_token_once() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            {
                "method": request.method,
                "url": str(request.url),
                "authorization": request.headers.get("authorization"),
                "body": json.loads(request.content.decode("utf-8")),
            }
        )
        return httpx.Response(
            200,
            json={
                "token": "agt_tok_once",
                "credential": {
                    "credential_id": "cred_1",
                    "principal_id": "openclaw:agent-a",
                    "runtime": "openclaw",
                    "agent_id": "agent-a",
                },
            },
        )

    exit_code, output, error = _run_cli(
        ["credential", "issue", "--runtime", "openclaw", "--agent-id", "agent-a"],
        env={
            "AGENTGUARD_API_URL": "https://guard.local",
            "AGENTGUARD_CONTROL_TOKEN": "control-secret",
        },
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 0
    assert error == ""
    assert output == (
        "Credential: cred_1\n"
        "Runtime: openclaw\n"
        "Agent: agent-a\n"
        "Token (shown once): agt_tok_once\n"
    )
    assert seen == [
        {
            "method": "POST",
            "url": "https://guard.local/v1/credentials",
            "authorization": "Bearer control-secret",
            "body": {
                "principal_id": "openclaw:agent-a",
                "runtime": "openclaw",
                "agent_id": "agent-a",
            },
        }
    ]


def test_credential_list_and_revoke_use_control_plane_endpoints() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        if request.method == "GET":
            return httpx.Response(
                200,
                json=[
                    {
                        "credential_id": "cred_1",
                        "principal_id": "openclaw:agent-a",
                        "runtime": "openclaw",
                        "agent_id": "agent-a",
                        "revoked_at": None,
                    }
                ],
            )
        return httpx.Response(
            200, json={"credential_id": "cred_1", "revoked_at": "now"}
        )

    env = {
        "AGENTGUARD_API_URL": "https://guard.local",
        "AGENTGUARD_CONTROL_TOKEN": "control-secret",
    }
    list_code, list_output, list_error = _run_cli(
        ["credential", "list"], env=env, transport=httpx.MockTransport(handler)
    )
    revoke_code, revoke_output, revoke_error = _run_cli(
        ["credential", "revoke", "cred_1"],
        env=env,
        transport=httpx.MockTransport(handler),
    )

    assert list_code == revoke_code == 0
    assert list_error == revoke_error == ""
    assert list_output == "cred_1  openclaw/agent-a  openclaw:agent-a  active\n"
    assert revoke_output == "Revoked credential cred_1\n"
    assert seen == [
        ("GET", "https://guard.local/v1/credentials"),
        ("POST", "https://guard.local/v1/credentials/cred_1/revoke"),
    ]


def test_http_error_and_connection_error_return_nonzero() -> None:
    http_code, _, http_error = _run_cli(
        [
            "metrics",
            "--evaluated-from",
            "2026-08-01T00:00:00Z",
            "--evaluated-to",
            "2026-08-02T00:00:00Z",
        ],
        env={
            "AGENTGUARD_API_URL": "https://guard.local",
            "AGENTGUARD_CONTROL_TOKEN": "bad-token",
        },
        transport=httpx.MockTransport(
            lambda _: httpx.Response(403, json={"error": {"code": "SCOPE_DENIED"}})
        ),
    )

    def raise_connect_error(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    connect_code, _, connect_error = _run_cli(
        ["health"],
        env={"AGENTGUARD_API_URL": "https://guard.local"},
        transport=httpx.MockTransport(raise_connect_error),
    )

    assert http_code == 1
    assert "HTTP 403" in http_error
    assert "SCOPE_DENIED" in http_error
    assert connect_code == 1
    assert "ConnectError" in connect_error
    assert "connection refused" not in connect_error


def test_openclaw_verify_delegates_to_existing_pnpm_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_pnpm = "/test-bin/pnpm"
    monkeypatch.setattr(
        cli.shutil,
        "which",
        lambda executable: expected_pnpm if executable == "pnpm" else None,
    )
    commands: list[list[str]] = []

    def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    exit_code, output, error = _run_cli(["openclaw", "verify"], run_command=run_command)

    assert exit_code == 0
    assert output == ""
    assert error == ""
    assert commands == [[expected_pnpm, "openclaw:plugin:verify"]]


def test_openclaw_verify_record_passes_record_flag_to_dev_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_pnpm = "/test-bin/pnpm"
    monkeypatch.setattr(
        cli.shutil,
        "which",
        lambda executable: expected_pnpm if executable == "pnpm" else None,
    )
    commands: list[list[str]] = []

    def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    exit_code, output, error = _run_cli(
        ["openclaw", "verify", "--record"], run_command=run_command
    )

    assert exit_code == 0
    assert output == ""
    assert error == ""
    assert commands == [[expected_pnpm, "openclaw:plugin:verify", "--", "--record"]]


def test_eval_import_posts_evaluation_run(tmp_path: Path) -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            {
                "method": request.method,
                "url": str(request.url),
                "authorization": request.headers.get("authorization"),
                "body": json.loads(request.content.decode("utf-8")),
            }
        )
        return httpx.Response(200, json={"run_id": "eval_cli"})

    payload = {
        "run_id": "eval_cli",
        "run_at": "2026-06-28T00:00:00+00:00",
        "asr_before": 0.7,
        "asr_after": 0.1,
        "per_attack": {},
        "cases": [],
    }
    output_path = tmp_path / "agentguardctl-eval-import.json"
    output_path.write_text(json.dumps(payload), encoding="utf-8")

    exit_code, output, error = _run_cli(
        ["eval", "import", str(output_path)],
        env={
            "AGENTGUARD_API_URL": "https://guard.local",
            "AGENTGUARD_CONTROL_TOKEN": "control-secret",
        },
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 0
    assert output == "Imported evaluation run eval_cli\n"
    assert error == ""
    assert seen == [
        {
            "method": "POST",
            "url": "https://guard.local/v1/evaluations",
            "authorization": "Bearer control-secret",
            "body": payload,
        }
    ]


def test_eval_run_is_not_part_of_the_published_cli() -> None:
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["eval", "run"])

    assert exc_info.value.code == 2
