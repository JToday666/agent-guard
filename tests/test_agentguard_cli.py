from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import httpx

from agentguard_cli import cli


def _run_cli(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    transport: httpx.MockTransport | None = None,
    run_command=None,
    bench_main=None,
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
        bench_main=bench_main,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue()


def test_health_uses_host_and_port_default_api_url() -> None:
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(200, json={"status": "ok"})

    exit_code, output, error = _run_cli(
        ["health", "--json"],
        env={"AGENTGUARD_HOST": "10.0.0.5", "AGENTGUARD_PORT": "9090"},
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 0
    assert json.loads(output) == {"status": "ok"}
    assert error == ""
    assert seen_urls == ["http://10.0.0.5:9090/health"]


def test_health_check_db_requests_database_health() -> None:
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(200, json={"status": "ok", "database": "ok"})

    exit_code, output, error = _run_cli(
        ["health", "--check-db"],
        env={"AGENTGUARD_API_URL": "http://guard.local"},
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 0
    assert output == "Guard API: ok, database: ok\n"
    assert error == ""
    assert seen_urls == ["http://guard.local/health?check_db=true"]


def test_launch_requires_control_token_and_prints_dashboard_url() -> None:
    missing_code, missing_output, missing_error = _run_cli(
        ["launch"],
        env={"AGENTGUARD_API_URL": "http://guard.local"},
        transport=httpx.MockTransport(lambda _: httpx.Response(500)),
    )

    seen_auth: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append(request.headers.get("authorization"))
        return httpx.Response(200, json={"launch_code": "lc_test"})

    exit_code, output, error = _run_cli(
        ["launch", "--dashboard-url", "http://dashboard.local/app"],
        env={"AGENTGUARD_API_URL": "http://guard.local", "AGENTGUARD_CONTROL_TOKEN": "control-secret"},
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
        return httpx.Response(200, json=events)

    stdout_code, stdout_output, stdout_error = _run_cli(
        ["audit", "export", "--trace-id", "trace_1", "--limit", "2"],
        env={"AGENTGUARD_API_URL": "http://guard.local", "AGENTGUARD_CONTROL_TOKEN": "control-secret"},
        transport=httpx.MockTransport(handler),
    )
    output_path = tmp_path / "audit.jsonl"
    file_code, file_output, file_error = _run_cli(
        ["audit", "export", "--trace-id", "trace_1", "--limit", "2", "--output", str(output_path)],
        env={"AGENTGUARD_API_URL": "http://guard.local", "AGENTGUARD_CONTROL_TOKEN": "control-secret"},
        transport=httpx.MockTransport(handler),
    )

    assert stdout_code == 0
    assert [json.loads(line) for line in stdout_output.splitlines()] == events
    assert stdout_error == ""
    assert file_code == 0
    assert file_output == f"Wrote 2 audit events to {output_path}\n"
    assert file_error == ""
    assert [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()] == events
    assert seen_urls == [
        "http://guard.local/v1/audit/events?trace_id=trace_1&limit=2",
        "http://guard.local/v1/audit/events?trace_id=trace_1&limit=2",
    ]


def test_metrics_outputs_stable_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://guard.local/v1/metrics/eval?runtime=openclaw"
        return httpx.Response(200, json={"event_count": 1, "deny_count": 1})

    exit_code, output, error = _run_cli(
        ["metrics", "--runtime", "openclaw", "--json"],
        env={"AGENTGUARD_API_URL": "http://guard.local", "AGENTGUARD_CONTROL_TOKEN": "control-secret"},
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 0
    assert output == '{\n  "deny_count": 1,\n  "event_count": 1\n}\n'
    assert error == ""


def test_trace_get_writes_provenance_json(tmp_path: Path) -> None:
    output_path = tmp_path / "trace.json"

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://guard.local/v1/traces/trace_1/provenance"
        return httpx.Response(200, json={"trace_id": "trace_1", "graph": {"nodes": []}})

    exit_code, output, error = _run_cli(
        ["trace", "get", "trace_1", "--provenance", "--output", str(output_path)],
        env={"AGENTGUARD_API_URL": "http://guard.local", "AGENTGUARD_CONTROL_TOKEN": "control-secret"},
        transport=httpx.MockTransport(handler),
    )

    assert exit_code == 0
    assert output == f"Wrote trace trace_1 to {output_path}\n"
    assert error == ""
    assert json.loads(output_path.read_text(encoding="utf-8")) == {"graph": {"nodes": []}, "trace_id": "trace_1"}


def test_http_error_and_connection_error_return_nonzero() -> None:
    http_code, _, http_error = _run_cli(
        ["metrics"],
        env={"AGENTGUARD_API_URL": "http://guard.local", "AGENTGUARD_CONTROL_TOKEN": "bad-token"},
        transport=httpx.MockTransport(lambda _: httpx.Response(403, json={"error": {"code": "SCOPE_DENIED"}})),
    )

    def raise_connect_error(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    connect_code, _, connect_error = _run_cli(
        ["health"],
        env={"AGENTGUARD_API_URL": "http://guard.local"},
        transport=httpx.MockTransport(raise_connect_error),
    )

    assert http_code == 1
    assert "HTTP 403" in http_error
    assert "SCOPE_DENIED" in http_error
    assert connect_code == 1
    assert "connection refused" in connect_error


def test_openclaw_verify_delegates_to_existing_pnpm_script() -> None:
    commands: list[list[str]] = []

    def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    exit_code, output, error = _run_cli(["openclaw", "verify"], run_command=run_command)

    assert exit_code == 0
    assert output == ""
    assert error == ""
    assert commands == [["pnpm", "openclaw:plugin:verify"]]


def test_eval_run_delegates_to_attackbench_runner() -> None:
    seen_args: list[list[str] | None] = []

    def bench_main(argv: list[str] | None = None) -> int:
        seen_args.append(argv)
        return 0

    exit_code, output, error = _run_cli(
        ["eval", "run", "--dataset", "cases.jsonl", "--defense", "on"],
        bench_main=bench_main,
    )

    assert exit_code == 0
    assert output == ""
    assert error == ""
    assert seen_args == [["--dataset", "cases.jsonl", "--defense", "on"]]


def test_eval_run_forwards_help_to_attackbench_runner() -> None:
    seen_args: list[list[str] | None] = []

    def bench_main(argv: list[str] | None = None) -> int:
        seen_args.append(argv)
        return 0

    exit_code, _, _ = _run_cli(["eval", "run", "--help"], bench_main=bench_main)

    assert exit_code == 0
    assert seen_args == [["--help"]]


def test_attackbench_loader_works_when_console_script_path_hides_repo_root(monkeypatch) -> None:
    repo_root = Path.cwd().resolve()
    filtered_path = [
        item
        for item in sys.path
        if item and Path(item).resolve() != repo_root
    ]
    monkeypatch.setattr(sys, "path", filtered_path)
    sys.modules.pop("agentguard_langgraph_bench", None)
    sys.modules.pop("agentguard_langgraph_bench.bench", None)
    sys.modules.pop("agentguard_langgraph_bench.bench.runner", None)

    loaded = cli._load_bench_main()

    assert loaded.__name__ == "main"
