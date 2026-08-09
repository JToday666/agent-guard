"""Headless command-line control utility for AgentGuard."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from ._version import __version__

Env = Mapping[str, str]
RunCommand = Callable[[list[str]], subprocess.CompletedProcess[bytes]]


class CliError(RuntimeError):
    """Expected CLI failure shown without a traceback."""

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        self.exit_code = exit_code
        super().__init__(message)


def main(argv: list[str] | None = None) -> int:
    return run(argv)


def run(
    argv: list[str] | None = None,
    *,
    env: Env | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    transport: httpx.BaseTransport | None = None,
    run_command: RunCommand | None = None,
) -> int:
    actual_env: Env = os.environ if env is None else env
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    parser = build_parser()
    try:
        args, unknown_args = parser.parse_known_args(argv)
        handler = getattr(args, "handler", None)
        if handler is None:
            parser.print_help(out)
            return 0
        if unknown_args:
            raise CliError(
                f"Unrecognized arguments: {' '.join(unknown_args)}", exit_code=2
            )
        return int(
            handler(
                args,
                env=actual_env,
                stdout=out,
                transport=transport,
                run_command=run_command,
            )
        )
    except CliError as exc:
        err.write(f"{exc}\n")
        return exc.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentguardctl", description="AgentGuard headless control CLI"
    )
    parser.add_argument("--version", action="version", version=__version__)
    subcommands = parser.add_subparsers(dest="command")

    health = subcommands.add_parser("health", help="Check Guard API health")
    health.add_argument(
        "--check-db", action="store_true", help="Include database health"
    )
    health.add_argument("--json", action="store_true", help="Print JSON response")
    health.set_defaults(handler=_cmd_health)

    launch = subcommands.add_parser("launch", help="Create a Dashboard launch URL")
    launch.add_argument(
        "--dashboard-url", default="http://localhost:5173/", help="Dashboard URL prefix"
    )
    launch.set_defaults(handler=_cmd_launch)

    audit = subcommands.add_parser("audit", help="Audit event commands")
    audit_subcommands = audit.add_subparsers(dest="audit_command", required=True)
    export = audit_subcommands.add_parser("export", help="Export audit events as JSONL")
    export.add_argument("--trace-id")
    export.add_argument("--case-id")
    export.add_argument("--runtime")
    export.add_argument("--decision")
    export.add_argument("--limit", type=int, default=500)
    export.add_argument("--output", help="Write JSONL to this file instead of stdout")
    export.set_defaults(handler=_cmd_audit_export)

    metrics = subcommands.add_parser("metrics", help="Read policy evaluation metrics")
    metrics.add_argument("--evaluated-from")
    metrics.add_argument("--evaluated-to")
    metrics.add_argument("--outcomes-as-of")
    metrics.add_argument("--case-id")
    metrics.add_argument("--runtime")
    metrics.add_argument("--json", action="store_true", help="Print JSON response")
    metrics.set_defaults(handler=_cmd_metrics)

    trace = subcommands.add_parser("trace", help="Trace commands")
    trace_subcommands = trace.add_subparsers(dest="trace_command", required=True)
    trace_get = trace_subcommands.add_parser("get", help="Read a trace")
    trace_get.add_argument("trace_id")
    trace_get.add_argument(
        "--provenance", action="store_true", help="Read trace provenance graph"
    )
    trace_get.add_argument("--output", help="Write JSON to this file instead of stdout")
    trace_get.set_defaults(handler=_cmd_trace_get)

    credential = subcommands.add_parser(
        "credential", help="Manage runtime adapter credentials"
    )
    credential_subcommands = credential.add_subparsers(
        dest="credential_command", required=True
    )
    credential_issue = credential_subcommands.add_parser(
        "issue", help="Issue a runtime-bound adapter token"
    )
    credential_issue.add_argument("--runtime", required=True)
    credential_issue.add_argument("--agent-id", required=True)
    credential_issue.add_argument(
        "--principal-id",
        help="Stable adapter principal; defaults to <runtime>:<agent-id>",
    )
    credential_issue.add_argument("--expires-at", help="RFC 3339 expiry timestamp")
    credential_issue.add_argument("--json", action="store_true")
    credential_issue.set_defaults(handler=_cmd_credential_issue)

    credential_list = credential_subcommands.add_parser(
        "list", help="List issued adapter credentials"
    )
    credential_list.add_argument("--json", action="store_true")
    credential_list.set_defaults(handler=_cmd_credential_list)

    credential_revoke = credential_subcommands.add_parser(
        "revoke", help="Revoke an adapter credential"
    )
    credential_revoke.add_argument("credential_id")
    credential_revoke.add_argument("--json", action="store_true")
    credential_revoke.set_defaults(handler=_cmd_credential_revoke)

    openclaw = subcommands.add_parser("openclaw", help="OpenClaw helper commands")
    openclaw_subcommands = openclaw.add_subparsers(
        dest="openclaw_command", required=True
    )
    openclaw_verify = openclaw_subcommands.add_parser(
        "verify", help="Verify installed OpenClaw plugin"
    )
    openclaw_verify.add_argument(
        "--record", action="store_true", help="Record verify status in Guard API"
    )
    openclaw_verify.set_defaults(handler=_cmd_openclaw_verify)

    eval_parser = subcommands.add_parser("eval", help="AttackBench helper commands")
    eval_subcommands = eval_parser.add_subparsers(dest="eval_command", required=True)
    eval_import = eval_subcommands.add_parser(
        "import", help="Import evaluation results into Guard API"
    )
    eval_import.add_argument("path", help="Evaluation result JSON file")
    eval_import.set_defaults(handler=_cmd_eval_import)
    return parser


def _cmd_health(
    args: argparse.Namespace,
    *,
    env: Env,
    stdout: TextIO,
    transport: httpx.BaseTransport | None,
    **_: Any,
) -> int:
    params = {"check_db": True} if args.check_db else None
    payload = _request_json(
        "GET",
        "/health",
        env=env,
        transport=transport,
        params=params,
        token_required=False,
    )
    if args.json:
        _write_json(stdout, payload)
        return 0
    status = payload.get("status", "unknown")
    database = payload.get("database")
    if database is None:
        stdout.write(f"Guard API: {status}\n")
    else:
        stdout.write(f"Guard API: {status}, database: {database}\n")
    return 0


def _cmd_launch(
    args: argparse.Namespace,
    *,
    env: Env,
    stdout: TextIO,
    transport: httpx.BaseTransport | None,
    **_: Any,
) -> int:
    payload = _request_json(
        "POST", "/v1/auth/browser/launch", env=env, transport=transport
    )
    launch_code = payload.get("launch_code")
    if not isinstance(launch_code, str) or not launch_code:
        raise CliError("Guard API response did not include launch_code")
    stdout.write(_with_launch_code(args.dashboard_url, launch_code) + "\n")
    return 0


def _cmd_audit_export(
    args: argparse.Namespace,
    *,
    env: Env,
    stdout: TextIO,
    transport: httpx.BaseTransport | None,
    **_: Any,
) -> int:
    params = _filter_params(
        {
            "trace_id": args.trace_id,
            "case_id": args.case_id,
            "runtime": args.runtime,
            "decision": args.decision,
            "limit": args.limit,
        }
    )
    events: list[Any] = []
    cursor: str | None = None
    if args.limit <= 0:
        raise CliError("--limit must be greater than zero", exit_code=2)
    page_limit = min(args.limit, 1000)
    while len(events) < args.limit:
        page_params = (
            {**params, "limit": page_limit} if cursor is None else {"cursor": cursor}
        )
        payload = _request_json(
            "GET", "/v1/audit/window", env=env, transport=transport, params=page_params
        )
        if not isinstance(payload, dict):
            raise CliError("Guard API response for audit export was not an object")
        page_events = payload.get("events")
        scope = payload.get("scope")
        if not isinstance(page_events, list) or not isinstance(scope, dict):
            raise CliError("Guard API audit window response was incomplete")
        events.extend(page_events[: args.limit - len(events)])
        if scope.get("has_more") is not True:
            break
        next_cursor = scope.get("next_cursor")
        if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
            raise CliError("Guard API audit window cursor was invalid")
        cursor = next_cursor
    lines = "".join(
        json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in events
    )
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(lines, encoding="utf-8")
        stdout.write(f"Wrote {len(events)} audit events to {output_path}\n")
    else:
        stdout.write(lines)
    return 0


def _cmd_metrics(
    args: argparse.Namespace,
    *,
    env: Env,
    stdout: TextIO,
    transport: httpx.BaseTransport | None,
    **_: Any,
) -> int:
    if not args.evaluated_from or not args.evaluated_to:
        raise CliError("--evaluated-from and --evaluated-to are required", exit_code=2)
    params = _filter_params(
        {
            "evaluated_from": args.evaluated_from,
            "evaluated_to": args.evaluated_to,
            "outcomes_as_of": args.outcomes_as_of,
            "case_id": args.case_id,
            "runtime": args.runtime,
        }
    )
    payload = _request_json(
        "GET",
        "/v1/metrics/policy-evaluations",
        env=env,
        transport=transport,
        params=params,
    )
    if args.json:
        _write_json(stdout, payload)
    else:
        stdout.write(_format_metrics(payload) + "\n")
    return 0


def _cmd_trace_get(
    args: argparse.Namespace,
    *,
    env: Env,
    stdout: TextIO,
    transport: httpx.BaseTransport | None,
    **_: Any,
) -> int:
    suffix = "/provenance" if args.provenance else ""
    payload = _request_json(
        "GET", f"/v1/traces/{args.trace_id}{suffix}", env=env, transport=transport
    )
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(_json_text(payload), encoding="utf-8")
        stdout.write(f"Wrote trace {args.trace_id} to {output_path}\n")
    else:
        _write_json(stdout, payload)
    return 0


def _cmd_credential_issue(
    args: argparse.Namespace,
    *,
    env: Env,
    stdout: TextIO,
    transport: httpx.BaseTransport | None,
    **_: Any,
) -> int:
    principal_id = args.principal_id or f"{args.runtime}:{args.agent_id}"
    response = _request_json(
        "POST",
        "/v1/credentials",
        env=env,
        transport=transport,
        json_body=_filter_params(
            {
                "principal_id": principal_id,
                "runtime": args.runtime,
                "agent_id": args.agent_id,
                "expires_at": args.expires_at,
            }
        ),
    )
    if not isinstance(response, dict):
        raise CliError("Guard API credential response was not an object")
    token = response.get("token")
    credential = response.get("credential")
    if not isinstance(token, str) or not isinstance(credential, dict):
        raise CliError("Guard API credential response was incomplete")
    if args.json:
        _write_json(stdout, response)
        return 0
    stdout.write(f"Credential: {credential.get('credential_id', '<unknown>')}\n")
    stdout.write(f"Runtime: {args.runtime}\n")
    stdout.write(f"Agent: {args.agent_id}\n")
    stdout.write(f"Token (shown once): {token}\n")
    return 0


def _cmd_credential_list(
    args: argparse.Namespace,
    *,
    env: Env,
    stdout: TextIO,
    transport: httpx.BaseTransport | None,
    **_: Any,
) -> int:
    response = _request_json("GET", "/v1/credentials", env=env, transport=transport)
    if not isinstance(response, list):
        raise CliError("Guard API credential list was not an array")
    if args.json:
        _write_json(stdout, response)
        return 0
    if not response:
        stdout.write("No adapter credentials.\n")
        return 0
    for credential in response:
        if not isinstance(credential, dict):
            raise CliError("Guard API credential list contained an invalid row")
        stdout.write(
            "{credential_id}  {runtime}/{agent_id}  {principal_id}  {state}\n".format(
                credential_id=credential.get("credential_id", "<unknown>"),
                runtime=credential.get("runtime", "<unknown>"),
                agent_id=credential.get("agent_id", "<unknown>"),
                principal_id=credential.get("principal_id", "<unknown>"),
                state="revoked" if credential.get("revoked_at") else "active",
            )
        )
    return 0


def _cmd_credential_revoke(
    args: argparse.Namespace,
    *,
    env: Env,
    stdout: TextIO,
    transport: httpx.BaseTransport | None,
    **_: Any,
) -> int:
    response = _request_json(
        "POST",
        f"/v1/credentials/{args.credential_id}/revoke",
        env=env,
        transport=transport,
    )
    if not isinstance(response, dict):
        raise CliError("Guard API revoke response was not an object")
    if args.json:
        _write_json(stdout, response)
    else:
        stdout.write(f"Revoked credential {args.credential_id}\n")
    return 0


def _cmd_openclaw_verify(
    args: argparse.Namespace,
    *,
    run_command: RunCommand | None,
    **__: Any,
) -> int:
    runner = run_command or _default_run_command
    command = ["pnpm", "openclaw:plugin:verify"]
    if args.record:
        command.extend(["--", "--record"])
    completed = runner(command)
    return completed.returncode


def _cmd_eval_import(
    args: argparse.Namespace,
    *,
    env: Env,
    stdout: TextIO,
    transport: httpx.BaseTransport | None,
    **_: Any,
) -> int:
    input_path = Path(args.path)
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CliError(f"Failed to read evaluation file: {exc}") from exc
    except ValueError as exc:
        raise CliError("Evaluation file was not valid JSON") from exc
    response = _request_json(
        "POST", "/v1/evaluations", env=env, transport=transport, json_body=payload
    )
    run_id = response.get("run_id") if isinstance(response, dict) else None
    stdout.write(f"Imported evaluation run {run_id or '<unknown>'}\n")
    return 0


def _request_json(
    method: str,
    path: str,
    *,
    env: Env,
    transport: httpx.BaseTransport | None,
    params: dict[str, Any] | None = None,
    json_body: Any | None = None,
    token_required: bool = True,
) -> Any:
    headers = {}
    if token_required:
        token = env.get("AGENTGUARD_CONTROL_TOKEN")
        if not token:
            raise CliError(
                "AGENTGUARD_CONTROL_TOKEN is required for this command", exit_code=2
            )
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(timeout=10.0, transport=transport) as client:
            response = client.request(
                method,
                _join_url(_api_base_url(env), path),
                params=params,
                headers=headers,
                json=json_body,
            )
    except httpx.HTTPError as exc:
        raise CliError(f"Guard API request failed: {exc}") from exc
    if response.status_code >= 400:
        raise CliError(_http_error_message(response))
    try:
        return response.json()
    except ValueError as exc:
        raise CliError("Guard API response was not valid JSON") from exc


def _api_base_url(env: Env) -> str:
    explicit = env.get("AGENTGUARD_API_URL")
    if explicit:
        return explicit.rstrip("/")
    host = env.get("AGENTGUARD_HOST", "127.0.0.1")
    port = env.get("AGENTGUARD_PORT", "8088")
    return f"http://{host}:{port}"


def _join_url(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def _filter_params(params: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in params.items() if value is not None}


def _write_json(stdout: TextIO, payload: Any) -> None:
    stdout.write(_json_text(payload))


def _json_text(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _format_metrics(payload: Any) -> str:
    if not isinstance(payload, dict):
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)
    metrics = payload.get("policy_metrics")
    if not isinstance(metrics, dict):
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)
    keys = [
        "evaluation_count",
        "allow_count",
        "deny_count",
        "ask_count",
        "intervention_rate",
        "policy_deny_rate",
        "approval_trigger_rate",
        "policy_intervention_fpr",
        "policy_intervention_fnr",
        "average_decision_latency_ms",
    ]
    parts = [f"{key}={metrics[key]}" for key in keys if key in metrics]
    return (
        " ".join(parts)
        if parts
        else json.dumps(payload, ensure_ascii=False, sort_keys=True)
    )


def _with_launch_code(dashboard_url: str, launch_code: str) -> str:
    parts = urlsplit(dashboard_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["launch_code"] = launch_code
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path or "/",
            urlencode(query),
            parts.fragment,
        )
    )


def _http_error_message(response: httpx.Response) -> str:
    code = ""
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict) and error.get("code"):
            code = f": {error['code']}"
    return f"HTTP {response.status_code} from Guard API{code}"


def _default_run_command(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
