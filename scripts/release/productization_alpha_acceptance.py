#!/usr/bin/env python3
"""Clean-clone Productization Alpha acceptance check.

The check is deliberately self-contained: it starts a loopback-only Guard API,
issues a short-lived runtime credential, evaluates one known-benign and one
known-malicious action, queries the authoritative audit window, builds the
Dashboard into a fresh temporary directory, and serves that build over a local
HTTP server.  No provider-backed feature is enabled.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import partial
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MAX_HTTP_BODY_BYTES = 2 * 1024 * 1024
_MAX_LOG_TAIL_BYTES = 24 * 1024
_DOTENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_POSTGRESQL_SCHEMES = {"postgresql", "postgresql+psycopg"}
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_PROVIDER_ENV_KEYS = {
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_OPENAI_API_KEY",
    "COHERE_API_KEY",
    "DEEPSEEK_API_KEY",
    "FIREWORKS_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "MISTRAL_API_KEY",
    "OPENAI_API_KEY",
    "TOGETHER_API_KEY",
}
_DASHBOARD_EXAMPLE_KEYS = {
    "VITE_API_BASE_URL",
    "VITE_API_HEALTH_URL",
    "VITE_API_MOCK_DELAY",
    "VITE_API_REQUEST_TIMEOUT_MS",
    "VITE_BACKEND_TARGET",
    "VITE_EVIDENCE_POLL_INTERVAL_MS",
    "VITE_RUNTIME_SUPERVISION_S1_ENABLED",
}
_IGNORED_DASHBOARD_ENTRIES = {
    ".vite",
    "coverage",
    "dist",
    "dist-ssr",
    "node_modules",
    "playwright-report",
    "test-results",
    "test-results-api",
}


class AcceptanceError(RuntimeError):
    """A safe, user-facing acceptance failure."""


@dataclass(frozen=True, slots=True)
class AcceptanceConfig:
    repo_root: Path = _REPO_ROOT
    postgresql_url: str | None = None
    guard_port: int = 0
    dashboard_port: int = 0
    startup_timeout_seconds: float = 30.0
    request_timeout_seconds: float = 5.0
    dashboard_build_timeout_seconds: float = 180.0

    @property
    def storage_backend(self) -> str:
        return "postgres" if self.postgresql_url else "memory"


@dataclass(frozen=True, slots=True)
class HttpPayload:
    status: int
    headers: Mapping[str, str]
    body: bytes


class _DashboardAssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        candidate = attributes.get("src") if tag == "script" else None
        if tag == "link":
            candidate = attributes.get("href")
        if candidate and candidate.startswith("/assets/"):
            parsed = urlsplit(candidate)
            if not parsed.netloc and ".." not in Path(parsed.path).parts:
                self.assets.append(candidate)


class _QuietStaticHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *args: object) -> None:
        del args


class DashboardServer:
    """Serve a temporary Dashboard build on a loopback-only listener."""

    def __init__(self, directory: Path, port: int) -> None:
        self.directory = directory
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise AcceptanceError("Dashboard static server is not running")
        actual_port = int(self._server.server_address[1])
        return f"http://127.0.0.1:{actual_port}"

    def __enter__(self) -> DashboardServer:
        handler = partial(_QuietStaticHandler, directory=str(self.directory))
        try:
            self._server = ThreadingHTTPServer(("127.0.0.1", self.port), handler)
        except OSError as exc:
            raise AcceptanceError(
                f"Dashboard loopback listener failed: {exc}"
            ) from None
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="agentguard-alpha-dashboard",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


class GuardApiProcess:
    """Own exactly one loopback uvicorn process and its diagnostic log."""

    def __init__(
        self,
        *,
        repo_root: Path,
        port: int,
        environment: Mapping[str, str],
        log_path: Path,
        startup_timeout_seconds: float,
        request_timeout_seconds: float,
        redactions: Sequence[str],
    ) -> None:
        self.repo_root = repo_root
        self.port = port
        self.environment = dict(environment)
        self.log_path = log_path
        self.startup_timeout_seconds = startup_timeout_seconds
        self.request_timeout_seconds = request_timeout_seconds
        self.redactions = tuple(redactions)
        self._process: subprocess.Popen[bytes] | None = None
        self._log_handle: Any | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> GuardApiProcess:
        command = [
            sys.executable,
            "-m",
            "uvicorn",
            "guard_api.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--log-level",
            "info",
            "--no-access-log",
        ]
        self._log_handle = self.log_path.open("wb")
        try:
            self._process = subprocess.Popen(
                command,
                cwd=self.repo_root,
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=self._log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            self._wait_until_ready()
        except (OSError, AcceptanceError) as exc:
            self._stop()
            tail = _log_tail(self.log_path, redactions=self.redactions)
            detail = f"\nGuard API log tail:\n{tail}" if tail else ""
            if isinstance(exc, AcceptanceError):
                raise AcceptanceError(f"{exc}{detail}") from None
            raise AcceptanceError(
                f"Guard API process failed to start: {exc}{detail}"
            ) from None
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop()

    def log_tail(self, *, extra_redactions: Sequence[str] = ()) -> str:
        return _log_tail(
            self.log_path,
            redactions=(*self.redactions, *extra_redactions),
        )

    def _wait_until_ready(self) -> None:
        assert self._process is not None
        deadline = time.monotonic() + self.startup_timeout_seconds
        last_failure = "no response"
        while time.monotonic() < deadline:
            return_code = self._process.poll()
            if return_code is not None:
                raise AcceptanceError(
                    f"Guard API exited before readiness (exit code {return_code})"
                )
            try:
                health = _request_json(
                    self.base_url,
                    "/health?check_db=true",
                    timeout_seconds=self.request_timeout_seconds,
                )
                if health == {"status": "ok", "database": "ok"}:
                    return
                last_failure = f"unexpected health payload: {_safe_json(health)}"
            except AcceptanceError as exc:
                last_failure = str(exc)
            time.sleep(0.2)
        raise AcceptanceError(
            "Guard API readiness timed out after "
            f"{self.startup_timeout_seconds:g}s ({last_failure})"
        )

    def _stop(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None


def _parse_dotenv_example(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise AcceptanceError(f"required example environment file is missing: {path}")
    parsed: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").strip()
        if "=" not in line:
            raise AcceptanceError(f"invalid .env.example entry at {path}:{line_number}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not _DOTENV_KEY.fullmatch(key):
            raise AcceptanceError(f"invalid .env.example key at {path}:{line_number}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        parsed[key] = value
    return parsed


def _required_example_values(
    values: Mapping[str, str], required: set[str], *, path: Path
) -> dict[str, str]:
    missing = sorted(key for key in required if key not in values)
    if missing:
        raise AcceptanceError(
            f"{path} is missing required acceptance keys: {', '.join(missing)}"
        )
    return {key: values[key] for key in required}


def _scrubbed_environment(base_environment: Mapping[str, str]) -> dict[str, str]:
    environment = {
        key: value
        for key, value in base_environment.items()
        if not key.startswith("AGENTGUARD_")
        and not key.startswith("VITE_")
        and key not in _PROVIDER_ENV_KEYS
    }
    environment.pop("NODE_OPTIONS", None)
    return environment


def _build_guard_environment(
    *,
    base_environment: Mapping[str, str],
    root_example: Mapping[str, str],
    control_token: str,
    port: int,
    postgresql_url: str | None,
) -> dict[str, str]:
    environment = _scrubbed_environment(base_environment)
    environment.update(
        {
            "AGENTGUARD_ADAPTER_TOKEN": "",
            "AGENTGUARD_AUDIT_CHECKPOINT_INTERVAL_SECONDS": root_example[
                "AGENTGUARD_AUDIT_CHECKPOINT_INTERVAL_SECONDS"
            ],
            "AGENTGUARD_AUDIT_CHECKPOINT_KEY": "",
            "AGENTGUARD_AUDIT_CHECKPOINT_KEY_ID": "",
            "AGENTGUARD_AUDIT_CHECKPOINT_PATH": "",
            "AGENTGUARD_BROWSER_COOKIE_SECURE": "false",
            "AGENTGUARD_CONTEXT_BUILDER_ENABLED": "false",
            "AGENTGUARD_CONTROL_TOKEN": control_token,
            "AGENTGUARD_CT_FACT_PROJECTION_ENABLED": "false",
            "AGENTGUARD_EVIDENCE_CONTENT_PREVIEW_ENABLED": "false",
            "AGENTGUARD_ENV": "test",
            "AGENTGUARD_HOST": "127.0.0.1",
            "AGENTGUARD_LLM_APPROVAL_API_KEY": "",
            "AGENTGUARD_LLM_APPROVAL_ENABLED": "false",
            "AGENTGUARD_LLM_APPROVAL_MODEL": "",
            "AGENTGUARD_MAX_REQUEST_BODY_BYTES": root_example[
                "AGENTGUARD_MAX_REQUEST_BODY_BYTES"
            ],
            "AGENTGUARD_PORT": str(port),
            "AGENTGUARD_RTE05_STRONG_BINDING_ENABLED": "false",
            "AGENTGUARD_STORAGE_BACKEND": ("postgres" if postgresql_url else "memory"),
            "AGENTGUARD_TASK_SCOPE_ACTIVE_KEY_ID": "",
            "AGENTGUARD_TASK_SCOPE_KEYS": "",
            "AGENTGUARD_V21_COMPETITION_ACTIVATION_PATH": "",
            "AGENTGUARD_V21_MODE": "off",
            "AGENTGUARD_V21_SEMANTIC_API_KEY": "",
            "AGENTGUARD_V21_SEMANTIC_ENABLED": "false",
            "AGENTGUARD_V21_SEMANTIC_MODEL": "",
            "AGENTGUARD_V21_SHADOW_SERVER_SECRET": "",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
        }
    )
    environment["AGENTGUARD_DATABASE_URL"] = postgresql_url or (
        "postgresql+psycopg://unused:unused@127.0.0.1:1/unused"
    )
    return environment


def _build_dashboard_environment(
    *,
    base_environment: Mapping[str, str],
    dashboard_example: Mapping[str, str],
    guard_port: int,
) -> dict[str, str]:
    if not dashboard_example["VITE_API_BASE_URL"].startswith("/"):
        raise AcceptanceError("Dashboard example API base URL must be same-origin")
    if not dashboard_example["VITE_API_HEALTH_URL"].startswith("/"):
        raise AcceptanceError("Dashboard example health URL must be same-origin")
    environment = _scrubbed_environment(base_environment)
    environment.update(dashboard_example)
    environment.update(
        {
            "NODE_ENV": "production",
            "VITE_BACKEND_TARGET": f"http://127.0.0.1:{guard_port}",
        }
    )
    return environment


def _is_dashboard_local_state(name: str) -> bool:
    if name in _IGNORED_DASHBOARD_ENTRIES or name.endswith(".tsbuildinfo"):
        return True
    return name == ".env" or (name.startswith(".env.") and name != ".env.example")


def _copy_dashboard_source(source: Path, destination: Path) -> None:
    node_modules = source / "node_modules"
    if not node_modules.is_dir():
        raise AcceptanceError(
            "Dashboard dependencies are missing; run pnpm install --frozen-lockfile"
        )
    destination.mkdir(parents=True)
    for entry in source.iterdir():
        if _is_dashboard_local_state(entry.name):
            continue
        target = destination / entry.name
        if entry.is_dir():
            shutil.copytree(entry, target, symlinks=True)
        else:
            shutil.copy2(entry, target, follow_symlinks=False)
    os.symlink(
        node_modules.resolve(), destination / "node_modules", target_is_directory=True
    )


def _build_dashboard(
    *,
    repo_root: Path,
    temporary_root: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> Path:
    package_root = repo_root / "apps" / "dashboard"
    for required in ("package.json", "index.html", "vite.config.ts"):
        if not (package_root / required).is_file():
            raise AcceptanceError(
                f"Dashboard source is missing: apps/dashboard/{required}"
            )

    isolated_workspace = temporary_root / "dashboard-workspace"
    isolated_source = isolated_workspace / "apps" / "dashboard"
    output_directory = temporary_root / "dashboard-dist"
    cache_directory = temporary_root / "dashboard-vite-cache"
    build_log = temporary_root / "dashboard-build.log"
    isolated_source.parent.mkdir(parents=True)
    _copy_dashboard_source(package_root, isolated_source)
    # Dashboard production modules intentionally share a small hook contract with
    # the OpenClaw package. Preserve the monorepo-relative layout without copying
    # or writing to those source trees.
    for shared_name in ("packages", "tests"):
        shared_source = repo_root / shared_name
        if shared_source.exists():
            os.symlink(
                shared_source.resolve(),
                isolated_workspace / shared_name,
                target_is_directory=True,
            )

    wrapper_config = isolated_source / "acceptance.vite.config.ts"
    wrapper_config.write_text(
        "\n".join(
            [
                'import { defineConfig, mergeConfig } from "vite";',
                'import dashboardConfig from "./vite.config.ts";',
                "",
                "export default defineConfig(async (configEnv) => {",
                "  const resolved =",
                '    typeof dashboardConfig === "function"',
                "      ? await dashboardConfig(configEnv)",
                "      : await dashboardConfig;",
                "  return mergeConfig(resolved, {",
                f"    cacheDir: {json.dumps(str(cache_directory))},",
                "  });",
                "});",
                "",
            ]
        ),
        encoding="utf-8",
    )

    pnpm = shutil.which("pnpm", path=environment.get("PATH"))
    if pnpm is None:
        raise AcceptanceError("pnpm is required to build the Dashboard")
    command = [
        pnpm,
        "--filter",
        "@agentguard/dashboard",
        "exec",
        "vite",
        "build",
        str(isolated_source),
        "--config",
        str(wrapper_config),
        "--configLoader",
        "runner",
        "--outDir",
        str(output_directory),
        "--emptyOutDir",
        "--mode",
        "productization-alpha-acceptance",
        "--logLevel",
        "info",
    ]
    try:
        with build_log.open("wb") as log_handle:
            completed = subprocess.run(
                command,
                cwd=repo_root,
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                timeout=timeout_seconds,
                check=False,
            )
    except subprocess.TimeoutExpired:
        tail = _log_tail(build_log)
        detail = f"\nDashboard build log tail:\n{tail}" if tail else ""
        raise AcceptanceError(
            f"Dashboard build timed out after {timeout_seconds:g}s{detail}"
        ) from None
    except OSError as exc:
        raise AcceptanceError(f"Dashboard build process failed: {exc}") from None

    if completed.returncode != 0:
        tail = _log_tail(build_log)
        detail = f"\nDashboard build log tail:\n{tail}" if tail else ""
        raise AcceptanceError(
            f"Dashboard build failed (exit code {completed.returncode}){detail}"
        )
    index_path = output_directory / "index.html"
    assets_path = output_directory / "assets"
    if not index_path.is_file() or not assets_path.is_dir():
        raise AcceptanceError(
            "Dashboard build did not produce index.html and an assets directory"
        )
    if not any(path.is_file() for path in assets_path.rglob("*")):
        raise AcceptanceError("Dashboard build produced an empty assets directory")
    return output_directory


def _find_loopback_port(requested_port: int) -> int:
    if not 0 <= requested_port <= 65535:
        raise AcceptanceError("loopback port must be between 0 and 65535")
    if requested_port:
        return requested_port
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return int(probe.getsockname()[1])
    except OSError as exc:
        raise AcceptanceError(f"loopback port allocation failed: {exc}") from None


def _local_url(base_url: str, path: str) -> str:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in _LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise AcceptanceError("acceptance HTTP requests must target loopback HTTP")
    if not path.startswith("/"):
        raise AcceptanceError("acceptance HTTP path must be absolute")
    return f"{base_url.rstrip('/')}{path}"


def _request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    token: str | None = None,
    payload: Mapping[str, Any] | None = None,
    timeout_seconds: float,
) -> HttpPayload:
    url = _local_url(base_url, path)
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, data=body, headers=headers, method=method)
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            response_body = response.read(_MAX_HTTP_BODY_BYTES + 1)
            status = int(response.status)
            response_headers = dict(response.headers.items())
    except HTTPError as exc:
        response_body = exc.read(_MAX_HTTP_BODY_BYTES + 1)
        summary = _body_summary(response_body)
        raise AcceptanceError(
            f"{method} {path} returned HTTP {exc.code}: {summary}"
        ) from None
    except (URLError, TimeoutError, OSError) as exc:
        raise AcceptanceError(f"{method} {path} failed: {exc}") from None
    if len(response_body) > _MAX_HTTP_BODY_BYTES:
        raise AcceptanceError(f"{method} {path} returned an oversized response")
    if status != 200:
        raise AcceptanceError(f"{method} {path} returned HTTP {status}")
    return HttpPayload(status=status, headers=response_headers, body=response_body)


def _request_json(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    token: str | None = None,
    payload: Mapping[str, Any] | None = None,
    timeout_seconds: float,
) -> Any:
    response = _request(
        base_url,
        path,
        method=method,
        token=token,
        payload=payload,
        timeout_seconds=timeout_seconds,
    )
    try:
        return json.loads(response.body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise AcceptanceError(f"{method} {path} returned invalid JSON") from None


def _request_bytes(base_url: str, path: str, *, timeout_seconds: float) -> HttpPayload:
    return _request(base_url, path, timeout_seconds=timeout_seconds)


def _event_payloads(
    *, run_id: str, trace_id: str, agent_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    timestamp = datetime.now(timezone.utc).isoformat()
    common = {
        "schema_version": "0.3",
        "event_type": "tool_call_proposed",
        "runtime": "langgraph",
        "trace_id": trace_id,
        "timestamp": timestamp,
        "pre_execution": True,
        "metadata": {"acceptance_run_id": run_id},
    }
    benign = {
        **common,
        "event_id": f"evt_alpha_benign_{run_id}",
        "case_id": f"alpha-benign-{run_id}",
        "attack_type": "benign",
        "is_malicious": False,
        "security_context": {
            "user_task": "Read the requested documentation and summarize it",
            "source_type": "user",
            "source_trust": "trusted",
            "agent_id": agent_id,
        },
        "payload": {
            "tool": {
                "name": "read_file",
                "category": "file",
                "kind": "file_read",
                "call_id": f"call_alpha_benign_{run_id}",
            },
            "arguments": {"path": "/docs/public.txt"},
            "derived_resources": [],
        },
    }
    malicious = {
        **common,
        "event_id": f"evt_alpha_malicious_{run_id}",
        "case_id": f"alpha-malicious-{run_id}",
        "attack_type": "indirect_prompt_injection",
        "is_malicious": True,
        "security_context": {
            "user_task": "Read the requested documentation and summarize it",
            "source_type": "webpage",
            "source_trust": "untrusted",
            "agent_id": agent_id,
        },
        "payload": {
            "tool": {
                "name": "read_file",
                "category": "file",
                "kind": "file_read",
                "call_id": f"call_alpha_malicious_{run_id}",
            },
            "arguments": {"path": "/private/token.txt"},
            "derived_resources": [],
        },
    }
    return benign, malicious


def _issue_runtime_credential(
    *,
    base_url: str,
    control_token: str,
    agent_id: str,
    run_id: str,
    timeout_seconds: float,
) -> tuple[str, str]:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    response = _request_json(
        base_url,
        "/v1/credentials",
        method="POST",
        token=control_token,
        payload={
            "principal_id": f"acceptance:{run_id}",
            "runtime": "langgraph",
            "agent_id": agent_id,
            "expires_at": expires_at.isoformat(),
        },
        timeout_seconds=timeout_seconds,
    )
    if not isinstance(response, dict):
        raise AcceptanceError("credential issuance returned a non-object response")
    token = response.get("token")
    credential = response.get("credential")
    if not isinstance(token, str) or not token:
        raise AcceptanceError("credential issuance omitted the runtime token")
    if not isinstance(credential, dict):
        raise AcceptanceError("credential issuance omitted the credential record")
    credential_id = credential.get("credential_id")
    expected_scopes = {
        "adapter:status:write",
        "approval:wait",
        "event:audit:write",
        "event:evaluate",
    }
    if (
        not isinstance(credential_id, str)
        or credential.get("role") != "adapter"
        or credential.get("runtime") != "langgraph"
        or credential.get("agent_id") != agent_id
        or set(credential.get("scopes", [])) != expected_scopes
    ):
        raise AcceptanceError("credential issuance returned an unsafe runtime profile")
    return token, credential_id


def _validate_evaluation(
    response: Any, *, expected_decision: str, event_id: str
) -> str:
    if not isinstance(response, dict) or not isinstance(response.get("decision"), dict):
        raise AcceptanceError(f"evaluation {event_id} omitted its decision")
    actual_decision = response["decision"].get("decision")
    if actual_decision != expected_decision:
        raise AcceptanceError(
            f"evaluation {event_id} expected {expected_decision}, got {actual_decision!r}"
        )
    if response.get("approval") is not None:
        raise AcceptanceError(
            f"evaluation {event_id} unexpectedly required human approval"
        )
    policy_audit_id = response.get("policy_audit_id")
    if not isinstance(policy_audit_id, str) or not policy_audit_id:
        raise AcceptanceError(f"evaluation {event_id} omitted policy_audit_id")
    return policy_audit_id


def _validate_audit_window(
    response: Any,
    *,
    trace_id: str,
    expected: Mapping[str, tuple[str, bool, str]],
) -> None:
    if not isinstance(response, dict) or not isinstance(response.get("events"), list):
        raise AcceptanceError("audit query returned an invalid window")
    events_by_id: dict[str, dict[str, Any]] = {}
    for event in response["events"]:
        if not isinstance(event, dict):
            continue
        links = event.get("links")
        event_id = links.get("event_id") if isinstance(links, dict) else None
        if isinstance(event_id, str):
            events_by_id[event_id] = event

    for event_id, (decision, blocked, audit_id) in expected.items():
        event = events_by_id.get(event_id)
        if event is None:
            raise AcceptanceError(f"audit query omitted evaluation {event_id}")
        if (
            event.get("trace_id") != trace_id
            or event.get("record_type") != "policy_evaluation"
            or event.get("decision") != decision
            or event.get("blocked") is not blocked
            or event.get("audit_id") != audit_id
        ):
            raise AcceptanceError(
                f"audit record for {event_id} does not match its evaluation"
            )

    metrics = response.get("policy_metrics")
    if not isinstance(metrics, dict):
        raise AcceptanceError("audit query omitted policy metrics")
    expected_metrics = {"evaluation_count": 2, "allow_count": 1, "deny_count": 1}
    for key, value in expected_metrics.items():
        if metrics.get(key) != value:
            raise AcceptanceError(
                f"audit metric {key} expected {value}, got {metrics.get(key)!r}"
            )


def _validate_dashboard_access(*, base_url: str, timeout_seconds: float) -> str:
    index = _request_bytes(base_url, "/", timeout_seconds=timeout_seconds)
    try:
        html = index.body.decode("utf-8")
    except UnicodeDecodeError:
        raise AcceptanceError("Dashboard index is not valid UTF-8") from None
    if "AgentGuard Dashboard" not in html or 'id="app"' not in html:
        raise AcceptanceError(
            "Dashboard index does not contain the production app shell"
        )
    parser = _DashboardAssetParser()
    parser.feed(html)
    if not parser.assets:
        raise AcceptanceError("Dashboard index does not reference a built asset")
    asset_path = parser.assets[0]
    asset = _request_bytes(base_url, asset_path, timeout_seconds=timeout_seconds)
    if not asset.body:
        raise AcceptanceError(f"Dashboard asset is empty: {asset_path}")
    return asset_path


def _revoke_runtime_credential(
    *,
    base_url: str,
    control_token: str,
    credential_id: str,
    timeout_seconds: float,
) -> None:
    response = _request_json(
        base_url,
        f"/v1/credentials/{quote(credential_id, safe='')}/revoke",
        method="POST",
        token=control_token,
        timeout_seconds=timeout_seconds,
    )
    if not isinstance(response, dict) or not response.get("revoked_at"):
        raise AcceptanceError("runtime credential revocation was not confirmed")


def _verify_repo_layout(repo_root: Path) -> None:
    required = [
        repo_root / ".env.example",
        repo_root / "pyproject.toml",
        repo_root / "apps" / "guard-api" / "guard_api" / "main.py",
        repo_root / "apps" / "dashboard" / ".env.example",
    ]
    missing = [
        str(path.relative_to(repo_root)) for path in required if not path.is_file()
    ]
    if missing:
        raise AcceptanceError(
            f"repository layout is incomplete: {', '.join(sorted(missing))}"
        )


def run_acceptance(config: AcceptanceConfig) -> dict[str, Any]:
    """Run the complete acceptance flow and return a CI-friendly summary."""

    repo_root = config.repo_root.resolve()
    _verify_repo_layout(repo_root)
    root_example_path = repo_root / ".env.example"
    dashboard_example_path = repo_root / "apps" / "dashboard" / ".env.example"
    root_example = _required_example_values(
        _parse_dotenv_example(root_example_path),
        {
            "AGENTGUARD_AUDIT_CHECKPOINT_INTERVAL_SECONDS",
            "AGENTGUARD_MAX_REQUEST_BODY_BYTES",
        },
        path=root_example_path,
    )
    dashboard_example = _required_example_values(
        _parse_dotenv_example(dashboard_example_path),
        _DASHBOARD_EXAMPLE_KEYS,
        path=dashboard_example_path,
    )

    guard_port = _find_loopback_port(config.guard_port)
    control_token = secrets.token_urlsafe(32)
    run_id = uuid4().hex
    trace_id = f"trace_alpha_{run_id}"
    agent_id = f"alpha-{run_id}"
    guard_environment = _build_guard_environment(
        base_environment=os.environ,
        root_example=root_example,
        control_token=control_token,
        port=guard_port,
        postgresql_url=config.postgresql_url,
    )
    dashboard_environment = _build_dashboard_environment(
        base_environment=os.environ,
        dashboard_example=dashboard_example,
        guard_port=guard_port,
    )

    checks: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(
        prefix="agentguard-productization-alpha-"
    ) as temporary_name:
        temporary_root = Path(temporary_name)
        dashboard_dist = _build_dashboard(
            repo_root=repo_root,
            temporary_root=temporary_root,
            environment=dashboard_environment,
            timeout_seconds=config.dashboard_build_timeout_seconds,
        )
        checks.append(
            {
                "name": "dashboard_build",
                "status": "pass",
                "detail": "isolated Vite build completed",
            }
        )

        redactions = tuple(
            value for value in (control_token, config.postgresql_url) if value
        )
        guard_log = temporary_root / "guard-api.log"
        with GuardApiProcess(
            repo_root=repo_root,
            port=guard_port,
            environment=guard_environment,
            log_path=guard_log,
            startup_timeout_seconds=config.startup_timeout_seconds,
            request_timeout_seconds=config.request_timeout_seconds,
            redactions=redactions,
        ) as guard:
            checks.append(
                {
                    "name": "guard_api_health",
                    "status": "pass",
                    "detail": f"{config.storage_backend} backend is ready",
                }
            )
            adapter_token: str | None = None
            credential_id: str | None = None
            primary_error: AcceptanceError | None = None
            cleanup_error: AcceptanceError | None = None
            try:
                adapter_token, credential_id = _issue_runtime_credential(
                    base_url=guard.base_url,
                    control_token=control_token,
                    agent_id=agent_id,
                    run_id=run_id,
                    timeout_seconds=config.request_timeout_seconds,
                )
                checks.append(
                    {
                        "name": "runtime_credential",
                        "status": "pass",
                        "detail": "short-lived runtime-bound credential issued",
                    }
                )

                benign, malicious = _event_payloads(
                    run_id=run_id, trace_id=trace_id, agent_id=agent_id
                )
                benign_response = _request_json(
                    guard.base_url,
                    "/v1/guard/evaluate",
                    method="POST",
                    token=adapter_token,
                    payload=benign,
                    timeout_seconds=config.request_timeout_seconds,
                )
                benign_audit_id = _validate_evaluation(
                    benign_response,
                    expected_decision="allow",
                    event_id=benign["event_id"],
                )
                checks.append(
                    {
                        "name": "benign_allow",
                        "status": "pass",
                        "detail": "public document read allowed",
                    }
                )

                malicious_response = _request_json(
                    guard.base_url,
                    "/v1/guard/evaluate",
                    method="POST",
                    token=adapter_token,
                    payload=malicious,
                    timeout_seconds=config.request_timeout_seconds,
                )
                malicious_audit_id = _validate_evaluation(
                    malicious_response,
                    expected_decision="deny",
                    event_id=malicious["event_id"],
                )
                checks.append(
                    {
                        "name": "malicious_block",
                        "status": "pass",
                        "detail": "sensitive file read denied before execution",
                    }
                )

                audit_response = _request_json(
                    guard.base_url,
                    f"/v1/audit/window?trace_id={quote(trace_id, safe='')}",
                    token=control_token,
                    timeout_seconds=config.request_timeout_seconds,
                )
                _validate_audit_window(
                    audit_response,
                    trace_id=trace_id,
                    expected={
                        benign["event_id"]: ("allow", False, benign_audit_id),
                        malicious["event_id"]: (
                            "deny",
                            True,
                            malicious_audit_id,
                        ),
                    },
                )
                checks.append(
                    {
                        "name": "audit_query",
                        "status": "pass",
                        "detail": "allow and blocked deny records are queryable",
                    }
                )

                with DashboardServer(
                    dashboard_dist, config.dashboard_port
                ) as dashboard:
                    asset_path = _validate_dashboard_access(
                        base_url=dashboard.base_url,
                        timeout_seconds=config.request_timeout_seconds,
                    )
                checks.append(
                    {
                        "name": "dashboard_static",
                        "status": "pass",
                        "detail": f"app shell and asset served ({asset_path})",
                    }
                )
            except AcceptanceError as exc:
                primary_error = exc
            finally:
                if credential_id is not None:
                    try:
                        _revoke_runtime_credential(
                            base_url=guard.base_url,
                            control_token=control_token,
                            credential_id=credential_id,
                            timeout_seconds=config.request_timeout_seconds,
                        )
                        checks.append(
                            {
                                "name": "credential_cleanup",
                                "status": "pass",
                                "detail": "runtime credential revoked",
                            }
                        )
                    except AcceptanceError as exc:
                        cleanup_error = exc

            if primary_error is not None or cleanup_error is not None:
                messages = []
                if primary_error is not None:
                    messages.append(str(primary_error))
                if cleanup_error is not None:
                    messages.append(f"cleanup failed: {cleanup_error}")
                tail = guard.log_tail(extra_redactions=(adapter_token or "",))
                if tail:
                    messages.append(f"Guard API log tail:\n{tail}")
                raise AcceptanceError("\n".join(messages))

    return {
        "status": "pass",
        "profile": "productization-alpha-clean-clone",
        "storage_backend": config.storage_backend,
        "provider_calls": "disabled",
        "temporary_artifacts_cleaned": True,
        "checks": checks,
    }


def _validate_postgresql_url(value: str) -> str:
    parsed = urlsplit(value)
    database_name = parsed.path.lstrip("/").rsplit("/", 1)[-1]
    if (
        parsed.scheme not in _POSTGRESQL_SCHEMES
        or parsed.hostname is None
        or not database_name
    ):
        raise AcceptanceError(
            "acceptance PostgreSQL URL must use postgresql[+psycopg]://host/database"
        )
    if database_name != "agent_guard_test" and not database_name.endswith("_test"):
        raise AcceptanceError(
            "acceptance PostgreSQL database name must be agent_guard_test or end with _test"
        )
    return value


def _resolve_postgresql_url(
    command_line_value: str | None, environment: Mapping[str, str]
) -> str | None:
    environment_value = environment.get("AGENTGUARD_ACCEPTANCE_DATABASE_URL")
    if (
        command_line_value
        and environment_value
        and command_line_value != environment_value
    ):
        raise AcceptanceError(
            "--postgresql-url conflicts with AGENTGUARD_ACCEPTANCE_DATABASE_URL"
        )
    selected = command_line_value or environment_value
    if selected is None:
        return None
    selected = selected.strip()
    if not selected:
        raise AcceptanceError("acceptance PostgreSQL URL cannot be empty")
    return _validate_postgresql_url(selected)


def _log_tail(path: Path, *, redactions: Sequence[str] = ()) -> str:
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - _MAX_LOG_TAIL_BYTES))
            text = stream.read().decode("utf-8", errors="replace")
    except OSError:
        return ""
    for secret in redactions:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text.strip()


def _body_summary(body: bytes) -> str:
    text = body[:1000].decode("utf-8", errors="replace")
    return " ".join(text.split()) or "empty response"


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)[:1000]
    except (TypeError, ValueError):
        return repr(value)[:1000]


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number") from None
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _port(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer") from None
    if not 0 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("must be between 0 and 65535")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the Productization Alpha acceptance flow using only local "
            "loopback services and temporary artifacts."
        )
    )
    parser.add_argument(
        "--postgresql-url",
        metavar="URL",
        help=(
            "use an explicitly supplied disposable PostgreSQL database instead "
            "of the default in-memory backend; alternatively set "
            "AGENTGUARD_ACCEPTANCE_DATABASE_URL"
        ),
    )
    parser.add_argument(
        "--guard-port",
        type=_port,
        default=0,
        help="loopback Guard API port (default: choose an ephemeral port)",
    )
    parser.add_argument(
        "--dashboard-port",
        type=_port,
        default=0,
        help="loopback Dashboard port (default: choose an ephemeral port)",
    )
    parser.add_argument(
        "--startup-timeout",
        type=_positive_float,
        default=30.0,
        metavar="SECONDS",
    )
    parser.add_argument(
        "--request-timeout",
        type=_positive_float,
        default=5.0,
        metavar="SECONDS",
    )
    parser.add_argument(
        "--dashboard-build-timeout",
        type=_positive_float,
        default=180.0,
        metavar="SECONDS",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit one machine-readable result object",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        postgresql_url = _resolve_postgresql_url(arguments.postgresql_url, os.environ)
        result = run_acceptance(
            AcceptanceConfig(
                postgresql_url=postgresql_url,
                guard_port=arguments.guard_port,
                dashboard_port=arguments.dashboard_port,
                startup_timeout_seconds=arguments.startup_timeout,
                request_timeout_seconds=arguments.request_timeout,
                dashboard_build_timeout_seconds=arguments.dashboard_build_timeout,
            )
        )
    except AcceptanceError as exc:
        if arguments.json:
            print(json.dumps({"status": "fail", "error": str(exc)}))
        else:
            print(f"[FAIL] Productization Alpha acceptance: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("[FAIL] Productization Alpha acceptance interrupted", file=sys.stderr)
        return 130

    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        for check in result["checks"]:
            print(f"[PASS] {check['name']}: {check['detail']}")
        print("[PASS] Productization Alpha clean-clone acceptance completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
