from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Any

import pytest

from scripts.release import productization_alpha_acceptance as alpha

pytestmark = pytest.mark.unit


_ROOT_EXAMPLE = {
    "AGENTGUARD_AUDIT_CHECKPOINT_INTERVAL_SECONDS": "300",
    "AGENTGUARD_MAX_REQUEST_BODY_BYTES": "1048576",
}
_DASHBOARD_EXAMPLE = {
    "VITE_API_BASE_URL": "/api/v1",
    "VITE_API_HEALTH_URL": "/api/health",
    "VITE_API_MOCK_DELAY": "250",
    "VITE_API_REQUEST_TIMEOUT_MS": "10000",
    "VITE_BACKEND_TARGET": "http://127.0.0.1:8088",
    "VITE_EVIDENCE_POLL_INTERVAL_MS": "10000",
    "VITE_RUNTIME_SUPERVISION_S1_ENABLED": "true",
}


def _write_fake_repo(root: Path) -> None:
    (root / "apps" / "guard-api" / "guard_api").mkdir(parents=True)
    dashboard = root / "apps" / "dashboard"
    (dashboard / "node_modules").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        "[project]\nname='fixture'\n", encoding="utf-8"
    )
    (root / ".env.example").write_text(
        "\n".join(f"{key}={value}" for key, value in _ROOT_EXAMPLE.items()),
        encoding="utf-8",
    )
    (root / "apps" / "guard-api" / "guard_api" / "main.py").write_text(
        "# fixture\n", encoding="utf-8"
    )
    (dashboard / ".env.example").write_text(
        "\n".join(f"{key}={value}" for key, value in _DASHBOARD_EXAMPLE.items()),
        encoding="utf-8",
    )
    (dashboard / "package.json").write_text("{}\n", encoding="utf-8")
    (dashboard / "index.html").write_text('<div id="app"></div>\n', encoding="utf-8")
    (dashboard / "vite.config.ts").write_text("export default {};\n", encoding="utf-8")


def test_guard_environment_overrides_inherited_runtime_and_provider_state() -> None:
    inherited = {
        "PATH": "/usr/bin",
        "OPENAI_API_KEY": "real-provider-secret",
        "VITE_API_BASE_URL": "https://outside.invalid",
        "AGENTGUARD_ENV": "production",
        "AGENTGUARD_STORAGE_BACKEND": "postgres",
        "AGENTGUARD_DATABASE_URL": "postgresql://production.invalid/prod",
        "AGENTGUARD_LLM_APPROVAL_ENABLED": "true",
        "AGENTGUARD_LLM_APPROVAL_API_KEY": "real-approval-secret",
        "AGENTGUARD_V21_SEMANTIC_ENABLED": "true",
    }

    environment = alpha._build_guard_environment(
        base_environment=inherited,
        root_example=_ROOT_EXAMPLE,
        control_token="ephemeral-control-token",
        port=18088,
        postgresql_url=None,
    )

    assert environment["PATH"] == "/usr/bin"
    assert environment["AGENTGUARD_ENV"] == "test"
    assert environment["AGENTGUARD_STORAGE_BACKEND"] == "memory"
    assert environment["AGENTGUARD_HOST"] == "127.0.0.1"
    assert environment["AGENTGUARD_LLM_APPROVAL_ENABLED"] == "false"
    assert environment["AGENTGUARD_V21_SEMANTIC_ENABLED"] == "false"
    assert environment["AGENTGUARD_LLM_APPROVAL_API_KEY"] == ""
    assert environment["AGENTGUARD_DATABASE_URL"].endswith("@127.0.0.1:1/unused")
    assert "OPENAI_API_KEY" not in environment
    assert "VITE_API_BASE_URL" not in environment
    assert "production.invalid" not in "\n".join(environment.values())


def test_dashboard_environment_uses_only_example_values_and_loopback_target() -> None:
    environment = alpha._build_dashboard_environment(
        base_environment={
            "PATH": "/usr/bin",
            "NODE_OPTIONS": "--require=/untrusted.js",
            "VITE_API_BASE_URL": "https://outside.invalid",
            "OPENAI_API_KEY": "provider-secret",
            "AGENTGUARD_CONTROL_TOKEN": "do-not-inherit",
        },
        dashboard_example=_DASHBOARD_EXAMPLE,
        guard_port=19099,
    )

    assert environment["VITE_API_BASE_URL"] == "/api/v1"
    assert environment["VITE_BACKEND_TARGET"] == "http://127.0.0.1:19099"
    assert environment["NODE_ENV"] == "production"
    assert "NODE_OPTIONS" not in environment
    assert "OPENAI_API_KEY" not in environment
    assert "AGENTGUARD_CONTROL_TOKEN" not in environment


def test_postgresql_is_opt_in_and_regular_database_environment_is_ignored() -> None:
    assert (
        alpha._resolve_postgresql_url(
            None,
            {
                "AGENTGUARD_DATABASE_URL": "postgresql://production.invalid/prod",
                "AGENTGUARD_TEST_DATABASE_URL": "postgresql://test.invalid/test",
            },
        )
        is None
    )
    assert (
        alpha._resolve_postgresql_url(
            None,
            {
                "AGENTGUARD_ACCEPTANCE_DATABASE_URL": (
                    "postgresql+psycopg://postgres@127.0.0.1/alpha_test"
                )
            },
        )
        == "postgresql+psycopg://postgres@127.0.0.1/alpha_test"
    )
    with pytest.raises(alpha.AcceptanceError, match="must use postgresql"):
        alpha._resolve_postgresql_url("sqlite:///tmp/unsafe.db", {})
    with pytest.raises(alpha.AcceptanceError, match="end with _test"):
        alpha._resolve_postgresql_url(
            "postgresql+psycopg://postgres@127.0.0.1/production", {}
        )
    with pytest.raises(alpha.AcceptanceError, match="conflicts"):
        alpha._resolve_postgresql_url(
            "postgresql://one.invalid/alpha",
            {"AGENTGUARD_ACCEPTANCE_DATABASE_URL": "postgresql://two.invalid/alpha"},
        )


def test_dashboard_source_copy_excludes_local_state_and_generated_artifacts(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "isolated"
    (source / "src").mkdir(parents=True)
    (source / "node_modules").mkdir()
    (source / "dist").mkdir()
    (source / "test-results").mkdir()
    (source / "src" / "main.ts").write_text("export {};\n", encoding="utf-8")
    (source / "package.json").write_text("{}\n", encoding="utf-8")
    (source / ".env").write_text("VITE_SECRET=local\n", encoding="utf-8")
    (source / ".env.local").write_text("VITE_SECRET=local\n", encoding="utf-8")
    (source / ".env.example").write_text(
        "VITE_API_BASE_URL=/api/v1\n", encoding="utf-8"
    )
    (source / "dist" / "old.js").write_text("old\n", encoding="utf-8")

    alpha._copy_dashboard_source(source, destination)

    assert (destination / "src" / "main.ts").is_file()
    assert (destination / ".env.example").is_file()
    assert not (destination / ".env").exists()
    assert not (destination / ".env.local").exists()
    assert not (destination / "dist").exists()
    assert not (destination / "test-results").exists()
    assert (destination / "node_modules").is_symlink()


def test_dashboard_build_preserves_monorepo_import_layout_in_temporary_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root = tmp_path / "repo"
    _write_fake_repo(repo_root)
    (repo_root / "packages").mkdir()
    (repo_root / "tests").mkdir()
    temporary_root = tmp_path / "run"
    temporary_root.mkdir()

    monkeypatch.setattr(alpha.shutil, "which", lambda *_args, **_kwargs: "/bin/pnpm")

    def fake_run(
        command: list[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[bytes]:
        assert command[command.index("--configLoader") + 1] == "runner"
        isolated_source = Path(command[command.index("build") + 1])
        isolated_workspace = isolated_source.parents[1]
        assert isolated_source == isolated_workspace / "apps" / "dashboard"
        assert (isolated_workspace / "packages").is_symlink()
        assert (isolated_workspace / "tests").is_symlink()
        assert not (isolated_source / ".env").exists()
        output = Path(command[command.index("--outDir") + 1])
        (output / "assets").mkdir(parents=True)
        (output / "index.html").write_text("index\n", encoding="utf-8")
        (output / "assets" / "app.js").write_text("app\n", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(alpha.subprocess, "run", fake_run)

    output = alpha._build_dashboard(
        repo_root=repo_root,
        temporary_root=temporary_root,
        environment={"PATH": "/bin"},
        timeout_seconds=10,
    )

    assert output == temporary_root / "dashboard-dist"
    assert (output / "index.html").is_file()
    assert not (repo_root / "apps" / "dashboard" / "dist").exists()


def test_audit_validation_requires_authoritative_block_and_matching_audit_ids() -> None:
    response = {
        "events": [
            {
                "audit_id": "audit_allow",
                "record_type": "policy_evaluation",
                "trace_id": "trace_alpha",
                "decision": "allow",
                "blocked": False,
                "links": {"event_id": "evt_allow"},
            },
            {
                "audit_id": "audit_deny",
                "record_type": "policy_evaluation",
                "trace_id": "trace_alpha",
                "decision": "deny",
                "blocked": True,
                "links": {"event_id": "evt_deny"},
            },
        ],
        "policy_metrics": {
            "evaluation_count": 2,
            "allow_count": 1,
            "deny_count": 1,
        },
    }

    alpha._validate_audit_window(
        response,
        trace_id="trace_alpha",
        expected={
            "evt_allow": ("allow", False, "audit_allow"),
            "evt_deny": ("deny", True, "audit_deny"),
        },
    )

    response["events"][1]["blocked"] = False
    with pytest.raises(alpha.AcceptanceError, match="does not match"):
        alpha._validate_audit_window(
            response,
            trace_id="trace_alpha",
            expected={
                "evt_allow": ("allow", False, "audit_allow"),
                "evt_deny": ("deny", True, "audit_deny"),
            },
        )


def test_acceptance_events_share_one_trace_task_without_weakening_attack_case() -> None:
    benign, malicious = alpha._event_payloads(
        run_id="run", trace_id="trace", agent_id="agent"
    )

    assert (
        benign["security_context"]["user_task"]
        == malicious["security_context"]["user_task"]
    )
    assert benign["payload"]["arguments"]["path"] == "/docs/public.txt"
    assert malicious["payload"]["arguments"]["path"] == "/private/token.txt"
    assert benign["is_malicious"] is False
    assert malicious["is_malicious"] is True
    assert malicious["security_context"]["source_trust"] == "untrusted"


def test_http_boundary_rejects_non_loopback_and_non_http_targets() -> None:
    with pytest.raises(alpha.AcceptanceError, match="loopback HTTP"):
        alpha._local_url("https://127.0.0.1:8088", "/health")
    with pytest.raises(alpha.AcceptanceError, match="loopback HTTP"):
        alpha._local_url("http://api.example.invalid", "/health")
    with pytest.raises(alpha.AcceptanceError, match="path must be absolute"):
        alpha._local_url("http://127.0.0.1:8088", "health")


def test_loopback_port_allocation_failure_is_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_socket(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("sandbox denied socket")

    monkeypatch.setattr(alpha.socket, "socket", fail_socket)

    with pytest.raises(alpha.AcceptanceError, match="loopback port allocation failed"):
        alpha._find_loopback_port(0)


def test_run_acceptance_exercises_full_contract_and_cleans_temporary_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root = tmp_path / "repo"
    _write_fake_repo(repo_root)
    state: dict[str, Any] = {"events": {}, "revoked": False}

    def fake_build_dashboard(**kwargs: Any) -> Path:
        output = kwargs["temporary_root"] / "dashboard-dist"
        (output / "assets").mkdir(parents=True)
        (output / "index.html").write_text(
            """<!doctype html><title>AgentGuard Dashboard</title>
            <div id="app"></div><script src="/assets/app.js"></script>""",
            encoding="utf-8",
        )
        (output / "assets" / "app.js").write_text("export {};\n", encoding="utf-8")
        state["temporary_root"] = kwargs["temporary_root"]
        return output

    class FakeGuardApiProcess:
        def __init__(self, **_kwargs: Any) -> None:
            self.base_url = "http://127.0.0.1:18088"

        def __enter__(self) -> FakeGuardApiProcess:
            return self

        def __exit__(self, *_exc: object) -> None:
            state["guard_stopped"] = True

        def log_tail(self, *, extra_redactions: Any = ()) -> str:
            del extra_redactions
            return ""

    class FakeDashboardServer:
        def __init__(self, directory: Path, port: int) -> None:
            assert directory.name == "dashboard-dist"
            assert port == 14173
            self.base_url = "http://127.0.0.1:14173"

        def __enter__(self) -> FakeDashboardServer:
            return self

        def __exit__(self, *_exc: object) -> None:
            state["dashboard_stopped"] = True

    def fake_request_json(
        _base_url: str,
        path: str,
        *,
        method: str = "GET",
        token: str | None = None,
        payload: dict[str, Any] | None = None,
        timeout_seconds: float,
    ) -> Any:
        assert timeout_seconds == 2
        if path == "/v1/credentials" and method == "POST":
            assert payload is not None
            state["control_token"] = token
            state["agent_id"] = payload["agent_id"]
            return {
                "token": "ephemeral-adapter-token",
                "credential": {
                    "credential_id": "cred_alpha",
                    "role": "adapter",
                    "runtime": "langgraph",
                    "agent_id": payload["agent_id"],
                    "scopes": [
                        "event:evaluate",
                        "event:audit:write",
                        "approval:wait",
                        "adapter:status:write",
                    ],
                },
            }
        if path == "/v1/guard/evaluate" and method == "POST":
            assert token == "ephemeral-adapter-token"
            assert payload is not None
            event_id = payload["event_id"]
            decision = (
                "allow"
                if payload["payload"]["arguments"]["path"] == "/docs/public.txt"
                else "deny"
            )
            audit_id = f"audit_{event_id}"
            state["events"][event_id] = {
                "audit_id": audit_id,
                "record_type": "policy_evaluation",
                "trace_id": payload["trace_id"],
                "decision": decision,
                "blocked": decision == "deny",
                "links": {"event_id": event_id},
            }
            return {
                "decision": {"decision": decision},
                "approval": None,
                "policy_audit_id": audit_id,
            }
        if path.startswith("/v1/audit/window?"):
            assert token == state["control_token"]
            return {
                "events": list(state["events"].values()),
                "policy_metrics": {
                    "evaluation_count": 2,
                    "allow_count": 1,
                    "deny_count": 1,
                },
            }
        if path == "/v1/credentials/cred_alpha/revoke" and method == "POST":
            assert token == state["control_token"]
            state["revoked"] = True
            return {"credential_id": "cred_alpha", "revoked_at": "now"}
        raise AssertionError(f"unexpected request: {method} {path}")

    def fake_request_bytes(
        _base_url: str, path: str, *, timeout_seconds: float
    ) -> alpha.HttpPayload:
        assert timeout_seconds == 2
        if path == "/":
            body = (
                b"<!doctype html><title>AgentGuard Dashboard</title>"
                b'<div id="app"></div><script src="/assets/app.js"></script>'
            )
        elif path == "/assets/app.js":
            body = b"export {};"
        else:
            raise AssertionError(f"unexpected static request: {path}")
        return alpha.HttpPayload(status=200, headers={}, body=body)

    monkeypatch.setattr(alpha, "_build_dashboard", fake_build_dashboard)
    monkeypatch.setattr(alpha, "GuardApiProcess", FakeGuardApiProcess)
    monkeypatch.setattr(alpha, "DashboardServer", FakeDashboardServer)
    monkeypatch.setattr(alpha, "_request_json", fake_request_json)
    monkeypatch.setattr(alpha, "_request_bytes", fake_request_bytes)

    result = alpha.run_acceptance(
        alpha.AcceptanceConfig(
            repo_root=repo_root,
            guard_port=18088,
            dashboard_port=14173,
            request_timeout_seconds=2,
        )
    )

    assert result["status"] == "pass"
    assert result["provider_calls"] == "disabled"
    assert result["temporary_artifacts_cleaned"] is True
    assert {check["name"] for check in result["checks"]} == {
        "dashboard_build",
        "guard_api_health",
        "runtime_credential",
        "benign_allow",
        "malicious_block",
        "audit_query",
        "dashboard_static",
        "credential_cleanup",
    }
    assert state["revoked"] is True
    assert state["guard_stopped"] is True
    assert state["dashboard_stopped"] is True
    assert not state["temporary_root"].exists()


def test_log_tail_redacts_control_tokens_and_database_urls(tmp_path: Path) -> None:
    log = tmp_path / "guard.log"
    log.write_text(
        "token=control-secret db=postgresql://user:password@db.invalid/alpha\n",
        encoding="utf-8",
    )

    tail = alpha._log_tail(
        log,
        redactions=(
            "control-secret",
            "postgresql://user:password@db.invalid/alpha",
        ),
    )

    assert "control-secret" not in tail
    assert "password" not in tail
    assert tail.count("[REDACTED]") == 2
