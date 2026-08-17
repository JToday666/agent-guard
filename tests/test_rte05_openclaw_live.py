"""Opt-in cross-process RTE-05 acceptance for the built OpenClaw plugin."""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import httpx
import pytest
import uvicorn

from agentguard_core import PolicyBundle, RuleOverride
from agentguard_core.authority.models import TaskFact
from guard_api.main import create_app
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import ControlPlaneStore, TaskFactRecord
from guard_api.storage.integrity import canonical_sha256
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.auth import add_adapter_credential
from tests.support.postgres import get_test_database_url, reset_control_plane_schema

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "openclaw-rte05-host-chain.mjs"
OPENCLAW_DIST = ROOT / "packages" / "agentguard-openclaw-plugin" / "dist" / "index.js"
RESULT_MARKER = "AGENTGUARD_RTE05_OPENCLAW_RESULT="

ADAPTER_TOKEN = "rte05-openclaw-live-adapter"
CONTROL_TOKEN = "rte05-openclaw-live-control"
PRINCIPAL_ID = "cred_rte05_openclaw_live"
TASK_ID = "task_rte05_openclaw_live"
TASK_SCOPE_KEY_ID = "rte05-openclaw-live-key"
TASK_SCOPE_KEY = base64.urlsafe_b64encode(
    b"rte-05-openclaw-live-task-scope-key-material-0001"
).decode("ascii")
V21_SECRET = base64.urlsafe_b64encode(
    b"rte-05-openclaw-live-action-fingerprint-secret-0001"
).decode("ascii")
SCOPE_DIGEST = "hmac-sha256:" + "6b" * 32
FINGERPRINT_PATTERN = re.compile(r"hmac-sha256:[0-9a-f]{64}")
LEASE_TOKEN_PATTERN = re.compile(r"lease-v1:[0-9a-f]{64}")


def test_openclaw_rte05_live_exact_binding_and_toctou_failure(
    tmp_path: Path,
) -> None:
    """Drive real plugin hooks against a live Memory or PostgreSQL Guard API."""

    if os.getenv("AGENTGUARD_RTE05_LIVE_GATE") != "1":
        pytest.skip("set AGENTGUARD_RTE05_LIVE_GATE=1 to run RTE-05 live acceptance")
    if not OPENCLAW_DIST.is_file():
        pytest.fail("RTE-05 live gate requires the built OpenClaw plugin")
    backend = os.getenv("AGENTGUARD_RTE05_STORAGE_BACKEND", "memory").strip().lower()
    if backend not in {"memory", "postgres"}:
        pytest.fail("AGENTGUARD_RTE05_STORAGE_BACKEND must be memory or postgres")

    with _live_backend(backend) as (app, store):
        with _serve(app) as base_url:
            success = _run_openclaw_scenario(
                base_url=base_url,
                scenario="success",
                trace_id="trace_rte05_openclaw_live_success",
                action_id="call_rte05_openclaw_live_success",
                state_dir=tmp_path / "success-state",
                approval_delay=0.0,
            )
            success_trace = _wait_for_outcomes(
                base_url,
                success["result"]["trace_id"],
                {"approval_release", "execution_completed"},
            )
            _assert_success_chain(success, success_trace, store)

            drift = _run_openclaw_scenario(
                base_url=base_url,
                scenario="drift",
                trace_id="trace_rte05_openclaw_live_drift",
                action_id="call_rte05_openclaw_live_drift",
                state_dir=tmp_path / "drift-state",
                # Make the host mutation deterministic before human release.
                approval_delay=0.35,
            )
            drift_trace = _wait_for_outcomes(
                base_url,
                drift["result"]["trace_id"],
                {"pre_execution_deny"},
            )
            _assert_drift_chain(drift, drift_trace, store)


@contextmanager
def _live_backend(
    backend: str,
) -> Iterator[tuple[Any, ControlPlaneStore]]:
    database_url: str | None = None
    if backend == "postgres":
        database_url = get_test_database_url()
        reset_control_plane_schema(database_url)
        store: ControlPlaneStore = PostgresControlPlaneStore(database_url)
    else:
        store = MemoryControlPlaneStore()

    try:
        store.initialize()
        add_adapter_credential(
            store,
            token=ADAPTER_TOKEN,
            runtime="openclaw",
            agent_id="main",
            principal_id=PRINCIPAL_ID,
        )
        _seed_task(store)
        settings = GuardApiSettings(
            storage_backend=backend,
            database_url=database_url or GuardApiSettings().database_url,
            control_token=CONTROL_TOKEN,
            v21_shadow_enabled=True,
            v21_shadow_server_secret=V21_SECRET,
            task_scope_active_key_id=TASK_SCOPE_KEY_ID,
            task_scope_keys=json.dumps({TASK_SCOPE_KEY_ID: TASK_SCOPE_KEY}),
            rte05_strong_binding_enabled=True,
            approval_ttl_seconds=30,
        )
        app = create_app(
            store=store,
            settings=settings,
            policy_bundle=PolicyBundle(
                bundle_id="rte05-openclaw-live",
                version="1",
                rule_overrides={
                    "P005_external_send": RuleOverride(
                        decision="ask",
                        risk_score=62,
                        severity="medium",
                    )
                },
            ),
        )
        yield app, store
    finally:
        if database_url is not None:
            reset_control_plane_schema(database_url)


def _seed_task(store: ControlPlaneStore) -> None:
    task = TaskFact(
        task_id=TASK_ID,
        scope_digest=SCOPE_DIGEST,
        scope_key_id=TASK_SCOPE_KEY_ID,
        principal_id=PRINCIPAL_ID,
        task_summary="OpenClaw RTE-05 live exact-binding acceptance",
        task_digest="sha256:" + "d4" * 32,
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
    payload = task.model_dump(mode="json")
    store.create_task_fact(
        TaskFactRecord(
            task_fact=task,
            canonical_payload=payload,
            request_digest=canonical_sha256(payload),
            expected_revision=0,
            created_at="2026-08-16T00:00:00+00:00",
        )
    )


def _run_openclaw_scenario(
    *,
    base_url: str,
    scenario: str,
    trace_id: str,
    action_id: str,
    state_dir: Path,
    approval_delay: float,
) -> dict[str, Any]:
    environment = os.environ.copy()
    environment.update(
        {
            "OPENCLAW_STATE_DIR": str(state_dir),
            "AGENTGUARD_RTE05_LIVE_BASE_URL": base_url,
            "AGENTGUARD_RTE05_LIVE_ADAPTER_TOKEN": ADAPTER_TOKEN,
            "AGENTGUARD_RTE05_LIVE_TASK_ID": TASK_ID,
            "AGENTGUARD_RTE05_LIVE_RUNTIME_BINDING_ID": (f"binding:{PRINCIPAL_ID}"),
            "AGENTGUARD_RTE05_LIVE_TRACE_ID": trace_id,
            "AGENTGUARD_RTE05_LIVE_ACTION_ID": action_id,
            "AGENTGUARD_RTE05_LIVE_SCENARIO": scenario,
        }
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        approval_future = executor.submit(
            _resolve_browser_approval,
            base_url,
            action_id,
            approval_delay,
        )
        completed = subprocess.run(
            ["node", str(RUNNER)],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=25,
            check=False,
        )
        assert (
            completed.returncode == 0
        ), f"OpenClaw live runner failed ({scenario}): {completed.stderr}"
        resolved = approval_future.result(timeout=3)

    marker_lines = [
        line.removeprefix(RESULT_MARKER)
        for line in completed.stdout.splitlines()
        if line.startswith(RESULT_MARKER)
    ]
    assert len(marker_lines) == 1, completed.stdout
    result = json.loads(marker_lines[0])
    assert result["scenario"] == scenario
    assert result["trace_id"] == trace_id
    assert result["action_id"] == action_id
    return {
        "result": result,
        "resolved": resolved,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "spool": _read_state_files(state_dir),
    }


def _resolve_browser_approval(
    base_url: str,
    action_id: str,
    delay_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + 15.0
    with httpx.Client(base_url=base_url, timeout=3.0) as client:
        launch = client.post(
            "/v1/auth/browser/launch",
            headers={"Authorization": f"Bearer {CONTROL_TOKEN}"},
        )
        launch.raise_for_status()
        exchange = client.post(
            "/v1/auth/browser/exchange",
            json={"launch_code": launch.json()["launch_code"]},
        )
        exchange.raise_for_status()
        csrf_token = exchange.json()["csrf_token"]

        while time.monotonic() < deadline:
            pending_response = client.get("/v1/approvals/pending")
            pending_response.raise_for_status()
            approval = next(
                (
                    item
                    for item in pending_response.json()
                    if item.get("action_id") == action_id
                    and item.get("action_name") == "send_email"
                ),
                None,
            )
            if approval is not None:
                if delay_seconds > 0:
                    time.sleep(delay_seconds)
                response = client.post(
                    f"/v1/approvals/{approval['approval_id']}/resolve",
                    headers={"X-AgentGuard-CSRF": csrf_token},
                    json={"decision": "allow_once"},
                )
                response.raise_for_status()
                return response.json()
            time.sleep(0.025)
    raise AssertionError(f"approval for {action_id} did not become pending")


def _wait_for_outcomes(
    base_url: str,
    trace_id: str,
    expected_kinds: set[str],
) -> dict[str, Any]:
    deadline = time.monotonic() + 10.0
    headers = {"Authorization": f"Bearer {CONTROL_TOKEN}"}
    latest: dict[str, Any] = {}
    with httpx.Client(base_url=base_url, headers=headers, timeout=3.0) as client:
        while time.monotonic() < deadline:
            response = client.get(f"/v1/traces/{trace_id}")
            response.raise_for_status()
            latest = response.json()
            kinds = {
                event.get("metadata", {}).get("outcome_kind")
                for event in latest.get("audit_events", [])
                if event.get("record_type") == "runtime_outcome"
            }
            if expected_kinds <= kinds:
                return latest
            time.sleep(0.05)
    raise AssertionError(
        f"trace {trace_id} did not contain outcomes {sorted(expected_kinds)}: {latest}"
    )


def _assert_success_chain(
    run: dict[str, Any],
    trace: dict[str, Any],
    store: ControlPlaneStore,
) -> None:
    result = run["result"]
    assert result["blocked"] is False
    assert result["invocation_count"] == 1
    assert result["before_hook_count"] == 1
    assert result["after_hook_count"] >= 2
    assert result["service_count"] == 1
    assert result["evidence_layer"] == "in_process_host_path"
    assert result["host_sdk"] == "openclaw/plugin-sdk/agent-harness"
    assert result["openclaw_version"] == "2026.7.1-2"
    assert result["strong_binding_enabled"] is True
    assert result["runtime_binding_id_configured"] is True
    _assert_human_allow_once(run["resolved"], trace)

    outcomes = _outcomes_by_kind(trace)
    assert set(outcomes) == {"approval_release", "execution_completed"}
    release = outcomes["approval_release"]
    terminal = outcomes["execution_completed"]
    lease_id = release["links"]["lease_id"]
    consumption_id = release["links"]["consumption_id"]
    assert lease_id
    assert consumption_id
    assert terminal["links"]["lease_id"] == lease_id
    assert terminal["links"]["consumption_id"] == consumption_id
    assert terminal["links"]["action_id"] == result["action_id"]
    assert terminal["evidence"]["execution"]["status"] == "executed"
    for receipt in (release, terminal):
        enforcement = receipt["evidence"]["enforcement"]
        assert enforcement == {
            "gate_state": "approval_released",
            "binding_check_status": "passed",
            "lease_consume_outcome": "consumed",
            "reason_codes": ["rte-05:binding_exact", "rte-05:lease_consumed"],
        }

    binding = store.get_enforcement_binding(run["resolved"]["approval_id"])
    assert binding is not None
    lease = store.get_execution_lease(binding.scope_digest, lease_id)
    assert lease is not None
    assert lease.consumption_id == consumption_id
    _assert_secret_exclusion(run, trace, binding.authorization_fingerprint)


def _assert_drift_chain(
    run: dict[str, Any],
    trace: dict[str, Any],
    store: ControlPlaneStore,
) -> None:
    result = run["result"]
    assert result["blocked"] is True
    assert result["invocation_count"] == 0
    _assert_human_allow_once(run["resolved"], trace)

    outcomes = _outcomes_by_kind(trace)
    assert set(outcomes) == {"pre_execution_deny"}
    denied = outcomes["pre_execution_deny"]
    assert denied["links"]["action_id"] == result["action_id"]
    assert "lease_id" not in denied["links"]
    assert "consumption_id" not in denied["links"]
    assert denied["evidence"]["execution"]["status"] == "not_invoked"
    assert denied["evidence"]["enforcement"] == {
        "gate_state": "binding_failed",
        "binding_check_status": "failed",
        "lease_consume_outcome": "not_attempted",
        "reason_codes": ["rte-05:binding_mismatch"],
    }

    binding = store.get_enforcement_binding(run["resolved"]["approval_id"])
    assert binding is not None
    assert binding.grant_id is not None
    grant = getattr(store, "get_capability_grant_runtime")(binding.grant_id)
    assert grant is not None
    assert grant["remaining_uses"] == 1
    _assert_secret_exclusion(run, trace, binding.authorization_fingerprint)


def _assert_human_allow_once(approval: dict[str, Any], trace: dict[str, Any]) -> None:
    assert approval["status"] == "resolved"
    assert approval["decision"] == "allow_once"
    persisted = next(
        item
        for item in trace["approvals"]
        if item["approval_id"] == approval["approval_id"]
    )
    assert persisted["resolution_source"] == "human"


def _outcomes_by_kind(trace: dict[str, Any]) -> dict[str, dict[str, Any]]:
    outcomes: dict[str, dict[str, Any]] = {}
    for event in trace["audit_events"]:
        if event.get("record_type") != "runtime_outcome":
            continue
        kind = event.get("metadata", {}).get("outcome_kind")
        assert isinstance(kind, str)
        assert kind not in outcomes, f"duplicate terminal fact for {kind}"
        outcomes[kind] = event
    return outcomes


def _assert_secret_exclusion(
    run: dict[str, Any],
    trace: dict[str, Any],
    private_fingerprint: str,
) -> None:
    exposed = "\n".join(
        (
            run["stdout"],
            run["stderr"],
            run["spool"],
            json.dumps(trace, ensure_ascii=False, sort_keys=True),
        )
    )
    assert private_fingerprint not in exposed
    assert FINGERPRINT_PATTERN.search(exposed) is None
    assert LEASE_TOKEN_PATTERN.search(exposed) is None


def _read_state_files(state_dir: Path) -> str:
    if not state_dir.exists():
        return ""
    contents: list[str] = []
    for path in sorted(state_dir.rglob("*")):
        if path.is_file():
            contents.append(path.read_bytes().decode("utf-8", errors="replace"))
    return "\n".join(contents)


@contextmanager
def _serve(app: Any) -> Iterator[str]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = int(listener.getsockname()[1])
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="error",
            lifespan="on",
        )
    )
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [listener]},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 10.0
    while not server.started and time.monotonic() < deadline:
        if not thread.is_alive():
            raise RuntimeError("Guard API server stopped during startup")
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=3.0)
        raise RuntimeError("Guard API server did not start")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10.0)
        if thread.is_alive():
            raise RuntimeError("Guard API server did not stop")
