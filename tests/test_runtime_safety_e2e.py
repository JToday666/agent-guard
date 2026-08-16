from __future__ import annotations

import socket
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest
import uvicorn

from agentguard_langgraph_bench.bench.config import DEFAULT_DATASET_DIR
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import get_test_database_url, reset_control_plane_schema
from tests.support.runtime_safety_harness import (
    CONTROL_TOKEN,
    build_runtime_app,
    runtime_safety_case,
    run_runtime_scenario,
)


pytestmark = pytest.mark.e2e


@pytest.fixture(scope="module")
def memory_runtime_suite(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, dict[str, Any]]:
    app = build_runtime_app(
        store=MemoryControlPlaneStore(),
        settings=GuardApiSettings(
            storage_backend="memory",
            control_token=CONTROL_TOKEN,
        ),
    )
    with _serve(app) as base_url:
        return _run_acceptance_suite(
            base_url=base_url,
            work_dir=tmp_path_factory.mktemp("runtime-safety-memory"),
        )


@pytest.fixture(scope="module")
def postgres_runtime_suite(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, dict[str, Any]]:
    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    try:
        app = build_runtime_app(
            store=PostgresControlPlaneStore(database_url),
            settings=GuardApiSettings(
                storage_backend="postgres",
                database_url=database_url,
                control_token=CONTROL_TOKEN,
            ),
        )
        with _serve(app) as base_url:
            return _run_acceptance_suite(
                base_url=base_url,
                work_dir=tmp_path_factory.mktemp("runtime-safety-postgres"),
            )
    finally:
        reset_control_plane_schema(database_url)


def test_runtime_safety_memory_closes_allow_ask_deny_chain(
    memory_runtime_suite: dict[str, dict[str, Any]],
) -> None:
    _assert_acceptance_contract(memory_runtime_suite)


@pytest.mark.postgres
def test_runtime_safety_postgres_closes_allow_ask_deny_chain(
    postgres_runtime_suite: dict[str, dict[str, Any]],
) -> None:
    _assert_acceptance_contract(postgres_runtime_suite)


@pytest.mark.postgres
def test_runtime_safety_memory_postgres_have_identical_semantics(
    memory_runtime_suite: dict[str, dict[str, Any]],
    postgres_runtime_suite: dict[str, dict[str, Any]],
) -> None:
    assert {
        case_id: result["semantics"] for case_id, result in memory_runtime_suite.items()
    } == {
        case_id: result["semantics"]
        for case_id, result in postgres_runtime_suite.items()
    }


def test_jb_003_tool_gate_uses_the_byte_for_byte_frozen_case() -> None:
    frozen = next(
        case
        for case in load_attack_cases(DEFAULT_DATASET_DIR)
        if case.case_id == "JB-003"
    )
    projected = runtime_safety_case("JB-003")
    assert projected.model_dump() == frozen.model_dump()


def _run_acceptance_suite(
    *, base_url: str, work_dir: Path
) -> dict[str, dict[str, Any]]:
    return {
        case_id: run_runtime_scenario(
            base_url=base_url,
            case_id=case_id,
            work_dir=work_dir / case_id.lower(),
            auto_resolve_ask=case_id == "RUNTIME-SAFETY-001",
        )
        for case_id in ("BN-001", "RUNTIME-SAFETY-001", "JB-003")
    }


def _assert_acceptance_contract(suite: dict[str, dict[str, Any]]) -> None:
    assert set(suite) == {"BN-001", "RUNTIME-SAFETY-001", "JB-003"}
    for result in suite.values():
        _assert_common_evidence(result)

    benign = suite["BN-001"]
    benign_row = benign["row"]
    assert benign["semantics"]["invocation_count"] == 1
    assert len(benign_row["tool_calls"]) == 1
    benign_call = benign_row["tool_calls"][0]
    assert (
        benign_call["tool_name"],
        benign_call["decision"],
        benign_call["status"],
        benign_call["executed"],
    ) == ("read_file", "allow", "executed", True)
    assert "AgentGuard operator onboarding" in benign_call["result"]
    _assert_terminal_receipt(
        benign["trace"],
        action_id=benign_call["call_id"],
        decision="allow",
        outcome_kind="execution_completed",
        execution_status="executed",
        result_disposition="passed_through",
        require_started=True,
    )

    ask = suite["RUNTIME-SAFETY-001"]
    ask_row = ask["row"]
    assert ask["semantics"]["invocation_count"] == 2
    assert [call["tool_name"] for call in ask_row["tool_calls"]] == [
        "memory_read",
        "code_exec",
    ]
    memory_call, code_call = ask_row["tool_calls"]
    assert (
        memory_call["decision"],
        memory_call["status"],
        memory_call["executed"],
    ) == (
        "allow",
        "executed",
        True,
    )
    assert memory_call["result"]["found"] is True
    assert memory_call["result"]["source_trust"] == "trusted"
    assert (code_call["decision"], code_call["status"], code_call["executed"]) == (
        "ask",
        "executed",
        True,
    )
    assert code_call["approval_decision"] == "allow_once"
    assert code_call["tool_executed_after_approval"] is True
    assert code_call["result"]["mode"] == "safe_arithmetic"
    assert code_call["result"]["output"] == 56
    assert ask["resolved_approval"]["approval_id"] == code_call["approval_id"]
    _assert_terminal_receipt(
        ask["trace"],
        action_id=code_call["call_id"],
        decision="ask",
        outcome_kind="execution_completed",
        execution_status="executed",
        result_disposition="passed_through",
        approval_decision="allow_once",
        require_started=True,
    )
    assert len(ask["trace"]["approvals"]) == 1
    approval = ask["trace"]["approvals"][0]
    assert approval["action_id"] == code_call["call_id"]
    assert approval["status"] == "resolved"
    assert approval["decision"] == "allow_once"

    denied = suite["JB-003"]
    denied_row = denied["row"]
    assert denied["semantics"]["invocation_count"] == 0
    assert len(denied_row["tool_calls"]) == 1
    denied_call = denied_row["tool_calls"][0]
    assert (
        denied_call["tool_name"],
        denied_call["decision"],
        denied_call["status"],
        denied_call["executed"],
    ) == ("code_exec", "deny", "blocked", False)
    assert denied_call["side_effects"] == []
    assert denied_call["result"] is None
    _assert_terminal_receipt(
        denied["trace"],
        action_id=denied_call["call_id"],
        decision="deny",
        outcome_kind="pre_execution_deny",
        execution_status="not_invoked",
        result_disposition="not_applicable",
    )
    assert denied["semantics"]["calls"][0]["started"] is False


def _assert_common_evidence(result: dict[str, Any]) -> None:
    trace = result["trace"]
    provenance = result["provenance"]
    identifiers = result["evidence_ids"]
    audit_window = trace["audit_window"]
    assert identifiers["trace_id"] == result["trace_id"]
    assert len(identifiers["calls"]) == len(result["row"]["tool_calls"])
    audit_by_id = {audit["audit_id"]: audit for audit in trace["audit_events"]}
    for call in identifiers["calls"]:
        assert call["action_id"]
        assert call["event_ids"]
        assert call["decision_ids"]
        assert call["policy_audit_ids"]
        assert call["receipt_audit_ids"]
        terminal_receipt = audit_by_id[call["receipt_audit_ids"][0]]
        assert call["policy_audit_ids"][0] == terminal_receipt["links"]["policy_audit_id"]
        assert call["event_ids"][0] == terminal_receipt["links"]["event_id"]
    assert audit_window["limit"] == 1000
    assert audit_window["returned_count"] == len(trace["audit_events"])
    assert audit_window["has_more"] is False
    assert audit_window["next_cursor"] is None
    assert audit_window["snapshot_id"].startswith("sha256:")
    assert result["conditional_reads"] == {"trace": 304, "provenance": 304}
    assert result["semantics"]["trace_lifecycle"] == {
        "started": True,
        "completed": True,
    }
    assert result["semantics"]["provenance"]["dangling_edges"] == 0
    nodes = {node["node_id"] for node in provenance["nodes"]}
    assert all(
        edge["source_node_id"] in nodes and edge["target_node_id"] in nodes
        for edge in provenance["edges"]
    )


def _assert_terminal_receipt(
    trace: dict[str, Any],
    *,
    action_id: str,
    decision: str,
    outcome_kind: str,
    execution_status: str,
    result_disposition: str,
    approval_decision: str | None = None,
    require_started: bool = False,
) -> None:
    action_audits = [
        audit
        for audit in trace["audit_events"]
        if audit.get("links", {}).get("action_id") == action_id
    ]
    policy_events = [
        audit
        for audit in action_audits
        if audit.get("record_type") == "policy_evaluation"
        and audit.get("decision") == decision
    ]
    assert policy_events
    receipts = [
        audit
        for audit in action_audits
        if audit.get("record_type") == "runtime_outcome"
        and audit.get("metadata", {}).get("outcome_kind") == outcome_kind
    ]
    assert len(receipts) == 1
    receipt = receipts[0]
    assert receipt["evidence"]["execution"]["status"] == execution_status
    assert receipt["evidence"]["result"]["disposition"] == result_disposition
    assert receipt["links"]["event_id"]
    assert receipt["links"]["decision_id"]
    assert receipt["links"]["policy_audit_id"] in {
        event["audit_id"] for event in policy_events
    }
    assert receipt["links"]["action_id"] == action_id
    if approval_decision is not None:
        assert receipt["evidence"]["approval"]["decision"] == approval_decision
    started = any(
        audit.get("record_type") == "runtime_observation"
        and audit.get("event_type") == "tool_call_started"
        for audit in action_audits
    )
    assert started is require_started


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
