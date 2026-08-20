from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from agentguard_langgraph_bench.bench.competition_models import (
    CompetitionSuite,
    load_competition_profile,
)
from agentguard_langgraph_bench.bench.competition_parallel import (
    COMPETITION_ATTACK_TYPES,
    STREAM_SERVICE_DEFAULT_PORTS,
    STREAM_SERVICE_ENV_VARS,
    StreamWorkerRequest,
    StreamWorkerResult,
    _stream_worker,
    allocate_port_table,
    apply_stream_environment,
    build_streams,
    check_ports_available,
    port_env_mapping,
    rewrite_cases_for_ports,
    stream_result_from_dict,
    stream_result_to_dict,
)
from agentguard_langgraph_bench.bench.competition_runner import (
    ArmRunRequest,
    ArmRunResult,
    InvalidCompetitionRun,
    ProviderRuntimeConfig,
)
from agentguard_langgraph_bench.bench.dataset_contract import _case_digest
from agentguard_langgraph_bench.bench.models import AttackCase


_STREAM_ENV_KEYS = tuple(STREAM_SERVICE_ENV_VARS.values())


@pytest.fixture(autouse=True)
def restore_stream_port_env():
    snapshot = {key: os.environ[key] for key in _STREAM_ENV_KEYS if key in os.environ}
    yield
    for key in _STREAM_ENV_KEYS:
        os.environ.pop(key, None)
    os.environ.update(snapshot)


def _case(
    case_id: str,
    attack_type: str,
    *,
    payload: str = "Perform the frozen benchmark task.",
    metadata: dict | None = None,
    tool_plan: list[dict] | None = None,
    success_condition: dict | None = None,
) -> AttackCase:
    return AttackCase.model_validate(
        {
            "case_id": case_id,
            "attack_type": attack_type,
            "is_malicious": attack_type != "benign",
            "expected_decision": "allow" if attack_type == "benign" else "deny",
            "input": {
                "source_type": "user",
                "source_trust": "trusted",
                "payload": payload,
            },
            "target_behavior": {"tool": "call_api", "operation": "GET"},
            "success_condition": success_condition
            or {"type": "tool_executed", "tool": "call_api"},
            "tool_plan": tool_plan or [],
            "metadata": dict(metadata or {}),
        }
    )


def _with_digest(case: AttackCase) -> AttackCase:
    """Attach case_digest the way dataset_contract.attach_case_provenance does."""

    payload = case.model_dump(mode="json")
    metadata = dict(payload.get("metadata") or {})
    metadata["case_digest"] = _case_digest(payload)
    payload["metadata"] = metadata
    return AttackCase.model_validate(payload)


def _port_payload_case(case_id: str, attack_type: str = "benign") -> AttackCase:
    """A case referencing every legacy 127.0.0.1:1808x endpoint."""

    ports = STREAM_SERVICE_DEFAULT_PORTS
    return _with_digest(
        _case(
            case_id,
            attack_type,
            payload=(
                f"Query http://127.0.0.1:{ports['instrumentation']}/probe and "
                f"http://127.0.0.1:{ports['benign_api']}/status, then consult "
                f"http://127.0.0.1:{ports['poisonedrag']}/knowledge and "
                f"http://127.0.0.1:{ports['agent_abuse_api']}/abuse."
            ),
            tool_plan=[
                {
                    "tool": "call_api",
                    "arguments": {
                        "method": "GET",
                        "url": f"http://127.0.0.1:{ports['benign_mcp']}/weather",
                    },
                    "purpose": "benign mcp probe",
                },
                {
                    "tool": "call_api",
                    "arguments": {
                        "method": "POST",
                        "url": f"http://127.0.0.1:{ports['tool_hijacking_mcp']}/hijack",
                    },
                    "purpose": "tool hijacking probe",
                },
            ],
            success_condition={
                "type": "tool_executed",
                "tool": "call_api",
                "resource": f"http://127.0.0.1:{ports['exfiltration_collector']}/collect",
            },
            metadata={
                "note": f"collector at http://127.0.0.1:{ports['prompt_injection_api']}/inject",
            },
        )
    )


# ---------------------------------------------------------------------------
# allocate_port_table / port_env_mapping / check_ports_available
# ---------------------------------------------------------------------------


def test_port_table_is_deterministic() -> None:
    for stream_index in range(7):
        assert allocate_port_table(stream_index) == allocate_port_table(stream_index)


def test_port_tables_are_disjoint_across_streams() -> None:
    tables = [allocate_port_table(stream_index) for stream_index in range(7)]
    seen: set[int] = set()
    for table in tables:
        ports = set(table.values())
        assert len(ports) == len(STREAM_SERVICE_DEFAULT_PORTS)
        assert ports.isdisjoint(seen)
        seen.update(ports)


def test_port_table_follows_stride_formula() -> None:
    table = allocate_port_table(3)
    for service, legacy_port in STREAM_SERVICE_DEFAULT_PORTS.items():
        offset = legacy_port - 18080
        assert table[service] == 19080 + 10 * 3 + offset


def test_port_table_base_is_configurable() -> None:
    table = allocate_port_table(2, base=25000)
    assert table["instrumentation"] == 25020
    assert table["prompt_injection_api"] == 25027


def test_port_table_rejects_invalid_stream_index() -> None:
    with pytest.raises(InvalidCompetitionRun) as excinfo:
        allocate_port_table(-1)
    assert excinfo.value.reason_code == "stream_index_invalid"


def test_port_env_mapping_uses_service_env_names() -> None:
    table = allocate_port_table(1)
    mapping = port_env_mapping(table)
    assert set(mapping) == set(STREAM_SERVICE_ENV_VARS.values())
    for service, env_name in STREAM_SERVICE_ENV_VARS.items():
        assert mapping[env_name] == str(table[service])


def test_port_env_mapping_rejects_unknown_services() -> None:
    table = allocate_port_table(0)
    table["bogus"] = 19999
    with pytest.raises(InvalidCompetitionRun) as excinfo:
        port_env_mapping(table)
    assert excinfo.value.reason_code == "stream_port_table_invalid"


def test_check_ports_available_passes_for_free_ports() -> None:
    check_ports_available(allocate_port_table(0, base=39080))


def test_check_ports_available_detects_conflict() -> None:
    table = allocate_port_table(0, base=39080)
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        blocker.bind(("127.0.0.1", table["benign_api"]))
        with pytest.raises(InvalidCompetitionRun) as excinfo:
            check_ports_available(table)
        assert excinfo.value.reason_code == "stream_port_unavailable"
        assert "benign_api" in str(excinfo.value)
    finally:
        blocker.close()


def test_apply_stream_environment_writes_env() -> None:
    table = allocate_port_table(4)
    mapping = apply_stream_environment(table)
    for service, env_name in STREAM_SERVICE_ENV_VARS.items():
        assert os.environ[env_name] == str(table[service])
        assert mapping[env_name] == str(table[service])


# ---------------------------------------------------------------------------
# build_streams
# ---------------------------------------------------------------------------


def test_build_streams_partitions_seven_groups_in_order() -> None:
    profile = load_competition_profile()
    # Interleave the 70 frozen cases so grouping must restore type order.
    cases = [
        _with_digest(_case(f"{attack_type.upper()[:2]}-{index:03d}", attack_type))
        for index in range(10)
        for attack_type in COMPETITION_ATTACK_TYPES
    ]
    streams = build_streams(cases, profile.arms)
    assert len(streams) == len(COMPETITION_ATTACK_TYPES) == 7
    assert [stream.attack_type for stream in streams] == list(
        COMPETITION_ATTACK_TYPES
    )
    for stream_index, stream in enumerate(streams):
        assert stream.stream_index == stream_index
        assert len(stream.cases) == 10
        assert all(case.attack_type == stream.attack_type for case in stream.cases)
        # Intra-group order equals frozen input order.
        assert [case.case_id for case in stream.cases] == [
            f"{stream.attack_type.upper()[:2]}-{index:03d}" for index in range(10)
        ]
        assert stream.arms == profile.arms
    assert sum(len(stream.cases) for stream in streams) == 70


def test_build_streams_skips_absent_types_and_preserves_order() -> None:
    profile = load_competition_profile()
    cases = [
        _with_digest(_case("JB-000", "jailbreak")),
        _with_digest(_case("BN-000", "benign")),
        _with_digest(_case("JB-001", "jailbreak")),
    ]
    streams = build_streams(cases, profile.arms)
    assert [stream.attack_type for stream in streams] == ["benign", "jailbreak"]
    assert [case.case_id for case in streams[1].cases] == ["JB-000", "JB-001"]


def test_build_streams_rejects_unknown_attack_type() -> None:
    profile = load_competition_profile()
    raw = _case("XX-000", "benign").model_dump(mode="json")
    raw["attack_type"] = "smuggling"
    cases = [AttackCase.model_construct(**raw)]
    with pytest.raises(InvalidCompetitionRun) as excinfo:
        build_streams(cases, profile.arms)
    assert excinfo.value.reason_code == "stream_unknown_attack_type"


# ---------------------------------------------------------------------------
# rewrite_cases_for_ports
# ---------------------------------------------------------------------------


def _serialized(case: AttackCase) -> str:
    return json.dumps(
        case.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def test_rewrite_replaces_every_legacy_port() -> None:
    table = allocate_port_table(1)
    (rewritten,) = rewrite_cases_for_ports([_port_payload_case("BN-101")], table)
    text = _serialized(rewritten)
    assert "127.0.0.1:1808" not in text
    for service, port in table.items():
        assert f"127.0.0.1:{port}" in text, service


def test_rewrite_digest_matches_dataset_contract() -> None:
    table = allocate_port_table(2)
    (rewritten,) = rewrite_cases_for_ports([_port_payload_case("BN-102")], table)
    assert rewritten.metadata["case_digest"] == _case_digest(
        rewritten.model_dump(mode="json")
    )


def test_rewrite_is_idempotent() -> None:
    table = allocate_port_table(1)
    original = _port_payload_case("BN-103")
    once = rewrite_cases_for_ports([original], table)
    twice = rewrite_cases_for_ports(once, table)
    assert _serialized(once[0]) == _serialized(twice[0])
    assert (
        once[0].metadata["case_digest"] == twice[0].metadata["case_digest"]
    )


def test_rewrite_leaves_port_free_case_unchanged() -> None:
    table = allocate_port_table(1)
    case = _with_digest(_case("JB-200", "jailbreak"))
    (rewritten,) = rewrite_cases_for_ports([case], table)
    assert _serialized(rewritten) == _serialized(case)


def test_rewrite_is_stable_across_repeated_calls() -> None:
    # Cross-arm consistency invariant: one case rewritten twice with the same
    # stream port table must yield identical digests.
    table = allocate_port_table(3)
    original = _port_payload_case("BN-104")
    first = rewrite_cases_for_ports([original], table)
    second = rewrite_cases_for_ports([original], table)
    assert (
        first[0].metadata["case_digest"] == second[0].metadata["case_digest"]
    )
    assert _serialized(first[0]) == _serialized(second[0])


def test_rewrite_does_not_mutate_input_cases() -> None:
    table = allocate_port_table(1)
    original = _port_payload_case("BN-105")
    before = _serialized(original)
    rewrite_cases_for_ports([original], table)
    assert _serialized(original) == before
    assert "127.0.0.1:1808" in _serialized(original)


# ---------------------------------------------------------------------------
# _stream_worker skeleton (executor injected; run() wiring lands later)
# ---------------------------------------------------------------------------


class _RecordingExecutor:
    def __init__(self) -> None:
        self.requests: list[ArmRunRequest] = []

    def __call__(self, request: ArmRunRequest) -> ArmRunResult:
        self.requests.append(request)
        return ArmRunResult(
            rows=tuple({"case_id": case.case_id} for case in request.cases)
        )


def _worker_request(tmp_path: Path) -> StreamWorkerRequest:
    profile = load_competition_profile()
    cases = [_with_digest(_port_payload_case("BN-301"))]
    streams = build_streams(cases, profile.arms)
    return StreamWorkerRequest(
        stream=streams[0],
        port_table=allocate_port_table(streams[0].stream_index, base=39080),
        profile=profile,
        provider=ProviderRuntimeConfig(
            provider_id="local-compatible",
            model="stub-model",
            base_url="https://provider.example/v1",
            api_key_env="AGENTGUARD_LLM_API_KEY",
            api_key="stub-secret",
        ),
        artifact_root=tmp_path / "artifacts",
        suite=CompetitionSuite.PRODUCT,
        qualification_eligible=True,
    )


def test_stream_worker_runs_arms_a0_through_a4(tmp_path: Path) -> None:
    request = _worker_request(tmp_path)
    executor = _RecordingExecutor()
    result = _stream_worker(request, arm_executor=executor)
    assert result.arm_ids == ("A0", "A1", "A2", "A3", "A4")
    assert [arm_request.arm.arm_id for arm_request in executor.requests] == list(
        result.arm_ids
    )
    assert len(result.arm_results) == 5
    assert all(len(arm_result.rows) == 1 for arm_result in result.arm_results)
    for arm_request in executor.requests:
        assert arm_request.cases == request.stream.cases
        assert arm_request.artifact_directory == (
            tmp_path / "artifacts" / f"stream-{request.stream.stream_index}"
            / arm_request.arm.arm_id.lower()
        )


def test_stream_worker_applies_port_environment(tmp_path: Path) -> None:
    request = _worker_request(tmp_path)
    result = _stream_worker(request, arm_executor=_RecordingExecutor())
    assert result.attack_type == "benign"
    env = port_env_mapping(request.port_table)
    for env_name, port in env.items():
        assert os.environ[env_name] == port


def test_stream_result_roundtrip_preserves_data() -> None:
    """stream_result_to_dict / stream_result_from_dict must be lossless."""
    original = StreamWorkerResult(
        stream_index=3,
        attack_type="jailbreak",
        arm_ids=("A0", "A1", "A2", "A3", "A4"),
        arm_results=(
            ArmRunResult(
                rows=(
                    {"case_id": "JB-001", "arm_id": "A0", "run_valid": True},
                    {"case_id": "JB-002", "arm_id": "A0", "run_valid": False},
                ),
                contracts={"contract_a": {"status": "passed"}},
            ),
            ArmRunResult(
                rows=({"case_id": "JB-001", "arm_id": "A1", "run_valid": True},),
                contracts={},
            ),
        ),
    )
    data = stream_result_to_dict(original)
    assert data["schema_version"] == "stream-worker-result/1.0"
    assert data["stream_index"] == 3
    assert data["attack_type"] == "jailbreak"
    assert len(data["arm_results"]) == 2
    assert data["arm_results"][0]["rows"][0]["case_id"] == "JB-001"

    restored = stream_result_from_dict(data)
    assert restored.stream_index == original.stream_index
    assert restored.attack_type == original.attack_type
    assert restored.arm_ids == original.arm_ids
    assert len(restored.arm_results) == len(original.arm_results)
    assert restored.arm_results[0].rows[0]["case_id"] == "JB-001"
    assert restored.arm_results[0].rows[1]["run_valid"] is False
    assert restored.arm_results[0].contracts["contract_a"]["status"] == "passed"


def test_build_degraded_row_has_required_fields() -> None:
    """_build_degraded_row must produce a row with all required fields."""
    from agentguard_langgraph_bench.bench.competition_runner import (
        _build_degraded_row,
    )

    profile = load_competition_profile()
    arm = profile.arms[0]  # A0
    case = _with_digest(_case("JB-001", "jailbreak"))

    row = _build_degraded_row(
        arm,
        case,
        reason_code="stream_worker_failed",
        message="test failure",
    )
    assert row["arm_id"] == arm.arm_id
    assert row["case_id"] == "JB-001"
    assert row["attack_type"] == "jailbreak"
    assert row["is_malicious"] is True
    assert row["run_valid"] is False
    assert row["run_status"] == "degraded"
    assert row["model_invoked"] is False
    assert row["degraded"] is True
    assert row["degraded_reason"] == "stream_worker_failed"
    assert row["degraded_message"] == "test failure"
    assert row["attack_success"] is None
    assert row["task_input_digest"] is not None
