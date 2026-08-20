"""Wiring tests for the parallel stream competition runner (task #3).

Covers the CLI/config surface for ``--parallel-streams`` /
``--worker-port-base`` / ``--provider-rate-limit``, the runtime sandbox
port-rewrite and digest relaxation helpers, and an N=2 spawn smoke run with
a fake arm executor injected through ``run()``.
"""

from __future__ import annotations

import json
import os
import socket
from dataclasses import replace
from pathlib import Path

import pytest

from agentguard_langgraph_bench.bench.competition_parallel import (
    STREAM_SERVICE_DEFAULT_PORTS,
    STREAM_SERVICE_ENV_VARS,
    allocate_port_table,
    rewrite_cases_for_ports,
)
from agentguard_langgraph_bench.bench.competition_runner import (
    ArmRunRequest,
    ArmRunResult,
    ExitCode,
    InvalidCompetitionRun,
    RunRequest,
    _load_frozen_cases,
    _runtime_fixture_observation,
    build_parser,
    resolve_run_request,
    run,
)
from agentguard_langgraph_bench.bench.competition_runtime import (
    _bench_config,
    _rewrite_sandbox_stream_ports,
    _stream_port_table_from_env,
    _stream_ports_remapped,
)
from agentguard_langgraph_bench.bench.competition_models import (
    COMPETITION_CONFIG_SCHEMA_VERSION,
    authoritative_task_digest,
    canonical_sha256,
)
from agentguard_langgraph_bench.bench.runtime_fixture_contract import (
    RUNTIME_FIXTURE_CONTRACT_NAME,
    RUNTIME_FIXTURE_ROOT_IDS,
    RUNTIME_FIXTURE_SCHEMA_VERSION,
)
from test_competition_runner import (
    _POLICY_DIGEST,
    _SECRET,
    _TOOL_DIGEST,
    _exchange,
    _request,
)
from test_competition_runtime import _arm_request


_STREAM_ENV_KEYS = tuple(STREAM_SERVICE_ENV_VARS.values())
_SYNTHETIC_BUNDLE_DIGEST = "sha256:" + "ab" * 32
_SYNTHETIC_ROOT_DIGEST = "sha256:" + "cd" * 32


@pytest.fixture(autouse=True)
def restore_stream_port_env():
    snapshot = {key: os.environ[key] for key in _STREAM_ENV_KEYS if key in os.environ}
    yield
    for key in _STREAM_ENV_KEYS:
        os.environ.pop(key, None)
    os.environ.update(snapshot)


def _row(request: ArmRunRequest, case) -> dict:
    source_digest = canonical_sha256({"case": case.case_id, "sources": "canonical"})
    model_input_digest = canonical_sha256(
        {
            "case": case.case_id,
            "input": (
                "required-transform"
                if request.arm.context_mode.value == "required"
                else "raw"
            ),
        }
    )
    exchanges = [
        _exchange(
            request,
            case_id=case.case_id,
            source_digest=source_digest,
            model_input_digest=model_input_digest,
        )
    ]
    task_fact = (
        {"status": "not_applicable"}
        if not request.arm.guard_enabled
        else {
            "status": "provisioned",
            "task_id": (
                f"task-{request.arm.arm_id}-{request.repeat_index}-{case.case_id}"
            ),
            "trace_id": (
                f"trace-{request.arm.arm_id}-{request.repeat_index}-{case.case_id}"
            ),
            "task_digest": authoritative_task_digest(case.input.payload),
            "principal_id": request.profile.identity.principal_id,
            "agent_id": request.profile.identity.agent_id,
            "runtime_binding_id": request.profile.identity.runtime_binding_id,
        }
    )
    return {
        "arm_id": request.arm.arm_id,
        "repeat_index": request.repeat_index,
        "case_id": case.case_id,
        "case_digest": case.metadata["case_digest"],
        "attack_type": case.attack_type,
        "is_malicious": case.is_malicious,
        "run_valid": True,
        "run_status": "completed",
        "instrumentation_plan_mode": "autonomous",
        "llm_enabled": True,
        "planning_source": "llm_autonomous",
        "guided_plan_applied": False,
        "fallback_applied": False,
        "model_invoked": True,
        "task_input_digest": canonical_sha256(case.input.payload),
        "policy_digest": _POLICY_DIGEST,
        "round_1_source_set_digest": source_digest,
        "round_1_model_input_digest": model_input_digest,
        "tool_schema_digest": _TOOL_DIGEST,
        "observed_arm": request.arm.public_dump(),
        "task_fact": task_fact,
        "model_exchanges": exchanges,
        "tool_executions": [],
        "terminal_receipts": [],
        "attack_success": False,
        "overblocked": False,
        "task_success": True,
        "v21_selected": (
            request.arm.arm_id in {"A3", "A4"} if request.arm.v21_enabled else None
        ),
        "legacy_floor_applied": False if request.arm.v21_enabled else None,
        "receipt_covered": (
            False if request.arm.rte_mode.value == "enforce" else None
        ),
    }


def _synthetic_fixture_contract() -> dict:
    return {
        "status": "passed",
        "reason_code": "runtime_fixture_bundle_verified",
        "schema_version": RUNTIME_FIXTURE_SCHEMA_VERSION,
        "bundle_digest": _SYNTHETIC_BUNDLE_DIGEST,
        "file_count": len(RUNTIME_FIXTURE_ROOT_IDS),
        "byte_count": 10 * len(RUNTIME_FIXTURE_ROOT_IDS),
        "roots": [
            {
                "root_id": root_id,
                "file_count": 1,
                "byte_count": 10,
                "root_digest": _SYNTHETIC_ROOT_DIGEST,
            }
            for root_id in RUNTIME_FIXTURE_ROOT_IDS
        ],
        "digest_relaxed": True,
    }


class ParallelSmokeExecutor:
    """Top-level (pickleable) fake arm executor for spawn stream workers."""

    def __init__(
        self, *, emit_fixture_contract: bool = True, raise_case_id: str = ""
    ) -> None:
        self.emit_fixture_contract = emit_fixture_contract
        self.raise_case_id = raise_case_id

    def __call__(self, request: ArmRunRequest) -> ArmRunResult:
        rows = []
        for case in request.cases:
            if self.raise_case_id and case.case_id == self.raise_case_id:
                raise RuntimeError("synthetic stream executor failure")
            rows.append(_row(request, case))
        contracts: dict = {
            "guard_api_loopback": {
                "status": "passed",
                "reason_code": "guard_api_loopback_ready",
            },
        }
        if self.emit_fixture_contract:
            contracts[RUNTIME_FIXTURE_CONTRACT_NAME] = _synthetic_fixture_contract()
        return ArmRunResult(rows=tuple(rows), contracts=contracts)


def _parallel_request(
    tmp_path: Path,
    *,
    parallel_streams: int,
    case_ids: tuple[str, ...],
    worker_port_base: int = 29080,
    provider_rate_limit: float | None = None,
) -> RunRequest:
    base = _request(tmp_path)
    profile = base.profile.with_overrides(full_corpus=False)
    return replace(
        base,
        profile=profile,
        artifacts=tmp_path / "artifacts",
        selected_case_ids=case_ids,
        parallel_streams=parallel_streams,
        worker_port_base=worker_port_base,
        provider_rate_limit=provider_rate_limit,
    )


_SMOKE_CASE_IDS = ("BN-001", "BN-002", "PR-001")


def test_parallel_two_streams_smoke_reassembles_frozen_order(tmp_path: Path) -> None:
    request = _parallel_request(
        tmp_path, parallel_streams=2, case_ids=_SMOKE_CASE_IDS, provider_rate_limit=2.5
    )
    frozen = {case.case_id: case for case in _load_frozen_cases(request.profile)}

    exit_code = run(request, executor=ParallelSmokeExecutor())

    assert exit_code is ExitCode.PASSED
    root = request.artifacts
    report = json.loads((root / "result.json").read_text(encoding="utf-8"))
    assert report["status"] == "passed"
    assert report["competition_qualified"] is False
    assert report["expected_case_runs"] == 15
    assert report["attempted_case_runs"] == 15
    assert [arm["arm_id"] for arm in report["arms"]] == ["A0", "A1", "A2", "A3", "A4"]

    preflight = json.loads((root / "preflight.json").read_text(encoding="utf-8"))
    assert preflight["competition_qualification_eligible"] is False
    completeness = json.loads((root / "completeness.json").read_text(encoding="utf-8"))
    assert completeness["competition_qualification_eligible"] is False
    assert completeness["runtime_fixture_digest_relaxed"] is True

    schedule = json.loads((root / "schedule.json").read_text(encoding="utf-8"))
    parallelism = schedule["parallelism"]
    assert parallelism["parallel_streams"] == 2
    assert parallelism["worker_port_base"] == 29080
    assert parallelism["provider_rate_limit"] == 2.5
    assert [stream["attack_type"] for stream in parallelism["streams"]] == [
        "benign",
        "memory_poisoning",
    ]
    assert parallelism["streams"][0]["case_ids"] == ["BN-001", "BN-002"]
    assert parallelism["streams"][1]["case_ids"] == ["PR-001"]
    assert (
        parallelism["streams"][0]["port_table"]["instrumentation"] == 29080
    )
    assert parallelism["streams"][1]["port_table"]["instrumentation"] == 29090

    effective_config = json.loads(
        (root / "effective-config.json").read_text(encoding="utf-8")
    )
    assert effective_config["parallel_streams"] == 2
    assert effective_config["worker_port_base"] == 29080
    assert effective_config["provider_rate_limit"] == 2.5

    # Rows are reassembled in frozen case order for every arm.
    expected_port_table = allocate_port_table(1, base=29080)
    rewritten_pr = rewrite_cases_for_ports(
        [frozen["PR-001"]], expected_port_table
    )[0]
    benign_stream_table = allocate_port_table(0, base=29080)
    rewritten_bn = rewrite_cases_for_ports(
        [frozen["BN-001"]], benign_stream_table
    )[0]
    for arm_id in ("A0", "A1", "A2", "A3", "A4"):
        arm_rows = json.loads(
            (root / "arms" / arm_id / "repeat-1" / "run.json").read_text(
                encoding="utf-8"
            )
        )
        assert [row["case_id"] for row in arm_rows] == list(_SMOKE_CASE_IDS)
        by_id = {row["case_id"]: row for row in arm_rows}
        # Benign cases carry no legacy loopback endpoint, so the rewritten
        # payload is identical and the recomputed digest is stream-stable.
        assert (
            by_id["BN-001"]["case_digest"]
            == rewritten_bn.metadata["case_digest"]
        )
        # The poisonedrag case was port-rewritten and its digest recomputed.
        assert by_id["PR-001"]["case_digest"] != frozen["PR-001"].metadata[
            "case_digest"
        ]
        assert (
            by_id["PR-001"]["case_digest"]
            == rewritten_pr.metadata["case_digest"]
        )
        assert "127.0.0.1:1808" not in json.dumps(by_id["PR-001"], sort_keys=True)

    # One deduplicated fixture observation per arm, relaxation recorded.
    runtime_fixtures = json.loads(
        (root / "runtime-fixtures.json").read_text(encoding="utf-8")
    )
    assert runtime_fixtures["status"] == "verified"
    assert runtime_fixtures["expected_observations"] == 5
    assert runtime_fixtures["verified_observations"] == 5
    assert runtime_fixtures["observed_bundle_digest"] == _SYNTHETIC_BUNDLE_DIGEST
    assert [item["arm_id"] for item in runtime_fixtures["observations"]] == [
        "A0",
        "A1",
        "A2",
        "A3",
        "A4",
    ]

    manifest = json.loads((root / "sha256-manifest.json").read_text(encoding="utf-8"))
    assert manifest["secret_scan"]["status"] == "passed"
    assert _SECRET not in (root / "result.json").read_text(encoding="utf-8")


def test_parallel_one_stream_keeps_serial_behavior(tmp_path: Path) -> None:
    request = _parallel_request(
        tmp_path, parallel_streams=1, case_ids=_SMOKE_CASE_IDS
    )

    exit_code = run(
        request, executor=ParallelSmokeExecutor(emit_fixture_contract=False)
    )

    assert exit_code is ExitCode.PASSED
    root = request.artifacts
    schedule = json.loads((root / "schedule.json").read_text(encoding="utf-8"))
    assert "parallelism" not in schedule
    completeness = json.loads((root / "completeness.json").read_text(encoding="utf-8"))
    assert "runtime_fixture_digest_relaxed" not in completeness
    runtime_fixtures = json.loads(
        (root / "runtime-fixtures.json").read_text(encoding="utf-8")
    )
    assert runtime_fixtures["status"] == "not_applicable"
    report = json.loads((root / "result.json").read_text(encoding="utf-8"))
    assert report["attempted_case_runs"] == 15


def test_parallel_stream_executor_failure_is_fail_closed(tmp_path: Path) -> None:
    request = _parallel_request(
        tmp_path, parallel_streams=2, case_ids=_SMOKE_CASE_IDS
    )

    exit_code = run(
        request,
        executor=ParallelSmokeExecutor(raise_case_id="PR-001"),
    )

    assert exit_code is ExitCode.INVALID_RUN
    admission = json.loads(
        (request.artifacts / "admission.json").read_text(encoding="utf-8")
    )
    assert admission["status"] == "invalid"
    assert admission["reason_code"] == "stream_worker_failed"


def test_parallel_port_precheck_failure_is_fail_closed(tmp_path: Path) -> None:
    request = _parallel_request(
        tmp_path, parallel_streams=2, case_ids=_SMOKE_CASE_IDS
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
        blocker.bind(("127.0.0.1", 29080))
        exit_code = run(request, executor=ParallelSmokeExecutor())

    assert exit_code is ExitCode.INVALID_RUN
    admission = json.loads(
        (request.artifacts / "admission.json").read_text(encoding="utf-8")
    )
    assert admission["reason_code"] == "stream_port_unavailable"


def test_parallel_stream_count_mismatch_is_fail_closed(tmp_path: Path) -> None:
    request = _parallel_request(
        tmp_path, parallel_streams=3, case_ids=_SMOKE_CASE_IDS
    )

    exit_code = run(request, executor=ParallelSmokeExecutor())

    assert exit_code is ExitCode.INVALID_RUN
    admission = json.loads(
        (request.artifacts / "admission.json").read_text(encoding="utf-8")
    )
    assert admission["reason_code"] == "parallel_stream_count_mismatch"


def _resolve(tmp_path: Path, *extra: str):
    args = build_parser().parse_args(
        [
            "run",
            "--suite",
            "product",
            "--full-corpus",
            "--artifacts",
            str(tmp_path / "artifacts"),
            "--llm-provider-id",
            "local-compatible",
            "--llm-model",
            "stub-model",
            "--llm-base-url",
            "https://provider.example/v1",
            *extra,
        ]
    )
    return resolve_run_request(args, environ={"AGENTGUARD_LLM_API_KEY": _SECRET})


def test_parallel_cli_and_config_surface(tmp_path: Path) -> None:
    request = _resolve(
        tmp_path,
        "--parallel-streams",
        "7",
        "--worker-port-base",
        "20000",
        "--provider-rate-limit",
        "2.5",
    )
    assert request.parallel_streams == 7
    assert request.worker_port_base == 20000
    assert request.provider_rate_limit == 2.5
    assert request.value_sources["parallel_streams"] == "cli"

    defaults = _resolve(tmp_path)
    assert defaults.parallel_streams == 1
    assert defaults.worker_port_base == 19080
    assert defaults.provider_rate_limit is None
    assert defaults.value_sources["parallel_streams"] == "default"

    config_path = tmp_path / "competition-config.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": COMPETITION_CONFIG_SCHEMA_VERSION,
                "parallel_streams": 7,
                "worker_port_base": 21000,
                "provider_rate_limit": 1,
            }
        ),
        encoding="utf-8",
    )
    args = build_parser().parse_args(
        [
            "run",
            "--suite",
            "product",
            "--full-corpus",
            "--config",
            str(config_path),
            "--artifacts",
            str(tmp_path / "artifacts"),
            "--llm-provider-id",
            "local-compatible",
            "--llm-model",
            "stub-model",
            "--llm-base-url",
            "https://provider.example/v1",
        ]
    )
    from_config = resolve_run_request(
        args, environ={"AGENTGUARD_LLM_API_KEY": _SECRET}
    )
    assert from_config.parallel_streams == 7
    assert from_config.worker_port_base == 21000
    assert from_config.provider_rate_limit == 1.0
    assert from_config.value_sources["worker_port_base"] == "json_config"


@pytest.mark.parametrize(
    "extra,reason",
    [
        (("--parallel-streams", "8"), "configuration_invalid"),
        (("--parallel-streams", "0"), "configuration_invalid"),
        (("--worker-port-base", "0"), "configuration_invalid"),
        (("--worker-port-base", "70000"), "configuration_invalid"),
        (("--provider-rate-limit", "0"), "configuration_invalid"),
        (("--provider-rate-limit", "-2"), "configuration_invalid"),
    ],
)
def test_parallel_cli_rejects_invalid_values(
    tmp_path: Path, extra: tuple[str, ...], reason: str
) -> None:
    with pytest.raises(InvalidCompetitionRun) as caught:
        _resolve(tmp_path, *extra)
    assert caught.value.reason_code == reason


def test_parallel_streams_reject_variant_suites(tmp_path: Path) -> None:
    args = build_parser().parse_args(
        [
            "run",
            "--suite",
            "contracts",
            "--case-id",
            "BN-001",
            "--parallel-streams",
            "2",
            "--artifacts",
            str(tmp_path / "artifacts"),
            "--llm-provider-id",
            "local-compatible",
            "--llm-model",
            "stub-model",
            "--llm-base-url",
            "http://127.0.0.1:43122/v1",
        ]
    )
    with pytest.raises(InvalidCompetitionRun) as caught:
        resolve_run_request(args, environ={"AGENTGUARD_LLM_API_KEY": _SECRET})
    assert caught.value.reason_code == "parallel_streams_require_frozen_roster"


def test_stream_port_table_from_env_defaults_and_remap_detection() -> None:
    assert _stream_port_table_from_env() is None
    assert _stream_ports_remapped(None) is False

    os.environ[STREAM_SERVICE_ENV_VARS["poisonedrag"]] = "19082"
    table = _stream_port_table_from_env()
    assert table is not None
    assert table["poisonedrag"] == 19082
    assert table["instrumentation"] == STREAM_SERVICE_DEFAULT_PORTS["instrumentation"]
    # Only a moved instrumentation port counts as a parallel remap.
    assert _stream_ports_remapped(table) is False

    os.environ[STREAM_SERVICE_ENV_VARS["instrumentation"]] = "19080"
    table = _stream_port_table_from_env()
    assert table is not None
    assert table["instrumentation"] == 19080
    assert _stream_ports_remapped(table) is True

    os.environ[STREAM_SERVICE_ENV_VARS["instrumentation"]] = "not-a-port"
    with pytest.raises(InvalidCompetitionRun) as caught:
        _stream_port_table_from_env()
    assert caught.value.reason_code == "stream_port_env_invalid"


def test_rewrite_sandbox_stream_ports(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    (sandbox / "mcp" / "search").mkdir(parents=True)
    (sandbox / "files" / "rag").mkdir(parents=True)
    (sandbox / "untouched").mkdir(parents=True)
    (sandbox / "mcp" / "search" / "index.json").write_text(
        json.dumps(
            {
                "api": "http://127.0.0.1:18082/support/nq/test1",
                "collector": "http://127.0.0.1:18086/status",
            }
        ),
        encoding="utf-8",
    )
    (sandbox / "files" / "rag" / "view.json").write_text(
        "fetch http://127.0.0.1:18085/sites/search/x", encoding="utf-8"
    )
    (sandbox / "untouched" / "plain.txt").write_text("no endpoints", encoding="utf-8")

    port_table = allocate_port_table(2, base=29080)
    _rewrite_sandbox_stream_ports(sandbox, port_table)

    index = json.loads(
        (sandbox / "mcp" / "search" / "index.json").read_text(encoding="utf-8")
    )
    assert index["api"] == f"http://127.0.0.1:{port_table['poisonedrag']}/support/nq/test1"
    assert index["collector"] == (
        f"http://127.0.0.1:{port_table['exfiltration_collector']}/status"
    )
    view = (sandbox / "files" / "rag" / "view.json").read_text(encoding="utf-8")
    assert view == f"fetch http://127.0.0.1:{port_table['tool_hijacking_mcp']}/sites/search/x"
    assert (sandbox / "untouched" / "plain.txt").read_text(encoding="utf-8") == (
        "no endpoints"
    )


def test_rewrite_sandbox_stream_ports_rejects_binary_and_residue(
    tmp_path: Path,
) -> None:
    port_table = allocate_port_table(0, base=29080)

    binary_sandbox = tmp_path / "binary-sandbox"
    binary_sandbox.mkdir()
    (binary_sandbox / "blob.bin").write_bytes(b"\xff\xfe127.0.0.1:18082")
    with pytest.raises(InvalidCompetitionRun) as binary_error:
        _rewrite_sandbox_stream_ports(binary_sandbox, port_table)
    assert binary_error.value.reason_code == "stream_sandbox_rewrite_failed"

    residue_sandbox = tmp_path / "residue-sandbox"
    residue_sandbox.mkdir()
    # 18089 is outside the rewrite alphabet, so the marker would survive.
    (residue_sandbox / "note.txt").write_text(
        "legacy http://127.0.0.1:18089/status", encoding="utf-8"
    )
    with pytest.raises(InvalidCompetitionRun) as residue_error:
        _rewrite_sandbox_stream_ports(residue_sandbox, port_table)
    assert residue_error.value.reason_code == "stream_sandbox_rewrite_residue"


def test_bench_config_allows_stream_ports_when_remapped(tmp_path: Path) -> None:
    request = _arm_request(tmp_path, "http://127.0.0.1:9/v1")
    case_id = request.cases[0].case_id
    kwargs = {
        "base_url": "http://127.0.0.1:8088",
        "adapter_token": "adapter-token",
        "scratch": tmp_path / "scratch",
        "task_ids": {case_id: "task-1"},
        "trace_ids": {case_id: "trace-1"},
    }

    serial_config = _bench_config(request, **kwargs)
    assert set(serial_config.allowed_local_service_ports) == {18082, 18083}

    remap = allocate_port_table(3, base=29080)
    parallel_config = _bench_config(request, stream_port_remap=remap, **kwargs)
    assert set(parallel_config.allowed_local_service_ports) == (
        {18082, 18083} | set(remap.values())
    )


def test_runtime_fixture_observation_digest_relaxation(tmp_path: Path) -> None:
    request = _arm_request(tmp_path, "http://127.0.0.1:9/v1")
    contracts = {RUNTIME_FIXTURE_CONTRACT_NAME: _synthetic_fixture_contract()}

    observation = _runtime_fixture_observation(
        contracts, request=request, required=False, digest_relaxed=True
    )
    assert observation is not None
    assert observation["fixture"]["bundle_digest"] == _SYNTHETIC_BUNDLE_DIGEST

    with pytest.raises(InvalidCompetitionRun) as serial_error:
        _runtime_fixture_observation(
            contracts, request=request, required=False, digest_relaxed=False
        )
    assert serial_error.value.reason_code == "runtime_fixture_identity_mismatch"

    unflagged = {
        RUNTIME_FIXTURE_CONTRACT_NAME: {
            key: value
            for key, value in _synthetic_fixture_contract().items()
            if key != "digest_relaxed"
        }
    }
    with pytest.raises(InvalidCompetitionRun) as unflagged_error:
        _runtime_fixture_observation(
            unflagged, request=request, required=False, digest_relaxed=True
        )
    assert unflagged_error.value.reason_code == "runtime_fixture_identity_mismatch"
