"""Task #4 tests: retry relaxation with backoff and provider client rate limiting.

Covers the ``invoke_with_model_exchange`` retry wrapper (trigger, backoff,
independent per-attempt evidence, exhaustion semantics, byte-stable
``max_retries=0`` behaviour), the parallel retry exemption flag paths
(PlannerSpec / BenchConfig / resolve_run_request / _bench_config), the global
single provider token and the parallel worker wiring.
"""

from __future__ import annotations

import os
import random
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentguard_langgraph_bench.bench.competition_models import (
    COMPETITION_PARALLEL_RETRY_MAX,
    CompetitionConfigurationError,
    CompetitionSuite,
    PlannerSpec,
    load_competition_profile,
)
from agentguard_langgraph_bench.bench.competition_parallel import (
    STREAM_SERVICE_ENV_VARS,
    StreamWorkerRequest,
    _stream_worker,
    allocate_port_table,
    build_streams,
)
from agentguard_langgraph_bench.bench.competition_runner import (
    ArmRunResult,
    ArtifactDirectory,
    InvalidCompetitionRun,
    ProviderRuntimeConfig,
    _build_parallel_plan,
    _load_frozen_cases,
    build_parser,
    resolve_run_request,
)
from agentguard_langgraph_bench.bench.competition_runtime import _bench_config
from agentguard_langgraph_bench.bench.config import BenchConfig
from agentguard_langgraph_bench.bench.model_exchange import (
    ModelExchangeInvocationError,
    ModelExchangeOutcome,
    invoke_with_model_exchange,
    retry_backoff_seconds,
)
from agentguard_langgraph_bench.bench.provider_rate_limit import (
    global_provider_token,
    global_provider_token_installed,
    install_global_provider_token,
)
from test_competition_parallel import _case, _with_digest
from test_competition_runner import _request
from test_competition_runtime import _arm_request


_STREAM_ENV_KEYS = tuple(STREAM_SERVICE_ENV_VARS.values())


@pytest.fixture(autouse=True)
def restore_stream_port_env():
    snapshot = {key: os.environ[key] for key in _STREAM_ENV_KEYS if key in os.environ}
    yield
    for key in _STREAM_ENV_KEYS:
        os.environ.pop(key, None)
    os.environ.update(snapshot)


@pytest.fixture(autouse=True)
def clean_global_provider_token():
    install_global_provider_token(None)
    yield
    install_global_provider_token(None)


# --------------------------------------------------------------------------
# Retry wrapper semantics
# --------------------------------------------------------------------------


class FakeRateLimitError(Exception):
    """Classified as rate_limited (name contains ``ratelimit``)."""


class FakeConnectionError(Exception):
    """Classified as transport_error (name contains ``connection``)."""


class ScriptedInvoker:
    """Raises scripted exceptions or returns a fixed tool-call response."""

    def __init__(self, outcomes) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return SimpleNamespace(
            id=f"chatcmpl-attempt-{self.calls}",
            content="",
            tool_calls=[{"name": "read_file", "args": {"path": "/docs/public.txt"}}],
            response_metadata={"request_id": f"request-{self.calls}"},
        )


def _invoke_kwargs(invoker, **overrides):
    values = {
        "invoker": invoker,
        "model_input": [("system", "fixed protocol"), ("user", "public task")],
        "sources": [
            {"source_id": "protocol", "role": "system", "content": "fixed protocol"},
            {"source_id": "task", "role": "user", "content": "public task"},
        ],
        "tool_schemas": [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "parameters": {"type": "object"},
                },
            }
        ],
        "authority_binding": {"task_id": "task-1"},
        "case_id": "BN-001",
        "arm_id": "A4",
        "repeat_index": 0,
        "round_index": 1,
        "provider_id": "local-compatible",
        "model": "stub-model",
        "base_url": "http://127.0.0.1:43111/v1/",
        "context_mode": "off",
    }
    values.update(overrides)
    return values


def test_retry_recovers_from_transient_failures_with_independent_evidence() -> None:
    invoker = ScriptedInvoker(
        [
            FakeRateLimitError("status code: 429"),
            TimeoutError("provider slow"),
            "ok",
        ]
    )
    sleeps: list[float] = []

    response, evidence = invoke_with_model_exchange(
        **_invoke_kwargs(
            invoker,
            max_retries=3,
            retry_sleep=sleeps.append,
            retry_rng=random.Random(42),
        )
    )

    assert response.tool_calls[0]["name"] == "read_file"
    assert invoker.calls == 3
    assert evidence.outcome is ModelExchangeOutcome.SUCCESS
    assert evidence.attempt_index == 3
    assert evidence.retry_count == 2
    assert len(sleeps) == 2
    # Exponential backoff with equal-ratio jitter: k=0 -> [0.5, 1], k=1 -> [1, 2].
    assert 0.5 <= sleeps[0] <= 1.0
    assert 1.0 <= sleeps[1] <= 2.0


def test_retry_fails_fast_on_non_retryable_protocol_error() -> None:
    invoker = ScriptedInvoker([ValueError("unparseable provider payload")])
    sleeps: list[float] = []

    with pytest.raises(ModelExchangeInvocationError) as captured:
        invoke_with_model_exchange(
            **_invoke_kwargs(
                invoker,
                max_retries=3,
                retry_sleep=sleeps.append,
                retry_rng=random.Random(42),
            )
        )

    assert invoker.calls == 1
    assert sleeps == []
    evidence = captured.value.evidence
    assert evidence.outcome is ModelExchangeOutcome.PROTOCOL_ERROR
    assert evidence.attempt_index == 1
    assert evidence.retry_count == 0
    assert len(captured.value.attempt_evidence) == 1


def test_retry_exhaustion_preserves_model_exchange_failed_semantics() -> None:
    invoker = ScriptedInvoker([FakeConnectionError("reset")] * 3)
    sleeps: list[float] = []

    with pytest.raises(ModelExchangeInvocationError) as captured:
        invoke_with_model_exchange(
            **_invoke_kwargs(
                invoker,
                max_retries=2,
                retry_sleep=sleeps.append,
                retry_rng=random.Random(42),
            )
        )

    assert invoker.calls == 3
    assert len(sleeps) == 2
    error = captured.value
    # The raised error keeps the final attempt's evidence and failure outcome.
    assert error.evidence.outcome is ModelExchangeOutcome.TRANSPORT_ERROR
    assert error.evidence.attempt_index == 3
    assert error.evidence.retry_count == 2
    assert str(error) == "model invocation failed: transport_error"
    # Every attempt emitted its own evidence with a distinct exchange identity.
    assert len(error.attempt_evidence) == 3
    assert [item.attempt_index for item in error.attempt_evidence] == [1, 2, 3]
    assert [item.retry_count for item in error.attempt_evidence] == [0, 1, 2]
    assert len({item.exchange_id for item in error.attempt_evidence}) == 3
    assert all(
        item.outcome is ModelExchangeOutcome.TRANSPORT_ERROR
        for item in error.attempt_evidence
    )


def test_zero_retries_keeps_single_attempt_contract() -> None:
    failing = ScriptedInvoker([TimeoutError("provider timeout")])
    sleeps: list[float] = []

    with pytest.raises(ModelExchangeInvocationError) as captured:
        invoke_with_model_exchange(
            **_invoke_kwargs(failing, max_retries=0, retry_sleep=sleeps.append)
        )

    assert failing.calls == 1
    assert sleeps == []
    assert captured.value.evidence.attempt_index == 1
    assert captured.value.evidence.retry_count == 0
    # The legacy single-attempt path never populates per-attempt evidence.
    assert captured.value.attempt_evidence == ()

    success = ScriptedInvoker(["ok"])
    _, evidence = invoke_with_model_exchange(
        **_invoke_kwargs(success, max_retries=0, retry_sleep=sleeps.append)
    )
    assert success.calls == 1
    assert evidence.attempt_index == 1
    assert evidence.retry_count == 0
    assert sleeps == []


def test_retry_rejects_invalid_budgets() -> None:
    invoker = ScriptedInvoker(["ok"])
    with pytest.raises(Exception, match="max_retries"):
        invoke_with_model_exchange(**_invoke_kwargs(invoker, max_retries=-1))
    with pytest.raises(Exception, match="max_retries"):
        invoke_with_model_exchange(**_invoke_kwargs(invoker, max_retries=True))


def test_backoff_seconds_are_bounded_and_capped() -> None:
    rng = random.Random(7)
    for retry_number in range(9):
        deterministic = min(30.0, 1.0 * (2**retry_number))
        for _ in range(20):
            delay = retry_backoff_seconds(retry_number, rng=rng)
            assert deterministic / 2.0 <= delay <= deterministic


# --------------------------------------------------------------------------
# Parallel retry exemption flag paths
# --------------------------------------------------------------------------


def test_planner_parallel_retry_exemption_bounds() -> None:
    assert PlannerSpec(max_retries=0, parallel_retry_allowed=True).max_retries == 0
    assert PlannerSpec(
        max_retries=COMPETITION_PARALLEL_RETRY_MAX, parallel_retry_allowed=True
    ).max_retries == COMPETITION_PARALLEL_RETRY_MAX
    with pytest.raises(CompetitionConfigurationError, match="between 0 and"):
        PlannerSpec(
            max_retries=COMPETITION_PARALLEL_RETRY_MAX + 1,
            parallel_retry_allowed=True,
        )
    with pytest.raises(CompetitionConfigurationError, match="between 0 and"):
        PlannerSpec(max_retries=-1, parallel_retry_allowed=True)
    # Serial (flag absent) keeps the frozen zero-retry rule and dump contract.
    with pytest.raises(CompetitionConfigurationError, match="every request"):
        PlannerSpec(max_retries=1)
    exempt = PlannerSpec(max_retries=2, parallel_retry_allowed=True)
    assert "parallel_retry_allowed" not in exempt.public_dump()


def _competition_config_kwargs(**overrides):
    values = {
        "competition_mode": True,
        "competition_arm_id": "A3",
        "llm_enabled": True,
        "instrumentation_plan_mode": "autonomous",
        "llm_fallback_to_case_plan": False,
        "llm_temperature": 0.0,
        "llm_max_retries": 0,
    }
    values.update(overrides)
    return values


def test_bench_config_parallel_retry_exemption() -> None:
    # Serial competition runs keep forcing zero retries.
    with pytest.raises(ValueError, match="requires llm_max_retries=0"):
        BenchConfig(**_competition_config_kwargs(llm_max_retries=2))
    # Parallel exemption allows a bounded budget.
    config = BenchConfig(
        **_competition_config_kwargs(
            llm_max_retries=2, competition_parallel_retry_allowed=True
        )
    )
    assert config.llm_max_retries == 2
    with pytest.raises(ValueError, match="between 1 and"):
        BenchConfig(
            **_competition_config_kwargs(
                llm_max_retries=6, competition_parallel_retry_allowed=True
            )
        )
    # Zero retries stays valid with the flag (N=1 style behaviour).
    assert (
        BenchConfig(
            **_competition_config_kwargs(competition_parallel_retry_allowed=True)
        ).llm_max_retries
        == 0
    )


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
    return resolve_run_request(args, environ={"AGENTGUARD_LLM_API_KEY": "sk-test"})


def test_resolve_run_request_parallel_retry_exemption(tmp_path: Path) -> None:
    parallel = _resolve(
        tmp_path, "--parallel-streams", "7", "--max-retries", "3"
    )
    assert parallel.provider.max_retries == 3
    assert parallel.profile.planner.max_retries == 3

    with pytest.raises(InvalidCompetitionRun) as serial_error:
        _resolve(tmp_path, "--max-retries", "1")
    assert serial_error.value.reason_code == "configuration_invalid"

    with pytest.raises(InvalidCompetitionRun) as overflow:
        _resolve(tmp_path, "--parallel-streams", "7", "--max-retries", "6")
    assert overflow.value.reason_code == "configuration_invalid"


def test_bench_config_derives_parallel_flags_from_arm_request(tmp_path: Path) -> None:
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
    assert serial_config.llm_max_retries == 0
    assert serial_config.competition_parallel_retry_allowed is False

    parallel_request = replace(
        request,
        provider=replace(request.provider, max_retries=2),
    )
    parallel_config = _bench_config(parallel_request, **kwargs)
    assert parallel_config.llm_max_retries == 2
    assert parallel_config.competition_parallel_retry_allowed is True


# --------------------------------------------------------------------------
# Global single provider token
# --------------------------------------------------------------------------


def test_global_provider_token_noop_when_not_installed() -> None:
    assert not global_provider_token_installed()
    started = time.monotonic()
    for _ in range(50):
        with global_provider_token():
            pass
    assert time.monotonic() - started < 0.05


def test_global_provider_token_serializes_holders() -> None:
    lock = threading.Lock()
    install_global_provider_token(lock)
    assert global_provider_token_installed()

    in_flight = 0
    peak = 0
    state_lock = threading.Lock()
    barrier = threading.Barrier(4)

    def worker() -> None:
        nonlocal in_flight, peak
        barrier.wait(timeout=5.0)
        for _ in range(3):
            with global_provider_token():
                with state_lock:
                    in_flight += 1
                    peak = max(peak, in_flight)
                time.sleep(0.002)
                with state_lock:
                    in_flight -= 1

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10.0)
    assert not any(thread.is_alive() for thread in threads)
    # The single token allows at most one holder at a time.
    assert peak == 1


def test_global_provider_token_releases_on_failure() -> None:
    lock = threading.Lock()
    install_global_provider_token(lock)
    with pytest.raises(RuntimeError):
        with global_provider_token():
            raise RuntimeError("provider exploded")
    # The token was released even though the guarded block failed.
    with global_provider_token():
        pass


# --------------------------------------------------------------------------
# Parallel worker wiring
# --------------------------------------------------------------------------


_PARALLEL_CASE_IDS = ("BN-001", "BN-002", "PR-001")


def test_build_parallel_plan_shares_one_global_token(tmp_path: Path) -> None:
    base = _request(tmp_path)
    request = replace(
        base,
        profile=base.profile.with_overrides(full_corpus=False),
        artifacts=tmp_path / "artifacts",
        selected_case_ids=_PARALLEL_CASE_IDS,
        parallel_streams=2,
        worker_port_base=39380,
        provider_rate_limit=5.0,
    )
    frozen = {case.case_id: case for case in _load_frozen_cases(request.profile)}
    cases = [frozen[case_id] for case_id in _PARALLEL_CASE_IDS]
    artifacts = ArtifactDirectory(tmp_path / "plan-artifacts")

    plan = _build_parallel_plan(
        request, cases=cases, arms=request.profile.arms, artifacts=artifacts
    )

    assert len(plan) == 2
    tokens = {entry.worker_request.provider_global_token for entry in plan}
    assert len(tokens) == 1
    token = tokens.pop()
    assert token is not None
    # Single-token semantics: the shared token admits exactly one holder.
    token.acquire()
    assert not token.acquire(timeout=0.01)
    token.release()

    unlimited = replace(request, provider_rate_limit=None, artifacts=tmp_path / "a2")
    unlimited_plan = _build_parallel_plan(
        unlimited,
        cases=cases,
        arms=request.profile.arms,
        artifacts=ArtifactDirectory(tmp_path / "plan-artifacts-2"),
    )
    assert all(
        entry.worker_request.provider_global_token is None
        for entry in unlimited_plan
    )


class _RecordingExecutor:
    def __init__(self) -> None:
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        return ArmRunResult(
            rows=tuple({"case_id": case.case_id} for case in request.cases)
        )


def test_stream_worker_installs_global_provider_token(tmp_path: Path) -> None:
    profile = load_competition_profile()
    cases = [_with_digest(_case("BN-301", "benign"))]
    streams = build_streams(cases, profile.arms)
    token = threading.Lock()
    request = StreamWorkerRequest(
        stream=streams[0],
        port_table=allocate_port_table(streams[0].stream_index, base=39480),
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
        provider_global_token=token,
    )

    executor = _RecordingExecutor()
    result = _stream_worker(request, arm_executor=executor)

    assert result.arm_ids == ("A0", "A1", "A2", "A3", "A4")
    assert executor.requests
    # The worker installed the shared token before executing any arm.
    assert global_provider_token_installed()
    with global_provider_token():
        assert token.locked()

    # A worker without a token leaves limiting disabled (zero overhead).
    install_global_provider_token(None)
    untokened = replace(request, provider_global_token=None)
    _stream_worker(untokened, arm_executor=_RecordingExecutor())
    assert not global_provider_token_installed()
