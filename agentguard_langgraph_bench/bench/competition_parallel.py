"""Pure orchestration primitives for the parallel competition runner.

The frozen competition corpus is reorganized from a single serial queue into
seven parallel streams, one per ``attack_type``; every stream runs the full
five-arm roster (A0..A4) serially over its ten frozen cases.  This module
owns the deterministic stream partitioning, the per-stream loopback port
tables (so seven streams can run their local fixture services concurrently),
the case port rewriting and the spawn-friendly worker skeleton.  It never
touches the frozen dataset JSONL or manifest: rewriting happens on deep
in-memory copies only.

Default loopback ports and their environment variable names mirror the
single-stream services:

- instrumentation        AGENTGUARD_INSTRUMENTATION_PORT          18080
- benign_api             AGENTGUARD_BENIGN_API_PORT               18081
- poisonedrag            AGENTGUARD_POISONEDRAG_SERVICE_PORT      18082
- agent_abuse_api        AGENTGUARD_AGENT_ABUSE_API_PORT          18083
- benign_mcp             AGENTGUARD_BENIGN_MCP_PORT               18084
- tool_hijacking_mcp     AGENTGUARD_TOOL_HIJACKING_MCP_PORT       18085
- exfiltration_collector AGENTGUARD_EXFILTRATION_COLLECTOR_PORT   18086
- prompt_injection_api   AGENTGUARD_PROMPT_INJECTION_API_PORT     18087

Parallel streams are shifted to base 19080 with a stride of ten ports per
stream, keeping the per-service offsets identical.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import re
import socket
from dataclasses import dataclass
from multiprocessing.context import SpawnContext
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .competition_models import ArmSpec, CompetitionProfile, CompetitionSuite
from .competition_runner import (
    ArmRunRequest,
    ArmRunResult,
    InvalidCompetitionRun,
    ProviderRuntimeConfig,
)
from .dataset_contract import _case_digest
from .models import AttackCase
from .provider_rate_limit import install_global_provider_token


COMPETITION_ATTACK_TYPES: tuple[str, ...] = (
    "agent_abuse",
    "benign",
    "file_exfiltration",
    "jailbreak",
    "memory_poisoning",
    "prompt_injection",
    "tool_hijacking",
)
STREAM_PORT_BASE_DEFAULT = 19080
STREAM_PORT_STRIDE = 10
STREAM_SPAWN_METHOD = "spawn"
_ARM_IDS = ("A0", "A1", "A2", "A3", "A4")

# Service name -> legacy single-stream default port.  Values mirror the
# service defaults in browser_runtime.py, tools.py and poisonedrag_service.py.
STREAM_SERVICE_DEFAULT_PORTS: Mapping[str, int] = {
    "instrumentation": 18080,
    "benign_api": 18081,
    "poisonedrag": 18082,
    "agent_abuse_api": 18083,
    "benign_mcp": 18084,
    "tool_hijacking_mcp": 18085,
    "exfiltration_collector": 18086,
    "prompt_injection_api": 18087,
}

# Service name -> environment variable consumed by the service start-up code.
STREAM_SERVICE_ENV_VARS: Mapping[str, str] = {
    "instrumentation": "AGENTGUARD_INSTRUMENTATION_PORT",
    "benign_api": "AGENTGUARD_BENIGN_API_PORT",
    "poisonedrag": "AGENTGUARD_POISONEDRAG_SERVICE_PORT",
    "agent_abuse_api": "AGENTGUARD_AGENT_ABUSE_API_PORT",
    "benign_mcp": "AGENTGUARD_BENIGN_MCP_PORT",
    "tool_hijacking_mcp": "AGENTGUARD_TOOL_HIJACKING_MCP_PORT",
    "exfiltration_collector": "AGENTGUARD_EXFILTRATION_COLLECTOR_PORT",
    "prompt_injection_api": "AGENTGUARD_PROMPT_INJECTION_API_PORT",
}

# Legacy default-port last digit (0..7) -> service name.
_LEGACY_SERVICE_BY_PORT: Mapping[int, str] = {
    port % 10: service for service, port in STREAM_SERVICE_DEFAULT_PORTS.items()
}
_LEGACY_PORT_PATTERN = re.compile(r"127\.0\.0\.1:1808([0-7])")
_LEGACY_PORT_PREFIX = "127.0.0.1:1808"


@dataclass(frozen=True, slots=True)
class StreamSpec:
    """Execution plan for one parallel stream: one attack group, all arms."""

    stream_index: int
    attack_type: str
    cases: tuple[AttackCase, ...]
    arms: tuple[ArmSpec, ...]


@dataclass(frozen=True, slots=True)
class StreamWorkerRequest:
    """Everything a spawn child needs to execute one stream.

    ``stream.cases`` must already be rewritten for ``port_table`` by the
    caller; the worker applies the port table to the process environment
    before any fixture service is lazily started.
    """

    stream: StreamSpec
    port_table: dict[str, int]
    profile: CompetitionProfile
    provider: ProviderRuntimeConfig
    artifact_root: Path
    suite: CompetitionSuite
    qualification_eligible: bool
    repeat_index: int = 0
    seed: int = 0
    # Global single provider token shared by every stream worker (task #4):
    # at most one in-flight provider request across the parallel matrix.
    # ``None`` disables the token with zero overhead.
    provider_global_token: Any | None = None


@dataclass(frozen=True, slots=True)
class StreamWorkerResult:
    """Per-arm results of one stream, in frozen A0..A4 execution order."""

    stream_index: int
    attack_type: str
    arm_ids: tuple[str, ...]
    arm_results: tuple[ArmRunResult, ...]


def stream_result_to_dict(result: StreamWorkerResult) -> dict[str, Any]:
    """Serialize a StreamWorkerResult to a JSON-safe dict."""
    return {
        "schema_version": "stream-worker-result/1.0",
        "stream_index": result.stream_index,
        "attack_type": result.attack_type,
        "arm_ids": list(result.arm_ids),
        "arm_results": [
            {
                "rows": [dict(row) for row in arm.rows],
                "contracts": {k: dict(v) for k, v in arm.contracts.items()},
            }
            for arm in result.arm_results
        ],
    }


def stream_result_from_dict(data: Mapping[str, Any]) -> StreamWorkerResult:
    """Reconstruct a StreamWorkerResult from a JSON dict."""
    return StreamWorkerResult(
        stream_index=int(data["stream_index"]),
        attack_type=str(data["attack_type"]),
        arm_ids=tuple(data["arm_ids"]),
        arm_results=tuple(
            ArmRunResult(
                rows=tuple(dict(r) for r in arm["rows"]),
                contracts={k: dict(v) for k, v in arm["contracts"].items()},
            )
            for arm in data["arm_results"]
        ),
    )


StreamArmExecutor = Callable[[ArmRunRequest], ArmRunResult]


def build_streams(
    cases: Sequence[AttackCase], arms: Sequence[ArmSpec]
) -> list[StreamSpec]:
    """Partition frozen cases into per-attack-type streams.

    Groups follow ``COMPETITION_ATTACK_TYPES`` order; within each group the
    input (frozen dataset) order is preserved.  Every stream receives the
    full arm roster unchanged.
    """

    arm_tuple = tuple(arms)
    if not arm_tuple:
        raise InvalidCompetitionRun(
            "stream_arm_roster_empty", "streams require the frozen arm roster"
        )
    grouped: dict[str, list[AttackCase]] = {}
    for case in cases:
        if case.attack_type not in COMPETITION_ATTACK_TYPES:
            raise InvalidCompetitionRun(
                "stream_unknown_attack_type",
                f"case {case.case_id} has unknown attack_type {case.attack_type!r}",
            )
        grouped.setdefault(case.attack_type, []).append(case)
    return [
        StreamSpec(
            stream_index=stream_index,
            attack_type=attack_type,
            cases=tuple(grouped[attack_type]),
            arms=arm_tuple,
        )
        for stream_index, attack_type in enumerate(
            attack_type
            for attack_type in COMPETITION_ATTACK_TYPES
            if attack_type in grouped
        )
    ]


def allocate_port_table(
    stream_index: int, base: int = STREAM_PORT_BASE_DEFAULT
) -> dict[str, int]:
    """Deterministic per-stream loopback port table.

    Stream ``i`` owns ``base + STREAM_PORT_STRIDE * i + offset`` for every
    service, with offsets identical to the legacy single-stream defaults so
    rewritten cases keep their per-service mapping.
    """

    if isinstance(stream_index, bool) or not isinstance(stream_index, int):
        raise InvalidCompetitionRun(
            "stream_index_invalid", "stream_index must be an integer"
        )
    if stream_index < 0:
        raise InvalidCompetitionRun(
            "stream_index_invalid", "stream_index must be non-negative"
        )
    if isinstance(base, bool) or not isinstance(base, int):
        raise InvalidCompetitionRun(
            "stream_port_base_invalid", "port table base must be an integer"
        )
    offset_base = base + STREAM_PORT_STRIDE * stream_index
    return {
        service: offset_base + (port - STREAM_SERVICE_DEFAULT_PORTS["instrumentation"])
        for service, port in STREAM_SERVICE_DEFAULT_PORTS.items()
    }


def port_env_mapping(port_table: Mapping[str, int]) -> dict[str, str]:
    """Environment variable name -> port string for a stream port table."""

    _validate_port_table(port_table)
    return {
        STREAM_SERVICE_ENV_VARS[service]: str(port)
        for service, port in port_table.items()
    }


def check_ports_available(port_table: Mapping[str, int]) -> None:
    """Pre-flight loopback bind check for every port in the table."""

    _validate_port_table(port_table)
    for service, port in port_table.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as exc:
                raise InvalidCompetitionRun(
                    "stream_port_unavailable",
                    f"stream service {service} cannot bind 127.0.0.1:{port}",
                ) from exc


def apply_stream_environment(port_table: Mapping[str, int]) -> dict[str, str]:
    """Write the stream port table into ``os.environ`` for lazy services."""

    mapping = port_env_mapping(port_table)
    for env_name, port in mapping.items():
        os.environ[env_name] = port
    return mapping


def rewrite_cases_for_ports(
    cases: Sequence[AttackCase], port_table: Mapping[str, int]
) -> list[AttackCase]:
    """Deep-copy cases and retarget legacy 127.0.0.1:1808x endpoints.

    Every occurrence of the legacy single-stream endpoint
    ``127.0.0.1:1808x`` (x = 0..7) in the full JSON serialization of each
    case is replaced with the stream's port for the same service, covering
    ``input.payload``, ``tool_plan``, ``success_condition``, ``metadata``
    and any extra fields.  The ``metadata.case_digest`` is recomputed with
    the dataset-contract digest so downstream provenance checks stay
    consistent with the rewritten payload.  Inputs are never mutated and
    the dataset JSONL/manifest are never touched.
    """

    _validate_port_table(port_table)

    def _replace(match: re.Match[str]) -> str:
        service = _LEGACY_SERVICE_BY_PORT[int(match.group(1))]
        return f"127.0.0.1:{port_table[service]}"

    rewritten: list[AttackCase] = []
    for case in cases:
        payload = case.model_dump(mode="json")
        serialized = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        replaced = _LEGACY_PORT_PATTERN.sub(_replace, serialized)
        if _LEGACY_PORT_PREFIX in replaced:
            raise InvalidCompetitionRun(
                "stream_port_rewrite_residue",
                f"case {case.case_id} still references legacy loopback ports",
            )
        new_payload = json.loads(replaced)
        metadata = dict(new_payload.get("metadata") or {})
        metadata["case_digest"] = _case_digest(new_payload)
        new_payload["metadata"] = metadata
        rewritten.append(AttackCase.model_validate(new_payload))
    return rewritten


def stream_spawn_context() -> SpawnContext:
    """The spawn context all stream workers must be started with."""

    return multiprocessing.get_context(STREAM_SPAWN_METHOD)


def _stream_worker(
    request: StreamWorkerRequest,
    *,
    arm_executor: StreamArmExecutor | None = None,
) -> StreamWorkerResult:
    """Spawn-child entry point executing one stream.

    Runs the frozen A0..A4 roster serially over the stream's port-rewritten
    cases.  ``arm_executor`` is an injection seam: the wiring task will pass
    a pickleable top-level executor (or ``None`` for the live
    ``execute_competition_arm`` path) when launching this function through
    ``stream_spawn_context().Process``.
    """

    executor = arm_executor if arm_executor is not None else _default_arm_executor
    # Install the run-wide provider token (when enabled) before any arm runs;
    # model-exchange call sites acquire it around every provider request.
    install_global_provider_token(request.provider_global_token)
    arm_ids = tuple(arm.arm_id for arm in request.stream.arms)
    if arm_ids != _ARM_IDS:
        raise InvalidCompetitionRun(
            "stream_arm_order",
            "stream arms must be the frozen A0..A4 roster in order",
        )
    apply_stream_environment(request.port_table)
    check_ports_available(request.port_table)
    arm_results: list[ArmRunResult] = []
    for arm in request.stream.arms:
        arm_request = ArmRunRequest(
            profile=request.profile,
            arm=arm,
            repeat_index=request.repeat_index,
            seed=request.seed,
            cases=request.stream.cases,
            provider=request.provider,
            artifact_directory=(
                request.artifact_root
                / f"stream-{request.stream.stream_index}"
                / arm.arm_id.lower()
            ),
            suite=request.suite,
            qualification_eligible=request.qualification_eligible,
        )
        arm_results.append(executor(arm_request))
    return StreamWorkerResult(
        stream_index=request.stream.stream_index,
        attack_type=request.stream.attack_type,
        arm_ids=arm_ids,
        arm_results=tuple(arm_results),
    )


def _default_arm_executor(request: ArmRunRequest) -> ArmRunResult:
    # Lazy import keeps the orchestration primitives independently importable
    # in environments that only inspect stream plans.
    from .competition_runtime import execute_competition_arm

    return execute_competition_arm(request)


def _validate_port_table(port_table: Mapping[str, int]) -> None:
    expected = set(STREAM_SERVICE_DEFAULT_PORTS)
    actual = set(port_table)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("extra=" + ",".join(extra))
        raise InvalidCompetitionRun(
            "stream_port_table_invalid",
            f"stream port table is invalid: {'; '.join(details)}",
        )
    for service, port in port_table.items():
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            raise InvalidCompetitionRun(
                "stream_port_table_invalid",
                f"stream port for {service} is out of range",
            )


__all__ = [
    "COMPETITION_ATTACK_TYPES",
    "STREAM_PORT_BASE_DEFAULT",
    "STREAM_PORT_STRIDE",
    "STREAM_SERVICE_DEFAULT_PORTS",
    "STREAM_SERVICE_ENV_VARS",
    "STREAM_SPAWN_METHOD",
    "StreamArmExecutor",
    "StreamSpec",
    "StreamWorkerRequest",
    "StreamWorkerResult",
    "allocate_port_table",
    "apply_stream_environment",
    "build_streams",
    "check_ports_available",
    "port_env_mapping",
    "rewrite_cases_for_ports",
    "stream_result_from_dict",
    "stream_result_to_dict",
    "stream_spawn_context",
]
