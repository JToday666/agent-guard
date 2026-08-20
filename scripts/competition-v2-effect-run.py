#!/usr/bin/env python3
"""Dual-arm (A0 vs A4) effect evaluation driver.

Runs the frozen 70-case corpus under exactly two arms:

* A0 -- LangGraph autonomous planner, AgentGuard fully off (ASR baseline);
* A4 -- AgentGuard final product composition: V2.1 active/official, CT
  projection on, context isolation required, RTE enforce, ASK/approval and
  outcome/receipt chains active.  This is NOT a shadow arm.

The two arms execute in parallel child processes; every case inside an arm
runs strictly serially in frozen dataset order.  Each arm owns a dedicated
loopback port table (the stream remapping machinery), so fixture services
never collide across arms.

This is an effect-analysis tool, not a qualification run: artifacts are
never fed to ``POST /v1/evaluations`` and the report carries
``competition_qualified=false``.

Usage:

    export COMPETITION_LLM_KEY='<provider key>'
    uv run python scripts/competition-v2-effect-run.py run \
        --artifacts /tmp/agentguard-v2-effect \
        --llm-model qwen3.7-plus \
        --llm-base-url https://<provider>/v1 \
        --llm-api-key-env COMPETITION_LLM_KEY

Smoke (no provider, a couple of cases, arms serial):

    uv run python scripts/competition-v2-effect-run.py run \
        --artifacts /tmp/agentguard-v2-effect-smoke \
        --case-id BN-001 --case-id PI-001 --serial

Single-arm intra-parallel restart (shard one arm across N workers; each
shard is a disjoint round-robin case subset with its own port table):

    uv run python scripts/competition-v2-effect-run.py run \
        --artifacts /tmp/agentguard-v2-effect-a0 \
        --arm A0 --arm-parallel 4 --stream-index-offset 40 \
        --llm-model qwen3.7-plus --llm-base-url https://<provider>/v1 \
        --llm-api-key-env COMPETITION_LLM_KEY

Multi-repeat variance estimation (every repeat gets its own repeat-N/
subdirectory and a repeats-summary.json aggregate is written at the root):

    uv run python scripts/competition-v2-effect-run.py run \
        --artifacts /tmp/agentguard-v2-effect-r3 \
        --repeats 3 \
        --llm-model qwen3.7-plus --llm-base-url https://<provider>/v1 \
        --llm-api-key-env COMPETITION_LLM_KEY
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentguard_langgraph_bench.bench import competition_parallel as streams
from agentguard_langgraph_bench.bench.competition_models import (
    CompetitionProfile,
    load_competition_profile,
)
from agentguard_langgraph_bench.bench.competition_runner import (
    ArmRunRequest,
    ExitCode,
    InvalidCompetitionRun,
    ProviderRuntimeConfig,
    _load_frozen_cases,
)
from agentguard_langgraph_bench.bench.model_exchange import (
    ModelExchangeError,
    resolve_api_key,
)
from agentguard_langgraph_bench.bench.v2_effect_metrics import (
    BASELINE_ARM_ID,
    EFFECT_ARM_IDS,
    EFFECT_METRICS_SCHEMA_VERSION,
    PRODUCT_ARM_ID,
    compute_arm_report,
    compute_overview,
    compute_paired_metrics,
)

# Keep the dual-arm port tables away from the official runner's
# --parallel-streams window (stream indices 0..6 on the same base).
_DEFAULT_STREAM_INDEX_OFFSET = 20
_REPORT_SCHEMA_VERSION = "dual-arm-effect-report/1.0"
_REPEATS_SUMMARY_SCHEMA_VERSION = "dual-arm-repeats-summary/1.0"


@dataclass(frozen=True, slots=True)
class ArmWorkerRequest:
    """Everything one spawned arm process needs (pickle-safe)."""

    arm_index: int
    port_table: dict[str, int]
    profile: CompetitionProfile
    provider: ProviderRuntimeConfig
    cases: tuple[Any, ...]
    artifact_root: Path
    # Position of this worker in the run's work list; used as the queue key
    # so sharded single-arm workers stay distinguishable.
    slot: int = 0
    # Repeat round this worker belongs to (0-based); single-repeat runs keep
    # the historical default.
    repeat_index: int = 0
    # V21-13 semantic judgment env applied to the product arm only; the
    # API key value stays process-local and is never written to artifacts.
    semantic_env: dict[str, str] = field(default_factory=dict)


def build_effect_arms(profile: CompetitionProfile) -> dict[str, Any]:
    """Pick the frozen A0 and A4 arm specs out of the competition profile."""

    arms = {arm.arm_id: arm for arm in profile.arms}
    missing = [arm_id for arm_id in EFFECT_ARM_IDS if arm_id not in arms]
    if missing:
        raise InvalidCompetitionRun(
            "effect_arm_roster_missing",
            f"competition profile lacks effect arms: {', '.join(missing)}",
        )
    baseline = arms[BASELINE_ARM_ID]
    product = arms[PRODUCT_ARM_ID]
    if baseline.guard_enabled:
        raise InvalidCompetitionRun(
            "effect_baseline_arm_invalid",
            "baseline arm A0 must keep AgentGuard fully off",
        )
    if (
        product.v21_rollout_mode is None
        or product.v21_rollout_mode.value != "active"
        or product.context_mode.value != "required"
        or product.rte_mode.value != "enforce"
    ):
        raise InvalidCompetitionRun(
            "effect_product_arm_invalid",
            (
                "product arm A4 must be V2.1 active/official with context "
                "required and RTE enforce (no shadow)"
            ),
        )
    return {BASELINE_ARM_ID: baseline, PRODUCT_ARM_ID: product}


def resolve_provider(
    profile: CompetitionProfile, args: argparse.Namespace
) -> ProviderRuntimeConfig:
    planner = profile.planner
    provider_id = args.llm_provider_id or planner.provider_id
    model = args.llm_model or planner.model
    base_url = args.llm_base_url or planner.base_url
    api_key_env = args.llm_api_key_env or planner.api_key_env
    if not model or not base_url:
        raise InvalidCompetitionRun(
            "provider_configuration_missing",
            "--llm-model and --llm-base-url are required for a live dual-arm run",
        )
    try:
        api_key = resolve_api_key(api_key_env)
    except ModelExchangeError as exc:
        raise InvalidCompetitionRun(
            "provider_credential_missing",
            f"provider credential is unavailable from {api_key_env}",
        ) from exc
    return ProviderRuntimeConfig(
        provider_id=provider_id,
        model=model,
        base_url=base_url,
        api_key_env=api_key_env,
        api_key=api_key,
        temperature=(
            planner.temperature if args.temperature is None else args.temperature
        ),
        request_timeout=(
            planner.request_timeout
            if args.request_timeout is None
            else args.request_timeout
        ),
        max_retries=(
            planner.max_retries if args.max_retries is None else args.max_retries
        ),
        max_tool_rounds=(
            planner.max_tool_rounds
            if args.max_tool_rounds is None
            else args.max_tool_rounds
        ),
    )


def _timed_case_runner(durations: dict[str, float]):
    """Wrap the serial bench runner to record per-case wall time."""

    from agentguard_langgraph_bench.bench.runner import run_cases

    def runner(cases: Sequence[Any], **kwargs: Any) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for case in cases:
            started = time.monotonic()
            results.extend(run_cases([case], **kwargs))
            durations[str(case.case_id)] = (time.monotonic() - started) * 1000.0
        return results

    return runner


def execute_effect_arm(request: ArmWorkerRequest) -> dict[str, Any]:
    """Execute one effect arm serially over all selected cases."""

    from agentguard_langgraph_bench.bench.competition_runtime import (
        execute_competition_arm,
    )

    arm = build_effect_arms(request.profile)[
        EFFECT_ARM_IDS[request.arm_index]
    ]
    streams.apply_stream_environment(request.port_table)
    if arm.arm_id == PRODUCT_ARM_ID:
        # V2 core LLM-assisted judgment (V21-13 semantic shadow provider):
        # evidence inside the V2 pipeline, not LLM approval and not a
        # bypass.  GuardApiSettings picks these up at construction.
        for env_name, env_value in request.semantic_env.items():
            os.environ[env_name] = env_value
    streams.check_ports_available(request.port_table)
    rewritten = tuple(
        streams.rewrite_cases_for_ports(request.cases, request.port_table)
    )
    arm_request = ArmRunRequest(
        profile=request.profile,
        arm=arm,
        repeat_index=request.repeat_index,
        seed=request.profile.seed,
        cases=rewritten,
        provider=request.provider,
        artifact_directory=request.artifact_root / arm.arm_id.lower(),
        suite=request.profile.suite,
        qualification_eligible=False,
    )
    durations: dict[str, float] = {}
    result = execute_competition_arm(arm_request, case_runner=_timed_case_runner(durations))
    return {
        "arm_id": arm.arm_id,
        "rows": [dict(row) for row in result.rows],
        "contracts": {name: dict(payload) for name, payload in result.contracts.items()},
        "case_durations_ms": durations,
        "port_table": dict(request.port_table),
    }


def _arm_worker(request: ArmWorkerRequest, queue: Any) -> None:
    """Spawn-child entry point; writes payload to file to avoid queue pipe
    deadlock on large payloads (A0 rows can be several MB each)."""

    try:
        payload = execute_effect_arm(request)
    except Exception as exc:  # noqa: BLE001 - worker boundary is fail-closed.
        queue.put(("failed", request.slot, type(exc).__name__, str(exc)))
        return
    # Write payload to file; queue carries only the path (small string).
    payload_path = request.artifact_root / f".shard-{request.slot}.json"
    payload_path.write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8"
    )
    queue.put(("ok", request.slot, str(payload_path)))


def build_semantic_env(args: argparse.Namespace) -> dict[str, str]:
    """Resolve the V21-13 semantic judge configuration for the A4 arm.

    Returns the exact GuardApiSettings environment mapping; the API key is
    copied from the caller-selected environment variable and stays in
    process memory only.
    """

    if not args.semantic_model:
        return {}
    if not args.semantic_base_url or not args.semantic_api_key_env:
        raise InvalidCompetitionRun(
            "semantic_configuration_incomplete",
            (
                "semantic judgment requires --semantic-base-url and "
                "--semantic-api-key-env together with --semantic-model"
            ),
        )
    try:
        api_key = resolve_api_key(args.semantic_api_key_env)
    except ModelExchangeError as exc:
        raise InvalidCompetitionRun(
            "semantic_credential_missing",
            (
                "semantic judge credential is unavailable from "
                f"{args.semantic_api_key_env}"
            ),
        ) from exc
    return {
        "AGENTGUARD_V21_SEMANTIC_ENABLED": "true",
        "AGENTGUARD_V21_SEMANTIC_BASE_URL": args.semantic_base_url,
        "AGENTGUARD_V21_SEMANTIC_API_KEY": api_key,
        "AGENTGUARD_V21_SEMANTIC_MODEL": args.semantic_model,
        "AGENTGUARD_V21_SEMANTIC_TIMEOUT_SECONDS": str(
            args.semantic_timeout_seconds
        ),
        "AGENTGUARD_V21_SEMANTIC_SAMPLE_RATE": "1.0",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser(
        "run", help="run the dual-arm A0/A4 effect evaluation"
    )
    run_parser.add_argument("--artifacts", required=True, type=Path)
    run_parser.add_argument("--profile", default="competition-langgraph-v2")
    run_parser.add_argument(
        "--case-id",
        action="append",
        default=None,
        help="restrict the corpus to specific case ids (repeatable)",
    )
    run_parser.add_argument("--llm-provider-id")
    run_parser.add_argument("--llm-model")
    run_parser.add_argument("--llm-base-url")
    run_parser.add_argument("--llm-api-key-env")
    run_parser.add_argument("--temperature", type=float)
    run_parser.add_argument("--request-timeout", type=float)
    run_parser.add_argument("--max-retries", type=int)
    run_parser.add_argument("--max-tool-rounds", type=int)
    run_parser.add_argument(
        "--worker-port-base",
        type=int,
        default=streams.STREAM_PORT_BASE_DEFAULT,
        help="loopback port base for the per-arm fixture services",
    )
    run_parser.add_argument(
        "--stream-index-offset",
        type=int,
        default=_DEFAULT_STREAM_INDEX_OFFSET,
        help="port-table index offset keeping arms clear of official streams",
    )
    run_parser.add_argument(
        "--serial",
        action="store_true",
        help="run both arms sequentially in this process (smoke/diagnostics)",
    )
    run_parser.add_argument(
        "--semantic-model",
        help="V2 semantic judgment model for the A4 arm (V21-13)",
    )
    run_parser.add_argument(
        "--semantic-base-url",
        help="OpenAI-compatible endpoint for V2 semantic judgment",
    )
    run_parser.add_argument(
        "--semantic-api-key-env",
        help="environment variable holding the semantic judge API key",
    )
    run_parser.add_argument(
        "--semantic-timeout-seconds",
        type=float,
        default=15.0,
        help="semantic judgment request timeout",
    )
    run_parser.add_argument(
        "--arm",
        choices=EFFECT_ARM_IDS,
        help="restrict the run to a single arm (enables --arm-parallel sharding)",
    )
    run_parser.add_argument(
        "--arm-parallel",
        type=int,
        default=1,
        help="shard the selected single arm into N parallel workers (requires --arm)",
    )
    run_parser.add_argument(
        "--repeats",
        type=int,
        default=1,
        help=(
            "number of repeat rounds (>=1); with repeats>1 each round writes "
            "to artifacts/repeat-N/ and a repeats-summary.json aggregate is "
            "produced at the artifacts root"
        ),
    )
    return parser


def _select_cases(profile: CompetitionProfile, selected_ids: Sequence[str] | None):
    cases = _load_frozen_cases(profile)
    if not selected_ids:
        return cases
    known = {case.case_id: case for case in cases}
    unknown = [case_id for case_id in selected_ids if case_id not in known]
    if unknown:
        raise InvalidCompetitionRun(
            "case_selection_invalid",
            f"unknown case ids: {', '.join(sorted(unknown))}",
        )
    return tuple(case for case in cases if case.case_id in set(selected_ids))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def build_effect_report(
    *,
    profile: CompetitionProfile,
    provider: ProviderRuntimeConfig,
    arms_result: Mapping[str, Mapping[str, Any]],
    case_count: int,
    parallel: bool,
) -> dict[str, Any]:
    rows = {
        arm_id: arms_result[arm_id]["rows"] for arm_id in EFFECT_ARM_IDS
        if arm_id in arms_result
    }
    arm_reports = {
        arm_id: compute_arm_report(
            arm_id,
            rows[arm_id],
            case_durations_ms=arms_result[arm_id]["case_durations_ms"],
        )
        for arm_id in rows
    }
    report = {
        "schema_version": _REPORT_SCHEMA_VERSION,
        "metrics_schema_version": EFFECT_METRICS_SCHEMA_VERSION,
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "profile_id": profile.profile_id,
        "dataset": {
            "dataset_id": profile.dataset.dataset_id,
            "dataset_version": profile.dataset.dataset_version,
            "dataset_digest": profile.dataset.dataset_digest,
            "selected_case_count": case_count,
        },
        "provider": provider.public_dump(),
        "parallel_arms": parallel,
        "competition_qualified": False,
        "arms": arm_reports,
    }
    if len(arm_reports) == 2:
        paired = compute_paired_metrics(
            rows[BASELINE_ARM_ID], rows[PRODUCT_ARM_ID]
        )
        report["paired"] = paired
        report["overview"] = compute_overview(
            arm_reports[BASELINE_ARM_ID], arm_reports[PRODUCT_ARM_ID], paired
        )
    else:
        # Single-arm sharded run: paired/overview need both arms and are
        # produced by merging with the counterpart arm's artifacts later.
        (single_arm_id,) = arm_reports
        report["single_arm"] = single_arm_id
    return report


def _run_one_repeat(
    *,
    args: argparse.Namespace,
    profile: CompetitionProfile,
    provider: ProviderRuntimeConfig,
    semantic_env: dict[str, str],
    cases: tuple[Any, ...],
    arm_ids: list[str],
    shard_count: int,
    repeat_index: int,
    repeat_artifacts: Path,
    port_offset: int,
    mode: str,
) -> tuple[int, list[str]]:
    """Execute one repeat round (all arms/shards) and write its artifacts.

    Returns ``(exit_code, failures)``; a non-empty failure list is always
    carried back to the caller even on a fail-soft success.
    """

    # One work item per (arm, shard).  Shards split the arm's case set into
    # disjoint round-robin subsets; every shard still executes its cases
    # strictly serially, so per-case semantics match the serial arm run.
    work_items: list[tuple[int, int, tuple[Any, ...]]] = []
    for arm_id in arm_ids:
        arm_index = EFFECT_ARM_IDS.index(arm_id)
        for shard_index in range(shard_count):
            shard = (
                cases
                if shard_count == 1
                else tuple(
                    case
                    for position, case in enumerate(cases)
                    if position % shard_count == shard_index
                )
            )
            work_items.append((arm_index, shard_index, shard))

    def _work_label(slot: int) -> str:
        arm_index, shard_index, _ = work_items[slot]
        arm_id = EFFECT_ARM_IDS[arm_index]
        return arm_id if shard_count == 1 else f"{arm_id}[s{shard_index}]"

    worker_requests = [
        ArmWorkerRequest(
            arm_index=arm_index,
            slot=slot,
            repeat_index=repeat_index,
            port_table=streams.allocate_port_table(
                port_offset + arm_index * shard_count + shard_index,
                base=args.worker_port_base,
            ),
            profile=profile,
            provider=provider,
            cases=shard,
            artifact_root=repeat_artifacts,
            semantic_env=semantic_env,
        )
        for slot, (arm_index, shard_index, shard) in enumerate(work_items)
    ]

    print(
        f"=== dual-arm effect run: {len(cases)} cases x arms "
        f"{'/'.join(arm_ids)} ({mode}) ==="
    )
    started = time.monotonic()
    collected: dict[int, dict[str, Any]] = {}
    failures: list[str] = []
    if args.serial:
        for slot, request in enumerate(worker_requests):
            print(f"--- arm {_work_label(slot)} (serial) ---")
            try:
                collected[slot] = execute_effect_arm(request)
            except Exception as exc:  # noqa: BLE001 - fail-closed boundary.
                failures.append(f"{_work_label(slot)}: {type(exc).__name__}: {exc}")
    else:
        context = streams.stream_spawn_context()
        queue = context.Queue()
        processes = []
        for request in worker_requests:
            process = context.Process(
                target=_arm_worker,
                args=(request, queue),
                name=f"effect-arm-{_work_label(request.slot)}",
            )
            process.start()
            processes.append(process)
        for process in processes:
            process.join()
        while True:
            try:
                payload = queue.get(timeout=0.5)
            except Exception:
                break
            if not isinstance(payload, tuple) or len(payload) < 2:
                continue
            if payload[0] == "ok":
                # payload[2] is the path to the shard JSON file written by worker.
                payload_path = Path(payload[2])
                try:
                    collected[int(payload[1])] = json.loads(
                        payload_path.read_text(encoding="utf-8")
                    )
                    payload_path.unlink()  # Clean up temp file.
                except Exception as exc:  # noqa: BLE001
                    failures.append(
                        f"{_work_label(int(payload[1]))}: failed to read shard "
                        f"{payload_path}: {type(exc).__name__}: {exc}"
                    )
            else:
                failures.append(
                    f"{_work_label(int(payload[1]))}: {payload[2]}: {payload[3]}"
                )
        for slot, process in enumerate(processes):
            if slot not in collected and not any(
                failure.startswith(_work_label(slot)) for failure in failures
            ):
                failures.append(
                    f"{_work_label(slot)}: worker exited without a result "
                    f"(exit code {process.exitcode})"
                )

    if failures:
        for failure in failures:
            print(f"WARNING: {failure}", file=sys.stderr)
        # Fail-soft: continue with whatever was collected so data is
        # never thrown away.  Failures are recorded in the report.
        if not collected:
            _write_json(
                repeat_artifacts / "effect-failure.json",
                {"failures": failures, "completed_slots": []},
            )
            return int(ExitCode.INVALID_RUN), failures

    # Merge shard payloads back into one arm result in frozen dataset order.
    order = {str(case.case_id): position for position, case in enumerate(cases)}
    arms_result: dict[str, dict[str, Any]] = {}
    for arm_id in arm_ids:
        arm_slots = [
            slot
            for slot, request in enumerate(worker_requests)
            if EFFECT_ARM_IDS[request.arm_index] == arm_id
        ]
        rows: list[dict[str, Any]] = []
        durations: dict[str, float] = {}
        contracts: dict[str, dict[str, Any]] = {}
        for slot in arm_slots:
            if slot not in collected:
                continue
            payload = collected[slot]
            rows.extend(payload["rows"])
            durations.update(payload["case_durations_ms"])
            for name, item in payload["contracts"].items():
                contracts.setdefault(name, item)
        rows.sort(key=lambda row: order.get(str(row.get("case_id")), len(order)))
        if not rows:
            # No data at all for this arm; skip it.
            failures.append(f"{arm_id}: no collected result")
            continue
        if len(rows) != len(cases):
            failures.append(
                f"{arm_id}: merged rows {len(rows)} do not cover "
                f"{len(cases)} cases (partial data preserved)"
            )
        arms_result[arm_id] = {
            "rows": rows,
            "contracts": contracts,
            "case_durations_ms": durations,
        }
    if not arms_result:
        _write_json(
            repeat_artifacts / "effect-failure.json",
            {"failures": failures, "completed_arms": []},
        )
        for failure in failures:
            print(f"FAILED {failure}", file=sys.stderr)
        return int(ExitCode.INVALID_RUN), failures

    for arm_id, payload in arms_result.items():
        _write_json(repeat_artifacts / f"arms/{arm_id}/run.json", payload["rows"])
        _write_json(
            repeat_artifacts / f"arms/{arm_id}/durations.json",
            payload["case_durations_ms"],
        )
        _write_json(
            repeat_artifacts / f"arms/{arm_id}/contracts.json", payload["contracts"]
        )
    report = build_effect_report(
        profile=profile,
        provider=provider,
        arms_result=arms_result,
        case_count=len(cases),
        parallel=not args.serial,
    )
    report["arm_parallel"] = shard_count
    report["semantic_judgment"] = {
        "enabled": bool(semantic_env),
        "arm_id": (
            PRODUCT_ARM_ID if semantic_env and PRODUCT_ARM_ID in arms_result else None
        ),
        "model": args.semantic_model if semantic_env else None,
        "base_url": args.semantic_base_url if semantic_env else None,
        "timeout_seconds": args.semantic_timeout_seconds if semantic_env else None,
    }
    report["duration_seconds"] = round(time.monotonic() - started, 1)
    if failures:
        report["run_failures"] = list(failures)
        report["competition_qualified"] = False
    _write_json(repeat_artifacts / "effect-report.json", report)
    _print_summary(report)
    return int(ExitCode.PASSED), failures


def _report_summary_value(report: Mapping[str, Any], path: Sequence[str]) -> Any:
    value: Any = report
    for key in path:
        if not isinstance(value, Mapping) or key not in value:
            return None
        value = value[key]
    return value


def _extract_repeat_metrics(report: Mapping[str, Any]) -> dict[str, Any]:
    """Pull the headline effect metrics out of one repeat's report."""

    return {
        "paired_valid_asr_baseline": _report_summary_value(
            report, ("paired", "paired_valid_asr_baseline")
        ),
        "paired_valid_asr_product": _report_summary_value(
            report, ("paired", "paired_valid_asr_product")
        ),
        "blocked_successful_attack_rate": _report_summary_value(
            report, ("paired", "blocked_successful_attack_rate")
        ),
        "valid_run_rate_baseline": _report_summary_value(
            report, ("arms", BASELINE_ARM_ID, "stability", "valid_run_rate")
        ),
        "valid_run_rate_product": _report_summary_value(
            report, ("arms", PRODUCT_ARM_ID, "stability", "valid_run_rate")
        ),
        "asr_valid_malicious_baseline": _report_summary_value(
            report, ("arms", BASELINE_ARM_ID, "safety", "asr_valid_malicious")
        ),
        "asr_valid_malicious_product": _report_summary_value(
            report, ("arms", PRODUCT_ARM_ID, "safety", "asr_valid_malicious")
        ),
    }


def build_repeats_summary(
    *,
    profile_id: str,
    reports: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Aggregate per-repeat headline metrics with mean and range (max-min)."""

    repeats = [
        {
            "repeat_index": index,
            "duration_seconds": report.get("duration_seconds"),
            "has_failures": bool(report.get("run_failures")),
            "metrics": _extract_repeat_metrics(report),
        }
        for index, report in enumerate(reports)
    ]
    metric_names = sorted({key for item in repeats for key in item["metrics"]})
    aggregates: dict[str, dict[str, Any]] = {}
    for name in metric_names:
        values = [
            float(item["metrics"][name])
            for item in repeats
            if isinstance(item["metrics"][name], (int, float))
        ]
        if values:
            aggregates[name] = {
                "mean": round(sum(values) / len(values), 6),
                "min": min(values),
                "max": max(values),
                "range": round(max(values) - min(values), 6),
                "sample_count": len(values),
            }
        else:
            aggregates[name] = {
                "mean": None,
                "min": None,
                "max": None,
                "range": None,
                "sample_count": 0,
            }
    return {
        "schema_version": _REPEATS_SUMMARY_SCHEMA_VERSION,
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "profile_id": profile_id,
        "repeat_count": len(repeats),
        "repeats": repeats,
        "aggregates": aggregates,
    }


def run_effect(args: argparse.Namespace) -> int:
    artifacts = Path(args.artifacts).resolve()
    if artifacts.exists() and any(artifacts.iterdir()):
        print(
            f"artifacts directory must be fresh: {artifacts}", file=sys.stderr
        )
        return int(ExitCode.INVALID_RUN)
    artifacts.mkdir(parents=True, exist_ok=True)
    try:
        profile = load_competition_profile(args.profile)
        cases = _select_cases(profile, args.case_id)
        # Validates the frozen A0/A4 arm shapes; raises on drift.
        build_effect_arms(profile)
        provider = resolve_provider(profile, args)
        semantic_env = build_semantic_env(args)
    except InvalidCompetitionRun as exc:
        print(f"{exc.reason_code}: {exc}", file=sys.stderr)
        return int(ExitCode.INVALID_RUN)

    arm_ids = [args.arm] if args.arm else list(EFFECT_ARM_IDS)
    shard_count = args.arm_parallel
    if shard_count > 1 and not args.arm:
        print(
            "--arm-parallel requires --arm (intra-arm sharding is single-arm only)",
            file=sys.stderr,
        )
        return int(ExitCode.INVALID_RUN)

    repeats = args.repeats
    if repeats < 1:
        print("--repeats must be >= 1", file=sys.stderr)
        return int(ExitCode.INVALID_RUN)

    # repeats == 1 keeps the historical flat artifact layout; repeats > 1
    # isolates every round under its own repeat-N/ subdirectory so the
    # script-created directories never clash with the fresh-directory check.
    repeat_reports: list[dict[str, Any]] = []
    overall_failures: list[str] = []
    for repeat_index in range(repeats):
        repeat_artifacts = (
            artifacts if repeats == 1 else artifacts / f"repeat-{repeat_index}"
        )
        repeat_artifacts.mkdir(parents=True, exist_ok=True)
        # Each repeat owns a disjoint port-table window; within a repeat the
        # allocation is identical to the historical single-repeat behaviour.
        port_offset = args.stream_index_offset + repeat_index * len(arm_ids) * shard_count
        mode = "serial" if args.serial else "parallel"
        if shard_count > 1:
            mode += f" x{shard_count} shards"
        if repeats > 1:
            mode = f"repeat {repeat_index + 1}/{repeats}, {mode}"
        exit_code, failures = _run_one_repeat(
            args=args,
            profile=profile,
            provider=provider,
            semantic_env=semantic_env,
            cases=cases,
            arm_ids=arm_ids,
            shard_count=shard_count,
            repeat_index=repeat_index,
            repeat_artifacts=repeat_artifacts,
            port_offset=port_offset,
            mode=mode,
        )
        labeled = [
            f"repeat-{repeat_index}: {failure}" for failure in failures
        ]
        overall_failures.extend(labeled)
        if exit_code != int(ExitCode.PASSED):
            if repeats > 1:
                for failure in labeled:
                    print(f"FAILED {failure}", file=sys.stderr)
                print(
                    f"repeat {repeat_index} failed; aborting the remaining "
                    "repeat rounds",
                    file=sys.stderr,
                )
            return exit_code
        if repeats > 1:
            report_path = repeat_artifacts / "effect-report.json"
            repeat_reports.append(
                json.loads(report_path.read_text(encoding="utf-8"))
            )

    if repeats > 1:
        summary = build_repeats_summary(
            profile_id=profile.profile_id, reports=repeat_reports
        )
        if overall_failures:
            summary["run_failures"] = list(overall_failures)
        _write_json(artifacts / "repeats-summary.json", summary)
    return int(ExitCode.PASSED)


def _print_summary(report: Mapping[str, Any]) -> None:
    if report.get("single_arm"):
        _print_single_arm_summary(report)
        return
    overview = report["overview"]
    paired = report["paired"]

    def _percent(value: Any) -> str:
        return "-" if value is None else f"{value * 100:.1f}%"

    print("\n=== 安全结果 ===")
    for arm_id in EFFECT_ARM_IDS:
        safety = report["arms"][arm_id]["safety"]
        print(
            f"  {arm_id}: ASR(all)={_percent(safety['asr_all_malicious'])} "
            f"ASR(valid)={_percent(safety['asr_valid_malicious'])} "
            f"attack_success={safety['attack_success_count']}/{safety['malicious_valid']}"
        )
        per_attack = safety["per_attack_type_asr"]
        print(
            "      per-type: "
            + ", ".join(
                f"{attack_type}={_percent(item['asr'])}"
                for attack_type, item in per_attack.items()
            )
        )
    print(
        f"  paired-valid ASR: A0={_percent(paired['paired_valid_asr_baseline'])} -> "
        f"A4={_percent(paired['paired_valid_asr_product'])} "
        f"(n={paired['paired_valid_malicious_count']})"
    )
    print(
        f"  原成功攻击阻止率: {_percent(paired['blocked_successful_attack_rate'])} "
        f"({paired['blocked_successful_attack_count']}/"
        f"{paired['attack_success_count_baseline']})"
    )
    print("\n=== 正常使用 (A4) ===")
    usability = report["arms"][PRODUCT_ARM_ID]["usability"]
    print(
        f"  benign valid rate={_percent(usability['benign_valid_rate'])} "
        f"completion={_percent(usability['benign_task_completion'])} "
        f"FPR={_percent(usability['fpr'])} ASK rate={_percent(usability['ask_rate'])} "
        f"overblock={usability['overblocked_count']} "
        f"safe recovery={_percent(usability['overblock_safe_recovery'])}"
    )
    print("\n=== 稳定性 ===")
    for arm_id in EFFECT_ARM_IDS:
        stability = report["arms"][arm_id]["stability"]
        print(
            f"  {arm_id}: valid={_percent(stability['valid_run_rate'])} "
            f"infra_fail={stability['infrastructure_failure']} "
            f"timeout={stability['timeout']} tool_exception={stability['tool_exception']}"
        )
    print("\n=== 性能 (A4) ===")
    performance = report["arms"][PRODUCT_ARM_ID]["performance"]
    for label, key in (
        ("Core case", "core_case_ms"),
        ("Model exchange", "model_exchange_ms"),
        ("Fast path", "fast_path_ms"),
        ("Slow path", "slow_path_ms"),
    ):
        item = performance[key]
        print(
            f"  {label}: P50={item['p50']:.0f}ms P95={item['p95']:.0f}ms "
            f"P99={item['p99']:.0f}ms (n={item['count']})"
            if item["count"]
            else f"  {label}: no samples"
        )
    print(
        f"  LLM 深判触发: {performance['llm_deep_judgment_triggered']} "
        f"({_percent(performance['llm_deep_judgment_rate'])})"
    )
    print("\n=== V2 归因 (A4) ===")
    v2 = report["arms"][PRODUCT_ARM_ID]["v2_effect"]
    decisions = v2["v2_official_decisions"]
    print(
        f"  V2 official decisions: {v2['v2_official_decision_count']} "
        f"(allow={decisions['allow']} deny={decisions['deny']} ask={decisions['ask']})"
    )
    print(
        f"  current vs V2 disagreement: {v2['current_vs_v2_disagreement']} "
        f"(malicious={v2['current_vs_v2_disagreement_malicious']}, "
        f"benign={v2['current_vs_v2_disagreement_benign']})"
    )
    print(
        f"  V2 挽救 current false negative: {v2['v2_saves_over_current_false_negative']}"
    )
    print(f"  V2 新增 benign false positive: {v2['v2_benign_false_positive']}")
    print("\n=== 结论 ===")
    print(
        f"  ASR(valid): {_percent(overview['asr_valid_malicious_baseline'])} -> "
        f"{_percent(overview['asr_valid_malicious_product'])} "
        f"(降幅 {_percent(overview['asr_reduction'])})"
    )


def _print_single_arm_summary(report: Mapping[str, Any]) -> None:
    arm_id = report["single_arm"]
    arm = report["arms"][arm_id]

    def _percent(value: Any) -> str:
        return "-" if value is None else f"{value * 100:.1f}%"

    safety = arm["safety"]
    usability = arm["usability"]
    stability = arm["stability"]
    print(f"\n=== 单臂结果 ({arm_id}, shards={report.get('arm_parallel', 1)}) ===")
    print(
        f"  ASR(all)={_percent(safety['asr_all_malicious'])} "
        f"ASR(valid)={_percent(safety['asr_valid_malicious'])} "
        f"attack_success={safety['attack_success_count']}/{safety['malicious_valid']}"
    )
    print(
        "      per-type: "
        + ", ".join(
            f"{attack_type}={_percent(item['asr'])}"
            for attack_type, item in safety["per_attack_type_asr"].items()
        )
    )
    print(
        f"  benign valid rate={_percent(usability['benign_valid_rate'])} "
        f"completion={_percent(usability['benign_task_completion'])} "
        f"overblock={usability['overblocked_count']}"
    )
    print(
        f"  valid={_percent(stability['valid_run_rate'])} "
        f"infra_fail={stability['infrastructure_failure']} "
        f"timeout={stability['timeout']} tool_exception={stability['tool_exception']}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        return run_effect(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
