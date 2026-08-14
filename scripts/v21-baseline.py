#!/usr/bin/env python3
"""Generate the V21-00 regression and performance baseline evidence package."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import itertools
import json
import math
import os
import platform
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "packages" / "agentguard-core"
API_PATH = ROOT / "apps" / "guard-api"
for import_path in (ROOT, CORE_PATH, API_PATH):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from agentguard_core import GuardEvent, PolicyBundle, evaluate  # noqa: E402

FIXTURE_DIR = ROOT / "tests" / "fixtures"
V21_FIXTURE_DIR = FIXTURE_DIR / "v21"
ATTACK_DATASET = FIXTURE_DIR / "eval_gate" / "retained_attack_cases.jsonl"
BENIGN_DATASET = FIXTURE_DIR / "eval_gate" / "retained_benign.jsonl"
SCENARIO_MANIFEST = V21_FIXTURE_DIR / "baseline_scenarios.json"
MULTI_EVENT_FIXTURE = V21_FIXTURE_DIR / "multi_event" / "sample_traces.jsonl"
HOLDOUT_MANIFEST = V21_FIXTURE_DIR / "locked_holdout_manifest.json"
LEGACY_SNAPSHOT = V21_FIXTURE_DIR / "legacy_69efe2f_snapshot.json"
LEGACY_BASE_SHA = "69efe2f027d9a4ba9c18623838e84f6ce30ffa62"
DEFAULT_OUTPUT_DIR = (
    ROOT / "docs" / "AgentGuard_Core_V2.1_Final_Contract_Freeze" / "baseline"
)


def load_eval_gate_module() -> Any:
    path = ROOT / "scripts" / "core-metrics-gate.py"
    spec = importlib.util.spec_from_file_location("agentguard_core_metrics_gate", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load existing eval gate: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wilson_interval(
    successes: int, total: int, z: float = 1.959963984540054
) -> dict[str, float] | None:
    if total <= 0:
        return None
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total)
        )
        / denominator
    )
    return {"low": max(0.0, center - margin), "high": min(1.0, center + margin)}


def nearest_rank(values: list[int], percentile: float) -> int:
    if not values:
        raise ValueError("cannot calculate a percentile over an empty sample")
    if percentile <= 0.0 or percentile > 1.0:
        raise ValueError("percentile must be in (0, 1]")
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def latency_summary(samples_ns: list[int]) -> dict[str, int]:
    return {
        "sample_count": len(samples_ns),
        "p50_ns": nearest_rank(samples_ns, 0.50),
        "p95_ns": nearest_rank(samples_ns, 0.95),
        "p99_ns": nearest_rank(samples_ns, 0.99),
        "max_ns": max(samples_ns),
    }


def benchmark(
    operation: Callable[[int], None], *, warmup: int, iterations: int
) -> dict[str, int]:
    if warmup < 0 or iterations <= 0:
        raise ValueError("warmup must be >= 0 and iterations must be > 0")
    for index in range(warmup):
        operation(index)
    samples: list[int] = []
    for index in range(iterations):
        started = time.monotonic_ns()
        operation(index + warmup)
        samples.append(time.monotonic_ns() - started)
    return latency_summary(samples)


def redact_url(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return "<redacted>"
    hostname = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    netloc = (
        f"***@{hostname}{port}"
        if parsed.username or parsed.password
        else f"{hostname}{port}"
    )
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def redact_secrets(value: Any, key: str = "") -> Any:
    normalized_key = key.lower()
    if any(marker in normalized_key for marker in ("password", "secret", "token")):
        return "<redacted>"
    if "url" in normalized_key and isinstance(value, str):
        return redact_url(value)
    if isinstance(value, dict):
        return {
            item_key: redact_secrets(item, item_key) for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item, key) for item in value]
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} must contain an object")
            records.append(value)
    if not records:
        raise ValueError(f"fixture is empty: {path}")
    return records


def _fixture_inventory(
    path: Path, records: list[dict[str, Any]], id_key: str
) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "count": len(records),
        "ids": [str(record[id_key]) for record in records],
    }


def _current_legacy_snapshot(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "base_commit": LEGACY_BASE_SHA,
        "decision_distribution": dict(
            sorted(Counter(result["decision"] for result in results).items())
        ),
        "cases": [
            {
                "case_id": result["case_id"],
                "decision": result["decision"],
                "rule_hits": result["rule_hits"],
            }
            for result in results
        ],
    }


def write_legacy_snapshot(results: list[dict[str, Any]]) -> None:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if head != LEGACY_BASE_SHA:
        raise ValueError(
            f"legacy snapshot can only be captured at {LEGACY_BASE_SHA}; current HEAD is {head}"
        )
    source_diff = subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            "--",
            "packages/agentguard-core",
            "scripts/core-metrics-gate.py",
            "tests/fixtures/eval_gate",
        ],
        cwd=ROOT,
    )
    if source_diff.returncode != 0:
        raise ValueError(
            "cannot capture snapshot while Legacy Core or retained fixtures differ"
        )
    LEGACY_SNAPSHOT.write_text(
        json.dumps(_current_legacy_snapshot(results), ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def evaluate_regression() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    gate = load_eval_gate_module()
    attack_cases = gate.load_cases(ATTACK_DATASET)
    benign_cases = gate.load_cases(BENIGN_DATASET)
    attacks = [gate.evaluate_case(case, is_malicious=True) for case in attack_cases]
    benign = [gate.evaluate_case(case, is_malicious=False) for case in benign_cases]
    all_results = attacks + benign
    attack_interventions = sum(result["blocked"] for result in attacks)
    benign_ask = sum(result["decision"] == "ask" for result in benign)
    benign_deny = sum(result["decision"] == "deny" for result in benign)
    benign_interventions = benign_ask + benign_deny
    expected = {case["case_id"]: case for case in attack_cases + benign_cases}
    fixture_expectation_drift = [
        {
            "case_id": result["case_id"],
            "expected_decision": expected[result["case_id"]].get("expected_decision"),
            "actual_decision": result["decision"],
            "expected_rule_ids": expected[result["case_id"]].get(
                "expected_rule_ids", []
            ),
            "actual_rule_ids": result["rule_hits"],
        }
        for result in all_results
        if expected[result["case_id"]].get("expected_decision") != result["decision"]
        or expected[result["case_id"]].get("expected_rule_ids", [])
        != result["rule_hits"]
    ]
    current_snapshot = _current_legacy_snapshot(all_results)
    frozen_snapshot = (
        json.loads(LEGACY_SNAPSHOT.read_text(encoding="utf-8"))
        if LEGACY_SNAPSHOT.is_file()
        else None
    )
    snapshot_mismatches: list[dict[str, Any]] = []
    if frozen_snapshot is not None:
        expected_cases = {
            case["case_id"]: case for case in frozen_snapshot.get("cases", [])
        }
        actual_cases = {case["case_id"]: case for case in current_snapshot["cases"]}
        for case_id in sorted(set(expected_cases) | set(actual_cases)):
            if expected_cases.get(case_id) != actual_cases.get(case_id):
                snapshot_mismatches.append(
                    {
                        "case_id": case_id,
                        "expected": expected_cases.get(case_id),
                        "actual": actual_cases.get(case_id),
                    }
                )
    metrics = {
        "scope": "regression_baseline_only",
        "decision_distribution": dict(
            sorted(Counter(result["decision"] for result in all_results).items())
        ),
        "attack": {
            "count": len(attacks),
            "intervened": attack_interventions,
            "recall": attack_interventions / len(attacks),
            "recall_wilson_95": wilson_interval(attack_interventions, len(attacks)),
            "fnr": 1.0 - attack_interventions / len(attacks),
            "missed_case_ids": [
                result["case_id"] for result in attacks if not result["blocked"]
            ],
        },
        "benign": {
            "count": len(benign),
            "ask": benign_ask,
            "ask_rate": benign_ask / len(benign),
            "ask_rate_wilson_95": wilson_interval(benign_ask, len(benign)),
            "deny": benign_deny,
            "deny_rate": benign_deny / len(benign),
            "deny_rate_wilson_95": wilson_interval(benign_deny, len(benign)),
            "intervened": benign_interventions,
            "intervention_rate": benign_interventions / len(benign),
            "intervention_rate_wilson_95": wilson_interval(
                benign_interventions, len(benign)
            ),
            "false_intervention_case_ids": [
                result["case_id"] for result in benign if result["blocked"]
            ],
        },
        "legacy_parity": {
            "baseline_commit": LEGACY_BASE_SHA,
            "snapshot_present": frozen_snapshot is not None,
            "ok": frozen_snapshot is not None and not snapshot_mismatches,
            "mismatches": snapshot_mismatches,
        },
        "fixture_expectation_drift": fixture_expectation_drift,
        "per_case": all_results,
    }
    indexed_cases = {case["case_id"]: case for case in attack_cases + benign_cases}
    return metrics, indexed_cases


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_scenarios(
    indexed_cases: dict[str, dict[str, Any]],
) -> dict[str, list[GuardEvent]]:
    manifest = json.loads(SCENARIO_MANIFEST.read_text(encoding="utf-8"))
    traces = {trace["trace_id"]: trace for trace in _load_jsonl(MULTI_EVENT_FIXTURE)}
    scenarios: dict[str, list[GuardEvent]] = {}
    for scenario in manifest["scenarios"]:
        if "trace_ref" in scenario:
            event_dicts = [
                step["event"] for step in traces[scenario["trace_ref"]]["steps"]
            ]
        else:
            event_dicts = [
                indexed_cases[case_id]["event"] for case_id in scenario["case_refs"]
            ]
        overlay = scenario.get("event_overlay", {})
        scenarios[scenario["id"]] = [
            GuardEvent.model_validate(_deep_merge(event, overlay))
            for event in event_dicts
        ]
    return scenarios


def run_core_benchmark(
    scenarios: dict[str, list[GuardEvent]], *, warmup: int, iterations: int
) -> dict[str, Any]:
    policies = PolicyBundle()
    results: dict[str, Any] = {}
    for scenario_id, events in scenarios.items():
        results[scenario_id] = {
            **benchmark(
                lambda _index, scenario_events=events: [
                    evaluate(event, policies) for event in scenario_events
                ],
                warmup=warmup,
                iterations=iterations,
            ),
            "events_per_sample": len(events),
            "payload_bytes": sum(
                len(
                    json.dumps(
                        event.model_dump(mode="json"), separators=(",", ":")
                    ).encode("utf-8")
                )
                for event in events
            ),
        }
        print(f"core scenario complete: {scenario_id}", flush=True)
    return {
        "status": "measured",
        "warmup": warmup,
        "iterations": iterations,
        "scenarios": results,
    }


def _api_event(event: GuardEvent, *, backend: str, sequence: int) -> dict[str, Any]:
    payload = event.model_dump(mode="json")
    suffix = f"{backend}_{sequence}"
    payload["event_id"] = f"evt_v2100_{suffix}"
    payload["trace_id"] = f"trace_v2100_{suffix}"
    payload["case_id"] = f"V21-{backend[:2].upper()}-{sequence}"
    payload["runtime"] = "langgraph"
    payload["security_context"]["agent_id"] = "main"
    tool = payload.get("payload", {}).get("tool")
    if isinstance(tool, dict):
        tool["call_id"] = f"call_v2100_{suffix}"
    return payload


def _run_api_benchmark(
    *,
    backend: str,
    store_factory: Callable[[], Any],
    scenarios: dict[str, list[GuardEvent]],
    warmup: int,
    serial_iterations: int,
    concurrency: int,
    concurrent_total: int,
) -> dict[str, Any]:
    from fastapi.testclient import TestClient
    from guard_api.main import create_app
    from guard_api.settings import GuardApiSettings

    settings = GuardApiSettings(control_token="v21-baseline-control")
    sequence = itertools.count(1)

    def next_payload(event: GuardEvent) -> dict[str, Any]:
        return _api_event(event, backend=backend, sequence=next(sequence))

    def post_event(client: TestClient, event: GuardEvent) -> None:
        response = client.post(
            "/v1/guard/evaluate",
            headers={"Authorization": "Bearer v21-baseline-adapter"},
            json=next_payload(event),
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"Guard API benchmark request failed with HTTP {response.status_code}"
            )

    serial: dict[str, Any] = {}
    for scenario_id, events in scenarios.items():
        app = create_app(store=store_factory(), settings=settings)
        with TestClient(app) as client:
            serial[scenario_id] = {
                **benchmark(
                    lambda index, scenario_events=events: post_event(
                        client, scenario_events[index % len(scenario_events)]
                    ),
                    warmup=warmup,
                    iterations=serial_iterations,
                ),
                "payload_bytes": max(
                    len(
                        json.dumps(
                            event.model_dump(mode="json"), separators=(",", ":")
                        ).encode("utf-8")
                    )
                    for event in events
                ),
            }
        print(
            f"guard-api {backend} serial scenario complete: {scenario_id}",
            flush=True,
        )

    scenario_events = [event for events in scenarios.values() for event in events]
    concurrent_samples: list[int] = []
    concurrent_app = create_app(store=store_factory(), settings=settings)
    with TestClient(concurrent_app) as concurrent_client:

        def concurrent_request(index: int) -> int:
            started = time.monotonic_ns()
            post_event(concurrent_client, scenario_events[index % len(scenario_events)])
            return time.monotonic_ns() - started

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            concurrent_samples = list(
                executor.map(concurrent_request, range(concurrent_total))
            )
    print(f"guard-api {backend} concurrent complete", flush=True)

    return {
        "status": "measured",
        "warmup_per_scenario": warmup,
        "serial_iterations_per_scenario": serial_iterations,
        "serial": serial,
        "concurrent": {"workers": concurrency, **latency_summary(concurrent_samples)},
        "audit_mode": "synchronous_request_path",
    }


def run_memory_api_benchmark(
    scenarios: dict[str, list[GuardEvent]], **benchmark_args: int
) -> dict[str, Any]:
    from tests.support.auth import memory_store_with_adapter

    return _run_api_benchmark(
        backend="memory",
        store_factory=lambda: memory_store_with_adapter(token="v21-baseline-adapter"),
        scenarios=scenarios,
        **benchmark_args,
    )


def _dotenv_value(name: str) -> str | None:
    path = ROOT / ".env"
    if not path.is_file():
        return None
    prefix = f"{name}="
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith(prefix):
            return line.removeprefix(prefix).strip().strip("\"'")
    return None


def run_postgres_api_benchmark(
    scenarios: dict[str, list[GuardEvent]], **benchmark_args: int
) -> dict[str, Any]:
    database_url = os.getenv("AGENTGUARD_TEST_DATABASE_URL") or _dotenv_value(
        "AGENTGUARD_TEST_DATABASE_URL"
    )
    if not database_url:
        return {
            "status": "blocked",
            "reason": "AGENTGUARD_TEST_DATABASE_URL is not configured",
        }
    try:
        from sqlalchemy import create_engine, text
        from guard_api.storage.postgres import PostgresControlPlaneStore
        from tests.support.auth import add_adapter_credential
        from tests.support.postgres import (
            assert_safe_test_database_url,
            reset_control_plane_schema,
        )

        safe_url = assert_safe_test_database_url(database_url)
        engine = create_engine(safe_url)
        with engine.connect() as connection:
            server_version = str(
                connection.execute(text("SHOW server_version")).scalar_one()
            )
        host = urlsplit(safe_url).hostname or ""

        def store_factory() -> PostgresControlPlaneStore:
            reset_control_plane_schema(safe_url)
            store = PostgresControlPlaneStore(safe_url)
            store.initialize()
            add_adapter_credential(store, token="v21-baseline-adapter")
            return store

        result = _run_api_benchmark(
            backend="postgres",
            store_factory=store_factory,
            scenarios=scenarios,
            **benchmark_args,
        )
        result["database"] = {
            "url": redact_url(safe_url),
            "server_version": server_version,
            "location": (
                "local" if host in {"localhost", "127.0.0.1", "::1"} else "remote"
            ),
        }
        return result
    except Exception as exc:
        error_text = " ".join(str(exc).splitlines())
        return {"status": "blocked", "reason": f"{type(exc).__name__}: {error_text}"}


def environment_manifest() -> dict[str, Any]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    )
    try:
        import psutil

        memory_bytes: int | str = int(psutil.virtual_memory().total)
    except (ImportError, AttributeError):
        memory_bytes = "unknown"
    return {
        "commit": commit,
        "dirty": dirty,
        "os": platform.platform(),
        "cpu": platform.processor() or os.getenv("PROCESSOR_IDENTIFIER", "unknown"),
        "memory_bytes": memory_bytes,
        "python": platform.python_version(),
        "worker": "single-process TestClient; concurrent requests use threads",
    }


def render_markdown(report: dict[str, Any]) -> str:
    regression = report["regression"]
    attack = regression["attack"]
    benign = regression["benign"]
    freeze_metadata = json.loads(
        (DEFAULT_OUTPUT_DIR.parent / "FREEZE_METADATA.yaml").read_text(encoding="utf-8")
    )
    lines = [
        "# AgentGuard V21-00 基线报告",
        "",
        f"> 状态：`{report['completion_status']}`；冻结包为 `{freeze_metadata['status']}`。",
        "",
        "## 回归基线",
        "",
        f"- retained fixture：{attack['count']} attack / {benign['count']} benign，仅作 regression baseline。",
        f"- decision 分布：`{json.dumps(regression['decision_distribution'], ensure_ascii=False, sort_keys=True)}`。",
        f"- Attack Recall：{attack['recall']:.4f}；FNR：{attack['fnr']:.4f}；missed：{attack['missed_case_ids'] or '无'}。",
        f"- Benign ASK：{benign['ask_rate']:.4f}；DENY：{benign['deny_rate']:.4f}；Intervention：{benign['intervention_rate']:.4f}。",
        f"- Legacy 逐 case decision/rule hits 一致：`{regression['legacy_parity']['ok']}`。",
        f"- retained fixture 标注漂移：{len(regression['fixture_expectation_drift'])} cases；单列记录，不作为 69efe2f 行为快照。",
        "- 以上比例的 Wilson 95% CI 见机器可读 JSON。",
        "",
        "## 性能与执行证据",
        "",
        f"- 测量档位：`{report['performance']['measurement_profile']}`；正式性能基线：`{report['performance']['formal_performance_status']}`。",
        f"- Core：`{report['performance']['core']['status']}`。",
        f"- Guard API Memory：`{report['performance']['guard_api']['memory']['status']}`。",
        f"- Guard API PostgreSQL：`{report['performance']['guard_api']['postgres']['status']}`。",
        "- Semantic：`not_applicable`（尚未实现）。",
        "- Final ASR：`not_measured`；Runtime Prevention：`not_measured`（没有完整 runtime attack bench）。",
        "",
        "## 边界与阻塞",
        "",
    ]
    blockers = report["blockers"] or ["无"]
    lines.extend(f"- {blocker}" for blocker in blockers)
    lines.extend(
        [
            "- 当前机器结果是基线证据，不是跨环境硬 SLO。",
            "- nearest-rank P50/P95/P99/max 基于全部单调纳秒样本，不剔除异常值。",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--measurement-profile",
        choices=("formal_baseline", "functional_smoke"),
        default="formal_baseline",
    )
    parser.add_argument("--core-warmup", type=int, default=200)
    parser.add_argument("--core-iterations", type=int, default=5000)
    parser.add_argument("--api-warmup", type=int, default=100)
    parser.add_argument("--api-serial-iterations", type=int, default=1000)
    parser.add_argument("--api-concurrency", type=int, default=8)
    parser.add_argument("--api-concurrent-total", type=int, default=2000)
    parser.add_argument("--backends", default="memory,postgres")
    parser.add_argument("--allow-missing-postgres", action="store_true")
    parser.add_argument("--write-legacy-snapshot", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    formal_protocol = (200, 5000, 100, 1000, 8, 2000)
    selected_protocol = (
        args.core_warmup,
        args.core_iterations,
        args.api_warmup,
        args.api_serial_iterations,
        args.api_concurrency,
        args.api_concurrent_total,
    )
    if (
        args.measurement_profile == "formal_baseline"
        and selected_protocol != formal_protocol
    ):
        raise ValueError(
            "formal_baseline requires Core 200/5000 and API 100/1000 plus 8 workers/2000 requests"
        )
    regression, indexed_cases = evaluate_regression()
    if args.write_legacy_snapshot:
        write_legacy_snapshot(regression["per_case"])
        print(f"wrote {LEGACY_SNAPSHOT.relative_to(ROOT).as_posix()}")
        return 0
    scenarios = load_scenarios(indexed_cases)
    attack_records = _load_jsonl(ATTACK_DATASET)
    benign_records = _load_jsonl(BENIGN_DATASET)
    trace_records = _load_jsonl(MULTI_EVENT_FIXTURE)
    benchmark_args = {
        "warmup": args.api_warmup,
        "serial_iterations": args.api_serial_iterations,
        "concurrency": args.api_concurrency,
        "concurrent_total": args.api_concurrent_total,
    }
    requested_backends = {
        item.strip() for item in args.backends.split(",") if item.strip()
    }
    memory = (
        run_memory_api_benchmark(scenarios, **benchmark_args)
        if "memory" in requested_backends
        else {"status": "not_requested"}
    )
    postgres = (
        run_postgres_api_benchmark(scenarios, **benchmark_args)
        if "postgres" in requested_backends
        else {"status": "not_requested"}
    )
    blockers: list[str] = []
    if not regression["legacy_parity"]["ok"]:
        blockers.append(
            "Legacy retained fixture 与固化 expected decision/rule hits 不一致。"
        )
    if "postgres" in requested_backends and postgres["status"] != "measured":
        blockers.append(
            f"PostgreSQL E2E 基线未完成：{postgres.get('reason', postgres['status'])}"
        )
    report = {
        "schema_version": "1.0",
        "generated_at_unix_ns": time.time_ns(),
        "completion_status": (
            "blocked"
            if blockers
            else (
                "formal_baseline_measured"
                if args.measurement_profile == "formal_baseline"
                else "functional_smoke_passed"
            )
        ),
        "environment": environment_manifest(),
        "fixtures": {
            "retained_attack": _fixture_inventory(
                ATTACK_DATASET, attack_records, "case_id"
            ),
            "retained_benign": _fixture_inventory(
                BENIGN_DATASET, benign_records, "case_id"
            ),
            "multi_event": _fixture_inventory(
                MULTI_EVENT_FIXTURE, trace_records, "trace_id"
            ),
            "scenario_manifest_sha256": hashlib.sha256(
                SCENARIO_MANIFEST.read_bytes()
            ).hexdigest(),
            "locked_holdout_manifest": json.loads(
                HOLDOUT_MANIFEST.read_text(encoding="utf-8")
            ),
            "locked_holdout_manifest_sha256": hashlib.sha256(
                HOLDOUT_MANIFEST.read_bytes()
            ).hexdigest(),
            "legacy_snapshot": _fixture_inventory(
                LEGACY_SNAPSHOT,
                json.loads(LEGACY_SNAPSHOT.read_text(encoding="utf-8"))["cases"],
                "case_id",
            ),
        },
        "regression": regression,
        "performance": {
            "measurement_profile": args.measurement_profile,
            "formal_performance_status": (
                "measured"
                if args.measurement_profile == "formal_baseline"
                else "deferred_by_user_scope"
            ),
            "core": run_core_benchmark(
                scenarios, warmup=args.core_warmup, iterations=args.core_iterations
            ),
            "guard_api": {"memory": memory, "postgres": postgres},
            "semantic": {"status": "not_applicable"},
        },
        "runtime_effectiveness": {
            "final_asr": "not_measured",
            "runtime_prevention": "not_measured",
        },
        "blockers": blockers,
    }
    redacted_report = redact_secrets(report)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "baseline.json").write_text(
        json.dumps(redacted_report, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (args.output_dir / "baseline.md").write_text(
        render_markdown(redacted_report), encoding="utf-8", newline="\n"
    )
    print(
        json.dumps(
            {"completion_status": report["completion_status"], "blockers": blockers},
            ensure_ascii=False,
        )
    )
    if blockers and not args.allow_missing_postgres:
        return 3
    return 0 if regression["legacy_parity"]["ok"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"V21 baseline error: {exc}", file=sys.stderr)
        raise SystemExit(2)
