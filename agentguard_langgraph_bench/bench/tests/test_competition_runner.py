from __future__ import annotations

import hashlib
import json
from dataclasses import fields
from pathlib import Path

import pytest

from agentguard_langgraph_bench.bench.competition_models import (
    COMPETITION_CONFIG_SCHEMA_VERSION,
    CompetitionSuite,
    authoritative_task_digest,
    canonical_sha256,
)
from agentguard_langgraph_bench.bench.competition_runner import (
    ArmRunRequest,
    ArmRunResult,
    ExitCode,
    InvalidCompetitionRun,
    build_parser,
    main,
    resolve_run_request,
    run,
)
from agentguard_langgraph_bench.bench.config import BenchConfig
from agentguard_langgraph_bench.bench.model_exchange import (
    ModelExchangeEvidence,
    ModelExchangeOutcome,
    ModelParseStatus,
)
from agentguard_langgraph_bench.bench.runner import _copy_config


_SECRET = "stub-provider-secret-must-never-be-written"
_POLICY_DIGEST = canonical_sha256({"policy": "frozen-competition-policy"})
_TOOL_DIGEST = canonical_sha256({"tools": ["read_file", "browser_start"]})


def _request(tmp_path: Path, *extra: str):
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
            "http://127.0.0.1:43122/v1",
            *extra,
        ]
    )
    return resolve_run_request(args, environ={"AGENTGUARD_LLM_API_KEY": _SECRET})


def _exchange(
    request: ArmRunRequest,
    *,
    case_id: str,
    source_digest: str,
    model_input_digest: str,
) -> dict:
    plan_digest = (
        canonical_sha256({"plan": case_id, "arm": request.arm.arm_id})
        if request.arm.context_mode.value in {"observe", "required"}
        else None
    )
    identity = {
        "arm": request.arm.arm_id,
        "repeat": request.repeat_index,
        "case": case_id,
    }
    return ModelExchangeEvidence(
        exchange_id=canonical_sha256({**identity, "exchange": 1}),
        case_id=case_id,
        arm_id=request.arm.arm_id,
        repeat_index=request.repeat_index,
        round_index=1,
        provider_id=request.provider.provider_id,
        model=request.provider.model,
        endpoint_identity_digest=canonical_sha256(
            {"endpoint": request.provider.base_url}
        ),
        source_set_digest=source_digest,
        authority_binding_digest=canonical_sha256({**identity, "authority": True}),
        model_input_digest=model_input_digest,
        tool_schema_digest=_TOOL_DIGEST,
        request_digest=canonical_sha256({**identity, "request": 1}),
        response_digest=canonical_sha256({**identity, "response": 1}),
        context_mode=request.arm.context_mode.value,
        context_plan_digest=plan_digest,
        transform_applied=request.arm.context_mode.value == "required",
        request_observed=True,
        response_observed=True,
        outcome=ModelExchangeOutcome.SUCCESS,
        parse_status=ModelParseStatus.VALID_NO_TOOL_CALL,
        tool_call_count=0,
        tool_names=(),
        attempt_index=1,
        retry_count=0,
        elapsed_ms=1,
    ).public_dump()


class StubArmExecutor:
    def __init__(self, *, mutation: str | None = None) -> None:
        self.mutation = mutation
        self.requests: list[ArmRunRequest] = []

    def __call__(self, request: ArmRunRequest) -> ArmRunResult:
        self.requests.append(request)
        rows = []
        for case in request.cases:
            source_digest = canonical_sha256(
                {"case": case.case_id, "sources": "canonical"}
            )
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
            observed = request.arm.public_dump()
            if (
                self.mutation == "official_source_mismatch"
                and request.arm.arm_id == "A3"
                and case.case_id == request.cases[0].case_id
            ):
                observed = {**observed, "official_decision_source": "current"}
            exchanges = [
                _exchange(
                    request,
                    case_id=case.case_id,
                    source_digest=source_digest,
                    model_input_digest=model_input_digest,
                )
            ]
            if (
                self.mutation == "missing_exchange"
                and request.arm.arm_id == "A0"
                and case.case_id == request.cases[0].case_id
            ):
                exchanges = []
            if (
                self.mutation == "source_drift"
                and request.arm.arm_id == "A4"
                and case.case_id == request.cases[0].case_id
            ):
                source_digest = canonical_sha256(
                    {"case": case.case_id, "sources": "drift"}
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
                {
                    "status": "not_applicable",
                }
                if not request.arm.guard_enabled
                else {
                    "status": "provisioned",
                    "task_id": f"task-{request.arm.arm_id}-{request.repeat_index}-{case.case_id}",
                    "trace_id": f"trace-{request.arm.arm_id}-{request.repeat_index}-{case.case_id}",
                            "task_digest": authoritative_task_digest(
                                case.input.payload
                            ),
                    "principal_id": request.profile.identity.principal_id,
                    "agent_id": request.profile.identity.agent_id,
                    "runtime_binding_id": request.profile.identity.runtime_binding_id,
                }
            )
            rows.append(
                {
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
                    "model_invoked": bool(exchanges),
                    "task_input_digest": canonical_sha256(case.input.payload),
                    "policy_digest": _POLICY_DIGEST,
                    "round_1_source_set_digest": source_digest,
                    "round_1_model_input_digest": model_input_digest,
                    "tool_schema_digest": _TOOL_DIGEST,
                    "observed_arm": observed,
                    "task_fact": task_fact,
                    "model_exchanges": exchanges,
                    "attack_success": False,
                    "overblocked": False,
                    "task_success": True,
                    "v21_selected": (
                        request.arm.arm_id in {"A3", "A4"}
                        if request.arm.v21_enabled
                        else None
                    ),
                    "legacy_floor_applied": (
                        False if request.arm.v21_enabled else None
                    ),
                    "receipt_covered": (
                        True if request.arm.rte_mode.value == "enforce" else None
                    ),
                }
            )
        return ArmRunResult(
            rows=tuple(rows),
            contracts={
                "stub_runtime_contract": {
                    "status": "passed",
                    "reason_code": "stub_runtime_contract_passed",
                }
            },
        )


def test_full_stub_matrix_writes_qualified_competition_report_and_manifest(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    executor = StubArmExecutor()

    exit_code = run(request, executor=executor)

    assert exit_code is ExitCode.PASSED
    assert [(item.repeat_index, item.arm.arm_id) for item in executor.requests] == [
        (0, "A0"),
        (0, "A1"),
        (0, "A2"),
        (0, "A3"),
        (0, "A4"),
    ]
    root = request.artifacts
    report = json.loads((root / "result.json").read_text(encoding="utf-8"))
    assert report["schema_version"] == "competition-report/1.0"
    assert report["suite"] == "product"
    assert report["full_corpus"] is True
    assert report["status"] == "passed"
    assert report["competition_qualified"] is True
    assert report["expected_case_runs"] == 350
    assert report["attempted_case_runs"] == 350
    assert report["invalid_case_runs"] == 0
    assert [arm["arm_id"] for arm in report["arms"]] == ["A0", "A1", "A2", "A3", "A4"]
    assert all(arm["attempted"] == 70 for arm in report["arms"])
    assert report["arms"][3]["v21_selection_rate"] == 1.0
    assert report["arms"][0]["receipt_coverage"] is None
    manifest = json.loads((root / "sha256-manifest.json").read_text(encoding="utf-8"))
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "sha256-manifest.json"
    }
    assert {item["relative_path"] for item in manifest["artifacts"]} == actual
    for item in manifest["artifacts"]:
        content = (root / item["relative_path"]).read_bytes()
        assert item["sha256"] == "sha256:" + hashlib.sha256(content).hexdigest()
        assert _SECRET.encode() not in content


def test_valid_matrix_with_observed_authority_mismatch_is_exit_one(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)

    exit_code = run(
        request, executor=StubArmExecutor(mutation="official_source_mismatch")
    )

    assert exit_code is ExitCode.FUNCTIONAL_CONTRACT_FAILED
    report = json.loads((request.artifacts / "result.json").read_text(encoding="utf-8"))
    assert report["status"] == "functional_contract_failed"
    assert report["competition_qualified"] is False
    contracts = json.loads(
        (request.artifacts / "contract-results.json").read_text(encoding="utf-8")
    )
    assert contracts["failures"][0]["reason_code"] == "observed_arm_mismatch"


@pytest.mark.parametrize("mutation", ["missing_exchange", "source_drift"])
def test_non_interpretable_matrix_is_exit_two_with_explicit_invalid_report(
    tmp_path: Path, mutation: str
) -> None:
    request = _request(tmp_path)

    exit_code = run(request, executor=StubArmExecutor(mutation=mutation))

    assert exit_code is ExitCode.INVALID_RUN
    report = json.loads((request.artifacts / "result.json").read_text(encoding="utf-8"))
    assert report["status"] == "invalid"
    assert report["competition_qualified"] is False
    assert report["reason_code"] in {
        "baseline_model_not_invoked",
        "cross_arm_canonical_input_mismatch",
    }
    manifest = json.loads(
        (request.artifacts / "sha256-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["run_status"] == "invalid"


def test_json_then_cli_precedence_and_secret_is_never_public(
    tmp_path: Path,
) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": COMPETITION_CONFIG_SCHEMA_VERSION,
                "planner": {
                    "provider_id": "json-provider",
                    "model": "json-model",
                    "base_url": "http://127.0.0.1:43123/v1",
                    "api_key_env": "JSON_PROVIDER_KEY",
                    "max_tool_rounds": 8,
                },
                "seed": 12,
            }
        ),
        encoding="utf-8",
    )
    args = build_parser().parse_args(
        [
            "run",
            "--config",
            str(config),
            "--artifacts",
            str(tmp_path / "artifacts"),
            "--llm-model",
            "cli-model",
            "--seed",
            "22",
        ]
    )

    request = resolve_run_request(args, environ={"JSON_PROVIDER_KEY": _SECRET})

    assert request.provider.provider_id == "json-provider"
    assert request.provider.model == "cli-model"
    assert request.profile.seed == 22
    assert request.value_sources["planner.provider_id"] == "json_config"
    assert request.value_sources["planner.model"] == "cli"
    assert request.value_sources["seed"] == "cli"
    assert _SECRET not in repr(request.provider)
    assert _SECRET not in json.dumps(request.provider.public_dump())


def test_contracts_suite_accepts_public_axes_and_subset_but_never_qualifies(
    tmp_path: Path,
) -> None:
    args = build_parser().parse_args(
        [
            "run",
            "--suite",
            "contracts",
            "--case-id",
            "BN-001",
            "--v21-mode",
            "off",
            "--context-mode",
            "observe",
            "--rte-mode",
            "observe",
            "--detector-mode",
            "off",
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
    request = resolve_run_request(args, environ={"AGENTGUARD_LLM_API_KEY": _SECRET})

    assert request.profile.suite is CompetitionSuite.CONTRACTS
    assert request.profile.full_corpus is False
    assert request.selected_case_ids == ("BN-001",)
    assert request.variant is not None
    arm = request.variant.arm_spec()
    assert arm.arm_id == "V0"
    assert arm.v21_enabled is False
    assert arm.official_decision_source.value == "current"
    assert arm.context_mode.value == "observe"
    assert arm.rte_mode.value == "observe"
    assert arm.detector_mode.value == "off"

    assert run(request, executor=StubArmExecutor()) is ExitCode.PASSED
    report = json.loads((request.artifacts / "result.json").read_text())
    assert report["status"] == "passed"
    assert report["competition_qualified"] is False
    assert report["expected_case_runs"] == 1
    assert [item["arm_id"] for item in report["arms"]] == ["V0"]


@pytest.mark.parametrize("suite", ["matrix", "product"])
def test_main_suite_rejects_axis_overrides(suite: str, tmp_path: Path) -> None:
    args = build_parser().parse_args(
        [
            "run",
            "--suite",
            suite,
            "--full-corpus",
            "--v21-mode",
            "shadow",
            "--artifacts",
            str(tmp_path / "artifacts"),
            "--llm-model",
            "stub-model",
            "--llm-base-url",
            "http://127.0.0.1:43122/v1",
        ]
    )

    with pytest.raises(InvalidCompetitionRun) as caught:
        resolve_run_request(args, environ={"AGENTGUARD_LLM_API_KEY": _SECRET})

    assert caught.value.reason_code == "variant_not_allowed_for_suite"


def test_variant_json_then_cli_precedence(tmp_path: Path) -> None:
    config = tmp_path / "variant.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": COMPETITION_CONFIG_SCHEMA_VERSION,
                "suite": "demo",
                "case_ids": ["BN-001"],
                "v21_mode": "shadow",
                "context_mode": "off",
                "rte_mode": "observe",
                "detector_mode": "off",
                "planner": {
                    "model": "stub-model",
                    "base_url": "http://127.0.0.1:43122/v1",
                },
            }
        ),
        encoding="utf-8",
    )
    args = build_parser().parse_args(
        [
            "run",
            "--config",
            str(config),
            "--context-mode",
            "required",
            "--artifacts",
            str(tmp_path / "artifacts"),
        ]
    )

    request = resolve_run_request(args, environ={"AGENTGUARD_LLM_API_KEY": _SECRET})

    assert request.variant is not None
    assert request.variant.v21_mode.value == "shadow"
    assert request.variant.context_mode.value == "required"
    assert request.value_sources["v21_mode"] == "json_config"
    assert request.value_sources["context_mode"] == "cli"


def test_cli_entrypoint_returns_two_when_live_executor_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_LLM_API_KEY", _SECRET)
    artifacts = tmp_path / "artifacts"

    exit_code = main(
        [
            "run",
            "--suite",
            "demo",
            "--case-id",
            "BN-001",
            "--artifacts",
            str(artifacts),
            "--llm-model",
            "stub-model",
            "--llm-base-url",
            "http://127.0.0.1:43122/v1",
        ]
    )

    assert exit_code == 2
    report = json.loads((artifacts / "result.json").read_text())
    assert report["reason_code"] == "live_executor_unavailable"
    assert report["competition_qualified"] is False


def test_missing_named_credential_and_remote_http_are_rejected(
    tmp_path: Path,
) -> None:
    base = [
        "run",
        "--artifacts",
        str(tmp_path / "artifacts"),
        "--llm-model",
        "model",
        "--llm-api-key-env",
        "CUSTOM_KEY",
    ]
    missing = build_parser().parse_args(
        [*base, "--llm-base-url", "https://provider.example/v1"]
    )
    with pytest.raises(InvalidCompetitionRun, match="credential is unavailable"):
        resolve_run_request(missing, environ={"OPENAI_API_KEY": _SECRET})

    insecure = build_parser().parse_args(
        [*base, "--llm-base-url", "http://provider.example/v1"]
    )
    with pytest.raises(InvalidCompetitionRun, match="only on loopback"):
        resolve_run_request(insecure, environ={"CUSTOM_KEY": _SECRET})


def test_copy_config_preserves_every_field_not_explicitly_updated(
    tmp_path: Path,
) -> None:
    config = BenchConfig(
        runtime_binding_id="binding-1",
        approval_mode="wait",
        approval_timeout=3,
        context_isolation_mode="required",
        trusted_task_ids_by_case={"BN-001": "task-1"},
        trusted_trace_ids_by_case={"BN-001": "trace-1"},
        sandbox_dir=tmp_path / "sandbox",
        results_dir=tmp_path / "results",
    )

    copied = _copy_config(config, defense_enabled=False)

    assert copied is not config
    assert copied.defense_enabled is False
    for definition in fields(BenchConfig):
        if definition.name == "defense_enabled":
            continue
        assert getattr(copied, definition.name) == getattr(config, definition.name)
