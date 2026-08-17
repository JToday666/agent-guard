from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import fields, replace
from pathlib import Path
from urllib.parse import quote

import pytest
from guard_api.models import EvaluationRun

from agentguard_langgraph_bench.bench.competition_models import (
    COMPETITION_CONFIG_SCHEMA_VERSION,
    CompetitionSuite,
    authoritative_task_digest,
    canonical_sha256,
)
from agentguard_langgraph_bench.bench.competition_runner import (
    ArtifactDirectory,
    ArmRunRequest,
    ArmRunResult,
    ExitCode,
    InvalidCompetitionRun,
    _execution_arms,
    _expected_case_runs,
    _load_frozen_cases,
    _qualification_eligible,
    _validate_tool_and_receipt_evidence,
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
                    "task_digest": authoritative_task_digest(case.input.payload),
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
                    # Stub executors are never competition-qualified and do
                    # not manufacture runtime execution or receipt evidence.
                    "tool_executions": [],
                    "terminal_receipts": [],
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
                        False if request.arm.rte_mode.value == "enforce" else None
                    ),
                }
            )
            if (
                self.mutation
                in {
                    "a1_pre_model_deny_execute",
                    "a1_pre_model_ask_execute",
                    "a1_pre_model_deny_block",
                }
                and request.arm.arm_id == "A1"
                and case.case_id == request.cases[0].case_id
            ):
                block_decision = (
                    "ask" if self.mutation == "a1_pre_model_ask_execute" else "deny"
                )
                rows[-1].update(
                    {
                        "planning_source": "pre_model_blocked",
                        "model_invoked": False,
                        "model_exchanges": [],
                        "pre_model_block_evidence": {
                            "authenticated": True,
                            "decision": block_decision,
                            "decision_id": f"dec-a1-pre-model-{block_decision}",
                            "audit_id": f"audit-a1-pre-model-{block_decision}",
                        },
                    }
                )
            if (
                self.mutation
                in {
                    "a1_deny_execute",
                    "a1_missing_correlation",
                    "a1_runtime_receipt_error",
                    "a1_terminal_receipt_missing",
                    "a1_pre_model_deny_execute",
                    "a1_pre_model_ask_execute",
                }
                and request.arm.arm_id == "A1"
                and case.case_id == request.cases[0].case_id
            ):
                correlation = {
                    "decision": "deny",
                    "decision_id": "dec-a1-deny",
                    "policy_audit_id": "audit-a1-deny",
                    "approval_release": "not_applicable",
                }
                if self.mutation == "a1_missing_correlation":
                    correlation = {key: None for key in correlation}
                elif self.mutation in {
                    "a1_runtime_receipt_error",
                    "a1_terminal_receipt_missing",
                    "a1_pre_model_deny_execute",
                    "a1_pre_model_ask_execute",
                }:
                    correlation = {
                        "decision": "allow",
                        "decision_id": "dec-a1-allow",
                        "policy_audit_id": "audit-a1-allow",
                        "approval_release": "not_applicable",
                    }
                rows[-1]["tool_executions"] = [
                    {
                        "action_id": "call-a1-denied",
                        "tool_name": "read_file",
                        "status": "executed",
                        "invocation_count": 1,
                        **correlation,
                    }
                ]
                rows[-1]["terminal_receipts"] = [
                    {
                        "action_id": "call-a1-denied",
                        "status": "executed",
                        "receipt_count": 1,
                    }
                ]
                if self.mutation == "a1_terminal_receipt_missing":
                    rows[-1]["terminal_receipts"] = []
                rows[-1]["receipt_covered"] = self.mutation not in {
                    "a1_runtime_receipt_error",
                    "a1_terminal_receipt_missing",
                }
        return ArmRunResult(
            rows=tuple(rows),
            contracts={
                "stub_runtime_contract": {
                    "status": "passed",
                    "reason_code": "stub_runtime_contract_passed",
                }
            },
        )


def test_full_stub_matrix_is_complete_but_never_competition_qualified(
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
    assert report["competition_qualified"] is False
    preflight = json.loads((root / "preflight.json").read_text(encoding="utf-8"))
    assert preflight["competition_qualification_eligible"] is False
    completeness = json.loads((root / "completeness.json").read_text(encoding="utf-8"))
    assert completeness["competition_qualification_eligible"] is False
    assert report["expected_case_runs"] == 350
    assert report["attempted_case_runs"] == 350
    assert report["invalid_case_runs"] == 0
    assert [arm["arm_id"] for arm in report["arms"]] == ["A0", "A1", "A2", "A3", "A4"]
    assert all(arm["attempted"] == 70 for arm in report["arms"])
    assert report["arms"][3]["v21_selection_rate"] == 1.0
    assert report["arms"][0]["receipt_coverage"] is None
    dashboard_path = root / "dashboard-evaluation-run.json"
    dashboard_payload = json.loads(dashboard_path.read_text(encoding="utf-8"))
    parsed_dashboard = EvaluationRun.model_validate(dashboard_payload).model_dump(
        mode="json"
    )
    dashboard_report = parsed_dashboard["competition_report"]
    assert set(dashboard_payload) == {
        "run_id",
        "run_at",
        "dataset_id",
        "dataset_version",
        "dataset_digest",
        "dataset_locked",
        "asr_before",
        "asr_after",
        "competition_report",
    }
    assert set(dashboard_report) == {
        "schema_version",
        "profile_id",
        "status",
        "competition_qualified",
        "expected_case_runs",
        "attempted_case_runs",
        "invalid_case_runs",
        "provider_id",
        "model",
        "arms",
    }
    allowed_arm_keys = {
        "arm_id",
        "attempted",
        "evaluable",
        "invalid",
        "asr",
        "fpr",
        "benign_success",
        "v21_selection_rate",
        "legacy_floor_rate",
        "receipt_coverage",
    }
    assert all(set(arm) == allowed_arm_keys for arm in dashboard_report["arms"])
    assert all("counts" not in arm for arm in dashboard_report["arms"])
    assert dashboard_payload["asr_before"] == dashboard_report["arms"][0]["asr"]
    assert dashboard_payload["asr_after"] == dashboard_report["arms"][4]["asr"]
    assert dashboard_payload["dataset_id"] == request.profile.dataset.dataset_id
    assert (
        dashboard_payload["dataset_version"] == request.profile.dataset.dataset_version
    )
    assert dashboard_payload["dataset_digest"] == request.profile.dataset.dataset_digest
    assert dashboard_payload["dataset_locked"] is False
    assert dashboard_payload["run_at"].endswith("Z")
    effective_config = json.loads(
        (root / "effective-config.json").read_text(encoding="utf-8")
    )
    expected_identity = canonical_sha256(
        {
            "run_at": dashboard_payload["run_at"],
            "effective_config_digest": effective_config["effective_config_digest"],
            "competition_report": dashboard_report,
        }
    )
    assert dashboard_payload["run_id"] == (
        f"competition-{expected_identity.removeprefix('sha256:')}"
    )
    assert _SECRET not in dashboard_path.read_text(encoding="utf-8")
    manifest = json.loads((root / "sha256-manifest.json").read_text(encoding="utf-8"))
    assert manifest["secret_scan"]["status"] == "passed"
    assert manifest["secret_scan"]["files_scanned"] == manifest["artifact_count"]
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


@pytest.mark.parametrize(
    "encoded",
    [
        "sk/a+b=c?",
        "Bearer sk/a+b=c?",
        quote("sk/a+b=c?", safe=""),
        base64.b64encode(b"sk/a+b=c?").decode("ascii"),
        base64.urlsafe_b64encode(b"sk/a+b=c?").decode("ascii"),
    ],
)
@pytest.mark.parametrize("writer", ["json", "jsonl"])
def test_artifact_writer_rejects_provider_credential_variants_before_write(
    tmp_path: Path,
    encoded: str,
    writer: str,
) -> None:
    artifacts = ArtifactDirectory(
        tmp_path / "artifacts",
        forbidden_secrets=("sk/a+b=c?",),
    )
    artifacts.create()

    with pytest.raises(InvalidCompetitionRun) as caught:
        if writer == "json":
            artifacts.write_json("unsafe.json", {"diagnostic": encoded})
        else:
            artifacts.write_jsonl("unsafe.jsonl", [{"diagnostic": encoded}])

    assert caught.value.reason_code == "artifact_secret_detected"
    assert not (artifacts.root / f"unsafe.{writer}").exists()
    assert "sk/a+b=c?" not in str(caught.value)


def test_manifest_rescan_removes_executor_file_with_encoded_credential(
    tmp_path: Path,
) -> None:
    secret = "sk/a+b=c?"
    artifacts = ArtifactDirectory(
        tmp_path / "artifacts",
        forbidden_secrets=(secret,),
    )
    artifacts.create()
    leaked = artifacts.root / "executor-debug.log"
    leaked.write_text(base64.b64encode(secret.encode()).decode(), encoding="utf-8")

    with pytest.raises(InvalidCompetitionRun) as caught:
        artifacts.finalize_manifest(status="passed")

    assert caught.value.reason_code == "artifact_secret_detected"
    assert not leaked.exists()
    assert secret not in str(caught.value)


@pytest.mark.parametrize("surface", ["row", "contract", "exception"])
def test_runner_invalidates_secret_bearing_executor_output_without_persisting_it(
    tmp_path: Path,
    surface: str,
) -> None:
    request = _request(tmp_path)
    stub = StubArmExecutor()

    def executor(arm_request: ArmRunRequest) -> ArmRunResult:
        if surface == "exception":
            raise InvalidCompetitionRun(
                arm_request.provider.api_key,
                f"unsafe executor diagnostic: {arm_request.provider.api_key}",
            )
        result = stub(arm_request)
        if surface == "row":
            rows = list(result.rows)
            rows[0] = {**rows[0], "run_status": arm_request.provider.api_key}
            return ArmRunResult(rows=tuple(rows), contracts=result.contracts)
        return ArmRunResult(
            rows=result.rows,
            contracts={
                "unsafe_contract": {
                    "status": "failed",
                    "reason_code": arm_request.provider.api_key,
                }
            },
        )

    exit_code = run(request, executor=executor)

    assert exit_code is ExitCode.INVALID_RUN
    report = json.loads((request.artifacts / "result.json").read_text())
    assert report["reason_code"] == "artifact_secret_detected"
    assert report["competition_qualified"] is False
    dashboard_payload = json.loads(
        (request.artifacts / "dashboard-evaluation-run.json").read_text()
    )
    parsed_dashboard = EvaluationRun.model_validate(dashboard_payload).model_dump(
        mode="json"
    )
    assert parsed_dashboard["competition_report"]["status"] == "invalid"
    assert parsed_dashboard["competition_report"]["competition_qualified"] is False
    variants = {
        _SECRET.encode(),
        f"Bearer {_SECRET}".encode(),
        quote(_SECRET, safe="").encode(),
        base64.b64encode(_SECRET.encode()),
        base64.urlsafe_b64encode(_SECRET.encode()),
    }
    for path in request.artifacts.rglob("*"):
        if path.is_file():
            content = path.read_bytes()
            assert all(value not in content for value in variants)


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
    dashboard = EvaluationRun.model_validate_json(
        (request.artifacts / "dashboard-evaluation-run.json").read_text()
    ).model_dump(mode="json")
    assert dashboard["competition_report"]["status"] == "functional_contract_failed"
    contracts = json.loads(
        (request.artifacts / "contract-results.json").read_text(encoding="utf-8")
    )
    assert contracts["failures"][0]["reason_code"] == "observed_arm_mismatch"


def test_a1_committed_deny_followed_by_invocation_is_exit_one(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)

    exit_code = run(request, executor=StubArmExecutor(mutation="a1_deny_execute"))

    assert exit_code is ExitCode.FUNCTIONAL_CONTRACT_FAILED
    contracts = json.loads(
        (request.artifacts / "contract-results.json").read_text(encoding="utf-8")
    )
    assert "deny_action_invoked" in {
        item["reason_code"] for item in contracts["failures"]
    }


@pytest.mark.parametrize("block_decision", ["deny", "ask"])
def test_a1_authenticated_pre_model_block_followed_by_invocation_is_exit_one(
    tmp_path: Path,
    block_decision: str,
) -> None:
    request = _request(tmp_path)

    exit_code = run(
        request,
        executor=StubArmExecutor(mutation=f"a1_pre_model_{block_decision}_execute"),
    )

    assert exit_code is ExitCode.FUNCTIONAL_CONTRACT_FAILED
    contracts = json.loads(
        (request.artifacts / "contract-results.json").read_text(encoding="utf-8")
    )
    assert f"pre_model_{block_decision}_action_invoked" in {
        item["reason_code"] for item in contracts["failures"]
    }


def test_a1_authenticated_pre_model_block_without_invocation_remains_valid(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)

    exit_code = run(
        request,
        executor=StubArmExecutor(mutation="a1_pre_model_deny_block"),
    )

    assert exit_code is ExitCode.PASSED


def test_a1_invocation_without_committed_decision_correlation_is_exit_two(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)

    exit_code = run(
        request, executor=StubArmExecutor(mutation="a1_missing_correlation")
    )

    assert exit_code is ExitCode.INVALID_RUN
    report = json.loads((request.artifacts / "result.json").read_text(encoding="utf-8"))
    assert report["reason_code"] == "runtime_decision_correlation_missing"


@pytest.mark.parametrize(
    "mutation",
    ["a1_runtime_receipt_error", "a1_terminal_receipt_missing"],
)
def test_a1_incomplete_runtime_receipt_evidence_is_exit_two(
    tmp_path: Path,
    mutation: str,
) -> None:
    request = _request(tmp_path)

    exit_code = run(request, executor=StubArmExecutor(mutation=mutation))

    assert exit_code is ExitCode.INVALID_RUN
    report = json.loads((request.artifacts / "result.json").read_text(encoding="utf-8"))
    assert report["reason_code"] == "runtime_receipt_evidence_incomplete"


def test_guarded_pre_model_block_without_action_allows_false_receipt_coverage(
    tmp_path: Path,
) -> None:
    run_request = _request(tmp_path)
    case = _load_frozen_cases(run_request.profile)[0]
    arm = next(item for item in run_request.profile.arms if item.arm_id == "A1")
    request = ArmRunRequest(
        profile=run_request.profile,
        arm=arm,
        repeat_index=0,
        seed=run_request.profile.seed,
        cases=(case,),
        provider=run_request.provider,
        artifact_directory=tmp_path / "A1-pre-model",
        suite=run_request.profile.suite,
        qualification_eligible=False,
    )

    failures = _validate_tool_and_receipt_evidence(
        {
            "tool_executions": [],
            "terminal_receipts": [],
            "receipt_covered": False,
        },
        request=request,
        case=case,
        exchanges=(),
        identity=f"A1/r0/{case.case_id}",
    )

    assert failures == []


@pytest.mark.parametrize(
    ("arm_id", "decision", "approval_release"),
    [
        ("A1", "allow", "not_applicable"),
        ("A3", "ask", "strong_binding_required"),
    ],
)
def test_correlated_allow_and_reviewable_ask_execution_remain_valid(
    tmp_path: Path,
    arm_id: str,
    decision: str,
    approval_release: str,
) -> None:
    run_request = _request(tmp_path)
    case = _load_frozen_cases(run_request.profile)[0]
    arm = next(item for item in run_request.profile.arms if item.arm_id == arm_id)
    request = ArmRunRequest(
        profile=run_request.profile,
        arm=arm,
        repeat_index=0,
        seed=run_request.profile.seed,
        cases=(case,),
        provider=run_request.provider,
        artifact_directory=tmp_path / arm_id,
        suite=run_request.profile.suite,
        qualification_eligible=False,
    )
    row = {
        "tool_executions": [
            {
                "action_id": "call-correlated",
                "tool_name": "read_file",
                "status": "executed",
                "invocation_count": 1,
                "decision": decision,
                "decision_id": (
                    f"dec:v21-official:{decision}"
                    if arm_id == "A3"
                    else f"dec-{decision}"
                ),
                "policy_audit_id": f"audit-{decision}",
                "approval_release": approval_release,
            }
        ],
        "terminal_receipts": [
            {
                "action_id": "call-correlated",
                "status": "executed",
                "receipt_count": 1,
            }
        ],
        "receipt_covered": True,
    }

    failures = _validate_tool_and_receipt_evidence(
        row,
        request=request,
        case=case,
        exchanges=(),
        identity=f"{arm_id}/r0/{case.case_id}",
    )

    assert failures == []


def test_forbidden_v2_ask_followed_by_invocation_is_functional_failure(
    tmp_path: Path,
) -> None:
    run_request = _request(tmp_path)
    case = _load_frozen_cases(run_request.profile)[0]
    arm = next(item for item in run_request.profile.arms if item.arm_id == "A3")
    request = ArmRunRequest(
        profile=run_request.profile,
        arm=arm,
        repeat_index=0,
        seed=run_request.profile.seed,
        cases=(case,),
        provider=run_request.provider,
        artifact_directory=tmp_path / "A3",
        suite=run_request.profile.suite,
        qualification_eligible=False,
    )
    row = {
        "tool_executions": [
            {
                "action_id": "call-forbidden",
                "tool_name": "read_file",
                "status": "executed",
                "invocation_count": 1,
                "decision": "ask",
                "decision_id": "dec:v21-official:forbidden",
                "policy_audit_id": "audit-forbidden",
                "approval_release": "forbidden",
            }
        ],
        "terminal_receipts": [
            {
                "action_id": "call-forbidden",
                "status": "executed",
                "receipt_count": 1,
            }
        ],
        "receipt_covered": True,
    }

    failures = _validate_tool_and_receipt_evidence(
        row,
        request=request,
        case=case,
        exchanges=(),
        identity=f"A3/r0/{case.case_id}",
    )

    assert [item["reason_code"] for item in failures] == [
        "forbidden_ask_action_invoked"
    ]


def test_contradictory_v2_decision_release_correlation_is_invalid(
    tmp_path: Path,
) -> None:
    run_request = _request(tmp_path)
    case = _load_frozen_cases(run_request.profile)[0]
    arm = next(item for item in run_request.profile.arms if item.arm_id == "A3")
    request = ArmRunRequest(
        profile=run_request.profile,
        arm=arm,
        repeat_index=0,
        seed=run_request.profile.seed,
        cases=(case,),
        provider=run_request.provider,
        artifact_directory=tmp_path / "A3-invalid",
        suite=run_request.profile.suite,
        qualification_eligible=False,
    )
    row = {
        "tool_executions": [
            {
                "action_id": "call-contradictory",
                "tool_name": "read_file",
                "status": "executed",
                "invocation_count": 1,
                "decision": "allow",
                "decision_id": "dec:v21-official:contradictory",
                "policy_audit_id": "audit-contradictory",
                "approval_release": "forbidden",
            }
        ],
        "terminal_receipts": [
            {
                "action_id": "call-contradictory",
                "status": "executed",
                "receipt_count": 1,
            }
        ],
        "receipt_covered": True,
    }

    with pytest.raises(InvalidCompetitionRun) as caught:
        _validate_tool_and_receipt_evidence(
            row,
            request=request,
            case=case,
            exchanges=(),
            identity=f"A3/r0/{case.case_id}",
        )

    assert caught.value.reason_code == "runtime_decision_correlation_invalid"


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
    dashboard = EvaluationRun.model_validate_json(
        (request.artifacts / "dashboard-evaluation-run.json").read_text()
    ).model_dump(mode="json")
    assert dashboard["competition_report"]["status"] == "invalid"
    assert dashboard["competition_report"]["competition_qualified"] is False
    assert dashboard["competition_report"]["invalid_case_runs"] >= 1
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


@pytest.mark.parametrize("source", ["cli", "config"])
def test_main_suite_rejects_repeat_override(source: str, tmp_path: Path) -> None:
    config_args: list[str] = []
    cli_args: list[str] = []
    if source == "config":
        config = tmp_path / "repeats.json"
        config.write_text(
            json.dumps(
                {
                    "schema_version": COMPETITION_CONFIG_SCHEMA_VERSION,
                    "repeats": 2,
                }
            ),
            encoding="utf-8",
        )
        config_args = ["--config", str(config)]
    else:
        cli_args = ["--repeats", "2"]
    args = build_parser().parse_args(
        [
            "run",
            "--suite",
            "product",
            "--full-corpus",
            "--artifacts",
            str(tmp_path / "artifacts"),
            "--llm-model",
            "stub-model",
            "--llm-base-url",
            "http://127.0.0.1:43122/v1",
            *config_args,
            *cli_args,
        ]
    )

    with pytest.raises(InvalidCompetitionRun) as caught:
        resolve_run_request(args, environ={"AGENTGUARD_LLM_API_KEY": _SECRET})

    assert caught.value.reason_code == "exact_matrix_repeat_required"


def test_qualification_defensively_requires_exact_350_case_runs(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    cases = _load_frozen_cases(request.profile)
    arms = _execution_arms(request)

    assert _expected_case_runs(request) == 350
    assert _qualification_eligible(request, cases, arms) is True

    repeated = replace(request, profile=replace(request.profile, repeats=2))
    assert _expected_case_runs(repeated) == 700
    assert _qualification_eligible(repeated, cases, arms) is False


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


def test_cli_entrypoint_returns_two_when_live_provider_is_unavailable(
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
    assert report["reason_code"] in {
        "provider_preflight_failed",
        "provider_transport_unavailable",
    }
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
