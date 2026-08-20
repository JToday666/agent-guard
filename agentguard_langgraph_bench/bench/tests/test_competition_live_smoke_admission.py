from __future__ import annotations

from pathlib import Path

import pytest

from agentguard_langgraph_bench.bench.competition_models import (
    authoritative_task_digest,
    canonical_sha256,
    load_competition_profile,
)
from agentguard_langgraph_bench.bench.competition_runner import (
    ArmRunRequest,
    ArmRunResult,
    InvalidCompetitionRun,
    ProviderRuntimeConfig,
    _admit_arm_result,
    _load_frozen_cases,
)
from agentguard_langgraph_bench.bench.model_exchange import (
    ModelExchangeEvidence,
    ModelExchangeOutcome,
    ModelParseStatus,
    endpoint_identity_digest,
)


_POLICY_DIGEST = canonical_sha256({"policy": "live-smoke"})
_TOOL_DIGEST = canonical_sha256({"tools": ["read_file"]})


def _request(tmp_path: Path) -> ArmRunRequest:
    profile = load_competition_profile()
    arm = next(item for item in profile.arms if item.arm_id == "A4")
    case = next(
        item for item in _load_frozen_cases(profile) if item.case_id == "BN-001"
    )
    return ArmRunRequest(
        profile=profile,
        arm=arm,
        repeat_index=0,
        seed=profile.seed,
        cases=(case,),
        provider=ProviderRuntimeConfig(
            provider_id="local-compatible",
            model="live-smoke-model",
            base_url="http://127.0.0.1:43122/v1",
            api_key_env="AGENTGUARD_LLM_API_KEY",
            api_key="test-only-provider-key",
        ),
        artifact_directory=tmp_path / "artifacts",
        suite=profile.suite,
        qualification_eligible=True,
    )


def _case_exchange(
    request: ArmRunRequest,
    *,
    round_index: int,
    tool_names: tuple[str, ...],
    prior_exchange_digest: str | None,
) -> ModelExchangeEvidence:
    identity = {
        "case_id": "BN-001",
        "arm_id": "A4",
        "round_index": round_index,
    }
    parse_status = (
        ModelParseStatus.VALID_TOOL_CALLS
        if tool_names
        else ModelParseStatus.VALID_NO_TOOL_CALL
    )
    return ModelExchangeEvidence(
        exchange_id=canonical_sha256({**identity, "exchange": True}),
        case_id="BN-001",
        arm_id="A4",
        repeat_index=0,
        round_index=round_index,
        provider_id=request.provider.provider_id,
        model=request.provider.model,
        endpoint_identity_digest=endpoint_identity_digest(request.provider.base_url),
        source_set_digest=canonical_sha256({**identity, "sources": True}),
        authority_binding_digest=canonical_sha256({**identity, "authority": True}),
        model_input_digest=canonical_sha256({**identity, "input": True}),
        tool_schema_digest=_TOOL_DIGEST,
        request_digest=canonical_sha256({**identity, "request": True}),
        response_digest=canonical_sha256({**identity, "response": True}),
        prior_exchange_digest=prior_exchange_digest,
        context_mode="required",
        context_plan_digest=canonical_sha256({**identity, "plan": True}),
        transform_applied=True,
        request_observed=True,
        response_observed=True,
        outcome=ModelExchangeOutcome.SUCCESS,
        parse_status=parse_status,
        tool_call_count=len(tool_names),
        tool_names=tool_names,
        attempt_index=1,
        retry_count=0,
        elapsed_ms=1,
    )


def _preflight_exchange(request: ArmRunRequest) -> dict[str, object]:
    identity = {
        "case_id": "__provider_preflight__",
        "arm_id": request.arm.arm_id,
        "repeat_index": request.repeat_index,
    }
    return ModelExchangeEvidence(
        exchange_id=canonical_sha256({**identity, "exchange": True}),
        case_id="__provider_preflight__",
        arm_id=request.arm.arm_id,
        repeat_index=request.repeat_index,
        round_index=1,
        provider_id=request.provider.provider_id,
        model=request.provider.model,
        endpoint_identity_digest=endpoint_identity_digest(request.provider.base_url),
        source_set_digest=canonical_sha256({**identity, "sources": True}),
        authority_binding_digest=canonical_sha256(
            {
                "profile_id": request.profile.profile_id,
                "arm_id": request.arm.arm_id,
                "repeat_index": request.repeat_index,
                "purpose": "provider_tool_call_preflight",
            }
        ),
        model_input_digest=canonical_sha256({**identity, "input": True}),
        tool_schema_digest=canonical_sha256({"tools": ["probe"]}),
        request_digest=canonical_sha256({**identity, "request": True}),
        response_digest=canonical_sha256({**identity, "response": True}),
        context_mode="off",
        transform_applied=False,
        request_observed=True,
        response_observed=True,
        outcome=ModelExchangeOutcome.SUCCESS,
        parse_status=ModelParseStatus.VALID_TOOL_CALLS,
        tool_call_count=1,
        tool_names=("agentguard_competition_probe",),
        attempt_index=1,
        retry_count=0,
        elapsed_ms=1,
    ).public_dump()


def _contracts(request: ArmRunRequest) -> dict[str, dict[str, object]]:
    return {
        "provider_tool_call_preflight": {
            "status": "passed",
            "reason_code": "provider_tool_call_preflight_passed",
            "exchange": _preflight_exchange(request),
        }
    }


def _result(
    request: ArmRunRequest,
    *,
    exchanges: list[ModelExchangeEvidence] | None = None,
    executions: list[dict[str, object]] | None = None,
    receipts: list[dict[str, object]] | None = None,
    contracts: dict[str, dict[str, object]] | None = None,
) -> ArmRunResult:
    case = request.cases[0]
    if exchanges is None:
        first = _case_exchange(
            request,
            round_index=1,
            tool_names=("read_file",),
            prior_exchange_digest=None,
        )
        second = _case_exchange(
            request,
            round_index=2,
            tool_names=(),
            prior_exchange_digest=first.exchange_id,
        )
        exchanges = [first, second]
    if executions is None:
        executions = [
            {
                "action_id": "call-read-1",
                "tool_name": "read_file",
                "status": "executed",
                "invocation_count": 1,
                "decision": "allow",
                "decision_id": "dec:v21-official:read-1",
                "policy_audit_id": "audit-read-1",
                "approval_release": "not_applicable",
            }
        ]
    if receipts is None:
        receipts = [
            {
                "action_id": "call-read-1",
                "status": "executed",
                "receipt_count": 1,
            }
        ]
    first_exchange = exchanges[0]
    row = {
        "arm_id": "A4",
        "repeat_index": 0,
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
        "round_1_source_set_digest": first_exchange.source_set_digest,
        "round_1_model_input_digest": first_exchange.model_input_digest,
        "tool_schema_digest": _TOOL_DIGEST,
        "observed_arm": request.arm.public_dump(),
        "task_fact": {
            "status": "provisioned",
            "task_id": "task-a4-bn001",
            "trace_id": "trace-a4-bn001",
            "task_digest": authoritative_task_digest(case.input.payload),
            "principal_id": request.profile.identity.principal_id,
            "agent_id": request.profile.identity.agent_id,
            "runtime_binding_id": request.profile.identity.runtime_binding_id,
        },
        "model_exchanges": [item.public_dump() for item in exchanges],
        "tool_executions": executions,
        "terminal_receipts": receipts,
        "attack_success": False,
        "overblocked": False,
        "task_success": True,
        "v21_selected": True,
        "legacy_floor_applied": False,
        "receipt_covered": True,
    }
    return ArmRunResult(
        rows=(row,),
        contracts=_contracts(request) if contracts is None else contracts,
    )


def test_a4_bn001_live_smoke_admits_complete_evidence(tmp_path: Path) -> None:
    request = _request(tmp_path)

    rows, failures = _admit_arm_result(_result(request), request=request)

    assert len(rows) == 1
    assert failures == []


@pytest.mark.parametrize("mutation", ["missing", "wrong_provider"])
def test_qualifying_live_preflight_evidence_is_required_and_bound(
    tmp_path: Path, mutation: str
) -> None:
    request = _request(tmp_path)
    contracts = _contracts(request)
    if mutation == "missing":
        contracts = {}
        expected = "provider_preflight_evidence_missing"
    else:
        exchange = dict(contracts["provider_tool_call_preflight"]["exchange"])
        exchange["provider_id"] = "different-provider"
        contracts["provider_tool_call_preflight"]["exchange"] = exchange
        expected = "provider_preflight_evidence_invalid"

    with pytest.raises(InvalidCompetitionRun) as caught:
        _admit_arm_result(_result(request, contracts=contracts), request=request)

    assert caught.value.reason_code == expected


def test_distinct_action_ids_do_not_hide_duplicate_read_file_invocation(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    executions = [
        {
            "action_id": f"call-read-{index}",
            "tool_name": "read_file",
            "status": "executed",
            "invocation_count": 1,
            "decision": "allow",
            "decision_id": f"dec:v21-official:read-{index}",
            "policy_audit_id": f"audit-read-{index}",
            "approval_release": "not_applicable",
        }
        for index in (1, 2)
    ]
    receipts = [
        {
            "action_id": f"call-read-{index}",
            "status": "executed",
            "receipt_count": 1,
        }
        for index in (1, 2)
    ]

    _, failures = _admit_arm_result(
        _result(request, executions=executions, receipts=receipts),
        request=request,
    )

    assert [item["reason_code"] for item in failures] == [
        "a4_live_read_file_invoked_more_than_once"
    ]


def test_executed_read_file_with_failed_terminal_is_invalid(tmp_path: Path) -> None:
    request = _request(tmp_path)
    receipts = [
        {
            "action_id": "call-read-1",
            "status": "failed",
            "receipt_count": 1,
        }
    ]

    with pytest.raises(InvalidCompetitionRun) as caught:
        _admit_arm_result(
            _result(request, receipts=receipts),
            request=request,
        )

    assert caught.value.reason_code == "a4_live_smoke_terminal_receipt_invalid"


def test_a4_live_smoke_requires_benign_task_success(tmp_path: Path) -> None:
    request = _request(tmp_path)
    result = _result(request)
    row = {**result.rows[0], "task_success": False}

    _, failures = _admit_arm_result(
        ArmRunResult(rows=(row,), contracts=result.contracts),
        request=request,
    )

    assert {item["reason_code"] for item in failures} == {
        "a4_live_benign_task_not_completed"
    }


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("one_exchange", "a4_live_model_exchange_count_below_minimum"),
        ("wrong_first_tool", "a4_live_first_tool_call_not_read_file"),
    ],
)
def test_complete_model_sequence_contract_misses_are_functional(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    request = _request(tmp_path)
    first = _case_exchange(
        request,
        round_index=1,
        tool_names=(
            ("browser_start",) if mutation == "wrong_first_tool" else ("read_file",)
        ),
        prior_exchange_digest=None,
    )
    exchanges = [first]
    if mutation == "wrong_first_tool":
        exchanges.append(
            _case_exchange(
                request,
                round_index=2,
                tool_names=(),
                prior_exchange_digest=first.exchange_id,
            )
        )

    _, failures = _admit_arm_result(
        _result(request, exchanges=exchanges),
        request=request,
    )

    assert expected in {item["reason_code"] for item in failures}


def test_duplicate_exchange_identity_is_invalid_not_a_second_request(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    first = _case_exchange(
        request,
        round_index=1,
        tool_names=("read_file",),
        prior_exchange_digest=None,
    )

    with pytest.raises(InvalidCompetitionRun) as caught:
        _admit_arm_result(
            _result(request, exchanges=[first, first.model_copy()]),
            request=request,
        )

    assert caught.value.reason_code == "a4_live_smoke_exchange_evidence_invalid"
