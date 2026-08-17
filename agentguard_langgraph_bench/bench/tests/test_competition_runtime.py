from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

from langchain_openai import ChatOpenAI
from agentguard_langgraph_adapter.context_guard import REFERENCE_RUNTIME_FACT

from agentguard_langgraph_bench.bench.competition_models import (
    CompetitionSuite,
    RteMode,
    load_competition_profile,
)
from agentguard_langgraph_bench.bench.competition_runner import (
    ArmRunRequest,
    ProviderRuntimeConfig,
)
from agentguard_langgraph_bench.bench.competition_runtime import (
    _PREFLIGHT_TOOL,
    _bench_config,
    execute_competition_arm,
)
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from agentguard_langgraph_bench.bench.model_exchange import invoke_with_model_exchange
from agentguard_langgraph_bench.guard import GuardAdapter, GuardConfig


_PROVIDER_KEY = "competition-local-provider-key"


class _ProviderHandler(BaseHTTPRequestHandler):
    requests: list[dict[str, Any]] = []
    authorization: list[str] = []

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        type(self).requests.append(payload)
        type(self).authorization.append(self.headers.get("Authorization", ""))
        response = {
            "id": f"chatcmpl-competition-{len(type(self).requests)}",
            "object": "chat.completion",
            "created": 1,
            "model": "competition-stub-model",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call-competition-probe",
                                "type": "function",
                                "function": {
                                    "name": "agentguard_competition_probe",
                                    "arguments": '{"probe":"ready"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {
                "prompt_tokens": 2,
                "completion_tokens": 1,
                "total_tokens": 3,
            },
        }
        encoded = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("x-request-id", f"request-{len(type(self).requests)}")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:
        return


@contextmanager
def _provider_server() -> Iterator[str]:
    _ProviderHandler.requests = []
    _ProviderHandler.authorization = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/v1"
    finally:
        server.shutdown()
        thread.join(timeout=3.0)
        server.server_close()


def _arm_request(tmp_path: Path, base_url: str) -> ArmRunRequest:
    profile = load_competition_profile("competition-langgraph-v2").with_overrides(
        suite=CompetitionSuite.DEMO,
        full_corpus=False,
    )
    case = next(
        item
        for item in load_attack_cases(profile.dataset.path)
        if item.case_id == "BN-001"
    )
    arm = next(item for item in profile.arms if item.arm_id == "A3")
    return ArmRunRequest(
        profile=profile,
        arm=arm,
        repeat_index=0,
        seed=0,
        cases=(case,),
        provider=ProviderRuntimeConfig(
            provider_id="local-compatible",
            model="competition-stub-model",
            base_url=base_url,
            api_key_env="COMPETITION_LOCAL_KEY",
            api_key=_PROVIDER_KEY,
            temperature=0,
            request_timeout=10,
            max_retries=0,
            max_tool_rounds=2,
        ),
        artifact_directory=tmp_path / "arm",
        suite=CompetitionSuite.DEMO,
        qualification_eligible=False,
    )


def test_bench_config_propagates_each_competition_rte_mode(tmp_path: Path) -> None:
    request = _arm_request(tmp_path, "http://127.0.0.1:9/v1")
    case_id = request.cases[0].case_id

    for rte_mode in RteMode:
        variant = replace(
            request,
            arm=replace(request.arm, rte_mode=rte_mode),
        )
        config = _bench_config(
            variant,
            base_url="http://127.0.0.1:8088",
            adapter_token="adapter-token",
            scratch=tmp_path / rte_mode.value,
            task_ids={case_id: f"task-{rte_mode.value}"},
            trace_ids={case_id: f"trace-{rte_mode.value}"},
        )

        assert config.competition_rte_mode == rte_mode.value
        assert GuardConfig.from_bench_config(
            config,
            runtime="langgraph",
            agent_id="langgraph-demo",
        ).competition_rte_mode == rte_mode.value


def test_active_arm_uses_live_api_task_ingress_and_real_provider_stub(
    tmp_path: Path,
) -> None:
    observed_config: dict[str, Any] = {}

    def case_runner(cases, *, config, **kwargs):
        assert len(cases) == 1
        case = cases[0]
        observed_config.update(
            {
                "instrumentation_plan_mode": config.instrumentation_plan_mode,
                "fallback": config.llm_fallback_to_case_plan,
                "closure": config.closure_on_partial,
                "context": config.context_isolation_mode,
                "rte": config.competition_rte_mode,
                "task_id": config.trusted_task_ids_by_case[case.case_id],
                "trace_id": config.trusted_trace_ids_by_case[case.case_id],
            }
        )
        adapter = GuardAdapter(
            config=GuardConfig.from_bench_config(
                config,
                runtime="langgraph",
                agent_id="langgraph-demo",
            )
        )
        sources = [
            {
                "source_id": "langgraph:runtime:planner-system",
                "source_type": "runtime",
                "source_trust": "trusted",
                "role": "system",
                "content": REFERENCE_RUNTIME_FACT,
            },
            {
                "source_id": f"langgraph:task:{case.case_id}",
                "source_type": "user",
                "source_trust": "trusted",
                "role": "user",
                "content": case.input.payload,
            },
        ]
        security = {
            "case_id": case.case_id,
            "trace_id": observed_config["trace_id"],
            "attack_type": case.attack_type,
            "is_malicious": case.is_malicious,
            "source_type": case.input.source_type,
            "source_trust": case.input.source_trust,
            "user_task": case.input.payload,
            "payload": case.input.payload,
            "metadata": case.metadata,
            "agent_id": "langgraph-demo",
            "runtime": "langgraph",
            "task_id": observed_config["task_id"],
        }
        _, decision = adapter.evaluate_context(
            sources=sources,
            security=security,
            trace_id=observed_config["trace_id"],
        )
        print(json.dumps(decision.model_dump(mode="json"), ensure_ascii=False))
        assert decision.decision == "allow", decision.model_dump(mode="json")
        assert decision.decision_authority is not None
        assert decision.decision_authority.source == "v21"
        assert decision.context_plan is not None
        context_plan_digest = str(decision.context_plan["plan_digest"])
        messages = [
            ("system", REFERENCE_RUNTIME_FACT),
            ("user", case.input.payload),
        ]
        llm = ChatOpenAI(
            model=config.llm_model,
            api_key=config.llm_api_key,
            base_url=config.llm_base_url,
            temperature=0,
            max_retries=0,
        ).bind_tools([_PREFLIGHT_TOOL], tool_choice="required")
        _, evidence = invoke_with_model_exchange(
            llm,
            model_input=messages,
            sources=sources,
            tool_schemas=[_PREFLIGHT_TOOL],
            authority_binding={"task_id": observed_config["task_id"]},
            case_id=case.case_id,
            arm_id="A3",
            repeat_index=0,
            round_index=1,
            provider_id="local-compatible",
            model="competition-stub-model",
            base_url=config.llm_base_url,
            context_mode="observe",
            context_plan_digest=context_plan_digest,
            transform_applied=False,
        )
        return [
            {
                "case_id": case.case_id,
                "run_valid": True,
                "run_status": "completed",
                "guided_plan_applied": False,
                "fallback_applied": False,
                "model_exchanges": [evidence.public_dump()],
                "tool_calls": [],
                "attack_success": False,
                "overblocked": False,
                "task_success": True,
            }
        ]

    with _provider_server() as base_url:
        result = execute_competition_arm(
            _arm_request(tmp_path, base_url),
            case_runner=case_runner,
        )

    assert len(_ProviderHandler.requests) == 2
    assert _ProviderHandler.authorization == [
        f"Bearer {_PROVIDER_KEY}",
        f"Bearer {_PROVIDER_KEY}",
    ]
    assert observed_config == {
        "instrumentation_plan_mode": "autonomous",
        "fallback": False,
        "closure": False,
        "context": "off",
        "rte": "enforce",
        "task_id": result.rows[0]["task_fact"]["task_id"],
        "trace_id": result.rows[0]["task_fact"]["trace_id"],
    }
    row = result.rows[0]
    assert row["run_valid"] is True
    assert row["model_invoked"] is True
    assert row["observed_arm"]["official_decision_source"] == "v21"
    assert row["v21_selected"] is True
    assert row["receipt_covered"] is True
    assert row["task_fact"]["status"] == "provisioned"
    assert row["task_fact"]["principal_id"] == "competition-langgraph-runner"
    assert row["task_fact"]["agent_id"] == "langgraph-demo"
    assert row["task_fact"]["runtime_binding_id"] == (
        "binding:competition-langgraph-runner"
    )
    assert result.contracts["provider_tool_call_preflight"]["status"] == "passed"
    assert result.contracts["competition_activation"]["status"] == "passed"
    assert _PROVIDER_KEY not in repr(result)
