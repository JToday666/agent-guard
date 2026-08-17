"""Live LangGraph-only executor for the V2 competition profile.

Each invocation owns one arm/repeat isolation boundary: a fresh in-memory
control-plane store, a real loopback Uvicorn Guard API, server-created
TaskFacts, an immutable signed activation (when V2 is official), and a fresh
benchmark sandbox.  The module deliberately consumes model-exchange evidence
created at the graph invocation boundary; it never infers a model call from a
configuration flag or from the provider capability preflight.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

import httpx
import uvicorn
from agentguard_core import PolicyBundle, build_competition_activation_manifest
from agentguard_core.actions import ActionConstraint
from guard_api.auth import AuthContext
from guard_api.main import create_app
from guard_api.models import (
    ADAPTER_CREDENTIAL_SCOPES,
    CredentialRecord,
    TaskCreateRequest,
)
from guard_api.services.task_ingress import TaskIngressService
from guard_api.settings import GuardApiSettings
from guard_api.storage.memory import MemoryControlPlaneStore

from .competition_models import (
    ArmSpec,
    COMPETITION_ACTION_TYPES,
    ContextMode,
    DetectorMode,
    OfficialDecisionSource,
    RteMode,
    V21RolloutMode,
    canonical_sha256,
)
from .competition_runner import (
    ArmRunRequest,
    ArmRunResult,
    InvalidCompetitionRun,
)
from .config import BenchConfig
from .model_exchange import (
    ModelExchangeEvidence,
    ModelExchangeInvocationError,
    invoke_with_model_exchange,
)
from .runner import run_cases


_ALL_RULE_IDS = [f"P{number:03d}_{name}" for number, name in (
    (101, "prompt_injection"),
    (102, "jailbreak"),
    (103, "code_execution_abuse"),
    (104, "memory_poisoning"),
    (105, "environment_poisoning"),
    (106, "credential_exposure"),
    (107, "file_exfiltration"),
    (108, "agent_abuse"),
    (109, "mcp_tool_hijacking"),
)]
_PREFLIGHT_TOOL = {
    "type": "function",
    "function": {
        "name": "agentguard_competition_probe",
        "description": "Return the fixed competition provider capability probe.",
        "parameters": {
            "type": "object",
            "properties": {"probe": {"type": "string", "enum": ["ready"]}},
            "required": ["probe"],
            "additionalProperties": False,
        },
    },
}

CaseRunner = Callable[..., list[dict[str, Any]]]


def execute_competition_arm(
    request: ArmRunRequest,
    *,
    case_runner: CaseRunner = run_cases,
) -> ArmRunResult:
    """Execute one isolated arm/repeat and return admission-ready rows."""

    store = MemoryControlPlaneStore()
    store.initialize()
    policy = _competition_policy(request.arm)
    policy_digest = canonical_sha256(policy.model_dump(mode="json"))
    runtime_secrets = _RuntimeSecrets.create()
    if request.arm.guard_enabled:
        _provision_adapter_credential(
            store,
            request=request,
            token=runtime_secrets.adapter_token,
        )

    with tempfile.TemporaryDirectory(
        prefix=f"agentguard-competition-{request.arm.arm_id.lower()}-"
    ) as raw_scratch:
        scratch = Path(raw_scratch)
        activation_path, activation_digest = _write_activation_manifest(
            request,
            scratch=scratch,
            policy_digest=policy_digest,
            server_secret=runtime_secrets.v21_secret_bytes,
        )
        settings = _arm_settings(
            request.arm,
            activation_path=activation_path,
            runtime_secrets=runtime_secrets,
        )
        settings.validate_for_startup()
        app = create_app(store=store, settings=settings, policy_bundle=policy)

        task_evidence, task_ids, trace_ids = _provision_task_facts(
            request,
            store=store,
            settings=settings,
        )
        with _serve(app) as base_url:
            _require_guard_api_ready(base_url)
            preflight = _provider_tool_call_preflight(request)
            config = _bench_config(
                request,
                base_url=base_url,
                adapter_token=runtime_secrets.adapter_token,
                scratch=scratch,
                task_ids=task_ids,
                trace_ids=trace_ids,
            )
            with _deny_approval_fixture(
                base_url=base_url,
                control_token=runtime_secrets.control_token,
                enabled=request.arm.guard_enabled,
            ) as approval_fixture:
                raw_rows = case_runner(
                    list(request.cases),
                    config=config,
                    fake_core=False,
                    reset_environment=True,
                    scenario_stateful=True,
                    isolate_scenarios=True,
                    benchmark_run_id=(
                        f"competition-{request.arm.arm_id.lower()}-"
                        f"r{request.repeat_index + 1}"
                    ),
                    run_metadata={
                        "competition_profile_id": request.profile.profile_id,
                        "competition_arm_id": request.arm.arm_id,
                        "competition_repeat_index": request.repeat_index,
                        "competition_seed": request.seed,
                        "approval_fixture": "deny",
                    },
                )

            if len(raw_rows) != len(request.cases):
                raise InvalidCompetitionRun(
                    "live_case_count_mismatch",
                    "live competition runtime returned the wrong case count",
                )
            rows: list[dict[str, Any]] = []
            for case, raw_row in zip(request.cases, raw_rows, strict=True):
                trace_id = trace_ids.get(case.case_id)
                trace = (
                    _fetch_trace(
                        base_url,
                        control_token=runtime_secrets.control_token,
                        trace_id=trace_id,
                    )
                    if trace_id is not None
                    else None
                )
                rows.append(
                    _normalize_case_row(
                        raw_row,
                        case=case,
                        request=request,
                        policy_digest=policy_digest,
                        task_fact=task_evidence[case.case_id],
                        trace=trace,
                    )
                )

        contracts = {
            "guard_api_loopback": _passed("guard_api_loopback_ready"),
            "fresh_memory_store": _passed("fresh_memory_store_per_arm_repeat"),
            "provider_tool_call_preflight": {
                **_passed("provider_tool_call_preflight_passed"),
                "exchange": preflight.public_dump(),
            },
            "task_ingress_identity": _passed(
                "task_ingress_not_applicable"
                if not request.arm.guard_enabled
                else "authoritative_task_facts_provisioned"
            ),
            "main_matrix_ask_fixture": {
                **_passed("reviewable_ask_deny_fixture_active"),
                "resolved_count": approval_fixture.resolved_count,
            },
            "competition_activation": {
                **_passed(
                    "activation_not_applicable"
                    if activation_digest is None
                    else "signed_read_only_activation_loaded"
                ),
                "activation_ref_digest": activation_digest,
            },
        }
        return ArmRunResult(rows=tuple(rows), contracts=contracts)


class _RuntimeSecrets:
    def __init__(
        self,
        *,
        adapter_token: str,
        control_token: str,
        v21_secret_bytes: bytes,
        v21_secret_encoded: str,
        task_scope_key_encoded: str,
    ) -> None:
        self.adapter_token = adapter_token
        self.control_token = control_token
        self.v21_secret_bytes = v21_secret_bytes
        self.v21_secret_encoded = v21_secret_encoded
        self.task_scope_key_encoded = task_scope_key_encoded

    @classmethod
    def create(cls) -> "_RuntimeSecrets":
        v21_secret = secrets.token_bytes(32)
        task_scope_key = secrets.token_bytes(32)
        return cls(
            adapter_token=secrets.token_urlsafe(32),
            control_token=secrets.token_urlsafe(32),
            v21_secret_bytes=v21_secret,
            v21_secret_encoded=base64.urlsafe_b64encode(v21_secret).decode("ascii"),
            task_scope_key_encoded=base64.urlsafe_b64encode(task_scope_key).decode(
                "ascii"
            ),
        )


def _competition_policy(arm: ArmSpec) -> PolicyBundle:
    # Detector-off is diagnostic-only.  A0 retains the same frozen policy
    # identity as A1-A4 even though the guard is physically bypassed.
    if arm.guard_enabled and arm.detector_mode is DetectorMode.OFF:
        return PolicyBundle(disabled_rules=list(_ALL_RULE_IDS))
    return PolicyBundle()


def _write_activation_manifest(
    request: ArmRunRequest,
    *,
    scratch: Path,
    policy_digest: str,
    server_secret: bytes,
) -> tuple[Path | None, str | None]:
    mode = request.arm.v21_rollout_mode
    if mode not in {V21RolloutMode.LIMITED_ENABLE, V21RolloutMode.ACTIVE}:
        return None, None
    manifest = build_competition_activation_manifest(
        server_secret=server_secret,
        principal_id=request.profile.identity.principal_id,
        agent_id=request.profile.identity.agent_id,
        runtime_binding_id=request.profile.identity.runtime_binding_id,
        policy_digest=policy_digest,
        dataset_digest=request.profile.dataset.dataset_digest,
        profile_digest=request.profile.effective_digest,
        selection_basis=(
            "profile_all" if mode is V21RolloutMode.ACTIVE else "path_allowlist"
        ),
    )
    path = (scratch / "server" / "competition-activation.json").resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(manifest.model_dump_json(), encoding="utf-8")
    path.chmod(0o400)
    return path, manifest.activation_ref_digest


def _arm_settings(
    arm: ArmSpec,
    *,
    activation_path: Path | None,
    runtime_secrets: _RuntimeSecrets,
) -> GuardApiSettings:
    v21_mode = arm.v21_rollout_mode.value if arm.v21_rollout_mode else "off"
    task_scope_key_id = "competition-task-scope-v1" if arm.guard_enabled else None
    task_scope_keys = (
        json.dumps(
            {task_scope_key_id: runtime_secrets.task_scope_key_encoded},
            sort_keys=True,
        )
        if task_scope_key_id is not None
        else None
    )
    return GuardApiSettings(
        storage_backend="memory",
        control_token=runtime_secrets.control_token,
        host="127.0.0.1",
        environment="test",
        v21_mode=v21_mode,
        v21_competition_activation_path=(
            str(activation_path) if activation_path is not None else None
        ),
        v21_shadow_server_secret=(
            runtime_secrets.v21_secret_encoded if arm.v21_enabled else None
        ),
        ct_fact_projection_enabled=arm.ct_projection_enabled,
        context_builder_enabled=arm.context_mode is not ContextMode.OFF,
        rte05_strong_binding_enabled=bool(
            arm.v21_enabled and arm.rte_mode is RteMode.ENFORCE
        ),
        task_scope_active_key_id=task_scope_key_id,
        task_scope_keys=task_scope_keys,
    )


def _provision_adapter_credential(
    store: MemoryControlPlaneStore,
    *,
    request: ArmRunRequest,
    token: str,
) -> None:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    store.create_credential(
        CredentialRecord(
            credential_id=f"cred_competition_{token_hash[:16]}",
            token_hash=token_hash,
            principal_type="component",
            principal_id=request.profile.identity.principal_id,
            role="adapter",
            # Deliberately excludes task:write. TaskIngress is server-internal.
            scopes=list(ADAPTER_CREDENTIAL_SCOPES),
            runtime=request.profile.runtime,
            agent_id=request.profile.identity.agent_id,
        )
    )


def _provision_task_facts(
    request: ArmRunRequest,
    *,
    store: MemoryControlPlaneStore,
    settings: GuardApiSettings,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, str],
    dict[str, str],
]:
    evidence: dict[str, dict[str, Any]] = {}
    task_ids: dict[str, str] = {}
    trace_ids: dict[str, str] = {}
    if not request.arm.guard_enabled:
        for case in request.cases:
            evidence[case.case_id] = {"status": "not_applicable"}
        return evidence, task_ids, trace_ids

    auth = AuthContext(
        principal_type="component",
        principal_id=request.profile.identity.principal_id,
        role="adapter",
        scopes=["task:write"],
        auth_method="server_competition_profile",
        runtime=request.profile.runtime,
        agent_id=request.profile.identity.agent_id,
    )
    service = TaskIngressService(store=store, settings=settings)
    for ordinal, case in enumerate(request.cases):
        trace_id = _trace_id(request, case.case_id, ordinal)
        response = service.create_task(
            TaskCreateRequest(
                task_text=case.input.payload,
                runtime=request.profile.runtime,
                runtime_binding_id=request.profile.identity.runtime_binding_id,
                trace_id=trace_id,
                action_constraints=[
                    ActionConstraint(action_types=list(COMPETITION_ACTION_TYPES))
                ],
            ),
            auth,
        )
        record = store.get_task_fact(response.task_id)
        if record is None:
            raise InvalidCompetitionRun(
                "task_fact_readback_missing",
                "authoritative TaskFact could not be read after creation",
            )
        fact = record.task_fact
        if (
            fact.principal_id != request.profile.identity.principal_id
            or response.task_digest != fact.task_digest
            or record.canonical_payload.get("task_digest") != fact.task_digest
        ):
            raise InvalidCompetitionRun(
                "task_fact_readback_mismatch",
                "authoritative TaskFact readback differs from TaskIngress response",
            )
        task_ids[case.case_id] = response.task_id
        trace_ids[case.case_id] = trace_id
        evidence[case.case_id] = {
            "status": "provisioned",
            "task_id": response.task_id,
            "trace_id": trace_id,
            "task_digest": response.task_digest,
            "principal_id": request.profile.identity.principal_id,
            "agent_id": request.profile.identity.agent_id,
            "runtime_binding_id": request.profile.identity.runtime_binding_id,
        }
    return evidence, task_ids, trace_ids


def _trace_id(request: ArmRunRequest, case_id: str, ordinal: int) -> str:
    digest = hashlib.sha256(
        (
            f"{request.profile.effective_digest}:{request.arm.arm_id}:"
            f"{request.repeat_index}:{ordinal}:{case_id}:{time.time_ns()}"
        ).encode("utf-8")
    ).hexdigest()[:20]
    return f"trace_competition_{request.arm.arm_id.lower()}_{digest}"


@contextmanager
def _serve(app: Any) -> Iterator[str]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = int(listener.getsockname()[1])
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="error",
            lifespan="on",
        )
    )
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [listener]},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 10.0
    while not server.started and time.monotonic() < deadline:
        if not thread.is_alive():
            raise InvalidCompetitionRun(
                "guard_api_startup_failed", "loopback Guard API stopped during startup"
            )
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=3.0)
        raise InvalidCompetitionRun(
            "guard_api_startup_timeout", "loopback Guard API did not become ready"
        )
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10.0)
        if thread.is_alive():
            raise RuntimeError("loopback Guard API did not stop")


def _require_guard_api_ready(base_url: str) -> None:
    try:
        with httpx.Client(base_url=base_url, timeout=3.0) as client:
            response = client.get("/health", params={"check_db": "true"})
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        raise InvalidCompetitionRun(
            "guard_api_readiness_failed", "loopback Guard API readiness failed"
        ) from exc
    if payload.get("status") != "ok" or payload.get("database") != "ok":
        raise InvalidCompetitionRun(
            "guard_api_readiness_failed", "loopback Guard API storage is not ready"
        )


def _provider_tool_call_preflight(request: ArmRunRequest) -> ModelExchangeEvidence:
    provider = request.provider
    try:
        from langchain_openai import ChatOpenAI  # type: ignore[import-not-found]
    except ImportError as exc:
        raise InvalidCompetitionRun(
            "provider_transport_unavailable",
            "langchain-openai is required for competition execution",
        ) from exc
    llm = ChatOpenAI(
        model=provider.model,
        api_key=provider.api_key,
        base_url=provider.base_url,
        temperature=0,
        timeout=provider.request_timeout,
        max_retries=0,
    ).bind_tools([_PREFLIGHT_TOOL], tool_choice="required")
    messages = [
        ("system", "You are a provider capability probe. Use the supplied tool."),
        ("user", "Call agentguard_competition_probe with probe=ready."),
    ]
    sources = [
        {
            "source_id": "competition:provider-preflight:protocol",
            "source_type": "runtime",
            "source_trust": "trusted",
            "role": "system",
            "content": messages[0][1],
        },
        {
            "source_id": "competition:provider-preflight:request",
            "source_type": "user",
            "source_trust": "trusted",
            "role": "user",
            "content": messages[1][1],
        },
    ]
    try:
        _, evidence = invoke_with_model_exchange(
            llm,
            model_input=messages,
            sources=sources,
            tool_schemas=[_PREFLIGHT_TOOL],
            authority_binding={
                "profile_id": request.profile.profile_id,
                "arm_id": request.arm.arm_id,
                "repeat_index": request.repeat_index,
                "purpose": "provider_tool_call_preflight",
            },
            case_id="__provider_preflight__",
            arm_id=request.arm.arm_id,
            repeat_index=request.repeat_index,
            round_index=1,
            provider_id=provider.provider_id,
            model=provider.model,
            base_url=provider.base_url,
            context_mode="off",
        )
    except ModelExchangeInvocationError as exc:
        raise InvalidCompetitionRun(
            "provider_preflight_failed",
            f"provider tool-call preflight failed: {exc.evidence.outcome.value}",
        ) from exc
    if evidence.tool_names != ("agentguard_competition_probe",):
        raise InvalidCompetitionRun(
            "provider_tool_call_unsupported",
            "provider did not return the required tool call",
        )
    return evidence


def _bench_config(
    request: ArmRunRequest,
    *,
    base_url: str,
    adapter_token: str,
    scratch: Path,
    task_ids: Mapping[str, str],
    trace_ids: Mapping[str, str],
) -> BenchConfig:
    values: dict[str, Any] = {
        "core_base_url": base_url,
        "token": adapter_token,
        "runtime_binding_id": request.profile.identity.runtime_binding_id,
        "timeout": min(10.0, request.provider.request_timeout),
        "fail_closed": True,
        "defense_enabled": request.arm.guard_enabled,
        "approval_mode": "wait",
        "approval_timeout": min(30.0, request.provider.request_timeout),
        "runtime": request.profile.runtime,
        "sandbox_dir": scratch / "sandbox",
        "results_dir": scratch / "results",
        "llm_enabled": True,
        "llm_provider": request.provider.provider_id,
        "llm_model": request.provider.model,
        "llm_api_key": request.provider.api_key,
        "llm_base_url": request.provider.base_url,
        "llm_temperature": 0.0,
        "llm_fallback_to_case_plan": False,
        "llm_max_tool_rounds": request.provider.max_tool_rounds,
        "llm_request_timeout": request.provider.request_timeout,
        "llm_max_retries": request.provider.max_retries,
        "instrumentation_plan_mode": "autonomous",
        "browser_mode": "real",
        "browser_fixture_compat_mode": "strict",
        "tool_hijacking_mode": "autonomous",
        "agent_adapter": request.profile.agent_adapter,
        "core_api_mode": "guard-api-v0.3",
        "context_isolation_mode": (
            "required"
            if request.arm.context_mode is ContextMode.REQUIRED
            else "off"
        ),
        "trusted_task_ids_by_case": dict(task_ids),
        "trusted_trace_ids_by_case": dict(trace_ids),
        "strict_runtime_targets": True,
        "agent_visible_payload_mode": "original",
        "closure_on_partial": False,
        "autonomous_planner_recovery_retry": False,
        "autonomous_planner_recovery_max_observations": 1,
        "competition_mode": True,
        "competition_arm_id": request.arm.arm_id,
        "competition_repeat_index": request.repeat_index,
        "competition_context_mode": request.arm.context_mode.value,
        "competition_rte_mode": request.arm.rte_mode.value,
    }
    return BenchConfig(**values)


class _DenyApprovalFixture:
    def __init__(self) -> None:
        self.resolved_count = 0
        self.error: BaseException | None = None


@contextmanager
def _deny_approval_fixture(
    *, base_url: str, control_token: str, enabled: bool
) -> Iterator[_DenyApprovalFixture]:
    fixture = _DenyApprovalFixture()
    if not enabled:
        yield fixture
        return
    stop = threading.Event()

    def resolve_loop() -> None:
        try:
            with httpx.Client(base_url=base_url, timeout=3.0) as client:
                launch = client.post(
                    "/v1/auth/browser/launch",
                    headers={"Authorization": f"Bearer {control_token}"},
                )
                launch.raise_for_status()
                exchange = client.post(
                    "/v1/auth/browser/exchange",
                    json={"launch_code": launch.json()["launch_code"]},
                )
                exchange.raise_for_status()
                csrf = str(exchange.json()["csrf_token"])
                while not stop.is_set():
                    pending = client.get("/v1/approvals/pending")
                    pending.raise_for_status()
                    for approval in pending.json():
                        if "deny" not in (approval.get("decision_options") or []):
                            continue
                        response = client.post(
                            f"/v1/approvals/{approval['approval_id']}/resolve",
                            headers={"X-AgentGuard-CSRF": csrf},
                            json={"decision": "deny"},
                        )
                        if response.status_code == 409:
                            continue
                        response.raise_for_status()
                        fixture.resolved_count += 1
                    stop.wait(0.03)
        except BaseException as exc:  # noqa: BLE001 - relayed to executor thread.
            fixture.error = exc

    thread = threading.Thread(target=resolve_loop, daemon=True)
    thread.start()
    try:
        yield fixture
    finally:
        stop.set()
        thread.join(timeout=5.0)
        if thread.is_alive():
            raise InvalidCompetitionRun(
                "approval_fixture_shutdown_failed",
                "competition ASK deny fixture did not stop",
            )
        if fixture.error is not None:
            raise InvalidCompetitionRun(
                "approval_fixture_failed",
                "competition ASK deny fixture failed",
            ) from fixture.error


def _fetch_trace(
    base_url: str, *, control_token: str, trace_id: str
) -> dict[str, Any]:
    try:
        with httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {control_token}"},
            timeout=5.0,
        ) as client:
            response = client.get(f"/v1/traces/{trace_id}")
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        raise InvalidCompetitionRun(
            "trace_evidence_missing",
            "guarded case has no committed trace evidence",
        ) from exc
    if not isinstance(payload, dict) or payload.get("trace_id") != trace_id:
        raise InvalidCompetitionRun(
            "trace_evidence_invalid", "committed trace evidence has the wrong identity"
        )
    return payload


def _normalize_case_row(
    raw: Mapping[str, Any],
    *,
    case: Any,
    request: ArmRunRequest,
    policy_digest: str,
    task_fact: Mapping[str, Any],
    trace: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if raw.get("case_id") != case.case_id:
        raise InvalidCompetitionRun(
            "live_case_identity_mismatch", "live row has the wrong case identity"
        )
    raw_exchanges = raw.get("model_exchanges")
    if raw_exchanges is None and isinstance(raw.get("raw_state"), Mapping):
        raw_exchanges = raw["raw_state"].get("model_exchanges")
    if raw_exchanges is None:
        raw_exchanges = []
    if not isinstance(raw_exchanges, list):
        raise InvalidCompetitionRun(
            "model_exchange_evidence_invalid", "model exchanges must be a list"
        )
    try:
        exchanges = [
            ModelExchangeEvidence.model_validate(item) for item in raw_exchanges
        ]
    except ValueError as exc:
        raise InvalidCompetitionRun(
            "model_exchange_evidence_invalid",
            "graph model exchange evidence is invalid",
        ) from exc
    model_invoked = any(item.model_invoked for item in exchanges)
    source_digest = _first_digest(raw, exchanges, "source_set_digest")
    input_digest = _first_digest(raw, exchanges, "model_input_digest")
    tool_digest = _first_digest(raw, exchanges, "tool_schema_digest")
    authority_rows = _decision_authorities(trace)
    pre_model = None
    if not model_invoked:
        pre_model = _pre_model_block_evidence(trace)
        if pre_model is None:
            raise InvalidCompetitionRun(
                "model_invocation_evidence_missing",
                "case neither invoked the model nor has an authenticated pre-model block",
            )

    receipt_covered = _receipt_coverage(raw, trace, request.arm)
    observed_arm = _observed_arm(request.arm, trace)
    row = {
        "arm_id": request.arm.arm_id,
        "repeat_index": request.repeat_index,
        "case_id": case.case_id,
        "case_digest": case.metadata.get("case_digest"),
        "attack_type": case.attack_type,
        "is_malicious": case.is_malicious,
        "run_valid": raw.get("run_valid") is True,
        "run_status": raw.get("run_status") or "completed",
        "instrumentation_plan_mode": "autonomous",
        "llm_enabled": True,
        "planning_source": (
            "llm_autonomous" if model_invoked else "pre_model_blocked"
        ),
        "guided_plan_applied": bool(raw.get("guided_plan_applied")),
        "fallback_applied": bool(raw.get("fallback_applied")),
        "model_invoked": model_invoked,
        "task_input_digest": canonical_sha256(case.input.payload),
        "policy_digest": policy_digest,
        "round_1_source_set_digest": source_digest,
        "round_1_model_input_digest": input_digest,
        "tool_schema_digest": tool_digest,
        "observed_arm": observed_arm,
        "task_fact": dict(task_fact),
        "pre_model_block_evidence": pre_model,
        "model_exchanges": [item.public_dump() for item in exchanges],
        "attack_success": raw.get("attack_success"),
        "overblocked": raw.get("overblocked"),
        "task_success": raw.get("task_success"),
        "v21_selected": _v21_selected(request.arm, authority_rows),
        "legacy_floor_applied": _legacy_floor(request.arm, authority_rows),
        "receipt_covered": receipt_covered,
    }
    if row["guided_plan_applied"] or row["fallback_applied"]:
        row["run_valid"] = False
    return row


def _first_digest(
    raw: Mapping[str, Any],
    exchanges: Sequence[ModelExchangeEvidence],
    field_name: str,
) -> str:
    if exchanges:
        return str(getattr(exchanges[0], field_name))
    public_name = {
        "source_set_digest": "round_1_source_set_digest",
        "model_input_digest": "round_1_model_input_digest",
        "tool_schema_digest": "tool_schema_digest",
    }[field_name]
    candidates: list[Any] = [raw.get(public_name)]
    raw_state = raw.get("raw_state")
    if isinstance(raw_state, Mapping):
        candidates.extend(
            [
                raw_state.get(public_name),
                raw_state.get(field_name),
            ]
        )
        for key in ("competition_input_digests", "canonical_input_digests"):
            nested = raw_state.get(key)
            if isinstance(nested, Mapping):
                candidates.append(nested.get(field_name))
    for value in candidates:
        if _is_sha256(value):
            return str(value)
    raise InvalidCompetitionRun(
        "canonical_input_evidence_missing",
        f"case has no authenticated {field_name} evidence",
    )


def _decision_authorities(
    trace: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    if trace is None:
        return []
    authorities: list[dict[str, Any]] = []
    for event in trace.get("audit_events", []):
        if not isinstance(event, Mapping) or event.get("record_type") != "policy_evaluation":
            continue
        authority = event.get("decision_authority")
        if isinstance(authority, Mapping):
            authorities.append(dict(authority))
    return authorities


def _observed_arm(
    expected: ArmSpec, trace: Mapping[str, Any] | None
) -> dict[str, Any]:
    if not expected.guard_enabled:
        return expected.public_dump()
    audits = [
        event
        for event in (trace or {}).get("audit_events", [])
        if isinstance(event, Mapping) and event.get("record_type") == "policy_evaluation"
    ]
    authorities = _decision_authorities(trace)
    v21_modes = {
        str(event.get("evidence", {}).get("decision_v21", {}).get("payload", {}).get("mode"))
        for event in audits
        if isinstance(event.get("evidence"), Mapping)
        and isinstance(event.get("evidence", {}).get("decision_v21"), Mapping)
    }
    observed = expected.public_dump()
    if expected.v21_enabled and not audits:
        observed["v21_enabled"] = False
        observed["v21_rollout_mode"] = None
    elif expected.v21_rollout_mode is not None and expected.v21_rollout_mode.value not in v21_modes:
        observed["v21_rollout_mode"] = next(iter(sorted(v21_modes)), None)
    if expected.official_decision_source is OfficialDecisionSource.V21:
        if not authorities or any(item.get("source") != "v21" for item in authorities):
            observed["official_decision_source"] = "current"
    elif expected.official_decision_source is OfficialDecisionSource.CURRENT:
        if any(item.get("source") == "v21" for item in authorities):
            observed["official_decision_source"] = "v21"
    return observed


def _pre_model_block_evidence(
    trace: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if trace is None:
        return None
    for event in trace.get("audit_events", []):
        if not isinstance(event, Mapping) or event.get("record_type") != "policy_evaluation":
            continue
        guard_decision = event.get("evidence", {}).get("guard_decision")
        if not isinstance(guard_decision, Mapping):
            continue
        decision = guard_decision.get("decision")
        if decision not in {"deny", "ask"}:
            continue
        decision_id = guard_decision.get("decision_id")
        audit_id = event.get("audit_id")
        if isinstance(decision_id, str) and decision_id and isinstance(audit_id, str) and audit_id:
            return {
                "authenticated": True,
                "decision": decision,
                "decision_id": decision_id,
                "audit_id": audit_id,
            }
    return None


def _receipt_coverage(
    raw: Mapping[str, Any],
    trace: Mapping[str, Any] | None,
    arm: ArmSpec,
) -> bool | None:
    if arm.rte_mode is not RteMode.ENFORCE:
        return None
    calls = [item for item in raw.get("tool_calls", []) if isinstance(item, Mapping)]
    action_ids = {str(item.get("call_id")) for item in calls if item.get("call_id")}
    if any(item.get("runtime_receipt_error") for item in calls):
        return False
    terminals = {
        str(event.get("links", {}).get("action_id"))
        for event in (trace or {}).get("audit_events", [])
        if isinstance(event, Mapping)
        and event.get("record_type") == "runtime_outcome"
        and isinstance(event.get("links"), Mapping)
        and event.get("links", {}).get("action_id")
    }
    return action_ids <= terminals


def _v21_selected(arm: ArmSpec, authorities: Sequence[Mapping[str, Any]]) -> bool | None:
    if not arm.v21_enabled:
        return None
    return bool(authorities) and all(item.get("source") == "v21" for item in authorities)


def _legacy_floor(
    arm: ArmSpec, authorities: Sequence[Mapping[str, Any]]
) -> bool | None:
    if not arm.v21_enabled:
        return None
    return any(item.get("legacy_floor_applied") is True for item in authorities)


def _passed(reason_code: str) -> dict[str, str]:
    return {"status": "passed", "reason_code": reason_code}


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)


__all__ = ["execute_competition_arm"]
