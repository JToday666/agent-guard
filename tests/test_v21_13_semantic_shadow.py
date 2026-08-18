"""V21-13 Stage 1 shadow：LLM 辅助评判接入测试（不修改任何现有测试）。

覆盖口径（03 §11/§12/§13/§14 冻结契约）：

1. Provider 单测（注入 httpx client）：合法 JSON → 完整 judgment 且五
   digest 与 assessment 全等；HTTP 500 / 超时 / 坏 JSON / verdict 越界
   → None（fail-closed）；
2. 确定性：同输入同 judgment_id / semantic_digest；时间/身份字段不入
   semantic_digest；禁 uuid（前缀 + hex 形态断言）；
3. 门控：非 DEFER 零 HTTP 调用；sample_rate=0 零调用；同
   assessment_digest 重放采样结果一致；
4. Pipeline 钩子：fake provider 产物在场；provider 抛异常 → Phase A
   不回退；provider=None → 与无接线基线逐字节一致；
5. Phase B 信封：binding valid → 证据槽填派生值；binding 漂移 → 双槽
   恒 None；``final_decision`` 恒 ask；信封其余键与基线逐字节一致；
6. e2e metadata：judgment 在场时审计 metadata 出现新键；缺席时键集与
   基线逐字节一致；确定性 fake provider 重放同值；
7. Settings：默认 flag off；timeout/ttl/sample_rate 越界 → startup
   校验报错。

组织仿 ``tests/test_v21_09_pipeline.py`` 的局部工厂惯例；fake judgment
构造器仿 ``tests/test_v21_09_revalidation.py`` 的 ``_judgment``。
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from agentguard_core import (
    GuardEvent,
    build_competition_activation_manifest,
    utc_now_iso,
)
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.authority.models import TaskFact
from agentguard_core.decisions.evidence import FastAssessment
from agentguard_core.events.payloads import (
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
)
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    OnlineSecurityState,
)
from agentguard_core.semantic.models import SemanticJudgment
from guard_api.auth import AuthContext
from guard_api.security_state import SecurityStateService
from guard_api.services import (
    ApprovalService,
    AuditService,
    EvaluationService,
    FrozenCompetitionActivation,
    PolicyService,
    V21PipelineService,
    V21ShadowService,
)
from guard_api.services.semantic import (
    PROMPT_VERSION,
    PROVIDER_NAME,
    _SYSTEM_PROMPT_V1,
    HttpSemanticJudge,
    semantic_provider_from_settings,
)
from guard_api.settings import (
    GuardApiConfigurationError,
    GuardApiSettings,
)
from guard_api.storage.base import SecurityStateRecord, TaskFactRecord
from guard_api.storage.memory import MemoryControlPlaneStore

#: ≥32 字节的 base64url 测试密钥（与 V21-09 pipeline 测试同口径）。
_TEST_SECRET = base64.urlsafe_b64encode(
    b"v21-13-semantic-shadow-test-secret-material"
).decode("ascii")

_SCOPE_DIGEST = "hmac-sha256:" + "b7" * 32
_TASK_ID = "task_semantic_fixture"
_TIMESTAMP = "2026-08-15T00:00:00+00:00"

_SEMANTIC_METADATA_KEYS = (
    "v21_semantic_judgment_id",
    "v21_semantic_digest",
    "v21_semantic_verdict",
    "v21_semantic_degraded",
    "v21_semantic_binding_valid",
)

#: 评审 M3 后不再落盘的全文键（redaction 会改写全文，与 digest 永久
#: 失配；全文承载归后续 typed bound 证据通道）。
_SEMANTIC_FULLTEXT_KEY = "v21_semantic_judgment"


# ---------------------------------------------------------------------------
# 局部工厂（仿 test_v21_09_pipeline.py）
# ---------------------------------------------------------------------------


def _event(
    *,
    event_id: str = "evt_semantic_1",
    task_id: str | None = _TASK_ID,
    call_id: str | None = "call_semantic_1",
    timestamp: str = _TIMESTAMP,
) -> GuardEvent:
    metadata: dict[str, object] = {}
    if task_id is not None:
        metadata["task_id"] = task_id
    tool_kwargs: dict[str, object] = {"name": "read_file"}
    if call_id is not None:
        tool_kwargs["call_id"] = call_id
    return GuardEvent(
        event_id=event_id,
        event_type="tool_call_proposed",
        runtime="langgraph",
        trace_id="trace_semantic_1",
        timestamp=timestamp,
        security_context=SecurityContext(
            agent_id="main", user_task="semantic fixture"
        ),
        payload=ToolCallPayload(tool=ToolDescriptor(**tool_kwargs)),
        metadata=metadata,
    )


def _task_fact() -> TaskFact:
    return TaskFact(
        task_id=_TASK_ID,
        scope_digest=_SCOPE_DIGEST,
        scope_key_id="scope_key_test",
        principal_id="principal_a",
        task_summary="semantic fixture task",
        task_digest="sha256:" + "cd" * 32,
        revision=1,
        status="active",
        action_constraints=[],
        resource_constraints=[],
        destination_constraints=[],
        created_sequence=None,
        producer="guard_api_task_ingress",
        authority="authoritative",
        evidence_refs=[],
    )


def _commit_task_fact(store: MemoryControlPlaneStore) -> TaskFact:
    task_fact = _task_fact()
    store.create_task_fact(
        TaskFactRecord(
            task_fact=task_fact,
            canonical_payload=task_fact.model_dump(mode="json"),
            request_digest="sha256:" + "ef" * 32,
            expected_revision=0,
            created_at="2026-08-15T00:00:00Z",
        )
    )
    return task_fact


def _pipeline_settings(
    *, enabled: bool = True, secret: str | None = _TEST_SECRET
) -> GuardApiSettings:
    return GuardApiSettings(
        control_token="control-secret",
        storage_backend="memory",
        v21_mode="shadow" if enabled else "off",
        v21_shadow_server_secret=secret,
    )


def _pipeline_service(
    store: MemoryControlPlaneStore | None = None,
    *,
    settings: GuardApiSettings | None = None,
    semantic_provider=None,
) -> tuple[V21PipelineService, MemoryControlPlaneStore]:
    store = store if store is not None else MemoryControlPlaneStore()
    state_service = SecurityStateService(store)
    policy_service = PolicyService(store=store)
    pipeline = V21PipelineService(
        settings=settings or _pipeline_settings(),
        store=store,
        state_service=state_service,
        policy_service=policy_service,
        semantic_provider=semantic_provider,
    )
    return pipeline, store


def _evaluation_stack(
    store: MemoryControlPlaneStore,
    *,
    settings: GuardApiSettings,
    semantic_provider=None,
) -> tuple[EvaluationService, V21PipelineService]:
    state_service = SecurityStateService(store)
    policy_service = PolicyService(store=store)
    pipeline = V21PipelineService(
        settings=settings,
        store=store,
        state_service=state_service,
        policy_service=policy_service,
        semantic_provider=semantic_provider,
    )
    shadow = V21ShadowService(
        settings=settings, store=store, state_service=state_service
    )
    evaluation = EvaluationService(
        policy_service=policy_service,
        audit_service=AuditService(store=store),
        approval_service=ApprovalService(store=store, settings=settings),
        v21_shadow_service=shadow,
        v21_pipeline=pipeline,
    )
    return evaluation, pipeline


def _envelope_payload(envelope: dict) -> dict:
    """取 decision_v21 信封 payload（断言 01 §28 信封形状）。"""

    if set(envelope) == {"decision_v21"}:
        inner = envelope["decision_v21"]
    else:
        inner = envelope
    assert set(inner) == {"schema_version", "payload"}
    assert inner["schema_version"] == "2.1"
    return inner["payload"]


def _normalized_decision_dump(decision) -> dict:
    """剔除随机/实例相关字段后的 legacy 决策 dump（官方语义逐字可比）。

    legacy ``build_guard_decision`` 的 ``decision_id`` 含 uuid 分量、
    ``latency_ms`` 为 wall-clock，均不参与跨实例逐字对照（仿
    test_v21_09_pipeline 的 ``_normalized_response_dump`` 口径）。
    """

    dump = decision.model_dump(mode="json")
    dump.pop("decision_id", None)
    dump.pop("latency_ms", None)
    return dump


def _defer_assessment() -> tuple[GuardEvent, FastAssessment]:
    """Phase A 真实产物：DEFER 评估（provider 单测的被测输入）。"""

    pipeline, store = _pipeline_service()
    _commit_task_fact(store)
    event = _event()
    materials = pipeline.run_phase_a(event)
    assert materials is not None and materials.snapshot is not None
    assert materials.assessment.disposition == "DEFER"
    return event, materials.assessment


# ---------------------------------------------------------------------------
# fake judgment 构造器（仿 test_v21_09_revalidation.py::_judgment）
# ---------------------------------------------------------------------------


def _fake_bound_judgment(
    event: GuardEvent, assessment: FastAssessment, **overrides
) -> SemanticJudgment:
    """五 digest 与 assessment 全等的确定性 judgment（overrides 可漂移
    binding 字段；digest/judgment_id 按 HttpSemanticJudge 同口径派生）。"""

    fields: dict[str, object] = {
        "schema_version": "2.1",
        "verdict": "aligned",
        "reported_confidence": "high",
        "reason_codes": ["v21-13:fake:aligned"],
        "evidence_refs": [],
        "assessment_digest": assessment.assessment_digest,
        "authorization_fingerprint": assessment.authorization_fingerprint,
        "task_digest": assessment.task_digest,
        "policy_digest": assessment.policy_digest,
        "snapshot_digest": assessment.snapshot_digest,
        "provider": "provider-fake",
        "model": "model-fake",
        "prompt_version": PROMPT_VERSION,
        "degraded": False,
    }
    fields.update(overrides)
    semantic_digest = canonical_sha256(
        {
            name: fields[name]
            for name in sorted(SemanticJudgment.digest_fields())
        }
    )
    identity = {
        "assessment_digest": fields["assessment_digest"],
        "assessment_id": assessment.assessment_id,
        "authorization_fingerprint": fields["authorization_fingerprint"],
        "model": fields["model"],
        "policy_digest": fields["policy_digest"],
        "prompt_version": fields["prompt_version"],
        "provider": fields["provider"],
        "reason_codes": fields["reason_codes"],
        "reported_confidence": fields["reported_confidence"],
        "snapshot_digest": fields["snapshot_digest"],
        "task_digest": fields["task_digest"],
        "verdict": fields["verdict"],
    }
    # expires_at / created_at 不入 digest 白名单与身份投影，override
    # 只影响 reference_time 过期判定（评审 W4 依赖此口径）。
    expires_at = fields.pop(
        "expires_at", "2026-08-15T01:00:00+00:00"
    )
    return SemanticJudgment(
        judgment_id="judg:" + canonical_sha256(identity),
        created_at=event.timestamp,
        expires_at=expires_at,
        semantic_digest=semantic_digest,
        **fields,
    )


class _FakeSemanticProvider:
    """确定性 fake provider（可直接以 Callable 形态接线）。"""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, event: GuardEvent, assessment: FastAssessment):
        self.calls += 1
        if assessment.disposition != "DEFER":
            return None
        return _fake_bound_judgment(event, assessment)


class _RaisingSemanticProvider:
    def __call__(self, event, assessment):
        raise RuntimeError("semantic backend exploded")


# ---------------------------------------------------------------------------
# httpx 注入工厂（provider 单测）
# ---------------------------------------------------------------------------

_VALID_LLM_JSON = json.dumps(
    {
        "verdict": "aligned",
        "reported_confidence": "high",
        "reason_codes": ["v21-13:task_alignment:aligned"],
    }
)


def _judge_client(
    *,
    content: str | None = _VALID_LLM_JSON,
    status_code: int = 200,
    raw_body: bytes | None = None,
    raise_exc: Exception | None = None,
    calls: list | None = None,
) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if raise_exc is not None:
            raise raise_exc
        if raw_body is not None:
            return httpx.Response(
                status_code,
                content=raw_body,
                headers={"content-type": "application/json"},
            )
        assert content is not None
        return httpx.Response(
            status_code,
            json={"choices": [{"message": {"content": content}}]},
        )

    return httpx.Client(transport=httpx.MockTransport(handler))


def _judge(
    client: httpx.Client | None,
    *,
    sample_rate: float = 1.0,
    ttl_seconds: float = 300.0,
) -> HttpSemanticJudge:
    return HttpSemanticJudge(
        base_url="https://judge.test/v1",
        api_key="test-key",
        model="model-x",
        timeout_seconds=3.0,
        ttl_seconds=ttl_seconds,
        sample_rate=sample_rate,
        client=client,
    )


# ---------------------------------------------------------------------------
# 1. Provider 单测
# ---------------------------------------------------------------------------


def test_provider_valid_response_builds_full_judgment() -> None:
    event, assessment = _defer_assessment()
    calls: list[httpx.Request] = []
    judge = _judge(_judge_client(calls=calls))

    judgment = judge.judge(event, assessment)

    assert judgment is not None
    assert len(calls) == 1
    # 五 digest binding 与 assessment 全等（03 §12 锚点）。
    assert judgment.assessment_digest == assessment.assessment_digest
    assert (
        judgment.authorization_fingerprint
        == assessment.authorization_fingerprint
    )
    assert judgment.task_digest == assessment.task_digest
    assert judgment.policy_digest == assessment.policy_digest
    assert judgment.snapshot_digest == assessment.snapshot_digest
    # 三态 verdict + 自报等级 + provider 元信息。
    assert judgment.verdict == "aligned"
    assert judgment.reported_confidence == "high"
    assert judgment.reason_codes == ["v21-13:task_alignment:aligned"]
    assert judgment.provider == PROVIDER_NAME
    assert judgment.model == "model-x"
    assert judgment.prompt_version == PROMPT_VERSION
    assert judgment.degraded is False
    # created_at 锚定 event.timestamp；expires_at = 基准 + ttl。
    assert judgment.created_at == event.timestamp
    assert judgment.expires_at == "2026-08-15T00:05:00+00:00"
    # 请求形状：temperature=0 + json_object（system prompt 无 allow/deny）。
    body = json.loads(calls[0].content)
    assert body["temperature"] == 0
    assert body["response_format"] == {"type": "json_object"}
    assert body["model"] == "model-x"
    assert calls[0].url.path.endswith("/chat/completions")


def test_system_prompt_forbids_allow_deny_semantics() -> None:
    lowered = _SYSTEM_PROMPT_V1.lower()
    assert "allow" not in lowered
    assert "deny" not in lowered


@pytest.mark.parametrize(
    "client",
    [
        _judge_client(status_code=500),
        _judge_client(raise_exc=httpx.ReadTimeout("hard deadline")),
        _judge_client(content="not-json"),
        _judge_client(raw_body=b"{broken"),
        _judge_client(
            content=json.dumps(
                {
                    "verdict": "allow",
                    "reported_confidence": "high",
                    "reason_codes": [],
                }
            )
        ),
        _judge_client(
            content=json.dumps(
                {
                    "verdict": "aligned",
                    "reported_confidence": "certain",
                    "reason_codes": [],
                }
            )
        ),
        _judge_client(content=json.dumps({"verdict": "aligned"})),
        _judge_client(content=json.dumps([1, 2, 3])),
        # 评审 M3：reason_codes 无界硬上限（超限/单条过长 fail-closed）。
        _judge_client(
            content=json.dumps(
                {
                    "verdict": "aligned",
                    "reported_confidence": "high",
                    "reason_codes": [f"code_{index}" for index in range(9)],
                }
            )
        ),
        _judge_client(
            content=json.dumps(
                {
                    "verdict": "aligned",
                    "reported_confidence": "high",
                    "reason_codes": ["x" * 65],
                }
            )
        ),
    ],
    ids=[
        "http_500",
        "timeout",
        "bad_json_content",
        "broken_body",
        "verdict_allow",
        "confidence_out_of_range",
        "missing_confidence",
        "non_object_json",
        "reason_codes_over_limit",
        "reason_code_too_long",
    ],
)
def test_provider_fail_closed_returns_none(client) -> None:
    event, assessment = _defer_assessment()
    assert _judge(client).judge(event, assessment) is None


def test_provider_reason_codes_boundary_is_accepted() -> None:
    """评审 M3 边界：8 条×64 字符恰好可接受（硬上限为严格大于）。"""

    event, assessment = _defer_assessment()
    codes = [f"code_{index}" + "x" * (59 - len(str(index))) for index in range(8)]
    assert all(len(code) == 64 for code in codes)
    judgment = _judge(
        _judge_client(
            content=json.dumps(
                {
                    "verdict": "aligned",
                    "reported_confidence": "high",
                    "reason_codes": codes,
                }
            )
        )
    ).judge(event, assessment)
    assert judgment is not None
    assert judgment.reason_codes == codes


def test_provider_close_only_when_owns_client() -> None:
    """评审 M2：close() 仅在 owns client（未注入外部 client）时关闭；
    main.py lifespan shutdown 调用它收拢共享连接池。注入式 client 不受
    影响；自有 client 关闭后 judge 收敛为 None（fail-closed）。"""

    event, assessment = _defer_assessment()
    injected = _judge(_judge_client())
    injected.close()
    assert injected.judge(event, assessment) is not None

    owned = HttpSemanticJudge(
        base_url="https://judge.test/v1",
        api_key="test-key",
        model="model-x",
        timeout_seconds=3.0,
        ttl_seconds=300.0,
    )
    owned.close()
    assert owned.judge(event, assessment) is None


# ---------------------------------------------------------------------------
# 2. 确定性派生（禁 uuid）
# ---------------------------------------------------------------------------


def test_provider_same_input_same_identity_and_digest() -> None:
    event, assessment = _defer_assessment()
    first = _judge(_judge_client()).judge(event, assessment)
    second = _judge(_judge_client()).judge(event, assessment)
    assert first is not None and second is not None
    assert first.judgment_id == second.judgment_id
    assert first.semantic_digest == second.semantic_digest
    assert first == second


def test_judgment_identity_shape_is_deterministic_not_uuid() -> None:
    event, assessment = _defer_assessment()
    judgment = _judge(_judge_client()).judge(event, assessment)
    assert judgment is not None
    assert judgment.judgment_id.startswith("judg:sha256:")
    assert judgment.semantic_digest.startswith("sha256:")
    hex_part = judgment.judgment_id.split(":", 2)[2]
    assert len(hex_part) == 64
    int(hex_part, 16)  # 纯 hex，非 uuid 形态。


def test_time_and_identity_fields_do_not_enter_semantic_digest() -> None:
    event, assessment = _defer_assessment()
    judgment = _judge(_judge_client()).judge(event, assessment)
    assert judgment is not None

    def _whitelist_digest(source: SemanticJudgment) -> str:
        dump = source.model_dump(mode="json")
        return canonical_sha256(
            {
                name: dump[name]
                for name in sorted(SemanticJudgment.digest_fields())
            }
        )

    # semantic_digest 即白名单投影摘要（自洽）。
    assert _whitelist_digest(judgment) == judgment.semantic_digest
    # 人为漂移 created_at/expires_at/judgment_id 不影响 semantic_digest。
    altered = judgment.model_copy(
        update={
            "created_at": "2030-01-01T00:00:00+00:00",
            "expires_at": "2030-01-01T01:00:00+00:00",
            "judgment_id": "judg:sha256:" + "00" * 32,
        }
    )
    assert _whitelist_digest(altered) == judgment.semantic_digest


# ---------------------------------------------------------------------------
# 3. 门控：DEFER-only + 确定性采样
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("disposition", ["CLEAR_ALLOW", "CLEAR_DENY"])
def test_non_defer_disposition_makes_zero_http_calls(disposition) -> None:
    event, assessment = _defer_assessment()
    gated = assessment.model_copy(update={"disposition": disposition})
    calls: list[httpx.Request] = []
    judge = _judge(_judge_client(calls=calls))
    assert judge.judge(event, gated) is None
    assert calls == []


def test_sample_rate_zero_makes_zero_http_calls() -> None:
    event, assessment = _defer_assessment()
    calls: list[httpx.Request] = []
    judge = _judge(_judge_client(calls=calls), sample_rate=0.0)
    assert judge.judge(event, assessment) is None
    assert calls == []


def test_sampling_is_deterministic_on_replay() -> None:
    event, assessment = _defer_assessment()
    results = [
        _judge(_judge_client(), sample_rate=0.5).judge(event, assessment)
        for _ in range(5)
    ]
    # 同 assessment_digest 重放采样结果恒定（全 None 或全在场）。
    assert all(result is None for result in results) or all(
        result is not None for result in results
    )


# ---------------------------------------------------------------------------
# 4. Pipeline 钩子
# ---------------------------------------------------------------------------


def test_pipeline_hook_captures_provider_judgment() -> None:
    provider = _FakeSemanticProvider()
    pipeline, store = _pipeline_service(semantic_provider=provider)
    _commit_task_fact(store)
    materials = pipeline.run_phase_a(_event())
    assert materials is not None
    assert provider.calls == 1
    assert materials.semantic_judgment is not None
    assert (
        materials.semantic_judgment.assessment_digest
        == materials.assessment.assessment_digest
    )


def test_pipeline_hook_swallows_provider_exception() -> None:
    baseline_pipeline, baseline_store = _pipeline_service()
    _commit_task_fact(baseline_store)
    baseline = baseline_pipeline.run_phase_a(_event())
    assert baseline is not None

    pipeline, store = _pipeline_service(
        semantic_provider=_RaisingSemanticProvider()
    )
    _commit_task_fact(store)
    materials = pipeline.run_phase_a(_event())

    # Phase A 不回退：materials 照常、judgment 收敛为 None、官方决策
    # 与无 provider 基线逐字节一致。
    assert materials is not None
    assert materials.semantic_judgment is None
    assert _normalized_decision_dump(
        materials.decision
    ) == _normalized_decision_dump(baseline.decision)


def test_pipeline_hook_zero_provider_calls_on_snapshot_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """评审 W3：snapshot 读取失败（缺态/component_failure）时门控生效
    ——provider 零调用、judgment 恒 None（仿 test_v21_09_pipeline 的
    REASON_SNAPSHOT_READ_FAILED 故障注入 fixture）。"""

    provider = _FakeSemanticProvider()
    pipeline, store = _pipeline_service(semantic_provider=provider)
    _commit_task_fact(store)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated snapshot read failure")

    monkeypatch.setattr(
        SecurityStateService, "read_snapshot_with_revoked", _boom
    )
    materials = pipeline.run_phase_a(_event())
    assert materials is not None
    assert materials.degraded_kind == "component_failure"
    assert materials.snapshot is None
    assert provider.calls == 0
    assert materials.semantic_judgment is None


def test_pipeline_without_provider_is_byte_identical_to_baseline() -> None:
    """评审 N2 澄清：此处「逐字节基线」是新代码自对照（确定性回归：
    provider=None 接线 vs 默认无 provider 接线的同构栈对照），不是改
    动前的历史冻结快照；真正的改动前冻结锚点由 test_v21_09_* 系列
    （既有四段式守门测试）承担。"""

    event = _event()

    baseline_pipeline, baseline_store = _pipeline_service()
    _commit_task_fact(baseline_store)
    baseline_materials = baseline_pipeline.run_phase_a(event)
    baseline_outcome = baseline_pipeline.build_phase_b(
        event, baseline_materials
    )

    pipeline, store = _pipeline_service(semantic_provider=None)
    _commit_task_fact(store)
    materials = pipeline.run_phase_a(event)
    outcome = pipeline.build_phase_b(event, materials)

    assert baseline_materials is not None and materials is not None
    assert materials.semantic_judgment is None
    assert _normalized_decision_dump(
        materials.decision
    ) == _normalized_decision_dump(baseline_materials.decision)
    assert baseline_outcome is not None and outcome is not None
    assert outcome.semantic_binding_valid is None
    assert outcome.envelope == baseline_outcome.envelope


# ---------------------------------------------------------------------------
# 5. Phase B 信封：双门禁填槽（binding valid 才登记）
# ---------------------------------------------------------------------------


def test_phase_b_envelope_fills_semantic_slots_when_binding_valid() -> None:
    provider = _FakeSemanticProvider()
    pipeline, store = _pipeline_service(semantic_provider=provider)
    _commit_task_fact(store)
    event = _event()
    materials = pipeline.run_phase_a(event)
    assert materials is not None and materials.semantic_judgment is not None

    outcome = pipeline.build_phase_b(event, materials)
    assert outcome is not None and outcome.revalidation.status == "valid"
    assert outcome.semantic_binding_valid is True

    payload = _envelope_payload(outcome.envelope)
    judgment = materials.semantic_judgment
    assert payload["semantic_judgment_id"] == judgment.judgment_id
    assert payload["semantic_digest"] == judgment.semantic_digest
    # 03 §11 shadow：信封 final_decision 恒 legacy 官方决策；V21
    # finalize（DEFER）恒 ask——judgment 在场不改变任何决策面。
    assert payload["final_decision"] == materials.decision.decision
    assert payload["v21_fast_disposition"] == "DEFER"
    assert outcome.raw_v21_decision is not None
    assert outcome.raw_v21_decision.decision == "ask"


@pytest.mark.parametrize(
    "binding_field",
    [
        "assessment_digest",
        "authorization_fingerprint",
        "task_digest",
        "policy_digest",
        "snapshot_digest",
    ],
)
def test_phase_b_envelope_rejects_drifted_binding(binding_field) -> None:
    class _DriftedProvider:
        def __call__(self, event, assessment):
            return _fake_bound_judgment(
                event,
                assessment,
                **{binding_field: "sha256:" + "f0" * 32},
            )

    pipeline, store = _pipeline_service(semantic_provider=_DriftedProvider())
    _commit_task_fact(store)
    event = _event()
    materials = pipeline.run_phase_a(event)
    assert materials is not None and materials.semantic_judgment is not None

    outcome = pipeline.build_phase_b(event, materials)
    assert outcome is not None and outcome.revalidation.status == "valid"
    assert outcome.semantic_binding_valid is False
    payload = _envelope_payload(outcome.envelope)
    # 双槽恒 None（fail-closed）；信封 final_decision 恒 legacy 官方
    # 决策，V21 finalize（DEFER）恒 ask。
    assert payload["semantic_judgment_id"] is None
    assert payload["semantic_digest"] is None
    assert payload["final_decision"] == materials.decision.decision
    assert outcome.raw_v21_decision is not None
    assert outcome.raw_v21_decision.decision == "ask"


def test_phase_b_stale_revalidation_blocks_semantic_slots() -> None:
    """评审 W1：双门禁 stale 半支——binding valid 但 revalidation
    stale（事务内 state_version 漂移，仿 test_v21_09_pipeline 的
    ``test_pipeline_phase_b_stale_state_version`` 构造手法）→ 信封
    semantic 双槽恒 None、final decision 不变（fail-closed）。"""

    provider = _FakeSemanticProvider()
    pipeline, store = _pipeline_service(semantic_provider=provider)
    _commit_task_fact(store)
    event = _event()
    materials = pipeline.run_phase_a(event)
    assert materials is not None
    assert materials.semantic_judgment is not None
    assert materials.scope_digest is not None

    # Phase A→B 窗口内 state version 推进 → revalidation stale。
    record = store.get_security_state(materials.scope_digest)
    assert record is not None
    state = OnlineSecurityState.model_validate(record.canonical_payload)
    bumped = state.model_copy(
        update={"state_version": record.state_version + 1}
    )
    assert store.cas_security_state(
        materials.scope_digest,
        record.state_version,
        SecurityStateRecord(
            scope_digest=materials.scope_digest,
            state_version=record.state_version + 1,
            canonical_payload=bumped.model_dump(mode="json"),
            dirty=False,
            dirty_domains=[],
            projector_version=PROJECTOR_VERSION,
            updated_at=utc_now_iso(),
        ),
    )

    outcome = pipeline.build_phase_b(event, materials)
    assert outcome is not None
    assert outcome.revalidation.status == "stale"
    # binding 本身有效（五 digest 全等），但 stale 半支同样不登记。
    assert outcome.semantic_binding_valid is True
    payload = _envelope_payload(outcome.envelope)
    assert payload["semantic_judgment_id"] is None
    assert payload["semantic_digest"] is None
    # final decision 不变：信封恒 legacy 官方决策、finalize 恒 ask。
    assert payload["final_decision"] == materials.decision.decision
    assert outcome.raw_v21_decision is None


def test_phase_b_expired_judgment_rejects_binding() -> None:
    """评审 W4：``validate_semantic_binding`` reference_time 分支——
    expires_at 早于 materials.clock.evaluated_at → binding invalid，
    信封双槽恒 None（fail-closed）。"""

    class _ExpiredProvider:
        def __call__(self, event, assessment):
            return _fake_bound_judgment(
                event,
                assessment,
                # 早于 fixture 事件时间戳（即 clock.evaluated_at）。
                expires_at="2026-08-14T23:00:00+00:00",
            )

    pipeline, store = _pipeline_service(semantic_provider=_ExpiredProvider())
    _commit_task_fact(store)
    event = _event()
    materials = pipeline.run_phase_a(event)
    assert materials is not None and materials.semantic_judgment is not None

    outcome = pipeline.build_phase_b(event, materials)
    assert outcome is not None and outcome.revalidation.status == "valid"
    assert outcome.semantic_binding_valid is False
    payload = _envelope_payload(outcome.envelope)
    assert payload["semantic_judgment_id"] is None
    assert payload["semantic_digest"] is None
    assert payload["final_decision"] == materials.decision.decision


def test_phase_b_envelope_rest_byte_identical_to_baseline() -> None:
    """评审 N2 澄清：同 ``test_pipeline_without_provider_is_byte_
    identical_to_baseline``，基线为同构栈的新代码自对照（确定性回归），
    改动前冻结锚点由 test_v21_09_* 系列承担。"""

    event = _event()

    baseline_pipeline, baseline_store = _pipeline_service()
    _commit_task_fact(baseline_store)
    baseline_materials = baseline_pipeline.run_phase_a(event)
    baseline_outcome = baseline_pipeline.build_phase_b(
        event, baseline_materials
    )

    pipeline, store = _pipeline_service(semantic_provider=_FakeSemanticProvider())
    _commit_task_fact(store)
    materials = pipeline.run_phase_a(event)
    outcome = pipeline.build_phase_b(event, materials)

    assert baseline_outcome is not None and outcome is not None
    baseline_payload = _envelope_payload(baseline_outcome.envelope)
    payload = _envelope_payload(outcome.envelope)
    # 仅 semantic 两槽差异；其余键逐字节一致。
    assert payload.pop("semantic_judgment_id") is not None
    assert payload.pop("semantic_digest") is not None
    assert baseline_payload.pop("semantic_judgment_id") is None
    assert baseline_payload.pop("semantic_digest") is None
    assert payload == baseline_payload


# ---------------------------------------------------------------------------
# 6. e2e 审计 metadata 承载
# ---------------------------------------------------------------------------


def _e2e_metadata(*, semantic_provider=None) -> dict:
    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, _ = _evaluation_stack(
        store,
        settings=_pipeline_settings(),
        semantic_provider=semantic_provider,
    )
    event = _event(
        event_id="evt_e2e_semantic",
        call_id="call_e2e_semantic",
    )
    evaluation_service.evaluate(event, requesting_principal_id="principal_a")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    return dict(audit.metadata)


def test_e2e_metadata_carries_semantic_keys_when_judgment_present() -> None:
    metadata = _e2e_metadata(semantic_provider=_FakeSemanticProvider())
    for key in _SEMANTIC_METADATA_KEYS:
        assert key in metadata
    assert metadata["v21_semantic_judgment_id"].startswith("judg:sha256:")
    assert metadata["v21_semantic_digest"].startswith("sha256:")
    assert metadata["v21_semantic_verdict"] == "aligned"
    assert metadata["v21_semantic_degraded"] is False
    assert metadata["v21_semantic_binding_valid"] is True
    # 评审 M3：全文键有意不在场——redaction 会改写全文（与 digest
    # 永久失配），shadow 初版只落五个确定性引用（D11 口径）。
    assert _SEMANTIC_FULLTEXT_KEY not in metadata
    # 既有同源键不受影响。
    assert "request_digest" in metadata and "policy_digest" in metadata


def test_e2e_metadata_replay_is_deterministic() -> None:
    first = _e2e_metadata(semantic_provider=_FakeSemanticProvider())
    second = _e2e_metadata(semantic_provider=_FakeSemanticProvider())
    assert (
        first["v21_semantic_judgment_id"]
        == second["v21_semantic_judgment_id"]
    )
    assert first["v21_semantic_digest"] == second["v21_semantic_digest"]
    for key in _SEMANTIC_METADATA_KEYS:
        assert first[key] == second[key]


def test_e2e_metadata_keyset_byte_identical_without_judgment() -> None:
    """judgment 缺席时键集逐字节不变：与 provider 在场运行对照，
    差异仅限五个 semantic 引用键（既有 D11 finalize 键不受影响）。

    注：pipeline enabled 的 valid 路径本就携带 D11 ``v21_final_*``
    键（既有行为），故基线取同构 pipeline 栈的 provider 缺席运行，
    而非无 pipeline 注入栈。

    评审 N2 澄清：此为同构栈新代码自对照（确定性回归），改动前冻结
    锚点由 test_v21_09_* 系列承担。
    """

    with_provider = _e2e_metadata(semantic_provider=_FakeSemanticProvider())
    without_provider = _e2e_metadata(semantic_provider=None)

    for key in _SEMANTIC_METADATA_KEYS:
        assert key not in without_provider
        assert key in with_provider
    assert _SEMANTIC_FULLTEXT_KEY not in with_provider

    # 剔除五个 semantic 引用键后，两次运行的 metadata 逐字节一致。
    stripped = {
        key: value
        for key, value in with_provider.items()
        if key not in _SEMANTIC_METADATA_KEYS
    }
    assert without_provider == stripped
    # 既有同源键不受影响。
    assert "request_digest" in without_provider
    assert "policy_digest" in without_provider


def test_e2e_metadata_flag_off_keyset_matches_pre_wiring_baseline() -> None:
    """V2 mode off（provider 自然 None）时与无 pipeline 注入基线
    逐字节一致（仿 test_v21_09_pipeline 的 flag-off 冻结测试）。"""

    event = _event(
        event_id="evt_semantic_flag_off",
        call_id="call_semantic_flag_off",
    )
    settings = _pipeline_settings(enabled=False)

    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    evaluation_service, pipeline = _evaluation_stack(
        store,
        settings=settings,
        semantic_provider=semantic_provider_from_settings(settings),
    )
    assert pipeline.enabled is False
    evaluation_service.evaluate(event, requesting_principal_id="principal_a")
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    for key in _SEMANTIC_METADATA_KEYS:
        assert key not in audit.metadata

    baseline_store = MemoryControlPlaneStore()
    _commit_task_fact(baseline_store)
    baseline_service = EvaluationService(
        policy_service=PolicyService(store=baseline_store),
        audit_service=AuditService(store=baseline_store),
        approval_service=ApprovalService(
            store=baseline_store, settings=settings
        ),
    )
    baseline_service.evaluate(event, requesting_principal_id="principal_a")
    baseline_audit = baseline_store.get_policy_evaluation_by_event_id(
        event.event_id
    )
    assert baseline_audit is not None
    assert audit.metadata == baseline_audit.metadata


# ---------------------------------------------------------------------------
# 7. Settings
# ---------------------------------------------------------------------------


def test_semantic_settings_default_off() -> None:
    settings = GuardApiSettings()
    assert settings.v21_semantic_enabled is False
    assert settings.v21_semantic_configured() is False
    assert semantic_provider_from_settings(settings) is None


def test_semantic_settings_configured_requires_key_and_model() -> None:
    base = {
        "v21_semantic_enabled": True,
        "v21_semantic_api_key": "sk-test",
        "v21_semantic_model": "model-x",
        # N1 门控后需显式给出非 off mode（默认 v21_mode=off → None）。
        "v21_mode": "shadow",
    }
    assert GuardApiSettings(**base).v21_semantic_configured() is True
    provider = semantic_provider_from_settings(GuardApiSettings(**base))
    assert provider is not None
    assert provider.model == "model-x"

    for missing in ("v21_semantic_api_key", "v21_semantic_model"):
        partial = {key: value for key, value in base.items() if key != missing}
        assert GuardApiSettings(**partial).v21_semantic_configured() is False
        assert semantic_provider_from_settings(GuardApiSettings(**partial)) is None
    disabled = dict(base, v21_semantic_enabled=False)
    assert semantic_provider_from_settings(GuardApiSettings(**disabled)) is None


@pytest.mark.parametrize(
    ("overrides", "needle"),
    [
        (
            {"v21_semantic_timeout_seconds": 0.0},
            "AGENTGUARD_V21_SEMANTIC_TIMEOUT_SECONDS",
        ),
        (
            {"v21_semantic_timeout_seconds": -1.0},
            "AGENTGUARD_V21_SEMANTIC_TIMEOUT_SECONDS",
        ),
        (
            {"v21_semantic_ttl_seconds": 0.0},
            "AGENTGUARD_V21_SEMANTIC_TTL_SECONDS",
        ),
        (
            {"v21_semantic_sample_rate": 1.5},
            "AGENTGUARD_V21_SEMANTIC_SAMPLE_RATE",
        ),
        (
            {"v21_semantic_sample_rate": -0.1},
            "AGENTGUARD_V21_SEMANTIC_SAMPLE_RATE",
        ),
        # 评审 M1：NaN/inf 前置拦截（NaN 比较恒 False、inf 通过 > 0）。
        (
            {"v21_semantic_timeout_seconds": float("nan")},
            "AGENTGUARD_V21_SEMANTIC_TIMEOUT_SECONDS",
        ),
        (
            {"v21_semantic_timeout_seconds": float("inf")},
            "AGENTGUARD_V21_SEMANTIC_TIMEOUT_SECONDS",
        ),
        (
            {"v21_semantic_ttl_seconds": float("nan")},
            "AGENTGUARD_V21_SEMANTIC_TTL_SECONDS",
        ),
        (
            {"v21_semantic_ttl_seconds": float("inf")},
            "AGENTGUARD_V21_SEMANTIC_TTL_SECONDS",
        ),
        (
            {"v21_semantic_sample_rate": float("nan")},
            "AGENTGUARD_V21_SEMANTIC_SAMPLE_RATE",
        ),
        (
            {"v21_semantic_sample_rate": float("inf")},
            "AGENTGUARD_V21_SEMANTIC_SAMPLE_RATE",
        ),
    ],
)
def test_semantic_settings_startup_validation(overrides, needle) -> None:
    settings = GuardApiSettings(**overrides)
    with pytest.raises(GuardApiConfigurationError) as excinfo:
        settings.validate_for_startup()
    assert needle in str(excinfo.value)


def test_semantic_settings_boundary_values_pass_startup() -> None:
    for rate in (0.0, 0.5, 1.0):
        GuardApiSettings(
            v21_semantic_sample_rate=rate
        ).validate_for_startup()


def test_semantic_provider_mode_off_returns_none() -> None:
    """评审 N1：v21_mode=off 时不构造 provider（避免空建 httpx
    连接池）；同配置下 shadow mode 在场对照。"""

    configured = {
        "v21_semantic_enabled": True,
        "v21_semantic_api_key": "sk-test",
        "v21_semantic_model": "model-x",
    }
    off = GuardApiSettings(v21_mode="off", **configured)
    assert semantic_provider_from_settings(off) is None
    shadow = GuardApiSettings(v21_mode="shadow", **configured)
    provider = semantic_provider_from_settings(shadow)
    assert provider is not None
    provider.close()


# ---------------------------------------------------------------------------
# 8. competition selection 重建信封不透传 semantic（评审 W2）
# ---------------------------------------------------------------------------


def _active_settings() -> GuardApiSettings:
    return GuardApiSettings(
        control_token="control-secret",
        storage_backend="memory",
        v21_mode="active",
        v21_shadow_server_secret=_TEST_SECRET,
        rte05_strong_binding_enabled=True,
    )


def _competition_activation(
    policy_digest: str,
) -> FrozenCompetitionActivation:
    """仿 test_lgv2_api_official 的 frozen activation 构造。"""

    manifest = build_competition_activation_manifest(
        server_secret=base64.urlsafe_b64decode(_TEST_SECRET),
        principal_id="principal_a",
        agent_id="main",
        runtime_binding_id="binding:principal_a",
        policy_digest=policy_digest,
        dataset_digest="sha256:" + "d" * 64,
        profile_digest="sha256:" + "e" * 64,
        selection_basis="profile_all",
    )
    return FrozenCompetitionActivation(
        manifest=manifest,
        source_path="/process/frozen/activation.json",
        content_digest=canonical_sha256(manifest.model_dump(mode="json")),
    )


def _active_auth() -> AuthContext:
    return AuthContext(
        principal_type="component",
        principal_id="principal_a",
        role="adapter",
        scopes=["event:evaluate"],
        auth_method="bearer",
        runtime="langgraph",
        agent_id="main",
    )


def test_competition_rebuilt_envelope_omits_semantic_slots() -> None:
    """评审 W2 freeze 断言：competition selection 在场且 judgment 在场
    时，重建信封有意不携带 semantic 槽（重建路径不复算 binding，
    宁缺勿滥），而审计 metadata 五个引用键在场；全文键恒不在场。

    构造方式：直接驱动 active 栈真实 selection 分支（仿
    test_lgv2_api_official 的 ``_stack`` 范式），不 monkeypatch
    选择器，保证断言锁定的是真实重建调用点。
    """

    settings = _active_settings()
    store = MemoryControlPlaneStore()
    _commit_task_fact(store)
    state_service = SecurityStateService(store)
    policy_service = PolicyService(store=store)
    activation = _competition_activation(
        canonical_sha256(policy_service.current_snapshot().model_dump(mode="json"))
    )
    pipeline = V21PipelineService(
        settings=settings,
        store=store,
        state_service=state_service,
        policy_service=policy_service,
        semantic_provider=_FakeSemanticProvider(),
    )
    evaluation = EvaluationService(
        policy_service=policy_service,
        audit_service=AuditService(store=store),
        approval_service=ApprovalService(store=store, settings=settings),
        v21_shadow_service=V21ShadowService(
            settings=settings, store=store, state_service=state_service
        ),
        v21_pipeline=pipeline,
        competition_activation=activation,
    )
    event = _event(
        event_id="evt_w2_competition",
        call_id="call_w2_competition",
    )

    response = evaluation.evaluate(event, auth_context=_active_auth())
    # 前置：competition selection 真实在场（否则未走到重建分支）。
    assert response.decision_authority is not None
    assert response.decision_authority.source == "v21"

    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    # judgment 在场：metadata 五个引用键在场，全文键恒不在场（M3）。
    for key in _SEMANTIC_METADATA_KEYS:
        assert key in audit.metadata
    assert _SEMANTIC_FULLTEXT_KEY not in audit.metadata
    # competition 重建信封：semantic 双槽恒 None（fail-closed 冻结）。
    assert audit.evidence is not None
    rebuilt_payload = audit.evidence["decision_v21"]["payload"]
    assert rebuilt_payload["semantic_judgment_id"] is None
    assert rebuilt_payload["semantic_digest"] is None
