#!/usr/bin/env python3
"""V21-13 Stage 1 shadow semantic 接入开销 smoke（04 §21 latency delta 门禁证据）。

口径声明：**机器结果非跨环境硬 SLO，CI 只校验工具正确性（05 §9）**；
本次为缩减 smoke 口径（A/B/C 预热 10 测 100，D 档预热 3 测 30，memory
后端，单进程直调 EvaluationService——与 CT-PR-03b smoke 先例同口径）。

四档对照（恒定项：V21 shadow pipeline 启用，即 v21_mode=shadow +
v21_shadow_server_secret 在场，栈构造与 tests/test_v21_09_pipeline.py
同口径；backend=memory；sample_rate 默认 1.0）：

- A ``a_off``：semantic flag off → ``semantic_provider_from_settings``
  返回 None（基线）。
- B ``b_flag_on_unconfigured``：flag on 但缺 api_key/model → provider
  仍恒 None（证明配置门控零开销，应与 A 逐位一致）。
- C ``c_fake_provider``：构造栈时直接注入确定性 in-process fake
  callable（产出五 digest 全等的合法 judgment，仿
  tests/test_v21_13_semantic_shadow.py 的 fixture），测量纯进程内净
  增量（judgment 产出 + validate_semantic_binding 比对 + 证据槽填充
  + metadata 写入）。
- D ``d_unreachable_endpoint``：flag on + configured，真实
  ``HttpSemanticJudge`` 指向不可达端点 ``http://127.0.0.1:9``（timeout
  保持默认 3.0s），测量 fail-closed 上界（连接快速拒绝路径每请求额外
  延迟）；D 档样本量缩减以免耗时，如实记录。

测量目标：evaluate 请求级（每次迭代新 event_id，走 Phase A 事务外 →
Phase B 短事务 → 审计提交全链路）。workload 为 code_execution 类
DEFER fixture（shell exec 形状工具调用 + 权威 TaskFact 在场，事件
metadata 携带 task_id trusted claim），钩子仅对 DEFER 触发；脚本内置
disposition 哨兵断言（fixture 必须 DEFER，否则测量面不成立）。

复跑：``uv run python scripts/v21-13-semantic-overhead-smoke.py``
输出：``reports/v21-13-semantic-overhead-smoke/semantic-overhead-smoke.json``

纪律：不引入新依赖；不修改任何实现/测试文件；不扩展
scripts/v21-baseline.py（其对 semantic 硬编码 not_applicable，属既有
口径，本次以独立脚本控回归面）。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import platform
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "packages" / "agentguard-core"
API_PATH = ROOT / "apps" / "guard-api"
for import_path in (ROOT, CORE_PATH, API_PATH):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from agentguard_core import GuardEvent  # noqa: E402
from agentguard_core.actions.canonical_json import canonical_sha256  # noqa: E402
from agentguard_core.authority.models import TaskFact  # noqa: E402
from agentguard_core.decisions.evidence import FastAssessment  # noqa: E402
from agentguard_core.events.payloads import (  # noqa: E402
    SecurityContext,
    ToolCallPayload,
    ToolDescriptor,
)
from agentguard_core.semantic.models import SemanticJudgment  # noqa: E402
from guard_api.security_state import SecurityStateService  # noqa: E402
from guard_api.services import (  # noqa: E402
    ApprovalService,
    AuditService,
    EvaluationService,
    PolicyService,
    V21PipelineService,
    V21ShadowService,
)
from guard_api.services.semantic import (  # noqa: E402
    PROMPT_VERSION,
    PROVIDER_NAME,
    HttpSemanticJudge,
    semantic_provider_from_settings,
)
from guard_api.settings import GuardApiSettings  # noqa: E402
from guard_api.storage.base import TaskFactRecord  # noqa: E402
from guard_api.storage.memory import MemoryControlPlaneStore  # noqa: E402

#: smoke 专用 server secret（确定性派生、仅基准工具内部使用，
#: 形态与 scripts/v21-baseline.py 的 SHADOW_BENCHMARK_SECRET 同口径）。
SMOKE_SECRET = base64.urlsafe_b64encode(
    hashlib.sha256(b"v21-13-semantic-overhead-smoke-secret").digest()
).decode("ascii")
SMOKE_TASK_ID = "task_v2113_smoke"
SMOKE_SCOPE_DIGEST = "hmac-sha256:" + "c3" * 32
SMOKE_TIMESTAMP = "2026-08-18T00:00:00+00:00"
#: D 档不可达端点（discard 端口，连接快速拒绝；timeout 保持默认 3.0s
#: 仅为 hard deadline 上界声明，实测路径为 connection refused）。
UNREACHABLE_BASE_URL = "http://127.0.0.1:9"

TIER_ORDER = (
    "a_off",
    "b_flag_on_unconfigured",
    "c_fake_provider",
    "d_unreachable_endpoint",
)


def _settings(
    *,
    semantic_enabled: bool,
    configured: bool = False,
    base_url: str = "https://judge.invalid/v1",
) -> GuardApiSettings:
    values: dict[str, object] = {
        "control_token": "control-secret",
        "storage_backend": "memory",
        "v21_mode": "shadow",
        "v21_shadow_server_secret": SMOKE_SECRET,
        "v21_semantic_enabled": semantic_enabled,
    }
    if configured:
        values["v21_semantic_api_key"] = "sk-smoke"
        values["v21_semantic_model"] = "model-smoke"
        values["v21_semantic_base_url"] = base_url
    return GuardApiSettings(**values)  # type: ignore[arg-type]


def _event(index: int) -> GuardEvent:
    """code_execution 形状 DEFER fixture（shell exec 类工具调用）。"""

    return GuardEvent(
        event_id=f"evt_semantic_smoke_{index}",
        event_type="tool_call_proposed",
        runtime="langgraph",
        trace_id="trace_semantic_smoke",
        timestamp=SMOKE_TIMESTAMP,
        security_context=SecurityContext(
            agent_id="main",
            user_task="run the project test suite locally",
        ),
        payload=ToolCallPayload(
            tool=ToolDescriptor(
                name="exec",
                category="shell",
                kind="exec",
            ),
            arguments={"command": "ls -la"},
        ),
        metadata={"task_id": SMOKE_TASK_ID},
    )


def _task_fact() -> TaskFact:
    return TaskFact(
        task_id=SMOKE_TASK_ID,
        scope_digest=SMOKE_SCOPE_DIGEST,
        scope_key_id="scope_key_smoke",
        principal_id="principal_smoke",
        task_summary="semantic overhead smoke task",
        task_digest="sha256:" + "c4" * 32,
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


class _SmokeFakeProvider:
    """确定性 in-process fake provider（仿
    tests/test_v21_13_semantic_shadow.py::_FakeSemanticProvider）：产出
    五 digest 与 assessment 全等的合法 judgment，digest/judgment_id 与
    HttpSemanticJudge 同口径派生（禁 uuid、禁 wall-clock）。"""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(
        self, event: GuardEvent, assessment: FastAssessment
    ) -> SemanticJudgment | None:
        self.calls += 1
        if assessment.disposition != "DEFER":
            return None
        fields: dict[str, Any] = {
            "schema_version": "2.1",
            "verdict": "aligned",
            "reported_confidence": "high",
            "reason_codes": ["v21-13:smoke:aligned"],
            "evidence_refs": [],
            "assessment_digest": assessment.assessment_digest,
            "authorization_fingerprint": assessment.authorization_fingerprint,
            "task_digest": assessment.task_digest,
            "policy_digest": assessment.policy_digest,
            "snapshot_digest": assessment.snapshot_digest,
            "provider": PROVIDER_NAME,
            "model": "model-smoke",
            "prompt_version": PROMPT_VERSION,
            "degraded": False,
        }
        semantic_digest = canonical_sha256(
            {
                name: fields[name]
                for name in sorted(SemanticJudgment.digest_fields())
            }
        )
        identity = dict(
            fields,
            assessment_id=assessment.assessment_id,
        )
        identity.pop("schema_version", None)
        identity.pop("evidence_refs", None)
        identity.pop("degraded", None)
        return SemanticJudgment(
            judgment_id="judg:" + canonical_sha256(identity),
            created_at=event.timestamp,
            expires_at="2026-08-18T01:00:00+00:00",
            semantic_digest=semantic_digest,
            **fields,
        )


def _build_stack(
    *,
    settings: GuardApiSettings,
    semantic_provider: Any,
) -> EvaluationService:
    store = MemoryControlPlaneStore()
    task_fact = _task_fact()
    store.create_task_fact(
        TaskFactRecord(
            task_fact=task_fact,
            canonical_payload=task_fact.model_dump(mode="json"),
            request_digest="sha256:" + "c5" * 32,
            expected_revision=0,
            created_at="2026-08-18T00:00:00Z",
        )
    )
    state_service = SecurityStateService(store)
    policy_service = PolicyService(store=store)
    pipeline = V21PipelineService(
        settings=settings,
        store=store,
        state_service=state_service,
        policy_service=policy_service,
        semantic_provider=semantic_provider,
    )
    return EvaluationService(
        policy_service=policy_service,
        audit_service=AuditService(store=store),
        approval_service=ApprovalService(store=store, settings=settings),
        v21_shadow_service=V21ShadowService(
            settings=settings, store=store, state_service=state_service
        ),
        v21_pipeline=pipeline,
    )


class _CountingHttpSemanticJudge(HttpSemanticJudge):
    """D 档调用计数封装（仅 smoke 观测用，行为与父类逐字节一致）。"""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.calls = 0

    def judge(
        self, event: GuardEvent, assessment: FastAssessment
    ) -> SemanticJudgment | None:
        self.calls += 1
        return super().judge(event, assessment)


def _tier_specs(
    d_warmup: int,
    d_iterations: int,
    warmup: int,
    iterations: int,
) -> dict[str, dict[str, Any]]:
    """四档构造：provider 一律按生产接线路径解析（A/B/D 经
    ``semantic_provider_from_settings``；C 为直接注入 fake callable，
    声明为纯进程内净增量档）。"""

    settings_a = _settings(semantic_enabled=False)
    settings_b = _settings(semantic_enabled=True, configured=False)
    settings_d = _settings(
        semantic_enabled=True,
        configured=True,
        base_url=UNREACHABLE_BASE_URL,
    )
    provider_a = semantic_provider_from_settings(settings_a)
    provider_b = semantic_provider_from_settings(settings_b)
    configured_d = semantic_provider_from_settings(settings_d)
    assert provider_a is None, "tier A provider must be None (flag off)"
    assert provider_b is None, "tier B provider must be None (unconfigured)"
    assert isinstance(
        configured_d, HttpSemanticJudge
    ), "tier D provider must be a real HttpSemanticJudge"
    configured_d.close()
    # 与生产接线同参数重建为带计数形态（仅观测，不改行为）。
    provider_d = _CountingHttpSemanticJudge(
        base_url=settings_d.v21_semantic_base_url,
        api_key=settings_d.v21_semantic_api_key or "",
        model=settings_d.v21_semantic_model or "",
        timeout_seconds=settings_d.v21_semantic_timeout_seconds,
        ttl_seconds=settings_d.v21_semantic_ttl_seconds,
        sample_rate=settings_d.v21_semantic_sample_rate,
    )
    return {
        "a_off": {
            "settings": settings_a,
            "provider": provider_a,
            "warmup": warmup,
            "iterations": iterations,
        },
        "b_flag_on_unconfigured": {
            "settings": settings_b,
            "provider": provider_b,
            "warmup": warmup,
            "iterations": iterations,
        },
        "c_fake_provider": {
            "settings": _settings(semantic_enabled=True, configured=True),
            "provider": _SmokeFakeProvider(),
            "warmup": warmup,
            "iterations": iterations,
        },
        "d_unreachable_endpoint": {
            "settings": settings_d,
            "provider": provider_d,
            "warmup": d_warmup,
            "iterations": d_iterations,
        },
    }


def _percentile(sorted_samples: list[int], percent: float) -> int:
    """nearest-rank 百分位（单调纳秒样本，不剔除异常值）。"""

    if not sorted_samples:
        raise ValueError("no samples")
    rank = max(1, math.ceil(percent * len(sorted_samples)))
    return sorted_samples[rank - 1]


def _latency_block(samples: list[int]) -> dict[str, Any]:
    ordered = sorted(samples)
    return {
        "p50_ms": _percentile(ordered, 0.50) / 1e6,
        "p95_ms": _percentile(ordered, 0.95) / 1e6,
        "p99_ms": _percentile(ordered, 0.99) / 1e6,
        "max_ms": ordered[-1] / 1e6,
        "mean_ms": sum(ordered) / len(ordered) / 1e6,
        "samples": len(ordered),
    }


def _delta_block(
    base: dict[str, Any], other: dict[str, Any]
) -> dict[str, float]:
    return {
        "delta_p50_ms": other["p50_ms"] - base["p50_ms"],
        "delta_p95_ms": other["p95_ms"] - base["p95_ms"],
        "delta_p99_ms": other["p99_ms"] - base["p99_ms"],
        "delta_max_ms": other["max_ms"] - base["max_ms"],
        "delta_mean_ms": other["mean_ms"] - base["mean_ms"],
    }


def _measure_tier(
    tier: str, spec: dict[str, Any]
) -> tuple[dict[str, Any], int]:
    evaluation = _build_stack(
        settings=spec["settings"], semantic_provider=spec["provider"]
    )
    warmup: int = spec["warmup"]
    iterations: int = spec["iterations"]
    index = 0
    for _ in range(warmup):
        evaluation.evaluate(
            _event(index), requesting_principal_id="principal_smoke"
        )
        index += 1
    # disposition 哨兵：fixture 必须 DEFER（钩子仅对 DEFER 触发，
    # 否则 C/D 档测量面不成立）。
    probe_pipeline = evaluation.v21_pipeline
    assert probe_pipeline is not None
    probe = probe_pipeline.run_phase_a(_event(index))
    assert probe is not None and probe.assessment.disposition == "DEFER", (
        f"fixture disposition must be DEFER, got "
        f"{probe.assessment.disposition if probe else None}"
    )
    samples: list[int] = []
    for _ in range(iterations):
        event = _event(index)
        start = time.perf_counter_ns()
        evaluation.evaluate(
            event, requesting_principal_id="principal_smoke"
        )
        samples.append(time.perf_counter_ns() - start)
        index += 1
    provider_calls = getattr(spec["provider"], "calls", None)
    block = _latency_block(samples)
    if provider_calls is not None:
        block["provider_calls"] = provider_calls
    print(
        f"tier {tier}: {iterations} samples measured "
        f"(warmup {warmup}, provider_calls={provider_calls})",
        flush=True,
    )
    return block, index


def main() -> int:
    parser = argparse.ArgumentParser(
        description="V21-13 semantic shadow overhead smoke (04 §21)"
    )
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument(
        "--d-warmup",
        type=int,
        default=3,
        help="tier D warmup (reduced to bound wall-clock)",
    )
    parser.add_argument(
        "--d-iterations",
        type=int,
        default=30,
        help="tier D iterations (reduced to bound wall-clock)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            ROOT
            / "reports"
            / "v21-13-semantic-overhead-smoke"
            / "semantic-overhead-smoke.json"
        ),
    )
    args = parser.parse_args()

    specs = _tier_specs(
        d_warmup=args.d_warmup,
        d_iterations=args.d_iterations,
        warmup=args.warmup,
        iterations=args.iterations,
    )
    tiers: dict[str, dict[str, Any]] = {}
    for tier in TIER_ORDER:
        block, _ = _measure_tier(tier, specs[tier])
        tiers[tier] = block
        # D 档真实 provider 的连接池在档间显式关闭（owns client）。
        provider = specs[tier]["provider"]
        if isinstance(provider, HttpSemanticJudge):
            provider.close()

    report: dict[str, Any] = {
        "profile": "functional_smoke",
        "task": "V21-13 Stage 1 shadow semantic 接入开销 smoke（04 §21）",
        "backend": "memory",
        "pipeline_mode": "shadow（四档恒定，栈构造同 test_v21_09_pipeline）",
        "sample_rate": 1.0,
        "workload": (
            "code_execution 类 DEFER fixture（shell exec 形状 "
            "tool_call_proposed + 权威 TaskFact 在场，事件 metadata "
            "携带 task_id trusted claim；每次迭代新 event_id，全链路 "
            "Phase A → Phase B → 审计提交）"
        ),
        "tiers": {
            "a_off": "semantic flag off → provider=None（基线）",
            "b_flag_on_unconfigured": (
                "flag on 缺 api_key/model → provider=None（配置门控）"
            ),
            "c_fake_provider": (
                "确定性 in-process fake provider 直接注入（纯进程内净增量）"
            ),
            "d_unreachable_endpoint": (
                f"真实 HttpSemanticJudge 指向 {UNREACHABLE_BASE_URL}"
                "（timeout 3.0s，连接快速拒绝 fail-closed 上界）"
            ),
        },
        "percentile_method": (
            "nearest-rank P50/P95/P99/max，单调纳秒样本"
            "（time.perf_counter_ns），不剔除异常值"
        ),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "latency": tiers,
        "overhead": {
            "b_vs_a": _delta_block(tiers["a_off"], tiers["b_flag_on_unconfigured"]),
            "c_vs_a": _delta_block(tiers["a_off"], tiers["c_fake_provider"]),
            "d_vs_a": _delta_block(tiers["a_off"], tiers["d_unreachable_endpoint"]),
        },
        "notes": (
            "D 档为缩减口径（预热 3 测 30，A/B/C 预热 10 测 100）：样本量"
            "与档内 store 累积深度（审计/投影行数）不对称，d_vs_a 百分位"
            "增量不可读作性能增益，仅 fail-closed 行为证据；每请求 HTTP"
            "往返为连接快速拒绝（loopback connection refused），未触及"
            " timeout 3.0s hard deadline。"
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"report written: {args.output}", flush=True)
    for tier in TIER_ORDER:
        block = tiers[tier]
        print(
            f"{tier}: P50={block['p50_ms']:.3f}ms "
            f"P95={block['p95_ms']:.3f}ms P99={block['p99_ms']:.3f}ms "
            f"max={block['max_ms']:.3f}ms mean={block['mean_ms']:.3f}ms",
            flush=True,
        )
    for name, delta in report["overhead"].items():
        print(
            f"{name}: ΔP50={delta['delta_p50_ms']:+.3f}ms "
            f"ΔP95={delta['delta_p95_ms']:+.3f}ms "
            f"ΔP99={delta['delta_p99_ms']:+.3f}ms "
            f"Δmax={delta['delta_max_ms']:+.3f}ms",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
