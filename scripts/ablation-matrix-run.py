#!/usr/bin/env python3
"""六臂模块级消融矩阵驱动脚本。

以 ``scripts/competition-v2-effect-run.py`` 为骨架改造：复用竞赛 runtime 的
真实 V2 决策链路（v21 active、激活清单、TaskFact、guard-api 服务全部由
execute_competition_arm 自动处理），默认以 replay 模式（确定性、零 LLM）
运行。六个臂的语义：

* core-off            -- AgentGuard 全关基线（冻结 A0 原样）；
* full                -- AgentGuard 全开最终产品形态（冻结 A4 原样）；
* no-context-isolation-- 上下文隔离降级 required -> observe；
* no-provenance-taint -- 关闭 CT 事实投影（partial：投影关闭后部分链路
                         无法完整归因）；
* no-memory-guard     -- 禁用 memory guard：P104 策略禁用 + memory
                         required-checks 豁免 env（partial：持久动作的
                         memory lineage safeguard 无法被 env 豁免）；
* no-semantic-judge   -- 恒不注入 V21-13 语义判定 env（决策不变量对照，
                         decision_invariant：与 full 的官方决策应一致）。

臂目录与报告一律使用 label；arm_id 保持 "A0"/"A4" 以通过 ArmSpec 白名单
校验。replay 定位为 Guard 组件级消融证据，不能替代 autonomous 端到端 ASR
对比结论，报告恒带 ``competition_qualified=false``。

Usage:

    # 打印六臂定义表（不运行任何 case）
    uv run python scripts/ablation-matrix-run.py arms

    # replay 冒烟（零 LLM，无需 provider 凭据）
    uv run python scripts/ablation-matrix-run.py run \
        --artifacts /tmp/agentguard-ablation \
        --case-id BN-001 --case-id PI-001 --serial

    # 按攻击类型整组运行 + 断点续跑（已 passed 的臂自动跳过）
    uv run python scripts/ablation-matrix-run.py run \
        --artifacts /tmp/agentguard-ablation --group prompt_injection

    # autonomous 模式（需要真实 provider）
    uv run python scripts/ablation-matrix-run.py run \
        --artifacts /tmp/agentguard-ablation --plan-mode autonomous \
        --llm-model qwen3.7-plus --llm-base-url https://<provider>/v1 \
        --llm-api-key-env COMPETITION_LLM_KEY

    # 单独汇总已有产物
    uv run python scripts/ablation-matrix-run.py report \
        --artifacts /tmp/agentguard-ablation
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from agentguard_langgraph_bench.bench import competition_parallel as streams
from agentguard_langgraph_bench.bench.competition_models import (
    COMPETITION_ACTION_TYPES,
    CompetitionProfile,
    ContextMode,
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
from agentguard_langgraph_bench.bench.provider_rate_limit import (
    install_global_provider_token,
)
from agentguard_langgraph_bench.bench.v2_effect_metrics import (
    BASELINE_ARM_ID,
    PRODUCT_ARM_ID,
    compute_arm_report,
    compute_paired_metrics,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = REPO_ROOT / "agentguard_langgraph_bench/bench/datasets/attack_cases"

# 六臂端口表默认偏移 40：远离官方 runner（stream 0..6）与 effect-run 常规
# 窗口（20..2x）；极端 repeats×shards 并行规模下仍可能与其它窗口重叠，
# 冲突时端口预检（check_ports_available）fail-closed 报错，需换偏移重跑。
_DEFAULT_STREAM_INDEX_OFFSET = 40
_REPORT_SCHEMA_VERSION = "ablation-matrix-report/1.0"
_REPEATS_SUMMARY_SCHEMA_VERSION = "ablation-matrix-repeats-summary/1.0"
_ARMS_CONFIG_SCHEMA_VERSION = "ablation-matrix-arms-config/1.0"
# replay 模式下 ProviderRuntimeConfig 的非空字段占位值（永不发起真实请求）。
_REPLAY_PROVIDER_PLACEHOLDER = "replay-placeholder"
# no-memory-guard 臂注入的 required-checks 豁免名单：竞赛全部 action 类型。
# 持久动作（effects.persistence / 显式 memory 引用）受 lineage safeguard
# 保护，无法被该名单豁免——这正是该臂 partial 标注的来源。
_MEMORY_NOT_REQUIRED_ENV = "AGENTGUARD_MEMORY_NOT_REQUIRED_ACTIONS"
_MEMORY_NOT_REQUIRED_ENV_VALUE = ",".join(COMPETITION_ACTION_TYPES)
_REPLAY_LIMITATION_NOTE = (
    "replay 模式将 agent 行为固定为冻结剧本（零 LLM、完全确定），"
    "结论只能作为 Guard 组件级消融证据，不能外推为 autonomous 端到端 "
    "ASR 差异；端到端结论请引用 autonomous + temperature=0 的效应评测。"
)

# 六臂 label（目录名与报告键）。
CORE_OFF_LABEL = "core-off"
FULL_LABEL = "full"
NO_CONTEXT_ISOLATION_LABEL = "no-context-isolation"
NO_PROVENANCE_TAINT_LABEL = "no-provenance-taint"
NO_MEMORY_GUARD_LABEL = "no-memory-guard"
NO_SEMANTIC_JUDGE_LABEL = "no-semantic-judge"

ABLATION_ARM_LABELS = (
    CORE_OFF_LABEL,
    FULL_LABEL,
    NO_CONTEXT_ISOLATION_LABEL,
    NO_PROVENANCE_TAINT_LABEL,
    NO_MEMORY_GUARD_LABEL,
    NO_SEMANTIC_JUDGE_LABEL,
)
# 与 core-off 配对比较的 5 个 Guard 臂。
GUARD_ARM_LABELS = tuple(label for label in ABLATION_ARM_LABELS if label != CORE_OFF_LABEL)
# 相对 full 计算模块净效应的 4 个消融臂。
ABLATION_VS_FULL_LABELS = tuple(
    label
    for label in GUARD_ARM_LABELS
    if label not in {FULL_LABEL, NO_SEMANTIC_JUDGE_LABEL}
) + (NO_SEMANTIC_JUDGE_LABEL,)


@dataclass(frozen=True, slots=True)
class AblationArm:
    """一个消融臂的完整定义：ArmSpec + 请求级附加参数 + 元数据标注。"""

    label: str
    arm: Any  # ArmSpec（冻结 dataclass，pickle 安全）
    ablation: str
    policy_disabled_rules: tuple[str, ...] = ()
    memory_not_required_env: bool = False
    partial: bool = False
    decision_invariant: bool = False

    def public_dump(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "arm_id": self.arm.arm_id,
            "ablation": self.ablation,
            "policy_disabled_rules": list(self.policy_disabled_rules),
            "memory_not_required_env": self.memory_not_required_env,
            "partial": self.partial,
            "decision_invariant": self.decision_invariant,
            "arm": self.arm.public_dump(),
        }


def _effect_arm_pair(profile: CompetitionProfile) -> tuple[Any, Any]:
    """提取冻结 A0/A4 并执行形状校验（与 effect-run 的 build_effect_arms
    等价：A0 必须 Guard 全关，A4 必须 V2.1 active/official + context
    required + RTE enforce）。"""

    arms = {arm.arm_id: arm for arm in profile.arms}
    missing = [
        arm_id
        for arm_id in (BASELINE_ARM_ID, PRODUCT_ARM_ID)
        if arm_id not in arms
    ]
    if missing:
        raise InvalidCompetitionRun(
            "ablation_arm_roster_missing",
            f"competition profile lacks ablation base arms: {', '.join(missing)}",
        )
    baseline = arms[BASELINE_ARM_ID]
    product = arms[PRODUCT_ARM_ID]
    if baseline.guard_enabled:
        raise InvalidCompetitionRun(
            "ablation_baseline_arm_invalid",
            "baseline arm A0 must keep AgentGuard fully off",
        )
    if (
        product.v21_rollout_mode is None
        or product.v21_rollout_mode.value != "active"
        or product.context_mode.value != "required"
        or product.rte_mode.value != "enforce"
    ):
        raise InvalidCompetitionRun(
            "ablation_product_arm_invalid",
            (
                "product arm A4 must be V2.1 active/official with context "
                "required and RTE enforce (no shadow)"
            ),
        )
    return baseline, product


def build_ablation_arms(profile: CompetitionProfile) -> dict[str, AblationArm]:
    """从冻结 A0/A4 派生六臂消融矩阵（arm_id 保持 A0/A4 过白名单校验）。"""

    baseline, product = _effect_arm_pair(profile)
    return {
        CORE_OFF_LABEL: AblationArm(
            label=CORE_OFF_LABEL,
            arm=baseline,
            ablation="AgentGuard 全关基线（冻结 A0 原样）",
        ),
        FULL_LABEL: AblationArm(
            label=FULL_LABEL,
            arm=product,
            ablation="AgentGuard 全开最终产品形态（冻结 A4 原样）",
        ),
        NO_CONTEXT_ISOLATION_LABEL: AblationArm(
            label=NO_CONTEXT_ISOLATION_LABEL,
            arm=replace(product, context_mode=ContextMode.OBSERVE),
            ablation="上下文隔离降级 required -> observe",
        ),
        NO_PROVENANCE_TAINT_LABEL: AblationArm(
            label=NO_PROVENANCE_TAINT_LABEL,
            arm=replace(product, ct_projection_enabled=False),
            ablation="关闭 CT 事实投影（污染溯源）",
            partial=True,
        ),
        NO_MEMORY_GUARD_LABEL: AblationArm(
            label=NO_MEMORY_GUARD_LABEL,
            arm=product,
            ablation=(
                "禁用 memory guard：P104 策略禁用 + memory required-checks "
                "豁免 env（持久动作的 lineage safeguard 无法豁免）"
            ),
            policy_disabled_rules=("P104_memory_poisoning",),
            memory_not_required_env=True,
            partial=True,
        ),
        NO_SEMANTIC_JUDGE_LABEL: AblationArm(
            label=NO_SEMANTIC_JUDGE_LABEL,
            arm=product,
            ablation="恒不注入 V21-13 语义判定 env（决策不变量对照）",
            decision_invariant=True,
        ),
    }


def build_arms_config(
    profile: CompetitionProfile,
    arms: Mapping[str, AblationArm],
    *,
    plan_mode: str,
    selected_labels: Sequence[str],
) -> dict[str, Any]:
    """arms-config.json 的结构（arms/run 子命令共用）。"""

    return {
        "schema_version": _ARMS_CONFIG_SCHEMA_VERSION,
        "profile_id": profile.profile_id,
        "plan_mode": plan_mode,
        "replay_limitation_note": _REPLAY_LIMITATION_NOTE,
        "competition_qualified": False,
        "selected_labels": list(selected_labels),
        "memory_not_required_env_value": _MEMORY_NOT_REQUIRED_ENV_VALUE,
        "arms": [arms[label].public_dump() for label in ABLATION_ARM_LABELS],
    }


def load_groups(dataset_dir: Path = DATASET_DIR) -> dict[str, list[str]]:
    """attack_type -> 有序 case id 列表，直接扫描冻结 JSONL。

    与 ``scripts/competition-grouped-run.py`` 的 load_groups 同口径：
    组名取自每行记录的 attack_type 字段（缺省回退文件名 stem），
    组名大小写敏感。
    """

    groups: dict[str, list[str]] = {}
    for path in sorted(dataset_dir.glob("*.jsonl")):
        case_ids: list[str] = []
        attack_type = path.stem
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                attack_type = str(record.get("attack_type") or path.stem)
                case_ids.append(str(record["case_id"]))
        if case_ids:
            groups.setdefault(attack_type, []).extend(case_ids)
    return groups


def select_cases(
    profile: CompetitionProfile,
    *,
    case_ids: Sequence[str] | None = None,
    group_names: Sequence[str] | None = None,
    groups: Mapping[str, Sequence[str]] | None = None,
) -> tuple[Any, ...]:
    """--case-id 与 --group 的并集过滤，保持冻结数据集顺序。"""

    cases = _load_frozen_cases(profile)
    wanted: set[str] = set(case_ids or ())
    for group in group_names or ():
        group_map = groups if groups is not None else load_groups()
        if group not in group_map:
            # 报错附上可用组列表（来自 load_groups 结果），便于纠正拼写/组名。
            raise InvalidCompetitionRun(
                "group_selection_invalid",
                (
                    f"unknown attack type group: {group} "
                    f"(available: {', '.join(sorted(group_map)) or '<none>'})"
                ),
            )
        wanted.update(group_map[group])
    if not wanted:
        return cases
    known = {case.case_id for case in cases}
    unknown = wanted - known
    if unknown:
        raise InvalidCompetitionRun(
            "case_selection_invalid",
            f"unknown case ids: {', '.join(sorted(unknown))}",
        )
    return tuple(case for case in cases if case.case_id in wanted)


def resolve_provider(
    profile: CompetitionProfile, args: argparse.Namespace
) -> ProviderRuntimeConfig:
    """解析 provider 配置；replay 模式放宽为占位值（零 LLM 永不调用）。"""

    planner = profile.planner
    provider_id = args.llm_provider_id or planner.provider_id
    model = args.llm_model or planner.model
    base_url = args.llm_base_url or planner.base_url
    api_key_env = args.llm_api_key_env or planner.api_key_env
    if args.plan_mode == "replay":
        # replay 全程零 LLM：model/base_url 允许为空、凭据 env 允许未
        # 设置，统一用占位值填满 ProviderRuntimeConfig 的非空字段。
        model = model or _REPLAY_PROVIDER_PLACEHOLDER
        base_url = base_url or _REPLAY_PROVIDER_PLACEHOLDER
        try:
            api_key = resolve_api_key(api_key_env)
        except ModelExchangeError:
            api_key = _REPLAY_PROVIDER_PLACEHOLDER
    else:
        if not model or not base_url:
            raise InvalidCompetitionRun(
                "provider_configuration_missing",
                (
                    "--llm-model and --llm-base-url are required for a "
                    "live ablation run (autonomous mode)"
                ),
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


def build_semantic_env(args: argparse.Namespace) -> dict[str, str]:
    """V21-13 语义判定 env（语义同 effect-run；仅注入 full 臂）。"""

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


@dataclass(frozen=True, slots=True)
class ArmWorkerRequest:
    """Spawn 子进程 worker 所需的全部字段（pickle 安全）。"""

    label: str
    slot: int
    repeat_index: int
    port_table: dict[str, int]
    profile: CompetitionProfile
    provider: ProviderRuntimeConfig
    cases: tuple[Any, ...]
    artifact_root: Path
    arm: Any  # ArmSpec
    plan_mode_override: str | None = None
    policy_disabled_rules: tuple[str, ...] = ()
    memory_not_required_env: bool = False
    semantic_env: dict[str, str] = field(default_factory=dict)
    # --provider-rate-limit 开启时由父进程在 spawn context 上创建的全局
    # 单 token（BoundedSemaphore(1)，pickle 安全）；子进程启动时安装，
    # provider 调用点经 global_provider_token() 串行化。默认 None 不限流。
    provider_global_token: Any | None = None


def _timed_case_runner(durations: dict[str, float]):
    """包装串行 bench runner，记录每 case 墙钟耗时（毫秒）。"""

    from agentguard_langgraph_bench.bench.runner import run_cases

    def runner(cases: Sequence[Any], **kwargs: Any) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for case in cases:
            started = time.monotonic()
            results.extend(run_cases([case], **kwargs))
            durations[str(case.case_id)] = (time.monotonic() - started) * 1000.0
        return results

    return runner


def execute_ablation_arm(request: ArmWorkerRequest) -> dict[str, Any]:
    """在本进程（serial）或 worker 进程内串行执行一个消融臂分片。"""

    from agentguard_langgraph_bench.bench.competition_runtime import (
        execute_competition_arm,
    )

    streams.apply_stream_environment(request.port_table)
    # 臂级计时起点：每个臂分片单独计时（合并段聚合为臂级 duration），
    # 不以 repeat 起点计算（评审 Ryan m1）。
    arm_started = time.monotonic()
    # 臂级 env 注入（memory 豁免 / V21-13 语义判定）。serial 模式下多个臂
    # 共享本进程：try/finally 恢复原值，避免 no-memory-guard 的豁免 env
    # 泄漏到后续臂的 guard-api 服务（GuardApiSettings 构造时读取）。
    managed_env: dict[str, str] = {}
    if request.memory_not_required_env:
        # no-memory-guard 臂：豁免 memory required-checks（持久动作仍受
        # lineage safeguard 保护，无法豁免）。
        managed_env[_MEMORY_NOT_REQUIRED_ENV] = _MEMORY_NOT_REQUIRED_ENV_VALUE
    if request.semantic_env:
        # V21-13 语义判定 env 仅注入 full 臂；GuardApiSettings 构造时读取。
        managed_env.update(request.semantic_env)
    env_backup = {name: os.environ.get(name) for name in managed_env}
    try:
        for env_name, env_value in managed_env.items():
            os.environ[env_name] = env_value
        streams.check_ports_available(request.port_table)
        rewritten = tuple(
            streams.rewrite_cases_for_ports(request.cases, request.port_table)
        )
        arm_request = ArmRunRequest(
            profile=request.profile,
            arm=request.arm,
            repeat_index=request.repeat_index,
            seed=request.profile.seed,
            cases=rewritten,
            provider=request.provider,
            artifact_directory=request.artifact_root / "arms" / request.label,
            suite=request.profile.suite,
            qualification_eligible=False,
            plan_mode_override=request.plan_mode_override,
            policy_disabled_rules=request.policy_disabled_rules,
        )
        durations: dict[str, float] = {}
        result = execute_competition_arm(
            arm_request, case_runner=_timed_case_runner(durations)
        )
        return {
            "label": request.label,
            "arm_id": request.arm.arm_id,
            "rows": [dict(row) for row in result.rows],
            "contracts": {
                name: dict(payload) for name, payload in result.contracts.items()
            },
            "case_durations_ms": durations,
            "port_table": dict(request.port_table),
            # 该臂分片本次执行的墙钟耗时，合并段聚合为臂级 duration。
            "shard_duration_seconds": time.monotonic() - arm_started,
        }
    finally:
        for env_name, original in env_backup.items():
            if original is None:
                os.environ.pop(env_name, None)
            else:
                os.environ[env_name] = original


def _arm_worker(request: ArmWorkerRequest, queue: Any) -> None:
    """Spawn 子进程入口；结果写 .shard-N.json 文件回传，避免大队列阻塞。"""

    # 安装 run 级 provider 全局 token（--provider-rate-limit 开启时由父
    # 进程创建传入；官方 runner 同模式，provider 调用点已包裹
    # global_provider_token()，token 为 None 时零开销 no-op）。
    install_global_provider_token(request.provider_global_token)
    try:
        payload = execute_ablation_arm(request)
    except Exception as exc:  # noqa: BLE001 - worker 边界 fail-closed。
        queue.put(("failed", request.slot, type(exc).__name__, str(exc)))
        return
    payload_path = request.artifact_root / f".shard-{request.slot}.json"
    payload_path.write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8"
    )
    queue.put(("ok", request.slot, str(payload_path)))


# ---------------------------------------------------------------------------
# 臂级断点续跑状态机
# ---------------------------------------------------------------------------


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def arm_result_path(repeat_root: Path, label: str) -> Path:
    return repeat_root / "arms" / label / "result.json"


def _load_arm_result(repeat_root: Path, label: str) -> dict[str, Any] | None:
    """读臂级 result.json；缺失/损坏/非对象时返回 None。"""

    path = arm_result_path(repeat_root, label)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def arm_passed(
    repeat_root: Path,
    label: str,
    *,
    expected_case_count: int | None = None,
    expected_case_ids_digest: str | None = None,
) -> bool:
    """该臂（该 repeat）已有 status=passed 且 case 集一致的 result.json。

    期望 case 数/case_ids 指纹不一致（如先 ``--group`` 跑子集、再跑全量）
    时返回 False，由调用方打印 WARNING 并重跑该臂（评审 Ryan M3）。
    """

    payload = _load_arm_result(repeat_root, label)
    if payload is None or payload.get("status") != "passed":
        return False
    if expected_case_count is not None and payload.get("case_count") != (
        expected_case_count
    ):
        return False
    if expected_case_ids_digest is not None and payload.get("case_ids_digest") != (
        expected_case_ids_digest
    ):
        return False
    return True


# rows_sha256 指纹只覆盖的确定性语义字段：行内 task_fact.trace_id/task_id
# （每次执行唯一，混入 time.time_ns()）与时间戳类字段必须排除，否则
# repeats>=2 时指纹必不相同、stability 恒 False（评审 Ryan M2）。
_DETERMINISTIC_ROW_KEYS = (
    "case_id",
    "attack_type",
    "is_malicious",
    "run_valid",
    "run_status",
    "attack_success",
    "overblocked",
    "task_success",
    "instrumentation_plan_mode",
    "planning_source",
)


def rows_sha256(rows: Sequence[Mapping[str, Any]]) -> str:
    """合并后行集的稳定指纹（断点续跑/stability 校验用）。

    只对 _DETERMINISTIC_ROW_KEYS 的确定性语义子集计算（行顺序保持
    冻结数据集顺序）；非确定字段（trace_id/task_id/时间戳类）不参与。
    """

    projection = [
        {key: row.get(key) for key in _DETERMINISTIC_ROW_KEYS} for row in rows
    ]
    encoded = json.dumps(
        projection, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def case_ids_digest(case_ids: Sequence[str]) -> str:
    """case_id 列表（冻结顺序）的 sha256，供断点续跑校验 case 集一致性。"""

    encoded = json.dumps(
        [str(case_id) for case_id in case_ids],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def write_arm_result(
    repeat_root: Path,
    label: str,
    *,
    status: str,
    duration_seconds: float,
    case_count: int,
    rows: Sequence[Mapping[str, Any]] = (),
    case_ids: Sequence[str] = (),
    error: str | None = None,
) -> None:
    """每臂完成后写 result.json（passed/failed 状态机）。

    case_ids 传本轮期望的冻结顺序全集：写入 case_ids_digest 供断点续跑
    校验 case 集一致性（换 --group/--case-id 后不误 skip）。
    """

    _write_json(
        arm_result_path(repeat_root, label),
        {
            "label": label,
            "status": status,
            "duration_seconds": round(duration_seconds, 1),
            "case_count": case_count,
            "case_ids_digest": case_ids_digest(case_ids) if case_ids else None,
            "rows_sha256": rows_sha256(rows) if rows else None,
            "error": error,
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        },
    )


# ---------------------------------------------------------------------------
# 执行引擎（仿 effect-run 的并行骨架）
# ---------------------------------------------------------------------------


def _provider_token_for(args: argparse.Namespace) -> Any | None:
    """--provider-rate-limit 开启且 parallel 执行时创建全局单 token。

    接受任意值即开启（与官方 runner 语义一致）：父进程在 spawn context
    上创建 BoundedSemaphore(1)，经 worker request 传入子进程安装，全程
    至多一个在途 provider 请求；serial 单进程下限流无意义，打印一行
    说明并返回 None（no-op）。
    """

    if getattr(args, "provider_rate_limit", None) is None:
        return None
    if args.serial:
        print(
            "--- provider-rate-limit: serial 单进程执行，provider 限流为 "
            "no-op ---"
        )
        return None
    return streams.stream_spawn_context().BoundedSemaphore(1)


def _run_one_repeat(
    *,
    args: argparse.Namespace,
    profile: CompetitionProfile,
    arms: Mapping[str, AblationArm],
    provider: ProviderRuntimeConfig,
    semantic_env: dict[str, str],
    cases: tuple[Any, ...],
    labels: Sequence[str],
    shard_count: int,
    repeat_index: int,
    repeat_root: Path,
    port_offset: int,
    mode: str,
) -> tuple[int, list[str]]:
    """执行一轮 repeat（全部选中臂/分片）并写各自的臂产物。

    返回 ``(exit_code, failures)``；臂/worker 级 fail-soft：失败 worker
    记入 failures 并写 failed result.json，不影响其他臂继续执行。
    """

    # work item = (label, shard)：分片把臂内 case 集按轮转切分为不相交
    # 子集，每个分片内仍严格串行，case 级语义与单分片臂一致。
    work_items: list[tuple[str, int, tuple[Any, ...]]] = []
    for label in labels:
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
            work_items.append((label, shard_index, shard))

    def _work_label(slot: int) -> str:
        label, shard_index, _ = work_items[slot]
        return label if shard_count == 1 else f"{label}[s{shard_index}]"

    # --provider-rate-limit：autonomous 多臂/分片并行时用全局单 token
    # 串行化 provider 请求（官方 runner 同模式）；replay 模式无 provider
    # 调用、flag 无效果；serial 单进程下为 no-op（函数内已打印说明）。
    provider_global_token = _provider_token_for(args)

    worker_requests = [
        ArmWorkerRequest(
            label=label,
            slot=slot,
            repeat_index=repeat_index,
            # 全局 slot 编号（跨臂×分片递增）保证端口表互不冲突。
            port_table=streams.allocate_port_table(
                port_offset + slot, base=args.worker_port_base
            ),
            profile=profile,
            provider=provider,
            cases=shard,
            artifact_root=repeat_root,
            arm=arms[label].arm,
            plan_mode_override=args.plan_mode,
            policy_disabled_rules=arms[label].policy_disabled_rules,
            memory_not_required_env=arms[label].memory_not_required_env,
            semantic_env=(
                semantic_env if label == FULL_LABEL and semantic_env else {}
            ),
            provider_global_token=provider_global_token,
        )
        for slot, (label, shard_index, shard) in enumerate(work_items)
    ]

    print(
        f"=== ablation matrix: {len(cases)} cases x arms "
        f"{'/'.join(labels)} ({mode}) ==="
    )
    started = time.monotonic()
    collected: dict[int, dict[str, Any]] = {}
    failures: list[str] = []
    skipped: list[str] = []

    # 臂级断点续跑：已 passed、case 集一致且非 --force 的臂整体跳过；
    # passed 但 case 集变化（如先 --group 跑子集、再跑全量）时不 skip，
    # 打 WARNING 说明后重跑该臂，避免 report 基于旧 case 集产物计算。
    expected_case_count = len(cases)
    expected_digest = case_ids_digest([str(case.case_id) for case in cases])
    runnable_requests: list[ArmWorkerRequest] = []
    pending_labels = set(labels)
    for request in worker_requests:
        if not args.force:
            payload = _load_arm_result(repeat_root, request.label)
            if payload is not None and payload.get("status") == "passed":
                if (
                    payload.get("case_count") == expected_case_count
                    and payload.get("case_ids_digest") == expected_digest
                ):
                    if request.label in pending_labels:
                        skipped.append(request.label)
                        pending_labels.discard(request.label)
                        print(
                            f"--- arm {request.label}: already passed, skipping "
                            "(--force to re-run) ---"
                        )
                    continue
                if request.label in pending_labels:
                    print(
                        f"WARNING: arm {request.label}: 已有 passed 产物但 case 集"
                        f"与本次运行不一致（期望 {expected_case_count} 例 "
                        f"digest={expected_digest[:12]}，产物记录 "
                        f"{payload.get('case_count')} 例 digest="
                        f"{str(payload.get('case_ids_digest') or 'none')[:12]}），"
                        f"重新运行该臂",
                        file=sys.stderr,
                    )
                    pending_labels.discard(request.label)
        runnable_requests.append(request)

    if args.serial:
        for request in runnable_requests:
            print(f"--- arm {_work_label(request.slot)} (serial) ---")
            try:
                collected[request.slot] = execute_ablation_arm(request)
            except Exception as exc:  # noqa: BLE001 - fail-closed 边界。
                failures.append(
                    f"{_work_label(request.slot)}: {type(exc).__name__}: {exc}"
                )
    else:
        context = streams.stream_spawn_context()
        queue = context.Queue()
        processes = []
        for request in runnable_requests:
            process = context.Process(
                target=_arm_worker,
                args=(request, queue),
                name=f"ablation-arm-{_work_label(request.slot)}",
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
                payload_path = Path(payload[2])
                try:
                    collected[int(payload[1])] = json.loads(
                        payload_path.read_text(encoding="utf-8")
                    )
                    payload_path.unlink()
                except Exception as exc:  # noqa: BLE001
                    failures.append(
                        f"{_work_label(int(payload[1]))}: failed to read shard "
                        f"{payload_path}: {type(exc).__name__}: {exc}"
                    )
            else:
                failures.append(
                    f"{_work_label(int(payload[1]))}: {payload[2]}: {payload[3]}"
                )
        for process, request in zip(processes, runnable_requests):
            if request.slot in collected or any(
                failure.startswith(_work_label(request.slot))
                for failure in failures
            ):
                continue
            failures.append(
                f"{_work_label(request.slot)}: worker exited without a "
                f"result (exit code {process.exitcode})"
            )

    for failure in failures:
        print(f"WARNING: {failure}", file=sys.stderr)
    if skipped:
        print(
            f"--- skipped arms (already passed): {', '.join(skipped)} ---"
        )

    # 合并分片回臂级行集（冻结数据集顺序），写臂产物与 result.json。
    order = {str(case.case_id): position for position, case in enumerate(cases)}
    for label in labels:
        label_requests = [
            request for request in runnable_requests if request.label == label
        ]
        if not label_requests:
            # 纯跳过臂（已 passed 且非 --force）：不重写产物，保留原 result.json。
            continue
        label_failures = [
            item
            for item in failures
            if item.startswith(f"{label}:") or item.startswith(f"{label}[")
        ]
        rows: list[dict[str, Any]] = []
        durations: dict[str, float] = {}
        contracts: dict[str, dict[str, Any]] = {}
        shard_durations: list[float] = []
        for request in label_requests:
            payload = collected.get(request.slot)
            if payload is None:
                continue
            rows.extend(payload["rows"])
            durations.update(payload["case_durations_ms"])
            shard_durations.append(
                float(payload.get("shard_duration_seconds") or 0.0)
            )
            for name, item in payload["contracts"].items():
                contracts.setdefault(name, item)
        if rows:
            rows.sort(key=lambda row: order.get(str(row.get("case_id")), len(order)))
            _write_json(repeat_root / f"arms/{label}/run.json", rows)
            _write_json(repeat_root / f"arms/{label}/durations.json", durations)
            _write_json(repeat_root / f"arms/{label}/contracts.json", contracts)
        complete = bool(rows) and len(rows) == len(cases) and not label_failures
        # 臂级耗时只统计该臂自身分片（serial 分片串行取和、parallel 分片
        # 并行取最大墙钟），不再以 repeat 起点计算（否则 serial 下后执行
        # 臂的 duration 会包含前序臂耗时，评审 Ryan m1）。
        if shard_durations:
            duration_seconds = (
                sum(shard_durations) if args.serial else max(shard_durations)
            )
        else:
            duration_seconds = time.monotonic() - started
        write_arm_result(
            repeat_root,
            label,
            status="passed" if complete else "failed",
            duration_seconds=duration_seconds,
            case_count=len(rows),
            rows=rows,
            case_ids=[str(case.case_id) for case in cases],
            error=(
                label_failures[0]
                if label_failures
                else (None if rows else "no collected result")
            ),
        )

    exit_code = int(ExitCode.INVALID_RUN) if failures else int(ExitCode.PASSED)
    return exit_code, failures


# ---------------------------------------------------------------------------
# report 汇总
# ---------------------------------------------------------------------------


def _discover_repeats(artifacts: Path) -> list[tuple[int, Path]]:
    """按 index 升序发现 repeat-N 目录。"""

    found: list[tuple[int, Path]] = []
    if not artifacts.is_dir():
        return found
    for path in artifacts.iterdir():
        if not path.is_dir() or not path.name.startswith("repeat-"):
            continue
        suffix = path.name[len("repeat-") :]
        if suffix.isdigit():
            found.append((int(suffix), path))
    return sorted(found)


def _load_arm_payloads(
    repeat_root: Path, label: str
) -> tuple[list[dict[str, Any]], dict[str, float]]:
    """读一个臂的 run.json 行集与 durations.json 毫秒耗时。"""

    rows_path = repeat_root / "arms" / label / "run.json"
    if not rows_path.exists():
        return [], {}
    rows = json.loads(rows_path.read_text(encoding="utf-8"))
    durations_path = repeat_root / "arms" / label / "durations.json"
    durations: dict[str, float] = {}
    if durations_path.exists():
        durations = {
            str(key): float(value)
            for key, value in json.loads(
                durations_path.read_text(encoding="utf-8")
            ).items()
        }
    return rows, durations


def _invalid_reasons_distribution(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, int]:
    """无效行 invalid_reasons 的计数分布。"""

    counter: dict[str, int] = {}
    for row in rows:
        if row.get("run_valid") is True:
            continue
        for reason in row.get("invalid_reasons") or []:
            counter[str(reason)] = counter.get(str(reason), 0) + 1
    return dict(sorted(counter.items()))


def _paired_module_net(
    baseline_rows: Sequence[Mapping[str, Any]],
    product_rows: Sequence[Mapping[str, Any]],
    *,
    baseline_label: str,
    product_label: str,
) -> dict[str, Any]:
    """配对指标 + 模块净效应：移除模块后重新得過的攻击（baseline 阻止、
    product 成功）计数与 case 列表。"""

    paired = compute_paired_metrics(
        baseline_rows,
        product_rows,
        baseline_arm_id=baseline_label,
        product_arm_id=product_label,
    )
    baseline_by_id = {str(row.get("case_id")): row for row in baseline_rows}
    product_by_id = {str(row.get("case_id")): row for row in product_rows}
    reenabled = [
        case_id
        for case_id in sorted(set(baseline_by_id) & set(product_by_id))
        if baseline_by_id[case_id].get("run_valid") is True
        and product_by_id[case_id].get("run_valid") is True
        and baseline_by_id[case_id].get("is_malicious") is True
        and baseline_by_id[case_id].get("attack_success") is False
        and product_by_id[case_id].get("attack_success") is True
    ]
    paired["module_removed_attack_success_count"] = len(reenabled)
    paired["module_removed_attack_success_case_ids"] = reenabled
    return paired


def build_ablation_report(
    *,
    profile: CompetitionProfile,
    artifacts: Path,
    allow_incomplete: bool = False,
    selected_labels: Sequence[str] | None = None,
    plan_mode: str | None = None,
) -> tuple[dict[str, Any], Path]:
    """汇总 arms/*/ 产物，返回 ``(report, report_repeat_root)``。

    报告基准取最新的、覆盖全部选中臂的 repeat 目录；problems 非空且未
    开 ``allow_incomplete`` 时报 InvalidCompetitionRun。
    """

    arms = build_ablation_arms(profile)
    labels = list(selected_labels) if selected_labels else list(ABLATION_ARM_LABELS)
    unknown = [label for label in labels if label not in arms]
    if unknown:
        raise InvalidCompetitionRun(
            "ablation_label_invalid",
            f"unknown ablation arm labels: {', '.join(unknown)}",
        )
    problems: list[str] = []
    repeats = _discover_repeats(artifacts)
    if not repeats:
        raise InvalidCompetitionRun(
            "ablation_artifacts_missing",
            f"no repeat-N directories under {artifacts}",
        )
    # 从新到旧选第一个覆盖全部选中臂的 repeat 作为报告基准。
    chosen = repeats[-1]
    for candidate in reversed(repeats):
        if all(
            (candidate[1] / "arms" / label / "run.json").exists()
            for label in labels
        ):
            chosen = candidate
            break
    report_repeat_index, report_root = chosen
    arm_payloads: dict[str, tuple[list[dict[str, Any]], dict[str, float]]] = {}
    for label in labels:
        if not (report_root / "arms" / label / "run.json").exists():
            problems.append(
                f"repeat-{report_repeat_index}: arm {label} missing run.json"
            )
            continue
        arm_payloads[label] = _load_arm_payloads(report_root, label)
    if problems and not allow_incomplete:
        raise InvalidCompetitionRun(
            "ablation_report_incomplete", "; ".join(problems)
        )

    arms_report: dict[str, Any] = {}
    for label in labels:
        if label not in arm_payloads:
            continue
        rows, durations = arm_payloads[label]
        entry = compute_arm_report(label, rows, case_durations_ms=durations)
        spec_arm = arms[label]
        # blocked 口径：显式 blocked 字段（竞赛 oracle 行）或 run_status=
        # blocked（replay 剧本中途被 Guard 拦截的行没有 blocked 布尔字段）。
        blocked = sum(
            1
            for row in rows
            if row.get("blocked") is True or row.get("run_status") == "blocked"
        )
        entry.update(
            {
                "arm_id": spec_arm.arm.arm_id,
                "ablation": spec_arm.ablation,
                "partial": spec_arm.partial,
                "decision_invariant": spec_arm.decision_invariant,
                "policy_disabled_rules": list(spec_arm.policy_disabled_rules),
                "row_count": len(rows),
                "blocked_rate": (blocked / len(rows)) if rows else None,
                "invalid_reasons": _invalid_reasons_distribution(rows),
            }
        )
        result_path = arm_result_path(report_root, label)
        if result_path.exists():
            try:
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                entry["result_status"] = payload.get("status")
            except (OSError, ValueError):
                entry["result_status"] = "unreadable"
        arms_report[label] = entry

    # 配对一：core-off 为 baseline 对 5 个 Guard 臂；
    # 配对二：full 为 baseline 对每个消融臂算模块净效应。
    paired_vs_core: dict[str, Any] = {}
    for label in GUARD_ARM_LABELS:
        if label in arm_payloads and CORE_OFF_LABEL in arm_payloads:
            paired_vs_core[label] = compute_paired_metrics(
                arm_payloads[CORE_OFF_LABEL][0],
                arm_payloads[label][0],
                baseline_arm_id=CORE_OFF_LABEL,
                product_arm_id=label,
            )
    module_net_vs_full: dict[str, Any] = {}
    for label in ABLATION_VS_FULL_LABELS:
        if label in arm_payloads and FULL_LABEL in arm_payloads:
            module_net_vs_full[label] = _paired_module_net(
                arm_payloads[FULL_LABEL][0],
                arm_payloads[label][0],
                baseline_label=FULL_LABEL,
                product_label=label,
            )

    report = {
        "schema_version": _REPORT_SCHEMA_VERSION,
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "profile_id": profile.profile_id,
        "plan_mode": plan_mode,
        "report_repeat_index": report_repeat_index,
        "repeat_count": len(repeats),
        "replay_limitation_note": _REPLAY_LIMITATION_NOTE,
        "competition_qualified": False,
        "allow_incomplete": allow_incomplete,
        "problems": problems,
        "arms": arms_report,
        "paired_vs_core_off": paired_vs_core,
        "module_net_vs_full": module_net_vs_full,
    }
    return report, report_root


def _fmt_pct(value: Any) -> str:
    return "-" if value is None else f"{value * 100:.1f}%"


def _fmt_ms(value: Any) -> str:
    return "-" if value is None else f"{float(value):.0f}"


def _render_markdown(report: Mapping[str, Any]) -> str:
    """人类可读对照表（markdown）。"""

    arms: Mapping[str, Any] = report["arms"]
    lines: list[str] = [
        "# AgentGuard 六臂消融矩阵报告",
        "",
        f"- 生成时间: {report['run_at']}",
        f"- profile: {report['profile_id']}",
        f"- plan_mode: {report.get('plan_mode')}",
        f"- 基准 repeat: repeat-{report.get('report_repeat_index')}"
        f"（共 {report.get('repeat_count')} 轮）",
        f"- competition_qualified: {report['competition_qualified']}",
        "",
        f"> {report['replay_limitation_note']}",
        "",
    ]
    if report.get("problems"):
        lines.append("## 缺失/问题")
        lines.extend(f"- {item}" for item in report["problems"])
        lines.append("")
    lines.append("## 臂级对照表")
    lines.append("")
    lines.append(
        "| label | arm_id | rows | ASR(valid) | blocked率 | FPR "
        "| valid率 | p50(ms) | p95(ms) | 标注 |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for label, entry in arms.items():
        marks = [
            name
            for name, flag in (
                ("partial", entry.get("partial")),
                ("decision_invariant", entry.get("decision_invariant")),
            )
            if flag
        ]
        performance = entry["performance"]["core_case_ms"]
        lines.append(
            f"| {label} | {entry.get('arm_id')} | {entry.get('row_count')} "
            f"| {_fmt_pct(entry['safety']['asr_valid_malicious'])} "
            f"| {_fmt_pct(entry.get('blocked_rate'))} "
            f"| {_fmt_pct(entry['usability']['fpr'])} "
            f"| {_fmt_pct(entry['stability']['valid_run_rate'])} "
            f"| {_fmt_ms(performance['p50'])} "
            f"| {_fmt_ms(performance['p95'])} "
            f"| {', '.join(marks) or '-'} |"
        )
    lines.append("")
    lines.append("### 消融语义")
    lines.extend(
        f"- **{label}**: {entry.get('ablation')}" for label, entry in arms.items()
    )
    lines.append("")
    lines.append("## 配对指标（baseline = core-off）")
    lines.append("")
    lines.append(
        "| Guard 臂 | paired ASR core-off | paired ASR arm | 阻止成功攻击 | n |"
    )
    lines.append("|---|---|---|---|---|")
    for label, paired in report.get("paired_vs_core_off", {}).items():
        lines.append(
            f"| {label} | {_fmt_pct(paired['paired_valid_asr_baseline'])} "
            f"| {_fmt_pct(paired['paired_valid_asr_product'])} "
            f"| {paired['blocked_successful_attack_count']}/"
            f"{paired['attack_success_count_baseline']} "
            f"| {paired['paired_valid_malicious_count']} |"
        )
    lines.append("")
    lines.append("## 模块净效应（baseline = full，移除模块）")
    lines.append("")
    lines.append(
        "| 消融臂 | paired ASR full | paired ASR arm | 移除后新增成功攻击 | n |"
    )
    lines.append("|---|---|---|---|---|")
    for label, paired in report.get("module_net_vs_full", {}).items():
        lines.append(
            f"| {label} | {_fmt_pct(paired['paired_valid_asr_baseline'])} "
            f"| {_fmt_pct(paired['paired_valid_asr_product'])} "
            f"| {paired['module_removed_attack_success_count']} "
            f"| {paired['paired_valid_malicious_count']} |"
        )
    lines.append("")
    lines.append("## per-attack-type ASR")
    lines.append("")
    attack_types: list[str] = []
    for entry in arms.values():
        for attack_type in entry["safety"]["per_attack_type_asr"]:
            if attack_type not in attack_types:
                attack_types.append(attack_type)
    header = ["attack_type", *arms.keys()]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "---|" * len(header))
    for attack_type in attack_types:
        cells = [
            _fmt_pct(
                entry["safety"]["per_attack_type_asr"]
                .get(attack_type, {})
                .get("asr")
            )
            for entry in arms.values()
        ]
        lines.append(f"| {attack_type} | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("## invalid_reasons 分布")
    lines.extend(
        f"- **{label}**: "
        f"{json.dumps(entry.get('invalid_reasons') or {}, ensure_ascii=False)}"
        for label, entry in arms.items()
    )
    if report.get("run_failures"):
        lines.append("")
        lines.append("## run_failures")
        lines.extend(f"- {item}" for item in report["run_failures"])
    lines.append("")
    lines.append("## 显著性检验用法")
    lines.append(
        "> 对任意两臂跑 McNemar 精确检验 / Wilson CI（repeat 布局，多轮默认\n"
        "> 取索引最大；用 --repeat N 显式指定）：\n>\n"
        "> ```\n"
        "> uv run python scripts/effect-paired-significance.py \\\n"
        ">     --artifacts-dir <本产物目录> \\\n"
        ">     --baseline-arm full --product-arm no-memory-guard \\\n"
        ">     --out significance.json\n"
        "> ```"
    )
    lines.append("")
    return "\n".join(lines)


def _print_report_table(report: Mapping[str, Any]) -> None:
    """控制台摘要表格。"""

    print("\n=== 六臂消融汇总 ===")
    for label, entry in report["arms"].items():
        safety = entry["safety"]
        print(
            f"  {label}: ASR(valid)={_fmt_pct(safety['asr_valid_malicious'])} "
            f"blocked={_fmt_pct(entry.get('blocked_rate'))} "
            f"FPR={_fmt_pct(entry['usability']['fpr'])} "
            f"valid={_fmt_pct(entry['stability']['valid_run_rate'])} "
            f"rows={entry.get('row_count')}"
        )
    for label, paired in report.get("paired_vs_core_off", {}).items():
        print(
            f"  paired vs core-off [{label}]: "
            f"{_fmt_pct(paired['paired_valid_asr_baseline'])} -> "
            f"{_fmt_pct(paired['paired_valid_asr_product'])} "
            f"(阻止 {paired['blocked_successful_attack_count']}/"
            f"{paired['attack_success_count_baseline']}, "
            f"n={paired['paired_valid_malicious_count']})"
        )
    for label, paired in report.get("module_net_vs_full", {}).items():
        print(
            f"  module-net vs full [{label}]: 移除后新增成功 "
            f"{paired['module_removed_attack_success_count']} "
            f"(n={paired['paired_valid_malicious_count']})"
        )
    if report.get("problems"):
        print(f"  problems: {'; '.join(report['problems'])}")


def _write_repeats_summary(
    artifacts: Path,
    *,
    profile_id: str,
    failures: Sequence[str],
    selected_labels: Sequence[str],
) -> None:
    """跨轮聚合：每臂每轮 result 状态 + rows 指纹稳定性（replay 应稳定）。"""

    repeats_payload: list[dict[str, Any]] = []
    for index, root in _discover_repeats(artifacts):
        arms_payload: dict[str, Any] = {}
        for label in selected_labels:
            path = arm_result_path(root, label)
            if not path.exists():
                arms_payload[label] = {"status": "missing"}
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                arms_payload[label] = {"status": "unreadable"}
                continue
            arms_payload[label] = {
                "status": payload.get("status"),
                "case_count": payload.get("case_count"),
                "duration_seconds": payload.get("duration_seconds"),
                "rows_sha256": payload.get("rows_sha256"),
            }
        repeats_payload.append({"repeat_index": index, "arms": arms_payload})
    stability: dict[str, dict[str, Any]] = {}
    for label in selected_labels:
        # 只对至少两轮都有指纹的臂判定稳定性：缺失/失败轮的 None 不再
        # 字符串化混入集合（否则有失败轮误报 unstable、全 None 误报
        # stable，评审 Ryan m2）；不足两轮时置 None 并附各轮 status 明细。
        arm_entries = [item["arms"].get(label, {}) for item in repeats_payload]
        digests = [
            str(entry["rows_sha256"])
            for entry in arm_entries
            if entry.get("rows_sha256")
        ]
        stability[label] = {
            "rows_sha256_stable_across_repeats": (
                len(set(digests)) <= 1 if len(digests) >= 2 else None
            ),
            "repeats_with_digest": len(digests),
            "per_repeat_status": [
                {
                    "repeat_index": item["repeat_index"],
                    "status": item["arms"].get(label, {}).get("status"),
                }
                for item in repeats_payload
            ],
        }
    _write_json(
        artifacts / "repeats-summary.json",
        {
            "schema_version": _REPEATS_SUMMARY_SCHEMA_VERSION,
            "run_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "profile_id": profile_id,
            "repeat_count": len(repeats_payload),
            "repeats": repeats_payload,
            "rows_sha256_stability": stability,
            "run_failures": list(failures),
        },
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    arms_parser = subparsers.add_parser(
        "arms", help="打印六臂定义表（不运行任何 case）"
    )
    arms_parser.add_argument("--profile", default="competition-langgraph-v2")

    run_parser = subparsers.add_parser("run", help="执行消融矩阵")
    run_parser.add_argument("--artifacts", required=True, type=Path)
    run_parser.add_argument("--profile", default="competition-langgraph-v2")
    run_parser.add_argument(
        "--plan-mode",
        choices=("replay", "autonomous"),
        default="replay",
        help="默认 replay（确定性、零 LLM）；autonomous 需要真实 provider",
    )
    run_parser.add_argument(
        "--arm",
        action="append",
        default=None,
        choices=ABLATION_ARM_LABELS,
        metavar="LABEL",
        help="限制到指定臂（可重复；默认全部六臂）",
    )
    run_parser.add_argument(
        "--group",
        action="append",
        default=None,
        help="attack_type 整组 case（可重复，与 --case-id 并集；冻结顺序）",
    )
    run_parser.add_argument("--case-id", action="append", default=None)
    run_parser.add_argument("--repeats", type=int, default=1)
    run_parser.add_argument(
        "--serial",
        action="store_true",
        help="在本进程内串行执行全部臂（smoke/诊断）",
    )
    run_parser.add_argument(
        "--arm-parallel",
        type=int,
        default=1,
        help="单臂分片为 N 个并行 worker（需配合单一 --arm）",
    )
    run_parser.add_argument(
        "--force", action="store_true", help="重跑已 passed 的臂（忽略断点续跑）"
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
        "--semantic-model",
        help="V2 语义判定模型（仅注入 full 臂；replay 模式忽略）",
    )
    run_parser.add_argument("--semantic-base-url")
    run_parser.add_argument("--semantic-api-key-env")
    run_parser.add_argument(
        "--semantic-timeout-seconds", type=float, default=15.0
    )
    run_parser.add_argument(
        "--worker-port-base",
        type=int,
        default=streams.STREAM_PORT_BASE_DEFAULT,
    )
    run_parser.add_argument(
        "--stream-index-offset",
        type=int,
        default=_DEFAULT_STREAM_INDEX_OFFSET,
        help=(
            "端口表 stream 索引偏移（默认 40，仅远离官方 0..6 与 effect-run "
            "常规 20..2x 窗口；极端 repeats×shards 并行时仍可能重叠，"
            "冲突时端口预检 fail-closed 报错）"
        ),
    )
    run_parser.add_argument(
        "--provider-rate-limit",
        default=None,
        metavar="VALUE",
        help=(
            "autonomous 多臂/分片并行时串行化 provider 请求（全局单 "
            "token，接受任意值即开启，与官方 runner 语义一致）；replay "
            "模式无 provider 调用、flag 无效果；serial 单进程下为 no-op"
        ),
    )

    report_parser = subparsers.add_parser("report", help="汇总已有产物")
    report_parser.add_argument("--artifacts", required=True, type=Path)
    report_parser.add_argument("--profile", default="competition-langgraph-v2")
    report_parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="允许缺失臂（记入 problems 而非报错）",
    )
    return parser


def cmd_arms(args: argparse.Namespace) -> int:
    profile = load_competition_profile(args.profile)
    arms = build_ablation_arms(profile)
    print("=== 六臂消融矩阵定义 ===")
    print(
        f"{'label':<22} {'arm_id':<7} {'partial':<8} "
        f"{'decision_invariant':<19} 消融语义"
    )
    for label in ABLATION_ARM_LABELS:
        spec = arms[label]
        print(
            f"{label:<22} {spec.arm.arm_id:<7} {str(spec.partial):<8} "
            f"{str(spec.decision_invariant):<19} {spec.ablation}"
        )
    config = build_arms_config(
        profile,
        arms,
        plan_mode="replay",
        selected_labels=list(ABLATION_ARM_LABELS),
    )
    print("\narms-config 结构（未运行任何 case）：")
    print(json.dumps(config, ensure_ascii=False, indent=2))
    return int(ExitCode.PASSED)


def cmd_run(args: argparse.Namespace) -> int:
    artifacts = Path(args.artifacts).resolve()
    if artifacts.exists() and any(artifacts.iterdir()):
        # 不做 fresh-directory 硬检查（支持断点续跑），但写清日志。
        print(
            f"NOTE: artifacts directory is not fresh: {artifacts} "
            "(resume mode: already-passed arms are skipped; "
            "use --force to re-run)"
        )
    artifacts.mkdir(parents=True, exist_ok=True)
    try:
        profile = load_competition_profile(args.profile)
        arms = build_ablation_arms(profile)  # 冻结 A0/A4 形状校验
        selected = list(dict.fromkeys(args.arm or list(ABLATION_ARM_LABELS)))
        cases = select_cases(
            profile, case_ids=args.case_id, group_names=args.group
        )
        if not cases:
            raise InvalidCompetitionRun(
                "case_selection_empty", "no cases selected"
            )
        provider = resolve_provider(profile, args)
        semantic_env = build_semantic_env(args)
    except InvalidCompetitionRun as exc:
        print(f"{exc.reason_code}: {exc}", file=sys.stderr)
        return int(ExitCode.INVALID_RUN)

    if args.plan_mode == "replay" and semantic_env:
        # replay 恒零 LLM，语义判定 env 不注入。
        semantic_env = {}
        print("NOTE: replay mode ignores --semantic-* (zero-LLM replay)")
    if args.arm_parallel > 1 and len(selected) != 1:
        print(
            "--arm-parallel requires exactly one --arm "
            "(intra-arm sharding is single-arm only)",
            file=sys.stderr,
        )
        return int(ExitCode.INVALID_RUN)
    if args.repeats < 1:
        print("--repeats must be >= 1", file=sys.stderr)
        return int(ExitCode.INVALID_RUN)

    _write_json(
        artifacts / "arms-config.json",
        build_arms_config(
            profile, arms, plan_mode=args.plan_mode, selected_labels=selected
        ),
    )

    overall_failures: list[str] = []
    for repeat_index in range(args.repeats):
        repeat_root = artifacts / f"repeat-{repeat_index}"
        repeat_root.mkdir(parents=True, exist_ok=True)
        # 每轮拥有互不重叠的端口表窗口；轮内按全局 slot 递增分配。
        port_offset = (
            args.stream_index_offset
            + repeat_index * len(selected) * args.arm_parallel
        )
        mode = "serial" if args.serial else "parallel"
        if args.arm_parallel > 1:
            mode += f" x{args.arm_parallel} shards"
        if args.repeats > 1:
            mode = f"repeat {repeat_index + 1}/{args.repeats}, {mode}"
        _, failures = _run_one_repeat(
            args=args,
            profile=profile,
            arms=arms,
            provider=provider,
            semantic_env=semantic_env,
            cases=cases,
            labels=selected,
            shard_count=args.arm_parallel,
            repeat_index=repeat_index,
            repeat_root=repeat_root,
            port_offset=port_offset,
            mode=mode,
        )
        overall_failures.extend(
            f"repeat-{repeat_index}: {failure}" for failure in failures
        )

    _write_repeats_summary(
        artifacts,
        profile_id=profile.profile_id,
        failures=overall_failures,
        selected_labels=selected,
    )

    # run 结束自动触发 report（allow-incomplete：run 尽力而为，缺失记 problems）。
    try:
        report, _ = build_ablation_report(
            profile=profile,
            artifacts=artifacts,
            allow_incomplete=True,
            selected_labels=selected,
            plan_mode=args.plan_mode,
        )
    except InvalidCompetitionRun as exc:
        print(f"report skipped: {exc.reason_code}: {exc}", file=sys.stderr)
        return int(ExitCode.INVALID_RUN)
    if overall_failures:
        report["run_failures"] = list(overall_failures)
    _write_json(artifacts / "ablation-report.json", report)
    (artifacts / "ablation-report.md").write_text(
        _render_markdown(report), encoding="utf-8"
    )
    _print_report_table(report)
    return (
        int(ExitCode.INVALID_RUN) if overall_failures else int(ExitCode.PASSED)
    )


def cmd_report(args: argparse.Namespace) -> int:
    artifacts = Path(args.artifacts).resolve()
    profile = load_competition_profile(args.profile)
    # arms-config 优先提供 plan_mode 与 selected_labels。
    plan_mode: str | None = None
    selected: list[str] | None = None
    config_path = artifacts / "arms-config.json"
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            plan_mode = config.get("plan_mode")
            selected = config.get("selected_labels") or None
        except (OSError, ValueError):
            pass
    try:
        report, _ = build_ablation_report(
            profile=profile,
            artifacts=artifacts,
            allow_incomplete=args.allow_incomplete,
            selected_labels=selected,
            plan_mode=plan_mode,
        )
    except InvalidCompetitionRun as exc:
        print(f"{exc.reason_code}: {exc}", file=sys.stderr)
        return int(ExitCode.INVALID_RUN)
    _write_json(artifacts / "ablation-report.json", report)
    (artifacts / "ablation-report.md").write_text(
        _render_markdown(report), encoding="utf-8"
    )
    _print_report_table(report)
    return int(ExitCode.PASSED)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "arms":
        return cmd_arms(args)
    if args.command == "run":
        return cmd_run(args)
    return cmd_report(args)


if __name__ == "__main__":
    sys.exit(main())
