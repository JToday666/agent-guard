"""CT-PR-03b CT 事实投影编排服务（独立 flag 门控，只读旁路，绝不外抛）。

冻结出处（docs/AgentGuard_Context_Isolation_Taint_Tracking_Final_RC/ 与
CT-PR-03 实施计划裁决 D1-D6）：

- **D1 独立投影身份**：CT facts 以 ``source_record_type=
  "runtime_observation"`` + 命名空间化 ``source_record_id=
  "ct-facts:{event_id}"`` + ``source_revision=1`` 的独立投影入五元组
  身份空间，与 evaluation/approval 完全隔离；
- **D2 独立编排服务**：本模块即独立编排服务（仿 ``V21PipelineService``
  形状），经 ``evaluation.py`` 最小 additive 钩子接入；不深改
  ``v21_pipeline.py``；
- **D3 独立 flag**：``AGENTGUARD_CT_FACT_PROJECTION_ENABLED``（默认
  False），与 V21 shadow flag 解耦；且仅在 ``v21_pipeline`` 就绪
  （pipeline 材料可用）时生效——无 task/scope 材料 → fail-closed
  跳过留痕，不伪造 scope（01 §25）；
- **D4 commit 载体**：facts 信封寄生 policy_evaluation 审计记录的
  ``evidence.ct_transient_facts`` typed-bound 通道（仿
  ``state_delta_v21`` 先例含 64 KiB 预算降级序，CT 先降 → digest
  引用留痕）；零新表、零迁移；
- **D5 PROJECTOR_VERSION 不 bump**：只向已全接线的 typed 容器
  （``v21-07.projector.2``）灌入真实 CT 内容，apply 语义零变化。

四段时序（commit-before-project，02 §3）：

1. ``build_commit_bundle``（事务外）：pipeline 材料 → ``FactBuildInputs``
   服务端装配 → ``build_transient_facts`` → ``build_ct_facts_delta``
   预检（fail-closed 拒绝降级 bundle/scope 不一致）→ 装配 commit
   信封（facts 本体以规范化 dump 随审计持久化，``bundle_digest``
   供失真对照）；
2. ``commit_envelope`` 产物经 ``record_evaluation`` 随审计事务原子
   提交（``ct_facts_evidence`` 参数）；
3. ``project_after_commit``（事务退出后）：scope_lock 内 ensure_ready
   → base 校验 → ``project_committed``（verify 钩子复核审计记录存在
   且信封 ``bundle_digest`` 一致，仿 ``_verify_evaluation_committed``
   F0-8 口径）；
4. ``backfill``（replay 路径 D9 同构）：自审计 evidence 重建 bundle
   → digest 对照（失真/降级引用/缺材料 → 跳过留痕）→ 五元组幂等
   短路 → 同一锁序补投影。

base 漂移裁决留痕（与 V21-09 ``_project_evaluation`` 的差异登记）：
evaluation 信封只存 ``delta_digest`` 引用（rebase 会使引用失真），
故漂移必须 fail-closed 跳过不置脏；CT 信封承载 **bundle 本体 +
``bundle_digest``**（与 base 无关），前向漂移（Phase B→投影窗口内
被 evaluation 投影或其他投影推进）在锁内以当前 base **确定性
rebase** 吸收——身份五元组不变、``delta_digest`` 以新 base 重算恒
真实，e2e 双投影共存场景依赖该语义。异常 base 回退（append-only
状态不应发生）仍 fail-closed 跳过**不置脏** + 计数器留痕。

性能纪律（采纳 Tina 案被否决接线方案中的合理部分）：bundle 构建
全部在事务外（纯 CPU，材料取自 Phase A 产物，零新增存储往返）；
事务内零新增 I/O（信封随既有 ``record_evaluation`` 写入）；投影在
事务退出后。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from agentguard_core import AuditEvent, GuardEvent
from agentguard_core.actions.builder import build_action_ir
from agentguard_core.security_context import (
    PROJECTOR_VERSION,
    CommittedRecord,
)

from guard_api.security_state import SecurityStateService
from guard_api.security_state.delta_builder import (
    CT_DELTA_BUILDER_VERSION,
    build_ct_facts_delta,
)
from guard_api.security_state.fact_authority import (
    ProducerIdentity,
    VerifiedSourceDescriptor,
)
from guard_api.security_state.fact_builder import (
    FactBuildInputs,
    build_transient_facts,
)
from guard_api.security_state.transient import (
    TransientSecurityFacts,
    compute_bundle_digest,
)
from guard_api.settings import GuardApiConfigurationError, GuardApiSettings
from guard_api.storage.base import ControlPlaneStore

from .v21_pipeline import V21PipelineMaterials

logger = logging.getLogger(__name__)

__all__ = [
    "CT_BASE_REWIND_SKIPS",
    "CT_FACTS_SOURCE_PREFIX",
    "CtCommitPlan",
    "CtProjectionService",
    "ct_transient_facts_envelope",
]

#: D1 命名空间化投影身份前缀：``source_record_id = "ct-facts:{event_id}"``。
#: 03a 留痕观察项兑现：接线层对该前缀形态做 fail-closed 校验（verify
#: 钩子与 backfill 重建路径均拒绝非法形态）。
CT_FACTS_SOURCE_PREFIX = "ct-facts:"

#: runtime_observation 单事件 bundle 无修订链：source_revision 恒 1
#: （与 delta_builder ``_OBSERVATION_SOURCE_REVISION`` 同源口径）。
_OBSERVATION_SOURCE_REVISION = 1

#: server 确定性证据位派生分类（不双跑检测器：直接消费 Phase A 单跑
#: 的 DetectionResult 列表，兑现 fact_builder ``FactBuildInputs``
#: L108-111 服务端装配承诺）。
_CREDENTIAL_CATEGORIES = frozenset({"credential_exposure"})
_SENSITIVE_CATEGORIES = frozenset(
    {"sensitive_file_access", "outbound_dlp", "file_exfiltration"}
)

#: 结构化留痕：异常 base 回退跳过计数器（进程级观测信号，非全局
#: 聚合——仅统计当前进程内发生的跳过，多进程部署下各进程独立计数；
#: 前向漂移由锁内确定性 rebase 吸收，不经过本计数器）。
CT_BASE_REWIND_SKIPS: dict[str, int] = {"count": 0}


def ct_transient_facts_envelope(payload: dict[str, Any]) -> dict[str, Any]:
    """``ct_transient_facts`` 版本信封（仿 07 §10 ``state_delta_v21`` 形状）。

    D4 commit 载体：payload 承载 ``commit_envelope`` 产物（facts 本体
    规范化 dump + 身份引用），随同一条 policy_evaluation 审计记录落盘。
    """

    return {
        "ct_transient_facts": {
            "schema_version": "1.0",
            "payload": payload,
        }
    }


@dataclass(frozen=True)
class CtCommitPlan:
    """CT 投影计划（事务外确定性构造，commit 与 project 两段消费）。

    ``envelope`` 供事务内 ``record_evaluation`` 随审计原子提交；
    ``scope_digest`` / ``source_record_id`` / ``bundle`` 供事务退出后
    ``project_after_commit`` 锁内投影；``base_state_version`` 为构造
    时刻的 state version（异常 base 回退校验基准；前向漂移锁内
    rebase 吸收，见模块 docstring 裁决留痕）。
    """

    scope_digest: str
    source_record_id: str
    bundle: TransientSecurityFacts
    base_state_version: int
    envelope: dict[str, Any]


class CtProjectionService:
    """CT-PR-03b 编排器（flag 门控；只读旁路，绝不外抛）。

    构造即完成 flag / secret 解析（仿 ``V21PipelineService.__init__``
    口径）；flag off 时全部入口仅一次布尔判断返回 None，零 I/O。
    server secret 复用 ``AGENTGUARD_V21_SHADOW_SERVER_SECRET``（ActionIR
    确定性构造所需；D3 双门控下 CT flag on 且生效时 pipeline 必然就绪，
    该密钥必然在场——不新增密钥配置面，域用途仍为 ActionIR 指纹/
    身份构造）。
    """

    def __init__(
        self,
        *,
        settings: GuardApiSettings,
        store: ControlPlaneStore,
        state_service: SecurityStateService,
    ) -> None:
        self._store = store
        self._state_service = state_service
        self._enabled = bool(settings.ct_fact_projection_enabled)
        self._server_secret = self._load_server_secret(settings)

    def _load_server_secret(self, settings: GuardApiSettings) -> bytes | None:
        """flag on 时解析 server secret；未配置/非法 → CT 投影禁用。

        与 ``V21PipelineService._load_server_secret`` 同一口径：绝不
        硬编码兜底密钥；flag off 时不读取任何密钥配置。
        """

        if not self._enabled:
            return None
        try:
            secret = settings.v21_shadow_server_secret_bytes()
        except GuardApiConfigurationError:
            logger.warning(
                "ct fact projection enabled but AGENTGUARD_V21_SHADOW_SERVER_SECRET "
                "is malformed; ct projection disabled"
            )
            return None
        if secret is None:
            logger.warning(
                "ct fact projection enabled but AGENTGUARD_V21_SHADOW_SERVER_SECRET "
                "is not configured; ct projection disabled"
            )
        return secret

    @property
    def enabled(self) -> bool:
        """flag 且 secret 均已就绪（调用方诊断/编排切换判定）。"""

        return self._enabled and self._server_secret is not None

    # ------------------------------------------------------------------
    # 事务外：bundle 构建与 commit 信封装配
    # ------------------------------------------------------------------

    def build_commit_bundle(
        self, event: GuardEvent, materials: V21PipelineMaterials
    ) -> CtCommitPlan | None:
        """事务外构建 transient bundle 与 commit 计划（纯 CPU）。

        返回 None 的语义（均 fail-closed 跳过留痕，绝不外抛）：
        flag/secret 门控未就绪；pipeline 材料缺 task/scope（D3：不
        伪造 scope）；delta_builder 拒绝（降级 bundle / scope 不一致）；
        任何不可恢复异常。
        """

        if not self.enabled:
            return None
        try:
            return self._build_commit_bundle(event, materials)
        except Exception:  # noqa: BLE001 - 旁路故障必须收敛，绝不上抛。
            logger.warning(
                "ct fact projection bundle build failed for event %s; "
                "skipping (fail-closed, legacy chain unaffected)",
                event.event_id,
                exc_info=True,
            )
            return None

    def _build_commit_bundle(
        self, event: GuardEvent, materials: V21PipelineMaterials
    ) -> CtCommitPlan | None:
        # D3：仅在 pipeline 材料就绪时生效；无 task/scope 材料 →
        # fail-closed 跳过留痕，不伪造 scope（01 §25）。
        if (
            materials.scope_digest is None
            or materials.snapshot is None
            or materials.task_id is None
        ):
            logger.info(
                "ct fact projection skipped for event %s: pipeline "
                "materials absent (no task/scope; fail-closed, no "
                "fabricated scope)",
                event.event_id,
            )
            return None
        scope_digest = materials.scope_digest
        inputs = self._build_inputs(event, materials, scope_digest)
        bundle = build_transient_facts(event=event, inputs=inputs)
        source_record_id = f"{CT_FACTS_SOURCE_PREFIX}{event.event_id}"
        # delta 预检（事务外纯函数）：降级 bundle / scope 不一致 →
        # None（此处只消费其 fail-closed 语义，正式 delta 在投影锁内
        # 以当前 base 构造/rebase，见模块 docstring 漂移裁决）。
        preflight = build_ct_facts_delta(
            scope_digest=scope_digest,
            source_record_id=source_record_id,
            base_state_version=materials.state_version,
            bundle=bundle,
        )
        if preflight is None:
            logger.info(
                "ct fact projection skipped for event %s: delta builder "
                "refused the bundle (degraded bundle or scope mismatch; "
                "fail-closed)",
                event.event_id,
            )
            return None
        envelope = ct_transient_facts_envelope(
            self.commit_envelope(
                bundle,
                source_record_id=source_record_id,
                projection_id=preflight.projection_id,
                base_state_version=materials.state_version,
            )
        )
        return CtCommitPlan(
            scope_digest=scope_digest,
            source_record_id=source_record_id,
            bundle=bundle,
            base_state_version=materials.state_version,
            envelope=envelope,
        )

    def _build_inputs(
        self,
        event: GuardEvent,
        materials: V21PipelineMaterials,
        scope_digest: str,
    ) -> FactBuildInputs:
        """``FactBuildInputs`` 服务端装配（兑现 fact_builder L108-111 承诺）。

        - ``credential_bearing_text`` / server 证据位从既有
          ``detection_results``（Phase A 单跑）派生，**不双跑检测器**；
          ``credential_bearing_text`` 只取 server 侧检测证据片段
          （DetectionResult.rule_hit.evidence），绝不使用 adapter 原始
          文本（信任边界）；
        - ``upstream_descriptors`` / ``upstream_memory_facts`` 从
          snapshot 索引查表（handler 内按 key 序迭代保确定性）；
        - ``visible_refs=()``：服务端接线 v1 无稳定 visible set 来源，
          空 tuple（非 None）不产生 ``visible_set_unavailable`` 降级；
          真实 visible set 派生归 CT-PR-04/05 扩展点（留痕）；
        - ``server_credential_fingerprints`` 恒空：server 注册密钥指纹
          库尚未接线（CT-PR-04/05 留痕）；证据位独立追加 taint 的
          fail-closed 语义不受影响；
        - ``memory_change_status="proposed"``：bundle 构建在事务外、
          先于 MemoryGuard lifecycle 判定，只能取 proposed 口径。
        """

        detection_results = list(materials.detection_results)
        credential_hits = [
            result
            for result in detection_results
            if result.category in _CREDENTIAL_CATEGORIES
        ]
        server_sensitive_evidence = any(
            result.category in _SENSITIVE_CATEGORIES
            for result in detection_results
        )
        credential_bearing_text: str | None = None
        if credential_hits:
            fragments = [
                item
                for result in credential_hits
                for item in result.rule_hit.evidence
            ]
            credential_bearing_text = (
                "\n".join(fragments) if fragments else None
            )
        snapshot = materials.snapshot
        assert snapshot is not None
        upstream_descriptors = {
            fact.source_id: VerifiedSourceDescriptor(
                source_id=fact.source_id,
                scope_digest=fact.scope_digest,
                source_type=fact.source_type,
                trust=fact.trust,
                verification_state=fact.verification_state,
                fact_authority=fact.authority,
                producer=fact.producer,
                initial_taints=tuple(fact.taints),
            )
            for fact in snapshot.sources
        }
        upstream_memory_facts = {
            f"memory:{fact.memory_id}": fact for fact in snapshot.memory_facts
        }
        task_fact = snapshot.task
        # enabled 前置门控保证 secret 在场（构造期解析）。
        assert self._server_secret is not None
        try:
            action_ir = build_action_ir(
                event,
                server_secret=self._server_secret,
                task_id=materials.task_id,
                task_revision=(
                    task_fact.revision if task_fact is not None else None
                ),
                scope_digest=scope_digest,
                principal_id=(
                    task_fact.principal_id if task_fact is not None else None
                ),
                runtime_binding_id=(
                    f"binding:{task_fact.principal_id}"
                    if task_fact is not None
                    else None
                ),
            )
        except Exception:  # noqa: BLE001 - ActionIR 构造失败 → 无 ActionIR 口径。
            logger.warning(
                "ct fact projection ActionIR construction failed for event %s; "
                "continuing without ActionIR (fail-closed handler semantics)",
                event.event_id,
                exc_info=True,
            )
            action_ir = None
        return FactBuildInputs(
            scope_digest=scope_digest,
            producer_identity=ProducerIdentity(),
            server_sensitive_evidence=server_sensitive_evidence,
            server_credential_evidence=bool(credential_hits),
            credential_bearing_text=credential_bearing_text,
            server_credential_fingerprints=frozenset(),
            visible_refs=(),
            action_ir=action_ir,
            upstream_descriptors=upstream_descriptors,
            upstream_memory_facts=upstream_memory_facts,
            memory_change_status="proposed",
        )

    def commit_envelope(
        self,
        bundle: TransientSecurityFacts,
        *,
        source_record_id: str,
        projection_id: str,
        base_state_version: int,
    ) -> dict[str, Any]:
        """装配 commit 信封 payload（D4：facts 本体 commit 载体）。

        ``bundle`` 以规范化 dump 随审计持久化（backfill 重建材料）；
        ``bundle_digest`` 供失真对照；``commit_id`` 确定性构造
        （禁 uuid）。预算超限时由 evidence 通道降级序处理（CT 先降
        → digest 引用留痕，绝不静默截断）。
        """

        return {
            "ct_delta_builder_version": CT_DELTA_BUILDER_VERSION,
            "commit_id": f"ct-commit:{bundle.event_id}",
            "bundle_digest": bundle.bundle_digest,
            "bundle": bundle.model_dump(mode="json"),
            "projection_id": projection_id,
            "base_state_version_at_commit": base_state_version,
            "source_identity": {
                "source_record_type": "runtime_observation",
                "source_record_id": source_record_id,
                "source_revision": _OBSERVATION_SOURCE_REVISION,
            },
        }

    # ------------------------------------------------------------------
    # 事务退出后：commit → project
    # ------------------------------------------------------------------

    def project_after_commit(self, plan: CtCommitPlan | None) -> None:
        """事务提交后投影（02 §3 commit → project 时序）。

        投影失败一律 fail-closed 收敛（告警 + projector 既有 dirty
        语义），**绝不影响已返回的响应与审计记录**；不重试（replay
        幂等补投影 ``backfill`` 承接）。**绝不外抛**。
        """

        if plan is None or not self.enabled:
            return
        try:
            self._project_ct_facts(
                plan.scope_digest, plan.source_record_id, plan.bundle,
                commit_base_state_version=plan.base_state_version,
            )
        except Exception:  # noqa: BLE001 - 投影故障必须收敛，绝不上抛。
            logger.warning(
                "ct fact projection failed for %s; response and audit "
                "record are unaffected (fail-closed, no retry; replay "
                "backfill owns recovery)",
                plan.source_record_id,
                exc_info=True,
            )

    def _project_ct_facts(
        self,
        scope_digest: str,
        source_record_id: str,
        bundle: TransientSecurityFacts,
        *,
        commit_base_state_version: int,
    ) -> None:
        """commit → project 锁内编排（照搬 ``_project_evaluation`` 锁序）。

        scope_lock(scope_digest) 内：ensure_ready → 读 base → base
        校验（异常回退 → fail-closed 跳过不置脏 + 计数器；前向漂移 →
        确定性 rebase 吸收，见模块 docstring 裁决留痕）→
        ``project_committed``（verify 钩子复核审计记录存在且信封
        ``bundle_digest`` 一致，F0-8）。
        """

        with self._state_service.store_access.scope_lock(scope_digest):
            self._state_service.ensure_ready(scope_digest)
            current = self._state_service.store_access.get_security_state(
                scope_digest
            )
            # 缺态哨兵口径与 V21-09 同源（-1 不与任何真实 state_version
            # 碰撞）：ensure_ready 后 current 正常必在场。
            base_state_version = (
                current.state_version if current is not None else -1
            )
            if base_state_version < commit_base_state_version:
                # 异常 base 回退（append-only 状态不应发生）：不 rebase、
                # 不置脏，计数器留痕（fail-closed）。
                CT_BASE_REWIND_SKIPS["count"] += 1
                logger.warning(
                    "ct fact projection skipped for %s: base state "
                    "version rewound (%s -> %s); fail-closed without "
                    "dirtying (ct_projection_skip_reason=base_rewind, "
                    "ct_projection_skip_total=%s)",
                    source_record_id,
                    commit_base_state_version,
                    base_state_version,
                    CT_BASE_REWIND_SKIPS["count"],
                )
                return
            # 前向漂移（含零漂移）：以当前 base 确定性构造 delta——
            # 身份五元组与 base 无关，delta_digest 以新 base 重算恒真实。
            delta = build_ct_facts_delta(
                scope_digest=scope_digest,
                source_record_id=source_record_id,
                base_state_version=base_state_version,
                bundle=bundle,
            )
            if delta is None:  # 理论上不可达（bundle 已在构建期预检）。
                logger.warning(
                    "ct fact projection skipped for %s: delta builder "
                    "refused at projection time (fail-closed)",
                    source_record_id,
                )
                return
            committed_record = CommittedRecord(
                record_id=f"runtime-observation:{source_record_id}",
                committed=True,
                source_record_type="runtime_observation",
                source_record_id=source_record_id,
                source_revision=_OBSERVATION_SOURCE_REVISION,
                scope_digest=scope_digest,
                projector_version=PROJECTOR_VERSION,
                delta=delta,
            )
            expected_bundle_digest = bundle.bundle_digest
            result = self._state_service.project_committed(
                committed_record,
                scope_digest=scope_digest,
                verify_source_committed=(
                    lambda record: self._verify_ct_facts_committed(
                        record, expected_bundle_digest
                    )
                ),
            )
        logger.info(
            "ct fact projection %s for %s (state_version=%s)",
            result.outcome,
            source_record_id,
            result.state_version,
        )

    def _verify_ct_facts_committed(
        self, record: CommittedRecord, expected_bundle_digest: str
    ) -> bool:
        """``verify_source_committed`` 钩子（F0-8 同港口径）。

        复核：``source_record_id`` 前缀形态合法（03a 留痕观察项兑现）；
        对应 policy_evaluation 审计记录已在 evaluation_transaction 内
        commit（commit → project 时序前置）；信封 ``bundle_digest``
        与本次投影材料一致。任一不符即拒绝投影，未提交记录不得成为
        后续历史状态。
        """

        if not record.source_record_id.startswith(CT_FACTS_SOURCE_PREFIX):
            return False
        event_id = record.source_record_id[len(CT_FACTS_SOURCE_PREFIX):]
        audit = self._store.get_policy_evaluation_by_event_id(event_id)
        if audit is None or audit.record_type != "policy_evaluation":
            return False
        evidence = audit.evidence if isinstance(audit.evidence, dict) else {}
        envelope = evidence.get("ct_transient_facts")
        payload = envelope.get("payload") if isinstance(envelope, dict) else None
        if not isinstance(payload, dict):
            return False
        return payload.get("bundle_digest") == expected_bundle_digest

    # ------------------------------------------------------------------
    # replay：D9 同构幂等补投影
    # ------------------------------------------------------------------

    def backfill(self, audit: AuditEvent) -> None:
        """replay 幂等补投影：不重算 fact 映射，仅自审计重建材料补投影。

        判定口径：审计 evidence 存在 ``ct_transient_facts`` 信封即
        “当时 bundle 构建成功且随 commit 落盘”的直接标志；无信封
        （flag off 存量 / 材料缺态 / 降级 bundle）→ 不补。材料全部
        自审计记录重建：bundle 规范化 dump → digest 对照（失真即跳过
        留痕）；降级引用（预算剥离）/缺材料 → 跳过留痕；scope 经
        ``metadata.task_id`` → 权威 active TaskFact 重建（绝不伪造
        scope）并与 bundle scope_digest 交叉校验；五元组幂等键短路
        保证重复安全。**绝不外抛**。
        """

        if not self.enabled:
            return
        try:
            self._backfill(audit)
        except Exception:  # noqa: BLE001 - 补投影故障必须收敛，绝不上抛。
            logger.warning(
                "ct replay projection backfill failed for audit %s; "
                "replayed response is unaffected (fail-closed)",
                audit.audit_id,
                exc_info=True,
            )

    def _backfill(self, audit: AuditEvent) -> None:
        evidence = audit.evidence if isinstance(audit.evidence, dict) else {}
        envelope = evidence.get("ct_transient_facts")
        if not isinstance(envelope, dict):
            # 无信封：当时未产生 commit 计划（flag off / 材料缺态 /
            # 降级 bundle），无补投影可做，静默返回。
            return
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            return
        if payload.get("_budget_dropped"):
            # 预算降级引用：bundle 本体不在场，材料缺失，跳过留痕。
            logger.info(
                "ct replay projection backfill skipped for audit %s: "
                "envelope was budget-degraded to a digest reference "
                "(missing materials)",
                audit.audit_id,
            )
            return
        raw_bundle = payload.get("bundle")
        expected_digest = payload.get("bundle_digest")
        source_identity = payload.get("source_identity")
        if (
            not isinstance(raw_bundle, dict)
            or not isinstance(expected_digest, str)
            or not isinstance(source_identity, dict)
        ):
            logger.info(
                "ct replay projection backfill skipped for audit %s: "
                "ct_transient_facts payload malformed (missing materials)",
                audit.audit_id,
            )
            return
        source_record_id = source_identity.get("source_record_id")
        raw_revision = source_identity.get("source_revision")
        source_revision = (
            raw_revision
            if isinstance(raw_revision, int) and not isinstance(raw_revision, bool)
            else _OBSERVATION_SOURCE_REVISION
        )
        # 03a 留痕观察项兑现：前缀形态 fail-closed 校验。
        if not isinstance(source_record_id, str) or not source_record_id.startswith(
            CT_FACTS_SOURCE_PREFIX
        ):
            logger.info(
                "ct replay projection backfill skipped for audit %s: "
                "source_record_id fails the ct-facts: prefix form check "
                "(fail-closed)",
                audit.audit_id,
            )
            return
        try:
            bundle = TransientSecurityFacts.model_validate(raw_bundle)
        except Exception:  # noqa: BLE001 - 重建失败 → 缺材料跳过留痕。
            logger.warning(
                "ct replay projection backfill skipped for audit %s: "
                "bundle rebuild failed (fail-closed)",
                audit.audit_id,
                exc_info=True,
            )
            return
        if bundle.bundle_digest != compute_bundle_digest(bundle):
            # 评审 S6 digest 口径统一：_project_ct_facts 的 verify 期望值
            # 取内嵌字段 bundle.bundle_digest，本处重建后、投影前显式
            # 断言内嵌字段与重算值一致；不一致即跳过留痕（fail-closed）。
            logger.warning(
                "ct replay projection backfill skipped for audit %s: "
                "embedded bundle_digest mismatches the recomputed digest "
                "(fail-closed)",
                audit.audit_id,
            )
            return
        if compute_bundle_digest(bundle) != expected_digest:
            # 信封引用与重建结果失真：不得静默覆盖，跳过留痕。
            logger.warning(
                "ct replay projection backfill skipped for audit %s: "
                "rebuilt bundle digest does not match the envelope "
                "reference (fail-closed)",
                audit.audit_id,
            )
            return

        # scope 重建：metadata.task_id → 权威 active TaskFact（仿
        # V21-09 backfill 同源口径，绝不伪造 scope）+ bundle 交叉校验。
        task_id = audit.metadata.get("task_id")
        if not isinstance(task_id, str) or not task_id.strip():
            logger.info(
                "ct replay projection backfill skipped for audit %s: "
                "no task_id in audit metadata (missing materials)",
                audit.audit_id,
            )
            return
        task_record = self._store.get_task_fact(task_id)
        if task_record is None or task_record.task_fact.status != "active":
            logger.info(
                "ct replay projection backfill skipped for audit %s: "
                "no active authoritative TaskFact for %s (missing "
                "materials)",
                audit.audit_id,
                task_id,
            )
            return
        scope_digest = task_record.task_fact.scope_digest
        if bundle.scope_digest != scope_digest:
            logger.warning(
                "ct replay projection backfill skipped for audit %s: "
                "rebuilt bundle scope mismatches the authoritative "
                "TaskFact scope (fail-closed)",
                audit.audit_id,
            )
            return

        # 五元组幂等键短路：已登记 → 无补投影可做。
        existing_projection = self._state_service.store_access.get_projection(
            scope_digest,
            "runtime_observation",
            source_record_id,
            source_revision,
            PROJECTOR_VERSION,
        )
        if existing_projection is not None:
            return

        raw_commit_base = payload.get("base_state_version_at_commit")
        commit_base = (
            raw_commit_base
            if isinstance(raw_commit_base, int)
            and not isinstance(raw_commit_base, bool)
            else 0
        )
        # 与在线投影同一锁序（前向漂移锁内 rebase 吸收）。
        self._project_ct_facts(
            scope_digest,
            source_record_id,
            bundle,
            commit_base_state_version=commit_base,
        )
