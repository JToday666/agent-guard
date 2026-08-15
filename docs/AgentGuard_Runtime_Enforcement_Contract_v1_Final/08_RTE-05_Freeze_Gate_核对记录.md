# RTE-05 Freeze Gate 核对记录

> 依据：`06_迁移_PR与实施计划.md` §7——PR-RTE-05（Strong Approval Binding）前必须确认的 8 项冻结。
> 核对时间：2026-08-15；核对基线：`dev@71b5a96`（含 #143）。
> 结论先行：**七项已冻结（其中 6 项已实现，1 项实现归 RTE-05），1 项 additive 冻结文本已存在但缺实现**；production evaluate wiring（06 §11 C3）未完成，列入 RTE-05 依赖跟踪。本 PR 对 02 §6 补 additive 语义澄清（在场/降级/回显/exact 比对）并增防漂移 guard 测试；RTE-05 可开工。

---

## 1. 八项逐条核对

### 1.1 ActionIR action_id —— 已冻结 ✅

- **契约**：01 §9（ActionIR 字段逐字冻结）；`ActionIR.action_id` 为必填 `str`，`extra="forbid"`。
- **代码证据**：
  - 模型：`packages/agentguard-core/agentguard_core/actions/models.py` `class ActionIR`（`action_id: str` 必填）。
  - 派生：`packages/agentguard-core/agentguard_core/actions/builder.py` `build_action_ir()`——`action_id = f"act_{event.event_id}"`（确定性派生，同事件同 action_id）。
- **测试覆盖**：`tests/test_v21_08_shadow_assessment.py`（`assessment.action_id == f"act_{event.event_id}"`）、`tests/test_v21_07_sequence.py`（action_id 序列语义）。
- **结论**：已冻结；RTE-05 的 consume endpoint 以 `action_id` 为消费键之一（UNIQUE(grant_id, action_id)）。

### 1.2 authorization_fingerprint 算法/版本 —— 已冻结 ✅

- **契约**：01 §9 L414-447（指纹冻结）。
- **代码证据**：`packages/agentguard-core/agentguard_core/actions/fingerprints.py`：
  - 算法：`HMAC-SHA256(server_secret, 域分离标签 + 受限 JCS(白名单投影))`，输出 `hmac-sha256:` 前缀；
  - 域分离标签：`AUTHORIZATION_DOMAIN_TAG = "agentguard/v21/action-ir/v1"`（版本号在标签内，升级即换标签）；
  - 白名单投影 `authorization_projection()`：schema_version/principal_id/task_id/task_revision/action_type/resources/destinations（剔除 display_summary、resource_id）/security_arguments/effects/runtime_binding_id/scope_digest/argument_digest；
  - `audit_fingerprint`（非 keyed sha256，`sha256:` 前缀）仅关联/解释语义，不承担授权安全语义。
- **测试覆盖**：`tests/test_v21_08_approval_grant.py`（grant `exact_authorization_fingerprint` 以 `hmac-sha256:` 前缀且与重算一致）。
- **结论**：已冻结 + 已实现。

### 1.3 runtime_binding_id authority —— 已冻结 ✅

- **契约**：01 §4 纪律（Adapter 不得自报权威身份）。
- **代码证据**：
  - `ActionIR.runtime_binding_id` 必填；参与 authorization 白名单投影（fingerprints.py `authorization_projection`）；
  - 权威来源：已认证 snapshot 的 `scope.runtime_binding_id`（`decisions/shadow.py` 构造 ActionIR 时取 `scope.runtime_binding_id`），**不接受 Adapter 自报**；
  - 消费侧纪律：`security_context/projection/authority_verdict.py` `build_consumption_intent()` 明确 "`runtime_binding_id` 取自已认证 ActionIR（不接受 Adapter 自报，01 §4 纪律）"。
- **结论**：已冻结 + 已实现（authority = 认证 scope，非 Adapter 自报）。

### 1.4 human approval CapabilityGrant 投影 —— 已冻结 ✅

- **契约**：02 §12（Approval → allow_once Grant 投影）；01 §14。
- **代码证据**：`security_context/projection/capability.py` `compile_approval_to_grant()`：
  - 仅 `resolution_source == "human"` 可投影；否则 `CapabilityProjectionError("v21-06:llm_reviewer_grant_forbidden")`；
  - 缺 `authorization_fingerprint` → `v21-06:missing_authorization_fingerprint`；空 action_types → `v21-06:empty_action_types`；
  - Grant 强制 `usage_limit=1 / remaining_uses=1 / delegable=false / source_type="human_approval" / exact_authorization_fingerprint` 绑定；`grant_id/grant_digest` 确定性派生。
- **测试覆盖**：`tests/test_v21_08_approval_grant.py`（投影、fingerprint 绑定、单用强制）。
- **结论**：已冻结 + 已实现。

### 1.5 GrantConsumption CAS —— 已冻结 ✅

- **契约**：02 §12（单事务原子消费）；V21-06 实现。
- **代码证据**：
  - 编排：`apps/guard-api/guard_api/security_state/lease_service.py` `consume_grant_atomic()`（校验 intent → 交付存储层单事务）；
  - 存储层单事务：`storage/postgres.py` `consume_grant()`（行锁序固定 grant→consumption→lease；`UNIQUE uq_grant_consumptions_grant_action (grant_id, action_id)`）；`storage/memory.py` 同语义（`capability_lease_lock` 读-校验-写）；
  - 双花语义：同 `(grant_id, action_id)` 重放且 fingerprint 一致 → 幂等返回既有 lease；fingerprint 不一致 → `GrantConsumptionConflictError("v21-06:consumption_conflict")`。
- **测试覆盖**：`tests/test_v21_06_lease_store_contract.py`、`tests/test_v21_06_capability_coverage.py`。
- **结论**：已冻结 + 已实现（存储层 CAS 单事务）。

### 1.6 ExecutionLease consume endpoint —— 契约已冻结，实现未完成 ⚠️

- **契约**：02 字段冻结（`POST /v1/approvals/{id}/execution-leases/consume`，单事务：验证 + consume + lease，见 06 §8）。
- **现状**：存储表 `execution_leases`（FK→grant_consumptions）、`lease_service` 编排、`consume_grant` 存储层均已就绪；**Guard API 路由层无该端点**（全库 grep `execution-leases/consume` 零命中）。
- **结论**：RTE-05 本体工作；依赖 1.8 enforcement_binding 冻结后定请求/响应字段。

### 1.7 LLM allow_once 不可消费 —— 已冻结 ✅

- **契约**：04 §12（V2 中 LLM Reviewer 不能产生可消费 allow_once grant）。
- **代码证据**：双层强制：
  - 投影层：`capability.py` `compile_approval_to_grant()` 拒绝 `resolution_source != "human"`；
  - 消费层：`authority_verdict.py` `build_consumption_intent()` 仅允许 `source_type == "human_approval"` 的 grant 进入消费（`"only human_approval allow_once grants are consumable"`）。
- **测试覆盖**：`tests/test_v21_08_approval_grant.py`（LLM 来源拒绝路径）。
- **结论**：已冻结 + 已实现（投影 + 消费双层 fail-closed）。

### 1.8 evaluation response enforcement_binding —— additive 冻结文本已存在，实现未完成 ⚠️

- **核对修正**：初核时代码层 grep 零命中曾误判为"未冻结"；复查确认 **02 §6 已存在 additive 冻结文本**（TARGET-P1）：字段集 `schema_version/action_id/authorization_fingerprint/runtime_binding_id/requires_execution_lease` + 4 条冻结要求（action_id 一致、fingerprint 仅服务端产生、Adapter 不得本地重算、audit_fingerprint 不可替代）。
- **缺口**：实现层零命中（evaluate 响应未输出 binding，依赖 C3 production wiring）；且原 §6 未定义在场条件/缺失降级/回显纪律/exact 比对语义。
- **处置**：本 PR commit 2 在 02 §6 补 4 条 additive 语义澄清（在场条件、缺失降级、回显纪律、exact 比对 → binding_failed + not_invoked）；JSON Schema 与实现归 RTE-05。
- **结论**：冻结文本完备（本 PR 补齐语义边界）；实现归 RTE-05。

---

## 2. 依赖跟踪（06 §11 C 轨道）

| 项 | 状态 |
|---|---|
| C1 ActionIR/TaskFact | 已有 |
| C2 State Projector / Authority | 已合（V21-05/06/07，#133） |
| C3 Production Evaluate Wiring | **未完成**；V21-08 Fusion Shadow 已合（#138，shadow 与 V21-09 `assess` 同形、零重构升级点已预留），V21-09 正式 `assess/finalize` 接入为 RTE-05 依赖 |
| C4 Grant + ExecutionLease | 存储/编排已实现；HTTP consume endpoint 缺（1.6） |

## 3. 缺口清单与 RTE-05 开工判定

| 缺口 | 归属 | 备注 |
|---|---|---|
| enforcement_binding additive 语义澄清 | 本 PR（commit 2） | 02 §6 补在场/降级/回显/exact 比对 4 条（字段集原已冻结） |
| enforcement_binding JSON Schema + evaluate 响应实现 | RTE-05 | 依赖 C3 production wiring 的评估输出 |
| `POST /v1/approvals/{id}/execution-leases/consume` 端点 | RTE-05 | 复用 lease_service 单事务编排 |
| production evaluate wiring（C3） | V21-09 / RTE-05 跟踪 | shadow 已同形，零重构升级 |
| 冻结不变量防漂移 guard 测试 | 本 PR（commit 3） | `tests/test_v21_freeze_gate_invariants.py` |

**判定**：八项中 7 项已冻结（6 项已实现；consume endpoint 与 enforcement_binding 实现明确归属 RTE-05）；本 PR 补齐 02 §6 additive 语义澄清与防漂移 guard 测试——**Freeze Gate 核对通过，RTE-05 可开工**。
