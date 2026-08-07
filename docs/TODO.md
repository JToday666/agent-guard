# 后端能力与 Dashboard 接入状态

## 状态

本文件记录原前端预留能力的后端落地状态，以及 Dashboard 当前的读取入口：

- 安全评测 ASR 数据：已提供导入、latest 查询和 dataset registry 汇总接口。
- 配置审计 findings：已提供只读查询接口。
- OpenClaw 插件验证状态：已提供最近一次 verify、E2E 和 reliability 状态摘要写入与读取接口。
- 运行时监控指标：已提供 `/v1/metrics/runtime`，可按 runtime 聚合审计事件、hook 活跃度和 adapter 状态。

Dashboard 已完成展示接入：安全评测页读取 latest evaluation，系统状态页读取配置审计 findings 与 OpenClaw verify/status。mock 数据源已补齐有数据状态，便于本地查看真实数据形态下的页面效果。

Dashboard 指标已完成三作用域隔离：

- 当前审计窗口从已加载审计记录中筛选并去重逻辑 `policy_evaluation`；
- 重复策略评估在 `integrity.sequence` 可用时采用最早审计记录；
- 历史聚合保留独立按需入口，在后端提供明确范围前不进入页面；
- 独立 evaluation run 不再从审计历史补入 FPR、FNR、介入率或延迟。

目标后端交互见
[Dashboard 指标作用域与审计窗口 API 协作契约](08_api/dashboard_metrics_api_contract.md)。

## 安全评测 ASR 数据接口

后端采用“导入并保存”方案，评测结果由 CLI/API 写入 Guard API，再由 Dashboard 或 CLI 读取最新一次 run。

### 写入

`POST /v1/evaluations`

- 鉴权：control token。
- 用途：导入 AttackBench/Core matrix 等评测结果。
- ASR 字段允许 `null`；非 `null` 时必须在 `[0, 1]`。

```json
{
  "run_id": "eval_20260628",
  "run_at": "2026-06-28T00:00:00+00:00",
  "dataset_id": "attackbench",
  "dataset_version": "v1",
  "dataset_digest": "sha256:...",
  "dataset_locked": true,
  "regression_gate": {
    "status": "passed",
    "baseline_run_id": "eval_baseline",
    "max_allowed_regression": 0.02,
    "asr_delta": -0.684,
    "failed_case_ids": []
  },
  "asr_before": 0.732,
  "asr_after": 0.048,
  "per_attack": {
    "prompt_injection": { "asr_before": 0.85, "asr_after": 0.05 }
  },
  "cases": [
    {
      "case_id": "PI-001",
      "attack_type": "prompt_injection",
      "runtime": "openclaw",
      "case_digest": "sha256:...",
      "provenance": {
        "source": "attackbench",
        "source_path": "bench/datasets/attack_cases/prompt_injection.jsonl",
        "line": 1
      },
      "expected_decision": "deny",
      "actual_decision": "ask",
      "blocked": true,
      "attack_success": false,
      "trace_id": "trace_001"
    }
  ]
}
```

### 读取

`GET /v1/evaluations/latest`

- 鉴权：browser session 或 control token。
- 无数据：`404 EVALUATION_NOT_FOUND`。

`GET /v1/evaluations/datasets`

- 鉴权：browser session 或 control token。
- 用途：从已保存 evaluation run 汇总 dataset 版本、锁定状态、case provenance 覆盖、latest run 和 regression gate 摘要。

### CLI

```bash
uv run agentguardctl eval import /path/to/evaluation-run.json
```

## 配置审计 findings 只读接口

`GET /v1/config-audit/findings?trace_id=&target_id=&target_type=&severity=&limit=`

- 鉴权：browser session 或 control token。
- 数据来源：`/v1/config-audit/evaluate` 写入的 `config_audit_findings`。
- 返回 finding 原文，并附带 `runtime`、`target_type`、`target_id`、`trace_id`、`event_id`、`timestamp`。

## OpenClaw 插件验证状态接口

OpenClaw 状态不是每次 Dashboard 刷新实时 shell 探测，而是最近一次 verify 上报结果。

### 写入

`PUT /v1/adapters/openclaw/status`

- 鉴权：control token。
- 写入方：`agentguardctl openclaw verify --record` 或 `scripts/openclaw-plugin-dev.mjs verify --record`。

```json
{
  "status": "loaded",
  "loaded": true,
  "hook_count": 22,
  "expected_hook_count": 22,
  "last_verified_at": "2026-06-28T00:00:00+00:00",
  "error": null,
  "source": "agentguardctl"
}
```

E2E / reliability runner 会把门禁摘要写入 `capabilities.release_gates`，用于后续发布前复查。

### 读取

`GET /v1/adapters/openclaw/status`

- 鉴权：browser session 或 control token。
- 无记录：返回 `status="unknown"`。

## 前端接入状态

以下 Dashboard 展示已接入：

- `EvaluationPage` 读取 `/v1/evaluations/latest`，展示 latest run、ASR before/after、per-attack ASR 和 cases 样本追踪。
- `OverviewPage` 与 `EvaluationPage` 只展示当前审计窗口内逻辑唯一策略评估的决策、介入、标注和判定延迟。
- 当前兼容路径读取 `/v1/audit/events` 并将窗口完整性保持为未知；不再自动请求 `/v1/metrics/eval`。
- `SystemPage` 读取 `/v1/adapters/openclaw/status`，展示 OpenClaw verify/heartbeat、hook 覆盖、版本、来源和错误状态。
- `SystemPage` 读取 `/v1/config-audit/findings`，展示配置审计 finding 明细、严重性分布、目标、建议和证据链入口。

## 证据链与溯源展示

状态标记：

- `[x]` 已完成并验证；
- `[~]` 目标契约已冻结，但代码或跨组件迁移尚未完成；
- `[ ]` 尚未实现。

详细请求、响应、字段、示例、兼容和验收目标见
[证据链与溯源 API 目标契约](08_api/evidence_trace_api_contract.md)。该目标契约已于
2026-08-05 冻结。Schema、Core 类型和 Guard API 基础双读已经支持 AuditEvent
`0.3 | 0.4`，但完整 writer、稳定 links、结构化 evidence、跨存储语义和运行时回执仍未
实现，不能把基础兼容描述为目标能力已经交付。

### 已完成

- [x] Dashboard `/evidence/:trace_id` 已升级为证据链详情，包含最终结论、六维事实、关键证据路径、攻击溯源关系、节点检查器、事件时间线、证据档案和脱敏原始证据。
- [x] 前端已区分执行前拒绝、工具结果隔离、模型输出修订、仅审计观察和审批后放行；`deny` 不再自动推断工具未调用或副作用为零。
- [x] API 与 Mock 共用证据规范化器、页面组件和图布局；API 模式失败时不实例化或回退到 Mock。
- [x] Mock 已覆盖五类代表 trace，并使用与目标 AuditEvent 一致的证据结构。
- [x] 溯源图已使用 Vue Flow、ELK Layered 和 Minimap，支持生命周期分区、关键路径、折叠、搜索、筛选、全屏、递归路径高亮及 URL/时间线/检查器同步。
- [x] Dashboard 已直接读取后端现有的 `AuditEvent.integrity.sequence`、`prev_hash`、`event_hash` 和 `canonicalization`；已删除 `evidence.audit`、`chain_index`、`entry_hash`、`previous_hash` 平行结构的读取和 Mock 生成逻辑。
- [x] 已建立本轮 API 协作契约文档，明确不新增 Dashboard 专用证据端点或独立 execution receipt 端点。
- [x] 已建立 [Provenance 丰富化后端实施要求](08_api/provenance_enrichment_backend_requirements.md)，细化节点、关系、写入时机、幂等、历史数据和跨存储验收；后端代码仍未实施。
- [x] AuditEvent JSON Schema、Core 类型和 Guard API 基础写入/读取已支持 `0.3 | 0.4`；完整跨组件迁移继续列为待办。
- [x] Dashboard 已分离 `AuditWindow` 与 `EvaluationRun`；旧 trace `metrics` 不再映射为未消费的前端领域对象，历史聚合待显式 cohort 接口上线后按需接入。
- [x] Dashboard API DTO 已允许 0.4 非策略记录的顶层策略字段为空，并以 `record_type` 和稳定 links 决定指标成员资格。
- [x] 已建立指标作用域与原子审计窗口协作契约；当前前端使用旧事件数组兼容重建，等待后端目标接口。
- [x] 2026-08-07 完成
      [运行时安全可观测阶段 0 设计冻结](04_apps/runtime_safety_observability_design.md)：
      选定 LangGraph / AttackBench 主演示链，冻结事实生产者、稳定 ID、三层状态、
      三视图联动、非对称刷新和 ETag 覆盖边界，并增加
      [共享目标 fixture](../tests/fixtures/runtime_safety_trace_v04.json)；代码实施尚未开始。

### 已冻结的目标契约

- [x] `GuardEvent` 保持 `schema_version="0.3"`；AuditEvent 默认兼容 `0.3`，完整迁移目标冻结为 `0.4`。
- [x] `runtime_outcome`、`runtime_observation` 等非策略记录允许顶层 `decision`、`risk_score`、`severity`、`blocked` 为 `null`。
- [x] `GET /v1/traces/{trace_id}` 的目标窗口字段冻结为 `audit_window.limit/returned_count/has_more`。
- [x] `POST /v1/guard/evaluate` 的目标幂等语义冻结为 `GuardEvent.event_id + 规范化请求摘要`；同内容复用原结果，不同内容返回 HTTP 409。
- [x] 证据投影默认限制冻结为正文 2000 字符、摘要 500 字符、普通数组及 context sources 20 项、资源 50 项、规则/风险因子 100 项、嵌套 6 层、单事件 evidence 64 KiB。
- [x] 运行时回执继续复用 `POST /v1/audit/events`，不新增 `/v1/runtime/outcomes`。
- [x] 执行轨迹不新增后端 ActionEvent；不扩 execution enum，不增加含义不清的 `complete` 或 JSON `snapshot_version`。

阶段 0 只完成设计、真实链选择和共享 fixture。LangGraph writer、Trace ETag、Dashboard
执行轨迹、动态刷新和 Provenance 联动均从后续阶段开始。

### 后端待完成

| 状态 | 优先级 | 待办                                                                                                     | 影响组件                                                         | 验收条件                                                                                                                                            |
| ---- | ------ | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [x]  | P0     | 冻结 AuditEvent 目标版本、`record_type`、`evidence`、`links`、字段可空性、幂等与证据边界                 | 稳定接口文档、API 目标契约                                       | D-01 至 D-05 已确认；默认 `0.3`、基础 `0.4` 兼容和完整迁移未交付状态清晰分离                                                                        |
| [x]  | P0     | 完成 AuditEvent `0.4` evaluate writer、跨存储语义与跨存储共享契约测试                                    | Guard API、Memory/PostgreSQL                                     | `policy_evaluation` 由 Guard API 写入；两种存储幂等与指标口径一致；旧记录有明确读取规则；缺失字段保持未知                                           |
| [ ]  | P0     | 完成 Adapters 与 Dashboard 的跨组件 `0.4` 共享契约测试                                                   | Adapters、Dashboard contract tests                               | 四类记录由权威生产者正确写入                                                                                                                        |
| [x]  | P0     | `POST /v1/guard/evaluate` 使用同一次策略快照完成判定和审计，只写一条 `policy_evaluation`                 | Policy store、Guard API、Audit service                           | 同一逻辑评估只有一条策略审计；审计中的 bundle、version、revision 和 digest 与实际判定一致                                                           |
| [ ]  | P0     | 移除 LangGraph Guard API 模式下的重复策略审计                                                            | LangGraph Adapter                                                | Adapter 不再为 Guard API 已写入的 `event_id + decision_id` 重复提交策略审计                                                                         |
| [ ]  | P0     | 通过现有 `POST /v1/audit/events` 回写结构化运行时结果（LangGraph Adapter）                               | LangGraph Adapter                                                | 成功、失败、未调用、隔离、修订、审批释放和观察路径均产生对应回执；未测量副作用不按零处理                                                            |
| [x]  | P0     | 通过现有 `POST /v1/audit/events` 回写结构化运行时结果（OpenClaw Plugin，最小覆盖集）                     | OpenClaw Plugin、Guard API                                       | 执行前拒绝、审批拒绝/超时、审批放行、工具结果隔离/改写产生回执并关联 `policy_audit_id`；observation 迁移至 `0.4`；allow 后 executed/measured 确证不在本期范围 |
| [x]  | P0     | 统一 `audit_id` 幂等行为                                                                                 | Guard API、Memory store、PostgreSQL store、provenance writer     | 新写入成功；同 ID 同内容重试成功且不延长哈希链；同 ID 不同内容返回 `409 AUDIT_ID_CONFLICT`                                                          |
| [x]  | P0     | 统一证据脱敏和有界投影                                                                                   | Guard API、Adapters、审批证据工具                                | 敏感键和值不进入浏览器可读字段；字符串、数组、嵌套深度和总大小均受限                                                                                |
| [x]  | P0     | 指标只统计逻辑唯一的 `policy_evaluation`                                                                 | Metrics service、Memory/PostgreSQL queries                       | runtime outcome/observation 不增加 allow/ask/deny；旧重复策略审计不会重复计数；`blocked_count` 明确为策略介入口径                                   |
| [x]  | P0     | 新增原子 `GET /v1/audit/window`                                                                          | Guard API、Audit/Metric service、Memory/PostgreSQL store         | 同一 sequence 快照返回事件、窗口元数据和策略指标；`has_more` 使用 `limit + 1`；并发写入不移动窗口                                                   |
| [x]  | P1     | 新增显式 cohort 的 `GET /v1/metrics/policy-evaluations`                                                  | Guard API、Metric service                                        | 必须回显 evaluated range、outcomes as-of、去重方式、分母和覆盖率；不提供无范围“全部历史”                                                            |
| [ ]  | P1     | 在窗口与历史指标响应中按 `action_id` 汇总授权终态与运行时执行覆盖                                        | Approval service、Adapters、Metric service                       | 与策略 cohort 共用 snapshot/outcomes-as-of；deny/审批拒绝无回执时执行结果保持未知；只有 `not_invoked` 回执进入确认阻止统计                          |
| [ ]  | P1     | 在 GuardDecision 和 AuditEvent 中增加同构的 `risk_breakdown`                                             | Core merge、GuardDecision、Guard API                             | 每个检测因子及 max 聚合过程可追溯；最终分数和决定一致；旧决策不补造分解                                                                             |
| [ ]  | P1     | 按 [详细实施要求](08_api/provenance_enrichment_backend_requirements.md) 扩展 provenance 写入的节点和关系 | Guard API provenance writer/query                                | 仅对新事件写入任务、来源、上下文、意图、动作、资源、规则、策略、决策、审批、结果、审计和复核；ID 稳定，无前端坐标，不读取时补造或自动回填历史 Trace |
| [ ]  | P1     | 为 trace 查询增加明确的窗口完整性信息                                                                    | Trace service、Memory/PostgreSQL store                           | Dashboard 不再根据“恰好返回 1000 条”猜测截断；旧客户端可忽略新增字段                                                                                |

### 运行时安全观测后续阶段

- [ ] **事实链实施**：LangGraph 主演示链真实产生唯一 `policy_evaluation`、审批终态、
      `tool_call_started` 和 `runtime_outcome`，所有记录通过稳定 `action_id` 关联；未观察
      start 时不产生 start 事件；policy override 产生的空审批资源由 Guard API 使用已规范化、
      已脱敏的资源目标回退。
- [ ] **前端静态投影**：Dashboard 以 `action_id` 聚合多次策略检查、Approval 和 outcome，
      在证据链详情实现“执行轨迹 / 溯源关系 / 审计记录”，不新增一级页面。
- [ ] **视图联动**：执行动作、Provenance action node 和 AuditEvent 通过原始稳定 ID
      双向定位；图更新保留筛选、折叠、选择和视口锚点。
- [ ] **动态刷新**：Trace 与 Provenance 分别支持 ETag/304；Trace ETag 覆盖 approvals
      等全部可变响应内容；执行轨迹约 2 秒条件轮询，Provenance 按需校准。
- [ ] **真实联调门禁**：共享 fixture 通过 Schema 和投影契约测试后，再用真实
      LangGraph + Guard API + Memory/PostgreSQL 跑同一场景；真实链通过前不得把 fixture
      或 Mock 录屏作为交付证据。
- [ ] **OpenClaw 增强链**：稳定 `toolCallId`、0.4 outcome、审批释放和断线恢复通过后，
      再升级为等价跨运行时演示，不阻塞 LangGraph 主链交付。

### 前端待后端实现后完成

- [ ] 根据冻结后的 `context_sources` 结构决定是否从字符串摘要升级为结构化来源对象。
- [ ] 后端提供 `audit_window.has_more` 后，将当前“是否截断未知”升级为服务端确认的完整或截断状态。
- [x] 非策略记录顶层策略字段允许为空时，Dashboard API DTO 保持 null，并只从真实策略评估读取策略结论。
- [ ] 后端原子窗口上线后，将 API data source 从旧 `/audit/events` 兼容重建切换到 `/audit/window`，并直接使用服务端 `has_more` 与 sequence scope。
- [ ] 基于已冻结的运行时安全共享 fixture，增加真实 Guard API 的四类 `record_type`、五类干预、幂等冲突和 provenance 节点跨端契约测试。

### 前端后续优化

- [x] 已在不削减 ELK 分层布局、Minimap、折叠、搜索、筛选和路径高亮能力的前提下，将 ELK Layered 拆为独立模块 Worker，并在组件卸载时释放。生产构建的溯源图主线程 chunk 已由约 1.67 MB（gzip 约 521 KB）降至约 240 KB（gzip 约 79 KB）；ELK Worker 独立约 1.43 MB（gzip 约 423 KB），默认 500 KB chunk 警告已消除。
