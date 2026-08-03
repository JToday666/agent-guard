# Dashboard 与审批流

## 1. 文档定位

Dashboard 是 AgentGuard 的监督端。它只通过 Guard API / Control Plane 获取数据和提交审批，用于展示审计事件、告警、策略拒绝、经运行时回执确认的阻止事实、审批、调查链路和评测指标。

Dashboard 前端采用 Vue 3 + TypeScript + Sass + Pinia，使用 pnpm 管理依赖。

本文负责页面职责、数据来源、鉴权边界和交付范围；信息架构、视觉层级、交互模式和前端实现要求由 [Dashboard 前端与 UI 设计规范](dashboard_ui_spec.md) 统一约束。

Dashboard 不做用户登录，不保存长期 token，不生成 launch code，不负责启动浏览器。启动链接由 launcher 通过 Guard API 生成，Vue 只通过 URL query 中的 `launch_code` 换取 browser session。

关联入口：

- [Dashboard 前端与 UI 设计规范](dashboard_ui_spec.md)
- [接口契约与事件模型](../02_core/interface_contract.md)
- [Dashboard 指标作用域与审计窗口 API 协作契约](../08_api/dashboard_metrics_api_contract.md)
- [系统总体架构](../01_overview/architecture.md)
- [演示脚本](../06_delivery/demo_script.md)

## 2. 模块职责

| 当前页面   | 路由                       | 职责                                                                                                          |
| ---------- | -------------------------- | ------------------------------------------------------------------------------------------------------------- |
| 安全总览   | `/overview`                | 展示当前窗口审计记录、逻辑策略决定、风险、待审批、规则命中 TopN 和审计完整性摘要                              |
| 事件调查   | `/investigations`          | 按事件 ID、任务、工具、资源、规则或 Trace 搜索审计事件，支持结构化筛选、CSV 导出和证据下钻                    |
| 证据链     | `/evidence`                | 汇总同一任务的证据链入口，按最新事件排序进入详情                                                              |
| 证据链详情 | `/evidence/:trace_id`      | 优先读取 Trace 详情接口生成时间线，展示溯源图与节点证据抽屉，时间线与溯源图联动，失败时回退已加载审计事件窗口 |
| 人工审批   | `/approvals/:approval_id?` | 展示待处理审批，处理 `allow_once` 和 `deny`                                                                   |
| 安全评测   | `/evaluation`              | 分开展示独立评测运行与当前窗口的策略介入率、策略 FPR/FNR、判定延迟、介入矩阵和运行时延迟对比                  |
| 系统状态   | `/system`                  | 展示 Guard API 健康、数据库、浏览器会话、轮询状态、只读策略快照、审计链完整性、运行时适配器验证、配置审计摘要 |

## 3. 数据来源

```text
GET  /v1/audit/events
GET  /v1/audit/integrity
GET  /v1/metrics/eval
GET  /v1/evaluations/latest
GET  /v1/approvals/pending
GET  /v1/traces/{trace_id}
GET  /v1/traces/{trace_id}/provenance
GET  /v1/policies/current
GET  /v1/policies/history
GET  /v1/config-audit/findings
GET  /v1/adapters/openclaw/status
GET  /health?check_db=true
POST /v1/approvals/{id}/resolve
```

当前页面自动刷新不再请求 `GET /v1/metrics/eval`。该接口仅作为历史兼容入口保留；后端提供明确时间范围、去重方式和分母前，Dashboard 不展示其结果。

目标新增接口：

```text
GET /v1/audit/window
GET /v1/metrics/policy-evaluations?evaluated_from=&evaluated_to=&outcomes_as_of=
```

在目标窗口接口落地前，API data source 从 `GET /v1/audit/events` 建立
`has_more=unknown` 的兼容窗口，并在当前返回记录内筛选、去重逻辑
`policy_evaluation`。页面领域模型保持 `AuditWindow = scope + events + metrics`，
后端上线后只替换数据源映射。

Dashboard 不直接读取 LangGraph、OpenClaw、本地工具或 AttackBench runner 的内部状态。证据链页优先读取 `GET /v1/traces/{trace_id}`；该接口失败时，前端只使用已加载的 `GET /v1/audit/events` 事件窗口按 `trace_id` 做局部回退，不补造链路事实。溯源图读取 `GET /v1/traces/{trace_id}/provenance`，失败时不影响审计时间线显示。

真实溯源响应沿用 Guard API 原始契约：`ref_id` 是未加展示前缀的实体 ID，审计节点通过原始 `audit_id` 与 Trace 时间线联动；关系值使用 `evaluated_to`、`recorded_as`、`reviewed_by`，风险元数据使用 `risk_score`。前端只在展示层映射中文标签，不以 Mock 字段形态替代真实接口。

安全总览分别展示策略 allow、ask 和 deny。`deny` 只称为“策略拒绝”，`ask + deny` 只称为“策略介入”；二者都不证明动作实际未执行。只有运行时回执明确 `execution.status=not_invoked` 时才能展示确认阻止事实。

Dashboard 只轮询当前页面所需的数据域。页面切换时复用最近 10 秒内已成功加载的健康、审批和原子审计窗口等共享资源，仅请求目标页面缺失或过期的数据；用户主动刷新和页面恢复可见时强制检查当前页面所需资源。独立 evaluation run、历史聚合和当前窗口拥有独立状态，复用不得改变接口数据含义、轮询周期和局部失败边界。

## 4. 鉴权边界

Dashboard 使用 HttpOnly browser session 访问 Guard API。状态改变请求必须带 CSRF token，审批 resolve 必须额外提交 approval nonce。

长期凭证不得进入前端：

```text
AGENTGUARD_CONTROL_TOKEN
AGENTGUARD_ADAPTER_TOKEN
Authorization Bearer token
```

## 5. 页面现状

全部六个页面均已实现：安全总览、事件调查、证据链（隐藏详情页）、人工审批、安全评测、系统状态。

## 6. 展示原则

- 每个告警必须展示原因，不只显示“危险”。
- 策略拒绝记录必须显示工具名、参数、资源目标、命中规则和用户任务；只有运行时回执明确 `not_invoked` 时才追加“确认阻止”结论。命中规则展示可读名称，不展示 P 开头的内部数字编号。
- 指标页必须分开独立 evaluation run、当前审计窗口和历史聚合；缺失指标不跨作用域补入。
- 审批页必须说明放行风险，避免只提供按钮。
- 溯源图节点使用固定宽高、多行截断和详情侧栏承载长文本；边标签只保留短动作词，避免覆盖节点内容。Vue Flow 组件按需加载，ELK Layered 通过独立模块 Worker 执行并在组件卸载时释放，不阻塞主线程解析和布局。
- API 模式遇到数组、链接、元数据、发现项或适配器状态字段缺省时，前端按空集合或“未提供”降级；局部接口失败只影响对应区块，不让整个 Dashboard 白屏。

## 7. 已交付边界

P0、P1 关键路径和部分 P2 功能均已交付：

- P0：事件调查列表、策略拒绝与执行事实、基础总览、Dashboard 审批、审计完整性
- P1：证据链时间线、溯源图、指标评测、混淆矩阵
- P2（已完成）：OpenClaw 验证、Hook 覆盖与心跳状态展示，配置审计发现项明细，审计完整性完整展示，规则命中 TopN，运行时延迟对比

## 8. 验收证据

1. `deny` 事件能出现在调查列表。
2. 策略拒绝记录显示原因、命中规则、资源目标；只有运行时回执可确认动作未执行。内部 `rule_hits` 仅用于筛选和 API 传参，页面、抽屉和导出内容不展示规则编号。
3. `ask` 事件能进入审批中心，并可由 Dashboard resolve 为 `allow_once` 或 `deny`。
4. 调查详情能读取 Trace detail，并在接口失败时显示局部回退状态。
5. 指标页能展示最新评测的攻击成功率、按攻击类型统计和评测样本，以及当前审计窗口中逻辑唯一策略评估的介入率、策略误报率、策略漏报率和判定延迟；runtime outcome/observation 不重复计数。
6. 系统页能展示只读策略快照、最近历史、OpenClaw 验证与心跳状态和配置审计发现项明细。
7. Dashboard 不直接访问运行时内部数据。
8. Dashboard 不保存长期 token，审批 resolve 使用 browser session、CSRF token 和 approval nonce，Adapter 能通过 wait 接口收到审批结果。
9. API 模式回归使用真实溯源字段和关系值，验证风险标签、关系文案以及审计节点与时间线的双向联动。
10. 调查页轮询到新事件时，用户位于旧滚动位置则保留当前列表并提供“有新事件”入口；用户主动查看后再定位到最新事件。
11. 封笔验证包含 `pnpm --filter @agentguard/dashboard typecheck`、`pnpm --filter @agentguard/dashboard build`、`pnpm --filter @agentguard/dashboard test:unit`、`pnpm --filter @agentguard/dashboard test:e2e` 和 `pnpm --filter @agentguard/dashboard test:e2e:api`。
12. 生产构建保持溯源图组件与 ELK Worker 分离，溯源图主线程 chunk 低于 Vite 默认 500 KB 警告阈值，且不得通过调高阈值掩盖回归。
