# Dashboard 与审批流

## 1. 文档定位

Dashboard 是 AgentGuard 的监督端。它只通过 Guard API / Control Plane 获取数据和提交审批，用于展示审计事件、告警、阻断记录、审批、调查链路和评测指标。

Dashboard 前端采用 Vue 3 + TypeScript + Sass + Pinia，使用 pnpm 管理依赖。

本文负责页面职责、数据来源、鉴权边界和交付范围；信息架构、视觉层级、交互模式和前端实现要求由 [Dashboard 前端与 UI 设计规范](dashboard_ui_spec.md) 统一约束。

Dashboard 不做用户登录，不保存长期 token，不生成 launch code，不负责启动浏览器。启动链接由 launcher 通过 Guard API 生成，Vue 只通过 URL query 中的 `launch_code` 换取 browser session。

关联入口：

- [Dashboard 前端与 UI 设计规范](dashboard_ui_spec.md)
- [接口契约与事件模型](../02_core/interface_contract.md)
- [系统总体架构](../01_overview/architecture.md)
- [演示脚本](../06_delivery/demo_script.md)

## 2. 模块职责

| 当前页面   | 路由                       | 职责                                                                                                          |
| ---------- | -------------------------- | ------------------------------------------------------------------------------------------------------------- |
| 安全总览   | `/overview`                | 展示事件、风险、阻断、审批、评测概况、规则命中 TopN、审计完整性摘要                                           |
| 事件调查   | `/investigations`          | 筛选审计事件，支持按决策、运行时、严重性、事件类型、攻击类型、规则筛选，导出 CSV，点击行进入证据链            |
| 证据链     | `/evidence`                | 汇总同一任务的证据链入口，按最新事件排序进入详情                                                              |
| 证据链详情 | `/evidence/:trace_id`      | 优先读取 Trace 详情接口生成时间线，展示溯源图与节点证据抽屉，时间线与溯源图联动，失败时回退已加载审计事件窗口 |
| 人工审批   | `/approvals/:approval_id?` | 展示待处理审批，处理 `allow_once` 和 `deny`                                                                   |
| 安全评测   | `/evaluation`              | 展示阻断率、误报率、漏报率、判定延迟、混淆矩阵、运行时延迟对比；攻击成功率仅在接口提供防护前后数据时展示      |
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

Dashboard 不直接读取 LangGraph、OpenClaw、本地工具或 AttackBench runner 的内部状态。证据链页优先读取 `GET /v1/traces/{trace_id}`；该接口失败时，前端只使用已加载的 `GET /v1/audit/events` 事件窗口按 `trace_id` 做局部回退，不补造链路事实。溯源图读取 `GET /v1/traces/{trace_id}/provenance`，失败时不影响审计时间线显示。

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
- 阻断记录必须显示工具名、参数、资源目标、命中规则和用户任务；命中规则展示可读名称，不展示 P 开头的内部数字编号。
- 指标页必须区分防护前后效果。
- 审批页必须说明放行风险，避免只提供按钮。
- 溯源图节点使用固定宽高、多行截断和详情侧栏承载长文本；边标签只保留短动作词，避免覆盖节点内容。
- API 模式遇到数组、链接、元数据、发现项或适配器状态字段缺省时，前端按空集合或“未提供”降级；局部接口失败只影响对应区块，不让整个 Dashboard 白屏。

## 7. 已交付边界

P0、P1 关键路径和部分 P2 功能均已交付：

- P0：事件调查列表、阻断记录、基础总览、Dashboard 审批、审计完整性
- P1：证据链时间线、溯源图、指标评测、混淆矩阵
- P2（已完成）：OpenClaw 验证、Hook 覆盖与心跳状态展示，配置审计发现项明细，审计完整性完整展示，规则命中 TopN，运行时延迟对比

## 8. 验收证据

1. `deny` 事件能出现在调查列表。
2. 阻断记录显示原因、命中规则、资源目标；内部 `rule_hits` 仅用于筛选和 API 传参，页面、抽屉和导出内容不展示规则编号。
3. `ask` 事件能进入审批中心，并可由 Dashboard resolve 为 `allow_once` 或 `deny`。
4. 调查详情能读取 Trace detail，并在接口失败时显示局部回退状态。
5. 指标页能展示最新评测的攻击成功率、按攻击类型统计和评测样本，以及当前审计窗口派生的阻断率、误报率、漏报率、判定延迟。
6. 系统页能展示只读策略快照、最近历史、OpenClaw 验证与心跳状态和配置审计发现项明细。
7. Dashboard 不直接访问运行时内部数据。
8. Dashboard 不保存长期 token，审批 resolve 使用 browser session、CSRF token 和 approval nonce，Adapter 能通过 wait 接口收到审批结果。
9. 封笔验证包含 `pnpm --filter @agentguard/dashboard typecheck`、`pnpm --filter @agentguard/dashboard build`、`pnpm --filter @agentguard/dashboard test:unit`、`pnpm --filter @agentguard/dashboard test:e2e` 和 `pnpm --filter @agentguard/dashboard test:e2e:api`。
