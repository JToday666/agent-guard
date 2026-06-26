# Dashboard 与审批流

## 1. 文档定位

Dashboard 是 AgentGuard 的监督端。它只通过 Guard API / Control Plane 获取数据和提交审批，用于展示审计事件、告警、阻断记录、审批、调查链路和评测指标。

Dashboard 前端采用 Vue 3 + TypeScript + Sass + Pinia，使用 pnpm 管理依赖。

Dashboard 不做用户登录，不保存长期 token，不生成 launch code，不负责启动浏览器。启动链接由 launcher 通过 Guard API 生成，Vue 只通过 URL query 中的 `launch_code` 换取 browser session。

关联入口：

- [接口契约与事件模型](../02_core/interface_contract.md)
- [系统总体架构](../01_overview/architecture.md)
- [演示脚本](../06_delivery/demo_script.md)

## 2. 模块职责

| 当前页面 | 职责                                                                                      |
| -------- | ----------------------------------------------------------------------------------------- |
| 总览     | 展示事件、风险、阻断、审批和评测概况                                                      |
| 调查     | 筛选 AuditEvent，按 `trace_id` 进入调查详情                                               |
| 调查详情 | 优先读取 Trace 详情接口生成时间线，失败时回退已加载审计事件窗口，并按 `event_id` 定位证据 |
| 审批     | 展示 pending approval，处理 `allow_once` 和 `deny`                                        |
| 评测     | 展示 Block Rate、FPR、FNR、Latency；ASR 仅在接口提供 before / after 数据时展示            |
| 系统状态 | 展示 Guard API、数据源健康状态和只读策略快照                                              |

## 3. 数据来源

```text
GET  /v1/audit/events
GET  /v1/metrics/eval
GET  /v1/approvals/pending
GET  /v1/traces/{trace_id}
GET  /v1/policies/current
GET  /v1/policies/history
GET  /health?check_db=true
POST /v1/approvals/{id}/resolve
```

Dashboard 不直接读取 LangGraph、OpenClaw、Mock Tools 或 AttackBench runner 的内部状态。调查详情优先读取 `GET /v1/traces/{trace_id}`；该接口失败时，前端只使用已加载的 `GET /v1/audit/events` 事件窗口按 `trace_id` 做局部回退，不补造链路事实。

## 4. 鉴权边界

Dashboard 使用 HttpOnly browser session 访问 Guard API。状态改变请求必须带 CSRF token，审批 resolve 必须额外提交 approval nonce。

长期凭证不得进入前端：

```text
AGENTGUARD_CONTROL_TOKEN
AGENTGUARD_ADAPTER_TOKEN
Authorization Bearer token
```

## 5. 页面优先级

| 阶段    | 页面                                       |
| ------- | ------------------------------------------ |
| 当前    | 总览、调查、调查详情、审批、评测、系统状态 |
| P1 规划 | 扩展 trace 和运行时指标能力                |
| P2 规划 | OpenClaw 配置审计、审计完整性              |

## 6. 展示原则

- 每个告警必须展示原因，不只显示“危险”。
- 阻断记录必须显示工具名、参数、资源目标、命中规则和用户任务。
- 指标页必须区分 defense before / after。
- 审批页必须说明放行风险，避免只提供按钮。

## 7. P0/P1/P2 开发边界

| 阶段 | 交付                                         |
| ---- | -------------------------------------------- |
| P0   | 调查列表、阻断记录、基础总览、Dashboard 审批 |
| P1   | trace 时间线、指标评测、CLI 审批             |
| P2   | OpenClaw 社交审批、配置审计、审计完整性      |

P0 Dashboard 审批是最小人工审批闭环：

```text
Core 返回 ask
→ Core 创建 pending approval
→ Dashboard 展示待审批
→ 用户 allow_once / deny
→ Adapter wait 收到结果
→ 工具继续或取消
→ AuditEvent 更新
```

P0 不做永久放行、多渠道审批、审批策略配置或 OpenClaw 社交审批。

## 8. 验收证据

1. `deny` 事件能出现在调查列表。
2. 阻断记录显示 `reason`、`rule_hits`、`resource_targets`。
3. `ask` 事件能进入审批中心，并可由 Dashboard resolve 为 `allow_once` 或 `deny`。
4. 调查详情能读取 Trace detail，并在接口失败时显示局部回退状态。
5. 指标页能展示 AttackBench 已提供的 Block Rate、FPR、FNR、Latency 和可用 ASR。
6. 系统页能展示只读策略快照和最近历史。
7. Dashboard 不直接访问 runtime 内部数据。
8. Dashboard 不保存长期 token，审批 resolve 使用 browser session、CSRF token 和 approval nonce，Adapter 能通过 wait 接口收到审批结果。
