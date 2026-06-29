# Dashboard 数据流与状态

## 1. 模块边界

Dashboard 页面通过 Pinia store 获取状态，不直接发起 Guard API 请求，也不直接引用场景数据。

```text
Page / Layout
→ authStore / dashboardStore
→ DashboardDataSource
→ ApiDashboardDataSource 或 MockDashboardDataSource
→ ViewModel
```

后端 DTO 在 `src/api/guard-api-mappers.ts` 中转换为页面使用的 ViewModel。页面不解释或补造后端未提供的安全事实。

## 2. 数据源

数据源由 Vite mode 显式选择：

- `pnpm --filter @agentguard/dashboard dev`：读取 Guard API。
- `pnpm --filter @agentguard/dashboard dev:mock`：读取本地场景数据。

API 请求失败时不会自动切换数据源。场景模式和 API 模式使用相同的 `DashboardDataSource` 接口。

API 模式当前读取的监督端接口包括：

- `GET /v1/audit/events`
- `GET /v1/audit/integrity`
- `GET /v1/metrics/eval`
- `GET /v1/approvals/pending`
- `GET /v1/traces/{trace_id}`
- `GET /v1/traces/{trace_id}/provenance`
- `GET /v1/policies/current`
- `GET /v1/policies/history`
- `GET /health?check_db=true`
- `POST /v1/approvals/{approval_id}/resolve`

## 3. 浏览器会话

API 模式的初始化顺序：

1. URL 存在 `launch_code` 时，调用 browser exchange。
2. exchange 成功后从地址栏移除 `launch_code`。
3. URL 不存在 `launch_code` 时，调用 browser me 恢复会话。
4. browser session 由 HttpOnly Cookie 携带。
5. CSRF token 只保存在 `authStore` 内存状态中。
6. 审批 resolve 同时提交 CSRF token 和 approval nonce。

Dashboard 不生成 launch code，不保存长期 token，也不将鉴权状态写入持久化存储。

## 4. 刷新与失败恢复

`dashboardStore` 在上一轮完成后等待 10 秒，再串行请求事件、指标、审批、健康状态和只读策略状态。页面不可见时暂停轮询，恢复可见后立即刷新；审批提交后立即刷新。证据链详情只在打开 `/evidence/:trace_id` 时按需请求。Skeleton 只在首次请求时显示，合法空数据不重复进入 loading。后台刷新和短暂失败保留现有页面、筛选、选择和详情状态；相同事件、指标、评测和审批数据保留现有响应式引用。

Store 状态包括：

- `loading`：首次加载。
- `ready`：本轮数据完整。
- `stale`：部分请求失败，但保留最近一次成功数据。
- `error`：首次请求失败且没有可展示数据。

Browser session 无效或过期时不属于普通 stale：Dashboard 停止轮询、清除内存 CSRF 状态，并进入需要由本机启动器重新打开的鉴权错误态。

事件接口成功而指标接口失败时，只使用同一批真实审计事件派生基础计数；FPR、FNR 等依赖标注的数据保持不可用。

证据链详情请求失败时，详情页回退到已加载审计事件窗口中同一 `trace_id` 的局部证据，并显示局部失败状态。策略接口失败只影响系统页策略区块，不触发全局鉴权错误态，除非 Guard API 返回 session 失效。

## 5. 页面消费

- 安全总览：指标、决策趋势、攻击类型分布、规则命中 TopN、防御效果摘要、审计完整性摘要、高风险事件。
- 事件调查：审计列表、搜索、多维筛选（decision/runtime/severity/event_type/attack_type/rule）、脱敏详情、CSV 导出，规则选项只来自真实 `rule_hits`。
- 人工审批：pending 队列、`allow_once` / `deny`，并用已加载审计事件按 `approval_id` 补齐关联事件、规则命中和 Agent 行为。
- 证据链：优先读取证据链详情接口，按真实事件时间排序展示；展示溯源图与节点证据抽屉，时间线与溯源图联动；接口失败时回退到当前审计事件窗口，并按 `event_id` 定位证据。
- 安全评测：展示接口或场景数据已提供的 Block Rate、FPR、FNR 和平均判定延迟；混淆矩阵由 `is_malicious + blocked` 派生；runtime 延迟对比由 `latency_ms` 字段派生；ASR 仅在 before / after 数据同时存在时展示。
- 系统状态：展示会话、健康检查、轮询、数据新鲜度、只读策略快照 / 历史、审计链完整性、运行时适配器活动（LangGraph/OpenClaw）、配置审计摘要。
