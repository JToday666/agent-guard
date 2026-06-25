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

`dashboardStore` 在上一轮完成后等待 10 秒，再串行请求事件、指标、审批和健康状态。页面不可见时暂停轮询，恢复可见后立即刷新；审批提交后立即刷新。Skeleton 只在首次请求时显示，合法空数据不重复进入 loading。后台刷新和短暂失败保留现有页面、筛选、选择和详情状态；相同事件、指标、评测和审批数据保留现有响应式引用。

Store 状态包括：

- `loading`：首次加载。
- `ready`：本轮数据完整。
- `stale`：部分请求失败，但保留最近一次成功数据。
- `error`：首次请求失败且没有可展示数据。

Browser session 无效或过期时不属于普通 stale：Dashboard 停止轮询、清除内存 CSRF 状态，并进入需要由本机启动器重新打开的鉴权错误态。

事件接口成功而指标接口失败时，只使用同一批真实审计事件派生基础计数；FPR、FNR 等依赖标注的数据保持不可用。

## 5. 页面消费

- 总览：指标、决策趋势、攻击类型分布和高风险事件。
- 调查：审计列表、筛选和脱敏详情。
- 审批：pending 队列和 `allow_once` / `deny`。
- 调查详情：按相同 `trace_id` 的真实事件排序展示，并按 `event_id` 定位证据。
- 评测：展示接口或场景数据已提供的指标，不推断 ground truth。
- 系统：展示会话、健康检查、轮询和数据新鲜度。
