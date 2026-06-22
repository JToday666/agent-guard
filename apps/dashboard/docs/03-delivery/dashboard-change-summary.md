# Dashboard 改动说明

## 1. 改动范围

本次只修改 `apps/dashboard/**`。Guard API、`agentguard-core`、运行时适配器、测试夹具和根目录工程配置均未改动。

## 2. 数据与通信

- 新增 `DashboardDataSource`，由 Vite 启动 mode 显式选择 API 或 Mock，接口失败时不自动切换数据源。
- API 模式接入 browser session exchange/me、HttpOnly Cookie、内存 CSRF token、审批 nonce、审计事件、评测指标、待审批列表和健康检查。
- Vite 将 `/api/v1/*` 和 `/api/health` 代理到 Guard API，默认目标为 `http://127.0.0.1:8088`。
- Guard API DTO 先经 mapper 转换为 Dashboard ViewModel；缺失指标显示 `--`，不补造评测事实。
- 上一轮完成后等待 10 秒，再串行刷新事件、指标、审批和健康状态；处理审批后立即刷新。
- Skeleton 仅用于首次加载；后台刷新、空数据和普通 stale 状态保留当前页面与用户选择，不重建主体布局。

## 3. 闭环功能

- 总览：事件量、阻断率、待审批、FPR、延迟、决策趋势、攻击类型和高风险事件下钻。
- 事件：决策/运行时/规则/文本筛选、快速筛选、20 条分页、键盘打开详情、关联 Trace/Case/审批、脱敏 Raw JSON。
- 审批：按风险和到期时间排序，展示任务、动作、影响和规则证据；支持 `allow_once` 与 `deny`，覆盖 CSRF、nonce、过期和提交状态。
- 链路：仅按真实 `trace_id` 聚合事件，提供链路列表、时间序列和事件证据下钻。
- 评测：展示 ASR 前后对比、Block Rate、FPR、判定延迟和样本证据；API 未提供 ASR 时保持不可用。
- 系统：展示 Guard API、数据库、浏览器会话、轮询、数据源和审批队列状态。

## 4. 页面与工程质量

- 重构为清晰的 API、data source、store、page、shared component 和 formatter 分层。
- 统一决策、风险、链路状态、时间与数据新鲜度文案。
- 增加 loading、error、empty、stale/partial、disabled 和 not-found 状态。
- 完善 360px 手机、平板和桌面布局；侧栏在小屏变为菜单，详情抽屉在小屏全屏显示。
- 补充键盘操作、焦点进入/恢复、Esc 关闭、表格语义、图表 accessible name 和 reduced-motion。
- 删除无路由引用的 `AdvancedPage.vue`、重复场景数据导出和无效果路由守卫。
- README 页面逻辑说明完整保留，仅校正 Dashboard 与 Guard API/Core 的边界表述。

## 5. 命名

新增普通 TypeScript、API、工具和测试文件使用 `kebab-case`；Vue 页面与组件使用 `PascalCase`；Pinia 模块使用 `camelCase`，store 函数使用 `useXxxStore`。组件目录使用 `PascalCase`，普通目录使用 `kebab-case`。
