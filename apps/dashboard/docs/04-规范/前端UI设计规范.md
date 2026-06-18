# 前端 UI 设计规范

本文约束 `apps/dashboard/**` 中用户可见页面、共享 UI、交互组件、表单、表格、状态展示、样式和布局的实现。目标是让 Dashboard 在真实数据、异常状态、长文本、小屏和多窗口尺寸下仍然可读、可用、可维护。

## 1. 基本原则

- 页面只呈现完成当前任务所需的信息和操作。
- Dashboard 是监督端工作台，不是展示型页面；优先服务事件排查、风险解释、审批处理和指标对比。
- 用户可见页面与共享 UI 禁止写入面向开发者、评委或设计评审的说明性文案，包括平台故事、视觉策略、Mock/Coming Soon、架构解释、布局说明、工作区理念、使用建议和开发注释。
- 设计文档可以解释产品意图、阶段边界和取舍；用户可见 UI 只能呈现任务、状态、证据、操作和结果。
- 不为局部视觉效果引入复杂实现、重复组件或不可测试逻辑。
- 修改 UI 时必须同时考虑加载、失败、空数据、权限不足、长文本、小屏和慢网络。

## 1.1 信息密度原则

- 默认视图只展示当前排查或审批路径必须使用的信息。
- 事件表默认列优先展示 `time`、`decision`、`risk_score`、`severity`、`blocked`、`runtime`、`tool`、`resource`、`reason`。
- 长 ID、长路径、长规则名、证据详情、原始 JSON、P1/P2 扩展字段进入抽屉、展开行、详情页或复制菜单，不挤占默认表格。
- 指标页默认展示结论性指标，样本明细、误报/漏报证据和原始报告进入下钻区域。
- 同一页面不得同时用大卡片、宽表格和复杂图谱承载同一业务事实。

## 1.2 阶段能力原则

- UI 必须区分 P0、P1、P2 能力，不能把 P1/P2 API 或页面写成 P0 必备功能。
- P0 只承诺已在接口契约中列为 P0 的 Core API、AuditEvent 展示能力和最小 Dashboard 审批能力。
- P1/P2 能力未启用时，不显示为可点击的主操作；如需要保留上下文，使用禁用态或阶段说明状态。
- 阶段未启用、API 不存在、权限不足、数据未生成、数据过期时，使用 `empty`、`disabled`、`stale`、`forbidden`、`partial` 等状态，不写 `Mock`、`Coming Soon` 或演示占位文案。
- Dashboard 不推断 redteam ground truth；评测结果必须来自 AttackBench 报告或 Core API。

## 2. 命名规范

新增文件和重命名文件必须使用以下统一标准：

| 文件类型 / 目录                          | 命名风格     | 示例                 |
| ---------------------------------------- | ------------ | -------------------- |
| 普通 `.ts` / `.js` 文件                  | `kebab-case` | `user-service.ts`    |
| 类型声明 `.d.ts`                         | `kebab-case` | `api-types.d.ts`     |
| Vue 组件（`components / views / pages`） | `PascalCase` | `UserProfile.vue`    |
| Composables                              | `camelCase`  | `useAuth.ts`         |
| Pinia store 模块                         | `camelCase`  | `userStore.ts`       |
| 路由文件                                 | `kebab-case` | `public-routes.ts`   |
| API 文件                                 | `kebab-case` | `leaderboard-api.ts` |
| 工具函数                                 | `kebab-case` | `format-date.ts`     |
| 自定义指令                               | `kebab-case` | `v-permission.ts`    |
| 文件夹（普通）                           | `kebab-case` | `user-profile/`      |
| 组件文件夹                               | `PascalCase` | `UserAvatar/`        |
| 视图文件夹                               | `PascalCase` | `EvaluationDetail/`  |

- Vue 组件名使用 PascalCase：`RiskScoreCard`、`AuditEventTable`。
- composable 函数名使用 `useXxx`：`useAuditEvents`。
- Pinia store 函数名使用 `useXxxStore`：`useDashboardStore`。
- 类型名使用 PascalCase：`AuditEventRow`、`RiskSeverity`。
- 布尔值使用明确语义：`isLoading`、`hasError`、`canResolveApproval`。
- 事件回调用动词短语：`handleRefresh`、`handleResolveApproval`。
- 不使用含糊命名：`data`、`list`、`temp`、`info`、`common2`、`newComponent`。

## 3. 目录组织

- 页面只编排数据、状态和组件，不直接散落 API 请求细节。
- API 字段进入页面前应通过 service、mapper 或 formatter 收敛。
- 共享组件不依赖具体页面 store；通过 props、emits 或 slot 通信。
- 单文件过大、职责混杂或重复逻辑出现时，优先拆分到同目录下的专用组件或 composable。

## 4. 复用与一致性

- 同一业务语义只能有一套主要实现：风险等级、决策状态、审批状态、指标卡、空态、错误态不得各自实现。
- 按钮、输入框、表格、弹窗、标签、徽章、分页、Toast、空态和错误态优先复用既有组件。
- 颜色、字号、间距、圆角、阴影和层级使用统一 tokens 或变量，不在页面里散落魔法值。
- 指标名称、状态文案、风险等级、时间格式、分数格式必须统一。
- 抽取公共逻辑必须减少真实重复和维护成本；不能为了“更优雅”增加抽象层。

## 5. 状态完整

所有异步、可失败、可为空、可禁用、受权限控制的 UI 必须覆盖必要状态：

```text
idle
loading
success
error
empty
disabled
forbidden
not-found
timeout
partial
offline
stale
```

- 用户触发操作后立即给反馈。
- loading 时防止重复提交。
- error 显示原因和可执行下一步。
- empty 说明当前为空的原因和下一步。
- disabled 必须能解释原因，不能只变灰。
- 局部模块失败不得导致整个页面空白。
- 长任务必须显示等待、运行中、成功、失败、取消、超时等状态。

## 6. 防错与可用性

- 表单字段必须有 label、校验、错误提示和提交中状态。
- 提交前能检查的错误，不等接口失败后才提示。
- 删除、覆盖、重跑、取消审批等危险操作必须确认影响范围。
- 用户已输入内容不得因切换 tab、局部刷新或接口失败而意外丢失。
- 表格必须支持必要的排序、筛选、分页、复制或展开查看。
- 高密度表格必须有默认列、可选列和详情承载位置；默认列优先保证横向扫描，不能为了展示完整字段导致主路径不可读。
- 表格单元格必须定义截断、换行、复制和展开策略；资源路径、规则 ID、trace ID、case ID、错误信息不能撑破列宽。
- 大数据量列表优先使用分页；确需虚拟列表时必须保证键盘访问、焦点恢复和行详情打开逻辑可用。
- 长 ID、长路径、长规则名、长错误信息必须有截断、换行、复制或展开策略。
- 颜色不能作为唯一信息载体，必须配合文本、图标或形状。
- 审批按钮必须展示提交中、失败、权限不足、CSRF 未就绪、approval nonce 缺失或过期状态。
- 审批放行、拒绝、重跑、取消等会改变运行时结果的操作必须说明影响范围；放行动作必须说明可能产生的工具副作用。

## 7. 响应式与多窗口抗压

页面必须在常见窗口尺寸下可用：

```text
360x640
390x844
768x1024
1024x768
1366x768
1440x900
1920x1080
```

- 使用 CSS Grid、Flexbox、media query、container query、minmax、clamp 和合理 overflow。
- 固定格式 UI 如工具栏、表格列、状态标签、指标卡必须有稳定尺寸约束，避免动态内容挤压变形。
- 长文本不得遮挡按钮、图标、表格列头或后续内容。
- 小屏优先保留主任务路径，次级信息可折叠、换行或进入详情。
- 桌面布局可以使用固定 top bar、sidebar、main workspace 和右侧 drawer。
- 平板布局中 sidebar 必须可折叠，drawer 可以占据更宽区域但不得遮挡主操作反馈。
- 手机布局中 sidebar 变为菜单，drawer 变为全屏详情或 bottom sheet，表格只保留核心列，图表纵向堆叠。
- 不用 JS 监听尺寸实现普通响应式；虚拟列表、图表、拖拽分栏等例外必须说明原因。

## 8. 语义与可访问性

- 点击操作用 `<button>`。
- 页面跳转用 `<a>` 或路由链接。
- 表单字段必须有 `<label>` 或等价 accessible name。
- 数据表格使用 `<table>` 语义或等价表格组件。
- 页面结构使用 `header`、`main`、`nav`、`section`、`article`。
- 图标按钮必须提供可访问名称。
- 交互元素必须可键盘访问，并有可见 focus 状态。
- 弹窗、抽屉、菜单必须处理 focus 进入、恢复和 Esc 关闭。

## 9. 前端安全

- 用户输入、后端报告正文、日志、错误信息默认按文本渲染。
- 禁止默认使用 `v-html`。
- 必须展示富文本时，先经过可信白名单清洗，并说明允许的标签、属性和 URL 协议。
- URL、文件名、下载地址、跳转地址必须校验。
- 长期凭证、secret、API key 不得出现在前端代码、前端 env、localStorage、sessionStorage、日志或 URL query 中。
- launch code、CSRF token、approval nonce、长期 token、secret、完整系统 prompt、真实敏感文件内容、真实邮箱正文和真实 API 响应默认不展示。
- 参数、资源、日志和 Raw JSON 默认按文本渲染；复制内容也必须应用同一套脱敏策略。
- secret、token、key、authorization、cookie、password、email、phone、真实路径和 API payload 必须按字段策略脱敏或摘要化展示。
- browser session 只能使用 HttpOnly Cookie，由浏览器自动携带。
- CSRF token 只保存在 Pinia 内存状态中，不做持久化。
- 鉴权状态不得持久化到 localStorage、sessionStorage、IndexedDB 或持久化 Pinia 插件。
- 权限控制以后端为准，前端只做体验层隐藏和提示。

## 10. 完成检查

修改用户可见 UI 后，至少检查：

```text
是否复用既有组件和 tokens
命名是否清晰且符合规范
目录职责是否单一
loading/error/empty/forbidden/partial 是否覆盖
表单和危险操作是否防错
长文本、长 ID、长路径是否有处理策略
360x640、768x1024、1366x768 是否可用
键盘访问和 focus 是否可用
是否误用 v-html
是否写入面向开发者或评审的页面文案
typecheck 和 build 是否通过
```
