# 前端 UI 设计规范

本文约束 `apps/dashboard/**` 中用户可见页面、共享 UI、交互组件、表单、表格、状态展示、样式和布局的实现。目标是让 Dashboard 在真实数据、异常状态、长文本、小屏和多窗口尺寸下仍然可读、可用、可维护。

## 1. 基本原则

- 页面只呈现完成当前任务所需的信息和操作。
- Dashboard 是监督端工作台，不是展示型页面；优先服务事件排查、风险解释、审批处理和指标对比。
- 用户可见页面与共享 UI 禁止写入面向开发者、评委或设计评审的说明性文案，包括平台故事、视觉策略、Mock/Coming Soon、架构解释、布局说明、工作区理念、使用建议和开发注释。
- 不为局部视觉效果引入复杂实现、重复组件或不可测试逻辑。
- 修改 UI 时必须同时考虑加载、失败、空数据、权限不足、长文本、小屏和慢网络。

## 2. 命名规范

- 文件和目录使用 kebab-case：`event-list.vue`、`risk-score-card.vue`。
- Vue 组件名使用 PascalCase：`RiskScoreCard`、`AuditEventTable`。
- composable 使用 `useXxx`：`useAuditEvents`。
- Pinia store 使用 `useXxxStore`：`useDashboardStore`。
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
- 长 ID、长路径、长规则名、长错误信息必须有截断、换行、复制或展开策略。
- 颜色不能作为唯一信息载体，必须配合文本、图标或形状。

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
- token、secret、API key 不得出现在前端代码、localStorage、sessionStorage、日志或 URL query 中。
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
