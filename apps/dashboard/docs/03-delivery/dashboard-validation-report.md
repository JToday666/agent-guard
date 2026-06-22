# Dashboard 测试与页面验证报告

验证日期：2026-06-22

## 1. 验证结论

Dashboard 已形成“总览发现风险 → 事件查看证据 → 审批处理 → 链路回溯 → 评测量化 → 系统确认状态”的前端闭环。前端请求路径和 DTO 已与当前 Guard API 源码契约逐项核对，API 与本地场景模式由环境文件显式切换。

纯 TypeScript 单元测试、源码语法、命名、安全模式和修改边界检查通过。当前执行环境版本与仓库锁定版本不一致且没有前端依赖和浏览器运行时，因此 `vue-tsc`、生产构建和真实浏览器截图验证未完成，不能将静态检查等同于完整渲染验收。

## 2. 自动检查结果

| 检查                                            | 结果   | 说明                                                                                 |
| ----------------------------------------------- | ------ | ------------------------------------------------------------------------------------ |
| Dashboard 单元测试                              | 通过   | 7/7：DTO mapper、审批状态、指标派生、趋势分桶、状态词汇、可见字段掩码、Raw JSON 脱敏 |
| 普通 `.ts` 语法检查                             | 通过   | `node --check`，排除声明文件和测试文件                                               |
| 文件与变量命名审计                              | 通过   | 符合 `前端UI设计规范.md` 中的 kebab/Pascal/camel 规则                                |
| 前端安全静态审计                                | 通过   | 未使用 `v-html`、localStorage、sessionStorage；CSRF 只在 Pinia 内存中                |
| Guard API 契约比对                              | 通过   | browser auth、audit、metrics、approvals、health 路径和字段一致                       |
| 后端/Core 修改边界                              | 通过   | 与原始包对比，受控源码无差异；运行缓存不进入交付包                                   |
| `pnpm --filter @agentguard/dashboard typecheck` | 阻塞   | 仓库要求 Node 24.15.0 / pnpm 11.5.2；环境为 Node 24.14.0 / pnpm 11.0.7               |
| `pnpm --filter @agentguard/dashboard build`     | 阻塞   | 同上，pnpm 在编译前拒绝运行                                                          |
| 浏览器响应式/交互回归                           | 未执行 | 环境无 `node_modules`、Chromium/Firefox 和 Browser 插件                              |

## 3. 单元测试输出摘要

```text
tests 7
pass 7
fail 0
duration_ms 88.783402
```

执行方式：在仓库外的 Dashboard 副本中运行 `pnpm --config.verify-deps-before-run=false run test:unit`，未安装、升级或改写项目依赖与锁文件。

## 4. 页面静态验证

| 页面 | 核心数据                        | 交互与状态                                | 静态结论 |
| ---- | ------------------------------- | ----------------------------------------- | -------- |
| 总览 | 指标、趋势、类型、高风险事件    | 刷新、下钻、loading/error/empty           | 通过     |
| 事件 | AuditEvent 默认关键列与脱敏详情 | 筛选、分页、复制、键盘打开、抽屉 Esc      | 通过     |
| 审批 | pending、风险、到期、影响、证据 | allow_once/deny、确认、禁用原因、提交反馈 | 通过     |
| 链路 | trace_id、事件序列、Case        | 列表到详情再到事件证据                    | 通过     |
| 评测 | ASR、Block Rate、FPR、延迟      | 指标和样本证据下钻、缺失值处理            | 通过     |
| 系统 | API、数据库、会话、轮询、数据源 | 手动检查、异常提示                        | 通过     |

响应式样式已覆盖 640px、768px、820/840/900px、1024px、1100/1180px 等断点，结构上满足 360px 手机、平板和桌面布局策略。由于未渲染浏览器页面，上述结论只代表模板、样式和交互代码静态检查结果。

## 5. 复验要求

在 Node 24.15.0、pnpm 11.5.2 且依赖完整的环境中，交付前还应执行：

```bash
pnpm --filter @agentguard/dashboard test:unit
pnpm --filter @agentguard/dashboard typecheck
pnpm --filter @agentguard/dashboard build
pnpm --filter @agentguard/dashboard dev:mock
```

浏览器至少复验 360x640、768x1024、1366x768；逐页检查控制台错误、筛选、分页、抽屉焦点、审批禁用/提交、API 模式会话交换以及刷新后的数据一致性。
