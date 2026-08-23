# 兼容矩阵

## 当前验证目标

| 组件 | 支持/验证目标 | 说明 |
| --- | --- | --- |
| 操作系统 | Ubuntu 24.04 CI；Linux 为主要开发环境 | 其他系统可运行，但未在本轮形成同等 CI 证据 |
| Python | 3.12 | 根项目和已发布 Control Plane 包的基线；更高版本尚未形成正式矩阵 |
| uv | 0.12.5 | 由根 `[tool.uv].required-version` 和 workflow 同时固定；必须使用 `uv sync --locked --all-groups` 验证锁文件 |
| Node.js | 24.18.0 | 由根 `package.json`、`.nvmrc` 固定 |
| pnpm | 11.9.0 | 由根 `packageManager` 固定 |
| PostgreSQL | 16 | 自动 CI 的 migration/持久化目标；本地测试库名必须为 `agent_guard_test` 或以 `_test` 结尾 |
| Dashboard browser | Playwright 1.61.1 管理的 Chromium | Firefox/WebKit 尚未进入正式 CI 矩阵 |
| OpenClaw | 2026.7.1-2 为当前证据 pin；2026.6.6 为历史 23-hook 基线 | 当前源码注册 24 hooks，但真实 runtime CI 矩阵尚未恢复；R05 仍受宿主能力缺口阻塞 |
| LangGraph adapter | Python 3.12 根锁环境 | `packages/agentguard-langgraph-adapter` 声明的最低 Python 版本不等于产品 CI 矩阵 |

## 运行模式兼容性

| 模式 | PostgreSQL | 外部 Provider | 用途 | 可作为生产/效果证据 |
| --- | --- | --- | --- | --- |
| Core 最小示例 | 否 | 否 | 契约与本地判定验证 | 仅 Core 行为证据 |
| Dashboard Mock | 否 | 否 | UI 开发、浏览器回归 | 否 |
| Guard API memory test | 否 | 否 | 单元/集成测试 | 否 |
| Guard API PostgreSQL | 是 | 否 | migration、持久化和 API 集成 | 仅对应测试范围 |
| LangGraph competition contracts/demo | 可选 | stub/可选 | runner 和证据链验证 | 否 |
| LangGraph competition qualifying matrix | 按 profile | 真实外部 Provider | 固定 70×5=350 正式测评 | 完整通过后才可声明 |
| OpenClaw live gate | 可选 | 否 | 真实插件进程/hook 链路 | 仅宿主链路证据；R05 限制仍保留 |

## 版本与升级规则

- Python 包版本必须通过 `scripts/check-release-versions.py` 与发布映射检查。
- 数据库升级只允许沿 Alembic migration 向前进行；涉及审计链重写的版本必须停写升级。
- Node workspace 使用根锁文件，禁止对子包单独生成未经说明的发布锁定口径。
- 公开 `v0.1.0-beta.1`/npm Beta 1 是 22-hook 制品；当前 24-hook 源码仍沿用预发布版本号，仅可做内部构建验证。下一次发布前必须整体升版，禁止同版本覆盖不同内容。
- 兼容矩阵中的“支持”表示项目计划维护的目标；只有对应 CI/验收实际通过后，才能写成已验证结果。
- `guard_event.content_preview` 是默认关闭的 optional 响应扩展；启用后仅允许服务端脱敏、限长的模型输出/待发送消息预览，模型输入不得投影。
- `visible_source_refs` 缺失表示无法证明，可信 `[]` 表示已证明为空，非空数组表示精确可见集合；消费者不得把缺失归一为空数组，非可信 metadata 不能声明该权威事实。

安装、升级与诊断步骤见[安装、升级和故障排查](install_upgrade_troubleshooting.md)。
