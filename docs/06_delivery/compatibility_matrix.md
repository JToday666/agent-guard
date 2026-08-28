# 兼容矩阵

## 当前兼容状态

| 组件 | 支持状态 | 说明 |
| --- | --- | --- |
| 操作系统 | 已支持：Ubuntu 24.04 CI；受限：其他 Linux/OS | 其他系统可能可运行，但没有同等托管 CI 证据 |
| Python | 已支持：3.12 | 根项目和已发布 Control Plane 包的验证基线；更高版本未形成支持矩阵 |
| uv | 已支持：0.12.5 | 由根 `[tool.uv].required-version` 和 workflow 同时固定；必须使用 `uv sync --locked --all-groups` 验证锁文件 |
| Node.js | 已支持：24.18.0 | 由根 `package.json`、`.nvmrc` 固定 |
| pnpm | 已支持：11.9.0 | 由根 `packageManager` 固定 |
| PostgreSQL | 已支持：16 | 自动 CI 的 migration/持久化目标；本地测试库名必须为 `agent_guard_test` 或以 `_test` 结尾 |
| Dashboard browser | 已支持：Playwright 1.61.1 管理的 Chromium | Firefox/WebKit 未支持为正式 CI 矩阵 |
| OpenClaw | 受限：证据 pin `2026.7.1-2` | 当前源码要求 24 个唯一 hook 名，注册 25 个 handler；真实 runtime CI 矩阵未恢复，OC-02 仍受宿主能力缺口阻塞 |
| LangGraph adapter | 已支持：Python 3.12 根锁环境 | strong binding 覆盖 CF-13 至 CF-16；CF-17 active-call-cache 明确未支持 |

## 运行模式兼容性

| 模式 | 支持状态 | PostgreSQL | 外部 Provider | 证据边界 |
| --- | --- | --- | --- | --- |
| Core 最小示例 | 已支持 | 否 | 否 | 仅证明 Core 契约与本地判定 |
| Dashboard Mock | 已支持 | 否 | 否 | 仅用于 UI 开发和浏览器回归 |
| Guard API memory test | 已支持 | 否 | 否 | 仅证明对应单元/集成范围 |
| Guard API PostgreSQL | 已支持 | 是 | 否 | 证明 migration、持久化和 API 集成范围 |
| LangGraph 可复现评测 | 受限 | 按 profile | stub/可选 | runner、契约和证据链可验证；历史竞赛资格不属于当前产品支持声明 |
| 历史 LangGraph 70×5 matrix | 未完成 | 按 profile | 真实外部 Provider | 350-run 没有完成，不能作为正式效果或发布证据 |
| OpenClaw live host chain | 受限 | 可选 | 否 | 仅证明对应宿主 hook 链；不解除 OC-02 strong-binding 限制 |

## 版本与升级规则

- Python 包版本必须通过 `scripts/check-release-versions.py` 与发布映射检查。
- 数据库升级只允许沿 Alembic migration 向前进行；涉及审计链重写的版本必须停写升级。
- Node workspace 使用根锁文件，禁止对子包单独生成未经说明的发布锁定口径。
- 公开 `v0.1.0-beta.1`/npm Beta 1 是 22 个 hook 名的制品；23-hook 是历史中间源码/证据基线，
  不是当前发布物或支持目标；当前未发布源码要求 24 个唯一 hook 名，并注册 25 个 handler，
  因为 `after_tool_call` 同时有通用观察和 terminal closure handler。下一次发布前必须整体升版，
  禁止同版本覆盖不同内容。
- “已支持”表示有当前代码和对应自动化验证；“受限”表示仅在表中边界内成立；“未完成/未支持”
  不得被本地演示或历史证据扩大。
- `guard_event.content_preview` 是默认关闭的 optional 响应扩展；启用后仅允许服务端脱敏、限长的模型输出/待发送消息预览，模型输入不得投影。
- `visible_source_refs` 缺失表示无法证明，可信 `[]` 表示已证明为空，非空数组表示精确可见集合；消费者不得把缺失归一为空数组，非可信 metadata 不能声明该权威事实。

安装、升级与诊断步骤见[安装、升级和故障排查](install_upgrade_troubleshooting.md)。
