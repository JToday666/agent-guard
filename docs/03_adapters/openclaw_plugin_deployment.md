# OpenClaw 插件部署、安装与配置

## 1. 文档定位

本文记录 AgentGuard OpenClaw 插件的本机开发安装、配置、验证、卸载和故障排查流程。插件设计、Hook 映射和事件语义见 [OpenClaw Security Plugin](openclaw_plugin.md)。

当前流程不依赖 Dashboard；OpenClaw 插件通过 Guard API adapter token 调用后端，审计、完整性和 provenance 由 Guard API 查询验证。

## 2. 前置条件

本机开发安装默认使用以下组件：

- OpenClaw `2026.6.6`，Gateway 监听 `127.0.0.1:18789`。
- 仓库根目录可运行 `pnpm` 和 `uv`。
- Guard API 可连接 PostgreSQL，并通过 `/health?check_db=true` 检查数据库。
- OpenClaw 本机 profile 允许执行插件安装、config patch、persisted plugin registry refresh 和 Gateway safe restart。

基础检查：

```bash
pnpm --filter @agentguard/openclaw-plugin test
uv run pytest tests/test_openclaw_plugin_contract.py -q
openclaw gateway status
```

## 3. `.env` 配置

仓库根目录 `.env` 提供 Guard API 和 OpenClaw 插件安装所需配置。`.env` 已被 `.gitignore` 忽略，不应提交。

最小配置：

```dotenv
AGENTGUARD_DATABASE_URL=postgresql+psycopg://postgres:<password>@127.0.0.1:5432/agent_guard
AGENTGUARD_ADAPTER_TOKEN=ag_adapter_xxx
AGENTGUARD_CONTROL_TOKEN=ag_control_xxx
AGENTGUARD_HOST=127.0.0.1
AGENTGUARD_PORT=8088
```

OpenClaw 插件安装脚本读取：

- `AGENTGUARD_ADAPTER_TOKEN`：必填。缺失或为空时安装失败，避免向 OpenClaw profile 写入空 token。
- `AGENTGUARD_HOST`：可选，默认 `127.0.0.1`。
- `AGENTGUARD_PORT`：可选，默认 `8088`。

`AGENTGUARD_ADAPTER_TOKEN` 会写入本机 OpenClaw profile，用于插件调用 Guard API 的 `Authorization: Bearer <token>` header。token 不应写入仓库、审计事件、metadata、错误消息或日志。

## 4. Guard API 启动与检查

启动 Guard API：

```bash
pnpm guard-api:dev
```

或直接运行：

```bash
uv run uvicorn guard_api.main:app --host 127.0.0.1 --port 8088
```

检查 API 和数据库：

```bash
curl -s "http://127.0.0.1:8088/health?check_db=true"
```

预期结果应显示服务健康，并且数据库检查正常。若使用非默认 host 或 port，以 `.env` 中的 `AGENTGUARD_HOST`、`AGENTGUARD_PORT` 为准。

## 5. 开发安装

正式开发安装使用 repo-local ignored staging：

```text
.openclaw-dev/agentguard-security
```

安装命令：

```bash
pnpm openclaw:plugin:install
```

该命令会执行：

1. `pnpm --filter @agentguard/openclaw-plugin build`
2. 重建 `.openclaw-dev/agentguard-security`
3. 只复制 `dist/`、`openclaw.plugin.json`、`package.json`、`README.md`
4. 备份当前 OpenClaw config 到 `.openclaw-dev/backups/`
5. 尝试卸载旧的 `agentguard-security`
6. 执行 `openclaw plugins install -l .openclaw-dev/agentguard-security`
7. patch OpenClaw config，写入 enabled、Guard API URL、adapter token 和短测试 timeout
8. 执行 `openclaw plugins registry --refresh`
9. 执行 `openclaw gateway restart --safe`
10. 轮询 `openclaw gateway status`，直到 runtime running 且 connectivity probe ok

不要直接从 `packages/agentguard-openclaw-plugin` 安装。pnpm workspace 包目录可能包含 `node_modules` symlink，会被 OpenClaw local install safety scan 拦截。

## 6. 验证

运行：

```bash
pnpm openclaw:plugin:verify
```

该命令会执行 `openclaw plugins inspect agentguard-security --runtime --json` 并校验：

- `plugin.status=loaded`
- `plugin.hookCount=16`
- `plugin.source` 或 `plugin.rootDir` 指向 `.openclaw-dev/agentguard-security`
- Gateway `Runtime: running`
- Gateway `Connectivity probe: ok`

必须存在的 hooks：

```text
before_tool_call
message_sending
before_install
tool_result_persist
gateway_start
gateway_stop
session_start
session_end
before_compaction
after_compaction
subagent_spawned
subagent_ended
model_call_started
model_call_ended
cron_changed
resolve_exec_env
```

需要人工复查时可直接运行：

```bash
openclaw plugins inspect agentguard-security --runtime --json
openclaw gateway status
```

## 7. 卸载与回滚

卸载开发安装：

```bash
pnpm openclaw:plugin:uninstall
```

该命令会：

- 备份当前 OpenClaw config 到 `.openclaw-dev/backups/`
- 删除 `plugins.entries.agentguard-security`
- 从 `plugins.load.paths` 移除 AgentGuard staging 路径和旧临时路径
- 执行 `openclaw plugins uninstall agentguard-security --force`
- 刷新 OpenClaw persisted plugin registry
- 重启 Gateway 并等待健康

默认保留 `.openclaw-dev/agentguard-security`，便于复查和快速重装。需要同时删除 staging：

```bash
pnpm openclaw:plugin:uninstall -- --clean-staging
```

卸载后再运行：

```bash
pnpm openclaw:plugin:verify
```

预期应失败并提示 `Plugin not found: agentguard-security` 或插件未加载。

## 8. 故障排查

### runtime 仍指向旧 `/tmp` staging

OpenClaw 2026.6.6 会优先使用 persisted plugin registry。若旧 registry 仍记录 `/tmp/agentguard-openclaw-plugin-install-p2*`，同 ID 插件可能覆盖 `.openclaw-dev/agentguard-security`。

处理方式：

```bash
openclaw plugins registry --refresh
pnpm openclaw:plugin:verify
```

正常状态下，`plugin.source` 应指向：

```text
/home/today/dev/agent-guard/.openclaw-dev/agentguard-security/dist/index.js
```

### install safety scan 拦截

不要安装 workspace 包目录：

```bash
openclaw plugins install -l packages/agentguard-openclaw-plugin
```

应使用：

```bash
pnpm openclaw:plugin:install
```

### `openclaw plugins validate` 报 metadata 缺失

OpenClaw 2026.6.6 的 `openclaw plugins validate --root ... --entry ...` 面向 `defineToolPlugin` simple tool plugin。当前 AgentGuard 插件是 hook-only `definePluginEntry`，因此可能返回：

```text
plugin entry does not expose defineToolPlugin metadata
```

这不是当前插件的失败标准。hook-only 插件以 runtime inspect、Gateway status 和 hook runner/E2E 验收作为真实验证依据。

### Gateway restart 短暂 1006

`openclaw gateway restart --safe` 过程中可能短暂返回 `gateway closed (1006 abnormal closure)`。安装脚本会继续轮询 `openclaw gateway status`，只要最终 `Runtime: running` 且 `Connectivity probe: ok` 即可。

## 9. E2E 复查入口

最近一次本机真实 E2E 验收报告：

```text
/tmp/agentguard-openclaw-e2e-acceptance-report.md
```

该验收使用 OpenClaw 2026.6.6、Guard API、独立 PostgreSQL 测试库和确定性 hook runner，覆盖 `before_tool_call`、`message_sending`、`before_install`、`tool_result_persist`、audit integrity 和 provenance。
