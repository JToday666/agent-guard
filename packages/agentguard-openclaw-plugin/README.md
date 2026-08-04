# AgentGuard OpenClaw Plugin

`@agentguard-ai/openclaw-plugin` 是 AgentGuard 的 OpenClaw runtime security plugin。它是 hook-only `definePluginEntry` 插件，不提供业务工具本身；插件负责在 OpenClaw 关键 hook 中构造 GuardEvent、调用 Guard API，并把 `allow`、`deny`、`ask` 映射为运行时控制结果。

## Hook 覆盖

默认启用 22 个 hook：

```text
before_tool_call
message_sending
before_install
before_prompt_build
llm_input
llm_output
tool_result_persist
message_received
before_message_write
before_agent_finalize
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

默认 fail-closed 阶段：

```text
before_tool_call
message_sending
before_install
before_prompt_build
llm_input
```

其他观察类 hook 以审计和证据记录为主，Guard API 不可用时不应阻断 OpenClaw 基础生命周期。

## 配置

OpenClaw plugin config 示例：

```json
{
  "guardApiBaseUrl": "http://127.0.0.1:8088",
  "adapterToken": "<AGENTGUARD_ADAPTER_TOKEN>",
  "requestTimeoutMs": 5000,
  "approvalPollIntervalMs": 1000,
  "approvalTimeoutMs": 120000,
  "approvalWaitBudgetMs": 25000,
  "diagnosticLogging": false
}
```

`adapterToken` 也可以通过 `AGENTGUARD_ADAPTER_TOKEN` 提供。`llm_input` 和 `llm_output` 若需要访问对话内容，OpenClaw 配置中应允许对应 conversation access；仓库级开发安装脚本会写入所需设置。

## 验证

在仓库根目录运行：

```bash
pnpm --filter @agentguard-ai/openclaw-plugin build
pnpm --filter @agentguard-ai/openclaw-plugin test
uv run pytest tests/test_openclaw_plugin_contract.py -q
```

开发安装、验证、E2E、reliability 和卸载：

```bash
pnpm openclaw:plugin:install
pnpm openclaw:plugin:verify
pnpm openclaw:plugin:e2e
pnpm openclaw:plugin:reliability
pnpm openclaw:plugin:uninstall
```

`pnpm openclaw:plugin:e2e` 会读取根 `.env`，触发关键 hook，并在系统临时目录输出 `agentguard-openclaw-e2e-report.json` 和 `agentguard-openclaw-e2e-acceptance-report.md`。

`pnpm openclaw:plugin:reliability` 会对注册 hook 做重复触发，使用隔离 PostgreSQL 测试库，并在系统临时目录输出 `agentguard-openclaw-reliability-report.json` 和 `agentguard-openclaw-reliability-acceptance-report.md`。

## 验收口径

`openclaw plugins validate` 主要验证 simple tool plugin metadata。当前包是 hook-only plugin，如果该命令提示缺少 tool-plugin metadata，不应单独判定为失败。有效验收应以以下证据为准：

- `pnpm openclaw:plugin:verify` 成功。
- OpenClaw runtime inspect 能看到 `agentguard-security` 已加载。
- Guard API 收到 heartbeat、审计事件和 runtime adapter 状态。
- `before_tool_call`、`message_sending`、`before_install`、`before_prompt_build`、`llm_input` 能按策略 fail closed。
- Dashboard 或 CLI 能查询到 OpenClaw 相关 audit、trace 和 provenance 数据。

## 边界

- 插件不保存 Dashboard browser session。
- 插件使用 adapter token，不使用 control token。
- 插件不修改 AgentGuard Core 规则，不直接写数据库。
- 插件不替代 OpenClaw 自身权限、沙箱、配置审计和安全扫描。
