# AgentGuard OpenClaw Plugin

`@agentguard-ai/openclaw-plugin` 是 AgentGuard 的 OpenClaw runtime security plugin。它是 hook-only `definePluginEntry` 插件，不提供业务工具本身；插件负责在 OpenClaw 关键 hook 中构造 GuardEvent、调用 Guard API，并把 `allow`、`deny`、`ask` 映射为运行时控制结果。

## Hook 覆盖

默认启用 23 个 hook：

```text
before_tool_call
message_sending
before_install
before_agent_run
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

固定执行与 fail-closed 阶段：

```text
before_tool_call
message_sending
before_install
before_agent_run
before_agent_finalize
tool_result_persist
before_message_write
```

`before_agent_run` 是 OpenClaw 正式支持的模型输入 gate；`before_prompt_build`、`llm_input` 和 `llm_output` 是观察 hook，不再返回 SDK 不支持的伪 `block`。`before_agent_finalize` 可要求安全重写，最终外发仍由 `message_sending` 取消。`tool_result_persist` 和 `before_message_write` 是同步 hook，只执行本地脱敏、清洗或隔离；远端结果评估异步写入证据，不伪装成同步远端裁决。工具消息在进入下一次模型调用前，会在 `before_agent_run` 作为不可信上下文再次评估。

其他生命周期观察 hook 只记录审计；Guard API 不可用时不阻断 OpenClaw 基础生命周期。

## 配置

OpenClaw plugin config 示例：

```json
{
  "guardApiBaseUrl": "http://127.0.0.1:8088",
  "adapterToken": {
    "source": "file",
    "provider": "agentguard_adapter",
    "id": "value"
  },
  "agentId": "main",
  "enforcementMode": "enforce",
  "requestTimeoutMs": 5000,
  "approvalPollIntervalMs": 1000,
  "approvalTimeoutMs": 25000,
  "diagnosticLogging": false
}
```

`adapterToken` 只接受 OpenClaw SecretRef，OpenClaw 在插件注册前把它解析为字符串；明文 token 和插件内环境变量回退均不再支持。SecretRef provider 需在 OpenClaw 的 `secrets.providers` 中配置。仓库开发安装脚本会把根 `.env` 中的 token 写入权限为 `0600` 的 `.openclaw-dev/secrets/openclaw-adapter-token`，并配置 file SecretRef，token 不进入 OpenClaw 主配置。

`agentId` 必须与 `agentguardctl credential issue --runtime openclaw --agent-id <id>` 签发时绑定的 agent 一致。`approvalTimeoutMs` 是唯一审批等待上限；插件会把 Guard API 请求超时、审批超时和轮询间隔一并计入阻断 hook 的 SDK timeout。读取对话内容的 hook 需要 `hooks.allowConversationAccess=true`，开发安装脚本会写入该设置。

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
- `before_tool_call`、`message_sending`、`before_install` 和 `before_agent_run` 能返回 SDK 正式支持的阻断结果。
- `before_agent_finalize` 在策略拒绝或 Guard API 不可用时请求一次安全重写，`message_sending` 作为最终外发阻断面。
- 同步持久化 hook 能完成本地脱敏/隔离，工具结果远端评估及下一次模型输入 gate 均有审计证据。
- Dashboard 或 CLI 能查询到 OpenClaw 相关 audit、trace 和 provenance 数据。

## 边界

- 插件不保存 Dashboard browser session。
- 插件使用 adapter token，不使用 control token。
- 插件不修改 AgentGuard Core 规则，不直接写数据库。
- 插件不替代 OpenClaw 自身权限、沙箱、配置审计和安全扫描。
