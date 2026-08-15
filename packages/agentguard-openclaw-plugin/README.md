# AgentGuard OpenClaw Plugin

`@agentguard-ai/openclaw-plugin` 是 AgentGuard 的 OpenClaw runtime security plugin。它是 hook-only `definePluginEntry` 插件，不提供业务工具本身；插件负责在 OpenClaw 关键 hook 中构造 GuardEvent、调用 Guard API，并把 `allow`、`deny`、`ask` 映射为运行时控制结果。

## Hook 覆盖

默认启用 24 个 hook（RTE-03 新增 `after_tool_call`）：

```text
before_tool_call
after_tool_call
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

RTE-03 terminal outcome closure：`before_tool_call` 在返回前同步写入 GateState 与 policy linkage；`after_tool_call`（观察型，不进 fail-closed 清单）对已放行调用产 `execution_completed/failed` runtime_outcome 回执。两条硬安全约束：blocked/timed_out/binding_failed gate 下 after hook 到达只记诊断、绝不派生 terminal fact（pin `openclaw@2026.7.1-2` 已证明 blocked 调用也会触发 after hook，Q9）；成败只能用非空 `error` 字符串判定，不得依赖 result/error 字段存在性（falsy 成功两者皆无，Q5）。回执中 `tool_result_entered_context/persisted` 保持 null，`side_effects` 一律 not_measured。

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

## Windows 支持

Windows 上安装脚本使用 env provider 而非 file provider：OpenClaw 的 file secret provider 在无法可靠校验文件 ACL 时会 fail-closed 拒绝加载（Windows 没有 POSIX 0600 权限语义），导致插件无法注册。作为折中，安装脚本把 adapter token 写入 OpenClaw state 目录下的 `.env`（键 `AGENTGUARD_OPENCLAW_ADAPTER_TOKEN`），并在 `secrets.providers` 中配置 `source: "env"` 且 allowlist 只含该键。

必须明确的边界：

- 这是明文保管的折中方案，仅缓解「token 进入 OpenClaw 主配置 / 审计事件 / 日志」的问题，不宣称加密保管。
- state `.env` 与仓库根 `.env` 一样应被视为敏感文件；卸载时会删除该键。
- 后续可接入 DPAPI 或 Windows Credential Manager 的 exec provider 替换 env provider，接口契约（SecretRef）不变。

安装、卸载与 verify 的口径与 POSIX 一致：config patch dry-run 先行、失败按基线整体回滚、卸载只移除 AgentGuard 自有引用；不再使用 `openclaw plugins install --link`。CI 的 `openclaw-runtime-smoke` 矩阵 job 在 ubuntu-latest 与 windows-latest 上对真实 OpenClaw 运行时执行同一门禁。

## 运行时版本兼容

`package.json` 的 peer range 为 `openclaw >=2026.6.6 <2027.0.0`，这是允许安装的声明范围，不表示范围内每个版本都已实测。开发/证据 pin 自 PR-RTE-02 rev5 起为 `2026.7.1-2`（C2 Gate PASS 的证据版本）。当前经过真实运行时验证（安装、hooks 加载、heartbeat、verify、卸载清理）的版本仅为：

- `2026.6.6`（23-hook 集）
- `2026.7.1-2`（23-hook 集；RTE-03 的 24-hook 集以 CI `openclaw-runtime-smoke` 矩阵复验为准）

CI `openclaw-runtime-smoke` 门禁即以上述两个版本 × ubuntu/windows 为矩阵运行；新增兼容版本时应同步扩展该矩阵与本文档。

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

`pnpm openclaw:plugin:verify` 采用多证据口径：`plugins inspect`（loaded、24 hooks、staging 指向）、Gateway RPC 连通、Guard API 新鲜 heartbeat、enforce 模式与版本范围一致性；任一证据缺失即失败。

真实运行时兼容门禁（CI `openclaw-runtime-smoke` job）由 `scripts/openclaw-runtime-smoke.mjs` 驱动：工作区外安装指定版本 OpenClaw → 隔离 profile 事务化安装 → 随机端口真实前台 Gateway → 新鲜 heartbeat（loaded、24 hooks）→ 安装器 verify → 卸载与残留检查，输出脱敏 JSON 报告。本机隔离干跑示例：

```bash
node scripts/openclaw-runtime-smoke.mjs --openclaw-root <工作区外的 openclaw 安装根目录> --expect-version 2026.7.1-2
```

干跑只使用临时目录中的隔离 profile 与 `_test` 库，严禁指向真实 `~/.openclaw` profile 或用户正在运行的 Gateway。

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
